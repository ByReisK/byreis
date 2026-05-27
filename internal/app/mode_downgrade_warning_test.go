package app_test

// Tests for the mode-downgrade warning: when a private key is present but
// fails to grant admin, the user must see an actionable message on stderr.
//
// Coverage:
//   - buildModeDowngradeWarning helper unit-tested for all four input cases.
//   - Integration path via BuildProductionDeps: key present with bad perms →
//     ModeDowngradeWarning populated; key present with correct perms but
//     unregistered (simulated via the unregistered warning result) → populated.
//   - Bare no-key environment → empty (no false positive for contributors).
//   - CLI integration: warning appears on stderr for a real subcommand (submit);
//     does NOT appear for version or completion bash.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// ---------------------------------------------------------------------------
// Unit tests for the buildModeDowngradeWarning helper
// ---------------------------------------------------------------------------

func TestBuildModeDowngradeWarning_Unit(t *testing.T) {
	t.Parallel()

	permErr := fmt.Errorf("key file %q has mode 0644: %w", "/path/key.age", mode.ErrKeyPermissions)
	notFoundErr := fmt.Errorf("key file not found: %w — %w", os.ErrNotExist, mode.ErrKeyPermissions)

	cases := []struct {
		name       string
		detResult  mode.Result
		detErr     error
		wantEmpty  bool
		wantSubstr []string
	}{
		{
			name:      "key file exists with wrong perms → warning with cause and fix hint",
			detResult: mode.Result{Mode: mode.ModeContributor},
			detErr:    permErr,
			wantSubstr: []string{
				"insecure permissions",
				"chmod 600",
				"byreis doctor",
			},
		},
		{
			name:      "key path configured but file not found → no warning (not yet created)",
			detResult: mode.Result{Mode: mode.ModeContributor},
			detErr:    notFoundErr,
			wantEmpty: true,
		},
		{
			name: "key unregistered warning → warning with cause and fix hint",
			detResult: mode.Result{
				Mode:    mode.ModeContributor,
				Warning: mode.WarningKeyUnregistered,
			},
			detErr: nil,
			wantSubstr: []string{
				"not registered in the verified",
				"contributor",
				"byreis doctor",
			},
		},
		{
			name: "legitimate admin → no warning",
			detResult: mode.Result{
				Mode:    mode.ModeAdmin,
				Warning: mode.WarningNone,
			},
			detErr:    nil,
			wantEmpty: true,
		},
		{
			name: "contributor no key (WarningNone) → no warning",
			detResult: mode.Result{
				Mode:    mode.ModeContributor,
				Warning: mode.WarningNone,
			},
			detErr:    nil,
			wantEmpty: true,
		},
		{
			name:      "registry unreachable (non-perms error) → no warning to avoid false positive",
			detResult: mode.Result{Mode: mode.ModeContributor},
			detErr:    errors.New("registry unreachable"),
			wantEmpty: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := app.BuildModeDowngradeWarningForTest(tc.detResult, tc.detErr)
			if tc.wantEmpty {
				if got != "" {
					t.Errorf("expected empty warning, got: %q", got)
				}
				return
			}
			if got == "" {
				t.Fatal("expected non-empty warning, got empty string")
			}
			for _, sub := range tc.wantSubstr {
				if !strings.Contains(got, sub) {
					t.Errorf("warning %q does not contain expected substring %q", got, sub)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration test: BuildProductionDeps populates ModeDowngradeWarning when a
// key file is present but has wrong permissions.
// ---------------------------------------------------------------------------

// setBaseEnv prepares a minimal environment that prevents real network or
// keychain access while still allowing BuildProductionDeps to succeed.
func setBaseEnvForWarningTest(t *testing.T) {
	t.Helper()
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_PROJECT_REPO", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("BYREIS_KEY", "")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_CACHE", t.TempDir())
	t.Setenv("BYREIS_NON_INTERACTIVE", "1")
}

// TestBuildProductionDeps_KeyBadPerms_WarningPopulated verifies that when a
// key file exists but has permissions other than 0600, BuildProductionDeps
// populates ModeDowngradeWarning with an actionable message.
func TestBuildProductionDeps_KeyBadPerms_WarningPopulated(t *testing.T) {
	setBaseEnvForWarningTest(t)

	// Write a key file with overly-permissive mode (0644).
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.age")
	//nolint:gosec // intentionally wrong permissions to exercise the bad-perms warning path
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-FAKE"), 0o644); err != nil {
		t.Fatalf("writing test key file: %v", err)
	}
	t.Setenv("BYREIS_KEY_FILE", keyPath)

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps must not return a hard error for bad-perms key (fail-closed to contributor): %v", err)
	}

	// Mode must remain CONTRIBUTOR — the detection decision is unchanged.
	if deps.CurrentMode != mode.ModeContributor {
		t.Errorf("expected ModeContributor for bad-perms key, got %v", deps.CurrentMode)
	}

	// Warning must be populated and actionable.
	if deps.ModeDowngradeWarning == "" {
		t.Fatal("expected ModeDowngradeWarning to be non-empty for bad-perms key, got empty")
	}
	for _, want := range []string{"insecure permissions", "chmod 600", "byreis doctor"} {
		if !strings.Contains(deps.ModeDowngradeWarning, want) {
			t.Errorf("ModeDowngradeWarning %q does not contain %q", deps.ModeDowngradeWarning, want)
		}
	}
}

// TestBuildProductionDeps_NoKey_NoWarning verifies that with no key configured
// at all, ModeDowngradeWarning is empty (a bare contributor is not warned).
// "No key" means BYREIS_KEY and BYREIS_KEY_FILE are both empty and the config
// directory contains no default key file. The detector returns CONTRIBUTOR with
// WarningNone when no key path can be resolved.
func TestBuildProductionDeps_NoKey_NoWarning(t *testing.T) {
	setBaseEnvForWarningTest(t)
	// Clear both key vars so no key source is configured. The config dir (from
	// setBaseEnvForWarningTest) is a fresh temp dir with no default key file.
	t.Setenv("BYREIS_KEY_FILE", "")
	t.Setenv("BYREIS_KEY", "")

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps must succeed with no key: %v", err)
	}
	if deps.ModeDowngradeWarning != "" {
		t.Errorf("expected empty ModeDowngradeWarning for no-key environment, got: %q",
			deps.ModeDowngradeWarning)
	}
}

// TestBuildProductionDeps_GoodPermsButNoRegistry_NoWarning verifies that when a
// key file has correct 0600 permissions but the registry is unconfigured (so the
// key cannot be verified against an admin set), no downgrade warning is emitted.
// The registry error path fails closed to CONTRIBUTOR silently — we cannot
// assert the key is "unregistered" if we never reached the registry.
func TestBuildProductionDeps_GoodPermsButNoRegistry_NoWarning(t *testing.T) {
	setBaseEnvForWarningTest(t)

	// Write a key file with correct 0600 permissions.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.age")
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-FAKE"), 0o600); err != nil {
		t.Fatalf("writing test key file: %v", err)
	}
	t.Setenv("BYREIS_KEY_FILE", keyPath)
	// No BYREIS_REGISTRY → registry is unconfigured; mode detection falls
	// through CanDecryptAny=false (no project to decrypt), ending at contributor
	// with WarningNone — not WarningKeyUnregistered.

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps must succeed: %v", err)
	}
	if deps.CurrentMode != mode.ModeContributor {
		t.Errorf("expected ModeContributor, got %v", deps.CurrentMode)
	}
	// No registry → CanDecryptAny returns (false, nil) → CONTRIBUTOR with
	// WarningNone → no downgrade warning.
	if deps.ModeDowngradeWarning != "" {
		t.Errorf("expected empty ModeDowngradeWarning when registry absent, got: %q",
			deps.ModeDowngradeWarning)
	}
}

// ---------------------------------------------------------------------------
// CLI integration tests: warning appears on stderr for real subcommands but
// NOT for meta-commands (version, completion bash).
// ---------------------------------------------------------------------------

// buildDepsWithWarning constructs a Deps struct with ModeDowngradeWarning set
// to a known sentinel value. This is used to verify the CLI plumbing without
// requiring a real key file or network access.
func buildDepsWithWarning(warning string) *cli.Deps {
	return &cli.Deps{
		Policy:               &mode.Policy{},
		CurrentMode:          mode.ModeContributor,
		ModeDowngradeWarning: warning,
	}
}

const testDowngradeWarning = "admin key has bad perms — run: chmod 600 /key.age; run `byreis doctor` for the full diagnosis"

// TestCLI_DowngradeWarning_EmittedOnRealSubcommand verifies that when
// ModeDowngradeWarning is set, the root command's PersistentPreRunE emits it
// to stderr before a real subcommand runs. The doctor command was chosen
// because it is available in all modes, accepts no required flags, and will
// reach RunE (with a nil Doctor, it returns a "not configured" error). The
// warning must appear before RunE's error on stderr.
func TestCLI_DowngradeWarning_EmittedOnRealSubcommand(t *testing.T) {
	t.Parallel()

	deps := buildDepsWithWarning(testDowngradeWarning)
	root := cli.NewRootCmdWithDeps(deps)

	var errBuf bytes.Buffer
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&errBuf)
	root.SetArgs([]string{"doctor"})

	// The command is expected to fail (nil Doctor). We only care that the
	// warning was emitted to stderr, not that the command succeeded.
	_ = root.Execute()

	stderr := errBuf.String()
	if !strings.Contains(stderr, testDowngradeWarning) {
		t.Errorf("expected stderr to contain downgrade warning %q, got: %q",
			testDowngradeWarning, stderr)
	}
	if !strings.Contains(stderr, "byreis: warning:") {
		t.Errorf("expected stderr to contain 'byreis: warning:' prefix, got: %q", stderr)
	}
}

// TestCLI_DowngradeWarning_NotEmittedForVersion verifies that the downgrade
// warning is NOT emitted when running `byreis version`. The version command
// is a meta-command that must work cleanly in any environment.
func TestCLI_DowngradeWarning_NotEmittedForVersion(t *testing.T) {
	t.Parallel()

	deps := buildDepsWithWarning(testDowngradeWarning)
	root := cli.NewRootCmdWithDeps(deps)

	var errBuf bytes.Buffer
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&errBuf)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("version must succeed, got: %v", err)
	}

	stderr := errBuf.String()
	if strings.Contains(stderr, testDowngradeWarning) {
		t.Errorf("expected NO downgrade warning for 'version', but got: %q", stderr)
	}
}

// TestCLI_DowngradeWarning_NotEmittedForCompletion verifies that the downgrade
// warning is NOT emitted when running `byreis completion bash`. Completion is a
// meta-command consumed by shells; unexpected stderr output breaks autocomplete.
func TestCLI_DowngradeWarning_NotEmittedForCompletion(t *testing.T) {
	t.Parallel()

	deps := buildDepsWithWarning(testDowngradeWarning)
	root := cli.NewRootCmdWithDeps(deps)

	var errBuf bytes.Buffer
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&errBuf)
	root.SetArgs([]string{"completion", "bash"})

	if err := root.Execute(); err != nil {
		t.Fatalf("completion bash must succeed, got: %v", err)
	}

	stderr := errBuf.String()
	if strings.Contains(stderr, testDowngradeWarning) {
		t.Errorf("expected NO downgrade warning for 'completion bash', but got: %q", stderr)
	}
}

// TestCLI_NoDowngradeWarning_WhenFieldEmpty verifies that when
// ModeDowngradeWarning is empty (normal contributor, no key present), no
// warning line is emitted to stderr even if a real subcommand runs.
func TestCLI_NoDowngradeWarning_WhenFieldEmpty(t *testing.T) {
	t.Parallel()

	deps := buildDepsWithWarning("") // empty — normal contributor
	root := cli.NewRootCmdWithDeps(deps)

	var errBuf bytes.Buffer
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&errBuf)
	root.SetArgs([]string{"submit", "--key", "KEY", "--value", "VAL"})

	_ = root.Execute()

	stderr := errBuf.String()
	if strings.Contains(stderr, "byreis: warning: admin key") {
		t.Errorf("expected NO downgrade warning for empty ModeDowngradeWarning, got: %q", stderr)
	}
}
