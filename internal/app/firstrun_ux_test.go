package app_test

// Tests for the first-run UX fix: meta-commands (help, version, completion)
// must succeed with EXIT 0 and zero configuration, while commands that
// actually touch secrets or the registry still fail closed when config is
// absent (fail-closed posture preserved, deferred to command time).

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/pkg/byreis"
)

// clearEnvForFirstRunTests removes environment variables that could cause
// production adapters to find real configuration on the test host.
func clearEnvForFirstRunTests(t *testing.T) {
	t.Helper()
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_PROJECT_REPO", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("BYREIS_KEY", "")
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_CACHE", t.TempDir())
	t.Setenv("BYREIS_NON_INTERACTIVE", "1")
}

// buildRootCmdNoEnv builds the real production cobra root command with no
// configuration in the environment. This exercises the full composition
// path that main.go uses.
func buildRootCmdNoEnv(t *testing.T) *cli.Deps {
	t.Helper()
	clearEnvForFirstRunTests(t)
	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps must succeed with no env: %v", err)
	}
	if deps == nil {
		t.Fatal("BuildProductionDeps returned nil deps with no env")
	}
	return deps
}

// TestFirstRunUX_VersionCmd verifies that `byreis version` exits 0 and
// prints the version string with no configuration in the environment.
func TestFirstRunUX_VersionCmd(t *testing.T) {
	deps := buildRootCmdNoEnv(t)
	root := cli.NewRootCmdWithDeps(deps)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("version must succeed with no env, got: %v", err)
	}
	if !strings.Contains(out.String(), byreis.Version) {
		t.Errorf("version output %q does not contain version string %q", out.String(), byreis.Version)
	}
}

// TestFirstRunUX_HelpFlag verifies that `byreis --help` exits 0 with no
// configuration in the environment.
func TestFirstRunUX_HelpFlag(t *testing.T) {
	deps := buildRootCmdNoEnv(t)
	root := cli.NewRootCmdWithDeps(deps)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})

	// cobra.Execute returns nil for --help (it prints and exits).
	// The command either exits 0 (nil error) or sets help flag and returns nil.
	err := root.Execute()
	if err != nil {
		t.Fatalf("--help must succeed with no env, got: %v", err)
	}
}

// TestFirstRunUX_NoArgs verifies that `byreis` (no args) exits 0 and prints
// help with no configuration in the environment.
func TestFirstRunUX_NoArgs(t *testing.T) {
	deps := buildRootCmdNoEnv(t)
	root := cli.NewRootCmdWithDeps(deps)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{})

	// A root command with no RunE and no args prints help and returns nil.
	err := root.Execute()
	if err != nil {
		t.Fatalf("byreis with no args must succeed with no env, got: %v", err)
	}
}

// TestFirstRunUX_CompletionBash verifies that `byreis completion bash` exits 0
// with no configuration in the environment.
func TestFirstRunUX_CompletionBash(t *testing.T) {
	deps := buildRootCmdNoEnv(t)
	root := cli.NewRootCmdWithDeps(deps)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"completion", "bash"})

	if err := root.Execute(); err != nil {
		t.Fatalf("completion bash must succeed with no env, got: %v", err)
	}
	if !strings.Contains(out.String(), "bash") {
		t.Errorf("completion output does not look like bash completion script: %q", out.String()[:min(200, len(out.String()))])
	}
}

// TestFirstRunUX_FailClosed_GetWithNoConfig is the critical fail-closed
// regression test. It verifies that `byreis get` with no configuration
// STILL fails (non-zero error) even after the first-run UX fix. The deferred
// fail-closed posture must be identical: the error occurs at command time
// (not at startup), but it still occurs.
func TestFirstRunUX_FailClosed_GetWithNoConfig(t *testing.T) {
	deps := buildRootCmdNoEnv(t)
	root := cli.NewRootCmdWithDeps(deps)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"get", "--key", "SOME_KEY"})

	err := root.Execute()
	if err == nil {
		t.Fatal("get with no config must fail closed; got nil error (command succeeded without deps)")
	}
	// Exit code must be non-zero. ExitCodeOf returns 1 for general errors.
	code := cli.ExitCodeOf(err)
	if code == 0 {
		t.Errorf("get with no config must return non-zero exit code; got 0")
	}
}

// TestFirstRunUX_FailClosed_GetNilGetter verifies the nil-Getter guard in the
// get command: when deps.Getter is nil, the command returns a "not configured"
// error, not a panic or a silent success.
func TestFirstRunUX_FailClosed_GetNilGetter(t *testing.T) {
	clearEnvForFirstRunTests(t)

	// Build deps without a registry — Getter will be nil.
	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps: %v", err)
	}
	if deps.Getter != nil {
		t.Skip("Getter is non-nil in this environment; skipping nil-guard test")
	}

	root := cli.NewRootCmdWithDeps(deps)

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"get", "--key", "ANY_KEY"})

	cmdErr := root.Execute()
	if cmdErr == nil {
		t.Fatal("get with nil Getter must return an error; got nil (silent success is a regression)")
	}
}

// min is a local helper because math.Min works on float64.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
