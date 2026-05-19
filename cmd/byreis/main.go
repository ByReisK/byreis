// Command byreis is the entry point for the byreis CLI.
// It wires the cobra root, builds adapters, injects them into core, and sets
// the process exit code. No business logic lives here.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/mode"
)

func main() {
	ctx := context.Background()

	deps := buildDeps(ctx)

	root := cli.NewRootCmdWithDeps(deps)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(cli.ExitCodeOf(err))
	}
}

// buildDeps constructs the real Deps for the production wiring path. It calls
// Detector.Detect before command dispatch so every command receives the
// cryptographically-derived mode. On any detector error or misconfiguration
// the deps fall back to least privilege (ModeContributor) with a non-nil Policy
// so review/merge hit a real denial, not a nil-skip.
func buildDeps(ctx context.Context) *cli.Deps {
	det := realDetector()
	pol := &mode.Policy{}

	detResult, err := det.Detect(ctx, projectIDFromEnv())
	var currentMode mode.Mode
	if err != nil {
		// Fail closed: least privilege. Policy is still non-nil so all
		// admin-only commands receive a real ErrPermissionDenied denial.
		currentMode = mode.ModeContributor
	} else {
		currentMode = detResult.Mode
	}

	return &cli.Deps{
		Policy:      pol,
		CurrentMode: currentMode,
		ConfigDir:   configDirFromEnv(),
	}
}

// realDetector builds a mode.Detector using no-op probes. Full adapter wiring
// (keychain, registry) will be added as the adapters are completed. The
// detector is functional for the permission gate: with no-op probes it always
// resolves ModeContributor (least privilege), which is the correct safe default
// before the key/registry adapters are wired.
func realDetector() *mode.Detector {
	return &mode.Detector{
		Probe:    &noopKeyProbe{},
		Registry: &noopRegistryTrust{},
		Clock:    &wallClock{},
		Audit:    audit.Discard,
	}
}

// projectIDFromEnv reads the project ID from the environment for mode
// detection. An empty string is safe: mode detection falls back to
// ModeContributor when no project can be identified.
func projectIDFromEnv() string {
	return os.Getenv("BYREIS_PROJECT")
}

// configDirFromEnv returns the config directory path. Defaults to
// ~/.config/byreis/ following the BYREIS_CONFIG env var convention.
func configDirFromEnv() string {
	if v := os.Getenv("BYREIS_CONFIG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.config/byreis"
}

// ---- no-op mode ports for the production skeleton ---------------------------
// Full implementations will be wired when the keychain/registry adapters land.
// These no-ops produce ModeContributor (least privilege) without any I/O.

type noopKeyProbe struct{}

func (n *noopKeyProbe) KeyFilePath(_ context.Context) string                    { return "" }
func (n *noopKeyProbe) KeyFilePerms(_ context.Context) (uint32, error)          { return 0, nil }
func (n *noopKeyProbe) CanDecryptAny(_ context.Context, _ string) (bool, error) { return false, nil }

type noopRegistryTrust struct{}

func (n *noopRegistryTrust) IsRegisteredAdmin(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// wallClock wraps time.Now() for mode detection. Real wall clock is appropriate
// here: main.go is the wiring layer, not a unit test.
type wallClock struct{}

func (w *wallClock) Now() interface{ Unix() int64 } {
	return time.Now()
}
