//go:build shipgate

package app_test

// TestS3_RunVerbWiredWhenConfigured is the S3 positive-composition guard for
// the run verb.
//
// Problem class: a refactor that re-nils deps.RunChild, or that drops the "run"
// command registration from the cobra tree, silently removes the run capability
// without any existing negative-direction test catching it. This test closes
// the run-specific gap in the existing S3 suite.
//
// What this test asserts:
//
//   - deps.RunChild is non-nil when BuildProductionDeps is called in any
//     environment. RunChild is wired unconditionally (unlike Decryptor / Reviewer
//     which require a configured registry): runner.Run needs no external config,
//     so the closure is always constructible. A nil RunChild means the run verb
//     will surface a "not configured" error at command time — the wrong failure
//     mode for an unconfigured-registry environment.
//
//   - The cobra tree produced by NewRootCmdWithDeps includes a "run" subcommand.
//     A dropped cmd.AddCommand call would silently make the verb vanish from the
//     CLI; this assertion catches that category of regression at ship-gate time.
//
// Strategy: reuse the D-1 fixture (real file:// registry signed by the ssh
// anchor, real admin age key, real project repo). After BuildProductionDeps the
// test asserts the two properties above. The same binary-availability guards
// used by TestD1_PositiveComposition are applied.
//
// Naming: the TestS3_ prefix places this test inside the existing app-leg
// shipgate -run filter ('TestD1_PositiveComposition|TestV35_|TestS1_|TestS3_')
// so it is automatically included in `make test-shipgate`, ci.yml, and
// release.yml without any filter string change.

import (
	"context"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
)

// TestS3_RunVerbWiredWhenConfigured is the positive-composition guard that
// ensures the run verb's RunChild func-field is non-nil (wired unconditionally)
// and that the "run" subcommand is present in the cobra tree returned by
// NewRootCmdWithDeps.
func TestS3_RunVerbWiredWhenConfigured(t *testing.T) {
	if d1GitMissing() {
		t.Fatalf("required binary 'git' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}
	if d1SSHKeygenMissing() {
		t.Fatalf("required binary 'ssh-keygen' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	fx := newD1Fixture(t)
	fx.applyAdminEnv(t)

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps returned error: %v", err)
	}

	// Primary guard: deps.RunChild must be non-nil. Unlike read-path use-cases
	// that require a configured registry, RunChild is wired unconditionally
	// (runner.Run needs no external config). A nil here means a wiring regression
	// at the composition root — the run verb would surface "not configured" in
	// every environment instead of running the child process.
	if deps.RunChild == nil {
		t.Fatalf("deps.RunChild is nil — " +
			"buildRunChildProd was not called or its return was not assigned in " +
			"BuildProductionDeps; the run verb cannot function (silent-nil regression class)")
	}

	// Secondary guard: the cobra tree must contain the "run" command.
	// A dropped cmd.AddCommand("run", ...) call would silently remove the verb
	// from the CLI; this assertion surfaces that category of regression at
	// ship-gate time rather than in a production report.
	root := cli.NewRootCmdWithDeps(deps)
	runFound := false
	for _, sub := range root.Commands() {
		if sub.Name() == "run" {
			runFound = true
			break
		}
	}
	if !runFound {
		t.Fatalf("cobra tree does not contain a 'run' subcommand — " +
			"the AddCommand call was dropped or the command name was changed; " +
			"verify newRunCmd is registered in NewRootCmdWithDeps")
	}
}
