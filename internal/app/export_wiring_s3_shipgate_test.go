//go:build shipgate

package app_test

// TestS3_ExportVerbWiredWhenConfigured is the S3 positive-composition guard for
// the export verb.
//
// Problem class: a refactor that re-nils deps.Decryptor, or that drops the
// "export" command registration from the cobra tree, silently removes the export
// capability without any existing negative-direction test catching it. The
// V-3.5 nil-fallback tests and the earlier S3 bridge tests guard only their own
// scope. This test closes the export-specific gap.
//
// What this test asserts:
//
//   - deps.Decryptor is non-nil when a fully-wired ADMIN environment is
//     configured. Because export is a thin shell over the Decryptor use-case,
//     a nil Decryptor means export silently fails at command time with a generic
//     "not configured" message rather than a permission denial — the wrong failure
//     mode. Non-nil is the necessary and sufficient condition for the export verb
//     to be operational; wiring correctness of the underlying crypto path is
//     asserted by the asymmetry_shipgate_test.go ADMIN/Export round-trip subtests.
//
//   - The cobra tree produced by NewRootCmdWithDeps includes an "export"
//     subcommand. A dropped cmd.AddCommand call would silently make the verb
//     vanish from the CLI; this assertion catches that category of regression.
//
// Strategy: reuse the D-1 fixture (real file:// registry signed by the ssh
// anchor, real admin age key, real project repo). After BuildProductionDeps the
// test asserts the two properties above. The same binary-availability guards
// used by TestD1_PositiveComposition are applied.

import (
	"context"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
)

// TestS3_ExportVerbWiredWhenConfigured is the positive-composition guard that
// ensures the export verb and its underlying Decryptor use-case are non-nil
// when a fully-configured ADMIN environment is wired via BuildProductionDeps.
//
// Naming: the TestS3_ prefix places this test inside the existing app-leg
// shipgate -run filter ('TestD1_PositiveComposition|TestV35_|TestS1_|TestS3_')
// so it is automatically included in `make test-shipgate`, ci.yml, and
// release.yml without any filter string change.
func TestS3_ExportVerbWiredWhenConfigured(t *testing.T) {
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

	// Primary guard: deps.Decryptor must be non-nil in a fully-wired ADMIN
	// environment. The export verb is a thin shell over this use-case; a nil
	// Decryptor silently degrades export to a "not configured" error at
	// command time instead of producing plaintext output.
	if deps.Decryptor == nil {
		t.Fatalf("deps.Decryptor is nil when registry and project repo are configured — " +
			"the Decryptor wiring at the composition root was silently dropped; " +
			"the export verb cannot function (silent-nil regression class)")
	}

	// Secondary guard: the cobra tree must contain the "export" command.
	// A dropped cmd.AddCommand("export", ...) call would silently remove the
	// verb from the CLI; this assertion surfaces that category of regression
	// at ship-gate time rather than in a production report.
	root := cli.NewRootCmdWithDeps(deps)
	exportFound := false
	for _, sub := range root.Commands() {
		if sub.Name() == "export" {
			exportFound = true
			break
		}
	}
	if !exportFound {
		t.Fatalf("cobra tree does not contain an 'export' subcommand — " +
			"the AddCommand call was dropped or the command name was changed; " +
			"verify newExportCmd is registered in NewRootCmdWithDeps")
	}
}
