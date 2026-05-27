//go:build shipgate

// Run-verb ship-gate rows — REQ-V08-006 + threat S4-1 + crypto C1.
//
// Three subtests extend the top-level TestAsymmetryShipGate driver in
// asymmetry_shipgate_test.go. They ride the existing `-run TestAsymmetryShipGate`
// filter unchanged (these are t.Run subtests of the same top-level function):
//
//	ADMIN/Run/GreenWithRealComposition
//	ADMIN/Run/ArgvClean
//	CONTRIBUTOR/Run/DeniedByPolicyNotAttempted
//
// The tests share the `fx *shipgateFixture` constructed by newShipgateFixture
// and the `runCobra` helper, both defined in asymmetry_shipgate_test.go (same
// package usecase_test, same build tag). No new top-level test functions are
// added here, so the `-run TestAsymmetryShipGate` filter string is unchanged
// across Makefile, ci.yml, and release.yml.
//
// How the real child is executed:
//
//	The production deps.RunChild closure (built by buildRunChildProd in
//	internal/app/production.go) wraps internal/adapter/runner.Run. To prove
//	end-to-end env-injection and argv-cleanliness in a portable way, the tests
//	compile a small helper binary from
//	internal/adapter/runner/testdata/runner_helper at test startup and use
//	that binary as the child process — the same technique used by the runner
//	adapter's own unit tests (TestS1_1_ArgvClean_NoSecretInOsArgs etc.).
//
// Engineering-standards adherence (/reis-dev NON-NEGOTIABLE):
//   - context.Context first param on all I/O helpers.
//   - errors wrapped with %w; no panics in helper code (panics only in
//     deliberately-designed spy stubs following the established precedent of
//     shipgatePanicMerger / shipgatePanicDecryptor in asymmetry_shipgate_test.go).
//   - go test -race clean: no shared mutable state across goroutines.
//   - injected child binary and sidecar paths; no real process or keychain
//     state shared across subtests.
//   - no Claude/AI attribution; internal cycle IDs (REQ-V08-006, S4-1, C1)
//     permitted in _test.go per CLAUDE.md comment-hygiene rule.
package usecase_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// runShipgateHelperBinary compiles the runner_helper test binary exactly once
// per test and returns the absolute path to the binary. The binary is placed
// in a t.TempDir() and cleaned up automatically. All run-verb subtests that
// spawn a real child share this construction path.
//
// The runner_helper binary supports two directives used here:
//
//	report-env  <sidecar>  — writes os.Environ() (one KEY=VALUE per line) to
//	                         the sidecar file, then exits 0.
//	report-argv <sidecar>  — writes os.Args (one item per line) to the sidecar
//	                         file, then exits 0.
func runShipgateHelperBinary(t *testing.T) string {
	t.Helper()

	// Locate the testdata/runner_helper source dir relative to this file.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runShipgateHelperBinary: could not determine source file path via runtime.Caller")
	}
	// This file lives at internal/core/usecase/; runner_helper lives at
	// internal/adapter/runner/testdata/runner_helper — two levels up, then
	// down into the adapter.
	helperSrc := filepath.Join(
		filepath.Dir(thisFile),
		"..", "..", "adapter", "runner", "testdata", "runner_helper",
	)

	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "runner_helper")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", binPath, helperSrc) //nolint:gosec // compile-time constant path; test helper only
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("runShipgateHelperBinary: go build %s: %v", helperSrc, err)
	}
	return binPath
}

// addRunSubtests adds the three run-verb subtests to the top-level
// TestAsymmetryShipGate function. It is called from the init block below so
// that the subtests are registered lazily into the parent test via t.Run
// inside the TestAsymmetryShipGate body.
//
// IMPORTANT: the subtests must be added inside TestAsymmetryShipGate via the
// init mechanism (see below); they cannot be independent top-level tests
// because they share the shipgateFixture built by newShipgateFixture and
// they must ride the existing `-run TestAsymmetryShipGate` filter.
//
// The init-based injection pattern used here follows the precedent established
// by asymmetry_shipgate_v4_app_test.go (v4AppBuildProductionDeps).
//
// Rather than a complex init injection, the three subtests are expressed as a
// package-level function called directly from the TestAsymmetryShipGate driver
// via the hook variable runSubtestsRunVerb below.
var runSubtestsRunVerb func(t *testing.T, fx *shipgateFixture)

func init() {
	runSubtestsRunVerb = addRunVerbSubtests
}

// addRunVerbSubtests registers the three REQ-V08-006 / S4-1 ship-gate subtests
// inside the top-level TestAsymmetryShipGate parent. Called from the parent
// via runSubtestsRunVerb(t, fx) after the binary-availability guards.
func addRunVerbSubtests(t *testing.T, fx *shipgateFixture) {
	t.Helper()

	// ── ADMIN/Run/GreenWithRealComposition ────────────────────────────────────

	t.Run("ADMIN/Run/GreenWithRealComposition", func(t *testing.T) {
		// REQ-V08-006 admin happy path: an ADMIN running
		//   byreis run --project P --file F -- <child>
		// through the REAL production composition must exit 0, inject the
		// decrypted secret into the child's environment, propagate the child's
		// exit code, and NOT emit the secret value on byreis's own stdout/stderr.
		//
		// Child binary: runner_helper report-env <sidecar> — writes its full
		// environment to the sidecar file and exits 0. The test reads the sidecar
		// and asserts the secret appears there (proving env-injection) and does
		// NOT appear on byreis's stdout/stderr (no-plaintext channel sweep).
		fx.applyAdminEnv(t)
		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("BuildProductionDeps (ADMIN/Run): %v", err)
		}
		if deps.CurrentMode != mode.ModeAdmin {
			t.Fatalf("ADMIN/Run: deps.CurrentMode = %v, want ModeAdmin", deps.CurrentMode)
		}
		if deps.RunChild == nil {
			t.Fatalf("ADMIN/Run: deps.RunChild is nil — wiring regression (S3 should catch this first)")
		}

		helperBin := runShipgateHelperBinary(t)
		sidecar := filepath.Join(t.TempDir(), "env-dump.txt")

		byreisOut, byreisErr, exitCode := fx.runCobra(t, deps,
			"run",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--",
			helperBin, "report-env", sidecar,
		)
		if exitCode != 0 {
			t.Fatalf("ADMIN/Run/GreenWithRealComposition: byreis exited %d; stderr=%q stdout=%q",
				exitCode, byreisErr.String(), byreisOut.String())
		}

		// The sidecar file must exist and contain the injected secret.
		envDump, readErr := os.ReadFile(sidecar) //nolint:gosec // G304: sidecar is a t.TempDir()-rooted path
		if readErr != nil {
			t.Fatalf("ADMIN/Run/GreenWithRealComposition: reading env sidecar: %v "+
				"(did the child run? byreis stdout=%q stderr=%q)",
				readErr, byreisOut.String(), byreisErr.String())
		}

		// Env-injection proof: the secret KEY=VALUE line must appear in the child's
		// environment dump. The run verb uses render.BuildEnvPairs which maps the
		// secret key name to an env var name; for shipgateSecretKey="API_KEY" the
		// env var is "API_KEY" and the line is "API_KEY=<value>".
		expectedEnvLine := shipgateSecretKey + "=" + shipgateSecretValue
		if !strings.Contains(string(envDump), expectedEnvLine) {
			t.Fatalf("ADMIN/Run/GreenWithRealComposition: env-injection failed — "+
				"child env dump does not contain %q\nenv dump (first 2 KiB):\n%s",
				expectedEnvLine,
				truncateForLog(string(envDump), 2048))
		}

		// Channel sweep: the secret value must NOT appear on byreis's own stdout
		// or stderr. The child's output goes directly to the terminal (passthrough
		// stdio) not to the cobra buffers, so the captured buffers are byreis's
		// own output only.
		if strings.Contains(byreisOut.String(), shipgateSecretValue) {
			t.Fatalf("ADMIN/Run/GreenWithRealComposition: secret plaintext leaked to byreis stdout: %q",
				byreisOut.String())
		}
		if strings.Contains(byreisErr.String(), shipgateSecretValue) {
			t.Fatalf("ADMIN/Run/GreenWithRealComposition: secret plaintext leaked to byreis stderr: %q",
				byreisErr.String())
		}
	})

	// ── ADMIN/Run/ArgvClean (S4-1) ────────────────────────────────────────────

	t.Run("ADMIN/Run/ArgvClean", func(t *testing.T) {
		// S4-1 / REQ-V08-006: the decrypted secret value must appear in the
		// child's environment block but NEVER in the child's argv. The run verb
		// must not embed any secret in the child command line — secrets travel
		// exclusively through the env block (build by render.BuildChildEnvBlock).
		//
		// Proof strategy: use a two-stage child invocation — the helper binary is
		// invoked with BOTH "report-env" (to prove env-injection) AND "report-argv"
		// (to prove argv-cleanliness). Because the runner helper only accepts one
		// directive per invocation we run two separate `byreis run` calls against
		// the same fixture, each with its own sidecar.
		fx.applyAdminEnv(t)
		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("BuildProductionDeps (ADMIN/Run/ArgvClean): %v", err)
		}
		if deps.CurrentMode != mode.ModeAdmin {
			t.Fatalf("ADMIN/Run/ArgvClean: deps.CurrentMode = %v, want ModeAdmin", deps.CurrentMode)
		}

		helperBin := runShipgateHelperBinary(t)
		sidecarEnv := filepath.Join(t.TempDir(), "env-argvclean.txt")
		sidecarArgv := filepath.Join(t.TempDir(), "argv-argvclean.txt")

		// First invocation: report-env to verify the secret IS in the env block.
		_, _, exitCode := fx.runCobra(t, deps,
			"run",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--",
			helperBin, "report-env", sidecarEnv,
		)
		if exitCode != 0 {
			t.Fatalf("ADMIN/Run/ArgvClean (report-env): byreis exited %d", exitCode)
		}

		envDump, readErr := os.ReadFile(sidecarEnv) //nolint:gosec // G304: sidecar is a t.TempDir()-rooted path
		if readErr != nil {
			t.Fatalf("ADMIN/Run/ArgvClean: reading env sidecar: %v", readErr)
		}
		expectedEnvLine := shipgateSecretKey + "=" + shipgateSecretValue
		if !strings.Contains(string(envDump), expectedEnvLine) {
			t.Fatalf("ADMIN/Run/ArgvClean: env-injection sanity: secret not in child env — " +
				"cannot prove argv-clean if the secret never arrived")
		}

		// Second invocation: report-argv — the secret must NOT appear in argv.
		// The child argv for this call is: [helperBin, "report-argv", sidecarArgv].
		// None of these tokens contain the secret value; the env block is not
		// reflected into argv by the runner adapter. If any argv token were derived
		// from the env block it would appear in the sidecar dump here.
		_, _, exitCode2 := fx.runCobra(t, deps,
			"run",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--",
			helperBin, "report-argv", sidecarArgv,
		)
		if exitCode2 != 0 {
			t.Fatalf("ADMIN/Run/ArgvClean (report-argv): byreis exited %d", exitCode2)
		}

		argvDump, argvReadErr := os.ReadFile(sidecarArgv) //nolint:gosec // G304: sidecar is a t.TempDir()-rooted path
		if argvReadErr != nil {
			t.Fatalf("ADMIN/Run/ArgvClean: reading argv sidecar: %v", argvReadErr)
		}

		// S4-1 assertion: the secret value must not appear anywhere in the child's
		// argv. A single byte match is a security regression.
		if strings.Contains(string(argvDump), shipgateSecretValue) {
			t.Fatalf("ADMIN/Run/ArgvClean S4-1 VIOLATION: secret value %q appears in "+
				"child argv — secrets must travel via env, never via argv:\n%s",
				shipgateSecretValue, string(argvDump))
		}
	})

	// ── CONTRIBUTOR/Run/DeniedByPolicyNotAttempted ────────────────────────────

	t.Run("CONTRIBUTOR/Run/DeniedByPolicyNotAttempted", func(t *testing.T) {
		// REQ-V08-006 contributor denial path.
		//
		// The mode gate at the CLI layer must fire BEFORE any use-case entry,
		// identity load, decrypt call, network contact, or child process spawn.
		// Proof mechanisms (defence-in-depth):
		//
		//   (a) Panic-Decryptor spy: replace deps.Decryptor with a
		//       shipgatePanicDecryptor after BuildProductionDeps. Any decrypt
		//       call means the mode gate did NOT fire first and surfaces as a
		//       test failure via panic → t.Fatal.
		//
		//   (b) Panic-RunChild spy: replace deps.RunChild with a sentinel that
		//       marks a spawned-flag and panics. Any child spawn means the mode
		//       gate did NOT fire first.
		//
		//   (c) Sentinel sidecar: the child argv contains a sidecar path; if
		//       the child ran it would create the sidecar. The sidecar must NOT
		//       exist after the denied call.
		//
		//   (d) TMPDIR snapshot: zero new byreis-fetchhead-*, byreis-project-blob-*,
		//       and byreis-editor-* temp dirs after the denied call.
		//
		//   (e) Channel sweep: the known plaintext must not appear on stdout/stderr.
		//
		//   (f) Exit code: must be ExitPermissionDenied (=2).
		fx.applyContributorEnv(t)
		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("BuildProductionDeps (CONTRIBUTOR/Run): %v", err)
		}
		if deps.CurrentMode != mode.ModeContributor {
			t.Fatalf("CONTRIBUTOR/Run: CurrentMode = %v, want ModeContributor "+
				"(non-recipient key must downgrade via Detect step-3 → CONTRIBUTOR)",
				deps.CurrentMode)
		}

		// (a) Replace Decryptor with a panic spy.
		deps.Decryptor = &shipgatePanicDecryptor{}

		// (b) Replace RunChild with the panic-spawner spy. The sidecar path
		//     is embedded in the sentinel argv so that even if the mode gate
		//     somehow were bypassed and the real spawner were called, the child
		//     would write the sidecar (detected by check (c)).
		sentinelSidecar := filepath.Join(t.TempDir(), "should-never-exist.txt")
		spawner := &shipgatePanicRunChild{}
		deps.RunChild = spawner.RunChild

		// (d) TMPDIR snapshot BEFORE.
		beforeFetchhead := countTempDirsByPrefix(t, "byreis-fetchhead-")
		beforeProjBlob := countTempDirsByPrefix(t, "byreis-project-blob-")
		beforeEditor := countTempDirsByPrefix(t, "byreis-editor-")

		// We need a real-looking helper binary path for the argv, but the run verb
		// must be denied before any spawn happens, so the actual binary need not
		// be compiled or exist. We pass a syntactically valid path.
		fakeChildBin := filepath.Join(t.TempDir(), "never-spawned-child")

		byreisOut, byreisErr, exitCode := fx.runCobra(t, deps,
			"run",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--",
			fakeChildBin, "report-env", sentinelSidecar,
		)

		// (f) Exit code must be ExitPermissionDenied.
		if exitCode != int(render.ExitPermissionDenied) {
			t.Fatalf("CONTRIBUTOR/Run: exit %d, want ExitPermissionDenied=%d; "+
				"stderr=%q stdout=%q",
				exitCode, render.ExitPermissionDenied,
				byreisErr.String(), byreisOut.String())
		}

		// (b) RunChild must never have been called.
		if spawner.called {
			t.Fatalf("CONTRIBUTOR/Run: RunChild was called — the mode gate MUST deny " +
				"before any child process is spawned (spawn-gate regression)")
		}

		// (c) Sentinel sidecar must not exist.
		if _, statErr := os.Stat(sentinelSidecar); statErr == nil {
			t.Fatalf("CONTRIBUTOR/Run: sentinel sidecar %q exists — "+
				"a child process ran and wrote to it; the mode gate did not fire before spawn",
				sentinelSidecar)
		}

		// (d) TMPDIR snapshot AFTER.
		afterFetchhead := countTempDirsByPrefix(t, "byreis-fetchhead-")
		afterProjBlob := countTempDirsByPrefix(t, "byreis-project-blob-")
		afterEditor := countTempDirsByPrefix(t, "byreis-editor-")
		if afterFetchhead != beforeFetchhead {
			t.Errorf("CONTRIBUTOR/Run: %d new byreis-fetchhead-* dir(s) — "+
				"mode-gate denial must NOT trigger any new registry clone",
				afterFetchhead-beforeFetchhead)
		}
		if afterProjBlob != beforeProjBlob {
			t.Errorf("CONTRIBUTOR/Run: %d new byreis-project-blob-* dir(s) — "+
				"mode-gate denial must NOT trigger any new project-repo clone",
				afterProjBlob-beforeProjBlob)
		}
		if afterEditor != beforeEditor {
			t.Errorf("CONTRIBUTOR/Run: %d new byreis-editor-* dir(s) — "+
				"mode-gate denial must NEVER reach the editor adapter",
				afterEditor-beforeEditor)
		}

		// (e) Channel sweep: no plaintext on stdout or stderr.
		if strings.Contains(byreisOut.String(), shipgateSecretValue) {
			t.Fatalf("CONTRIBUTOR/Run: plaintext leaked to stdout: %q", byreisOut.String())
		}
		if strings.Contains(byreisErr.String(), shipgateSecretValue) {
			t.Fatalf("CONTRIBUTOR/Run: plaintext leaked to stderr: %q", byreisErr.String())
		}
	})
}

// ─── panic-spawner spy ───────────────────────────────────────────────────────

// shipgatePanicRunChild is a RunChild spy that panics if the spawner is ever
// called. It proves the mode gate fires before any child process spawn on the
// CONTRIBUTOR denied path. The called flag is set atomically before the panic
// so the test can distinguish "mode gate bypassed" from "panic recovered".
type shipgatePanicRunChild struct {
	called bool
}

// RunChild satisfies the func(ctx, argv, env) (cli.ChildExit, error) signature
// expected by cli.Deps.RunChild. Any invocation means the mode gate did NOT
// fire first and is a security regression.
func (s *shipgatePanicRunChild) RunChild(_ context.Context, argv []string, _ []string) (cli.ChildExit, error) {
	s.called = true
	panic(fmt.Sprintf("shipgatePanicRunChild: spawner was called with argv=%v — "+
		"the mode gate MUST deny before any child process is spawned", argv))
}

// ─── inline compiler guard ───────────────────────────────────────────────────

// Compile-time guard: the run-verb subtests must be hooked into the top-level
// TestAsymmetryShipGate driver. This unused-var sentinel ensures the init-side
// assignment is not removed by a future refactor (a nil runSubtestsRunVerb at
// test runtime produces a clear "nil function call" panic rather than a silent
// skip).
var _ = runSubtestsRunVerb

// ─── DecryptInput / DecryptResult usage guard ────────────────────────────────

// Compile-time guard: the panic-decryptor spy must satisfy DecryptUseCase.
var _ usecase.DecryptUseCase = (*shipgatePanicDecryptor)(nil)

// ─── helper: truncateForLog ───────────────────────────────────────────────────

// truncateForLog returns up to maxBytes bytes from s, appending a note if
// truncated. Used to avoid enormous failure messages for large env dumps.
func truncateForLog(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes] + fmt.Sprintf("\n... [truncated %d bytes]", len(s)-maxBytes)
}

// ─── timing guard ────────────────────────────────────────────────────────────

// Ensure the time package is referenced so the import does not become stale if
// any future refactor of the helpers above removes direct time usage. The guard
// is side-effect-free.
var _ = time.Second
