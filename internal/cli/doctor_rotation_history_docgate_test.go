//go:build docgate

// V8a.3 (REQ-R-003-DOC R4b, MUST, release-blocking lock L19) — doctor
// rotation-history forward-secrecy warning verbatim docgate row.
//
// This file discharges the R4b obligation: `byreis doctor --rotation-history`,
// driven through the REAL cobra root over a REAL doctor use-case backed by a
// fake RotationEpochProbe, emits the verbatim rotate.ForwardSecrecyWarning to
// stdout when the project's rotation history contains a removed recipient
// (modelled as any file with rotation epoch >= 1).
//
// It is the doctor-side sibling of the R4a-CLI row in rotate_docgate_test.go.
// The two CLI emission sites (rotate --remove, doctor --rotation-history) and
// the rotate-level []byte fixture in rotate/forward_secrecy_doc_gate_test.go
// together close the three-way verbatim ring:
//
//	(a) the independent []byte fixture below (R4b's own copy) ⇄
//	(b) the production rotate.ForwardSecrecyWarning constant ⇄
//	(c) the doctor CLI render channel (doctor_cmd.go).
//
// (a) ⇄ (b) is asserted directly in TestR4b_DoctorRotationHistory_VerbatimFixtureMatchesConstant.
// (b) ⇄ (c) is asserted in TestR4b_DoctorRotationHistoryEmitsVerbatimForwardSecrecyWarning.
// (a) ⇄ (c) follows transitively; a typo on EITHER side (fixture or constant)
// fails the gate, exactly as the rotate-level R4a fixture does. The fixture is
// an INDEPENDENT literal — NOT a string-import of the constant — by design;
// DRY-collapsing it into the constant would defeat the cross-check.
//
// Build constraint: //go:build docgate ONLY. Non-default; never compiled into a
// shipped binary. The test injects a fake RotationEpochProbe and no-op mode
// ports — no real network, fs, clock, keychain, or git host.
package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// rotate_ForwardSecrecyWarning is the SINGLE permitted reference to the
// production rotate.ForwardSecrecyWarning constant in this file. Per the
// .golangci.yml forbidigo boundary rule the token may appear only at an
// equality/emission-assertion boundary; centralising it in one helper keeps
// the boundary to exactly one site (the rest of the file calls this helper).
func rotate_ForwardSecrecyWarning() string {
	return rotate.ForwardSecrecyWarning //nolint:forbidigo // boundary: R4b verbatim equality/emission assertion only
}

// r4bForwardSecrecyWarningFixture is the verbatim ADR-0016 §D9 warning text,
// embedded as an INDEPENDENT []byte literal — NOT derived from the production
// rotate.ForwardSecrecyWarning constant. It is byte-identical to the rotate-
// level docgate fixture (rotate/forward_secrecy_doc_gate_test.go) by design:
// the doctor CLI emission must agree with the same ADR §D9 source of truth.
//
// CRITICAL: do NOT replace this literal with a string-import of
// rotate.ForwardSecrecyWarning. The single-source equality that move would
// create defeats the three-way cross-check (AC-R4b-2 / BO-V4-3) and silently
// green-lights a regression in the production constant. The .golangci.yml
// forbidigo rule defends this boundary.
var r4bForwardSecrecyWarningFixture = []byte("WARNING: forward secrecy over git history is NOT provided by rotation.\n" +
	"\n" +
	"A removed recipient's private key, if retained, can still decrypt the\n" +
	"pre-rotation ciphertext from any retained clone or fork of the project\n" +
	"git history. byreis rotation re-encrypts every CURRENT secrets file to\n" +
	"the new recipient set, but it CANNOT retroactively remove past\n" +
	"ciphertext from past commits. If the removed recipient is a compromised\n" +
	"party, you MUST treat all secret values that were ever encrypted under\n" +
	"the pre-rotation recipient set as compromised and rotate the\n" +
	"underlying values (passwords, tokens, keys) themselves out-of-band.\n" +
	"\n" +
	"This is a property of the `age` cryptographic primitive (Model B) and\n" +
	"of git's append-only history, not a byreis bug. See docs/forward-\n" +
	"secrecy.md for the runbook.")

// --- file-local fakes (no real network/fs/clock/keychain) ---

// r4bFakeEpochProbe is an injected usecase.RotationEpochProbe. It returns a
// canned per-file epoch map (or an error) so the real doctor use-case derives
// HasRotationHistory / partial-rotation without any registry, git, or fs I/O.
type r4bFakeEpochProbe struct {
	epochs map[string]uint64
	err    error
}

func (f *r4bFakeEpochProbe) FetchRotationEpochs(_ context.Context, _ string) (map[string]uint64, error) {
	return f.epochs, f.err
}

// r4bNoopKeyProbe / r4bNoopRegistryTrust / r4bNoopClock are the minimal mode
// ports needed to build a real *mode.Detector. They resolve to CONTRIBUTOR
// without error so the doctor use-case constructs cleanly; the R4b rows do not
// depend on the resolved mode value (doctor --rotation-history is C+A, no gate).
type r4bNoopKeyProbe struct{}

func (r4bNoopKeyProbe) KeyFilePath(_ context.Context) string                    { return "" }
func (r4bNoopKeyProbe) KeyFilePerms(_ context.Context) (uint32, error)          { return 0, nil }
func (r4bNoopKeyProbe) CanDecryptAny(_ context.Context, _ string) (bool, error) { return false, nil }

type r4bNoopRegistryTrust struct{}

func (r4bNoopRegistryTrust) IsRegisteredAdmin(_ context.Context, _ string) (bool, error) {
	return false, nil
}

type r4bNoopClock struct{}

func (r4bNoopClock) Now() interface{ Unix() int64 } { return r4bNoopTime{} }

type r4bNoopTime struct{}

func (r4bNoopTime) Unix() int64 { return 0 }

// r4bRealRotationHistoryDoctor builds a REAL usecase.Doctor with
// RotationHistoryRequested=true and the given fake epoch probe wired. This
// exercises the production checkRotationHistory + HasRotationHistory derivation
// end-to-end; nothing about the warning decision is faked at the assertion
// boundary.
func r4bRealRotationHistoryDoctor(t *testing.T, probe usecase.RotationEpochProbe) usecase.Doctor {
	t.Helper()

	// Deterministic, isolated config dir + trust file (t.TempDir, never the real
	// ~/.config) with the exact perms the doctor's TOCTOU checks require: the
	// config dir must be exactly 0700. t.TempDir may return 0755 on some
	// platforms (observed on darwin), so we chmod it to 0700 explicitly and
	// create a 0600 regular trust file inside it. This keeps the config-dir /
	// trust-anchor findings at OK so they cannot contaminate the R4b advisory-exit
	// assertions, while still avoiding any real network/clock/fs/keychain.
	configDir := t.TempDir()
	// 0700 is the REQUIRED mode for a config directory (owner rwx, no group/world);
	// gosec G302's "<=0600" heuristic is for files, not directories — a 0700 dir
	// is the correct, secure mode here.
	if err := os.Chmod(configDir, 0o700); err != nil { //nolint:gosec // G302: 0700 is the required secure mode for a config DIRECTORY
		t.Fatalf("R4b: chmod config dir 0700 failed: %v", err)
	}
	trustPath := filepath.Join(configDir, "trust.yaml")
	if err := os.WriteFile(trustPath, []byte("schema: byreis.trust.v1\n"), 0o600); err != nil {
		t.Fatalf("R4b: writing 0600 trust file failed: %v", err)
	}

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector: &mode.Detector{
			Probe:    r4bNoopKeyProbe{},
			Registry: r4bNoopRegistryTrust{},
			Clock:    r4bNoopClock{},
			Audit:    audit.Discard,
		},
		ProjectID:                "docgate-proj",
		ConfigDir:                configDir,
		TrustFilePath:            trustPath,
		RotationEpochProbe:       probe,
		RotationHistoryRequested: true,
	})
	if err != nil {
		t.Fatalf("R4b: NewDoctor (rotation-history) failed: %v", err)
	}
	return doc
}

// r4bRunDoctorRotationHistory drives `byreis doctor --rotation-history` through
// the REAL cobra root with the given mode + RotationHistoryDoctor wired and
// returns (stdout, exitCode). A plain (non-base) Doctor is also wired so the
// command's nil-guard passes; the --rotation-history flag selects the history
// doctor per doctor_cmd.go.
func r4bRunDoctorRotationHistory(
	t *testing.T, currentMode mode.Mode, historyDoctor usecase.Doctor,
) (string, int) {
	t.Helper()

	deps := &cli.Deps{
		Policy:                &mode.Policy{},
		CurrentMode:           currentMode,
		Doctor:                historyDoctor,
		RotationHistoryDoctor: historyDoctor,
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	root := cli.NewRootCmdWithDeps(deps)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{"doctor", "--rotation-history"})

	execErr := root.ExecuteContext(context.Background())
	exitCode := cli.ExitCodeOf(execErr)

	t.Logf("R4b doctor --rotation-history (mode=%s): exit=%d stderr=%q",
		currentMode, exitCode, stderr.String())
	return stdout.String(), exitCode
}

// TestR4b_DoctorRotationHistory_VerbatimFixtureMatchesConstant asserts
// AC-R4b-2 (a) ⇄ (b): the R4b independent []byte fixture and the production
// rotate.ForwardSecrecyWarning constant are byte-for-byte equal. A divergence
// on either side is a deliberate review event (re-issue of ADR-0016 §D9 with
// crypto-auditor on the loop). This is the doctor-side companion to the rotate-
// level TestForwardSecrecyWarning_VerbatimMatch; both must hold for the three-
// way ring to close.
//
// This is the ONLY line in this file that references the constant as a token;
// per the .golangci.yml forbidigo boundary rule the single allowed reference is
// an equality assertion.
func TestR4b_DoctorRotationHistory_VerbatimFixtureMatchesConstant(t *testing.T) {
	t.Parallel()

	want := r4bForwardSecrecyWarningFixture
	got := []byte(rotate_ForwardSecrecyWarning()) // see helper below for the nolint boundary

	if len(got) != len(want) {
		t.Fatalf("R4b: fixture / rotate.ForwardSecrecyWarning length mismatch: "+
			"got %d, want %d.\nThe production constant has drifted from the "+
			"verbatim ADR-0016 §D9 block. Re-review against ADR-0016 §D9 before "+
			"changing either side.\n\nfull got:  %q\nfull want: %q",
			len(got), len(want), string(got), string(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("R4b: fixture / rotate.ForwardSecrecyWarning differ at byte %d: "+
				"got %q, want %q.\nDeliberate-review-event regression: the production "+
				"constant has drifted from the verbatim ADR-0016 §D9 block.\n\n"+
				"full got:  %q\nfull want: %q",
				i, string(got[i]), string(want[i]), string(got), string(want))
		}
	}
	t.Logf("R4b: PASS — fixture matches rotate.ForwardSecrecyWarning byte-for-byte (%d bytes)", len(want))
}

// TestR4b_DoctorRotationHistoryEmitsVerbatimForwardSecrecyWarning asserts
// AC-R4b-1 + the (b) ⇄ (c) leg: GIVEN a project whose rotation history
// contains a removed recipient (modelled by a fake probe returning an epoch
// >= 1), WHEN `byreis doctor --rotation-history` is invoked through the real
// cobra root, THEN stdout contains the verbatim warning byte-for-byte.
//
// The assertion checks BOTH the production constant (proving the CLI emits the
// real constant) AND the independent fixture (proving the emitted bytes match
// the ADR §D9 source of truth even if the constant itself regressed — the
// fixture-vs-constant equality is asserted separately above, so a match here
// against both is the load-bearing R4b honesty guarantee).
func TestR4b_DoctorRotationHistoryEmitsVerbatimForwardSecrecyWarning(t *testing.T) {
	t.Parallel()

	probe := &r4bFakeEpochProbe{
		epochs: map[string]uint64{
			"prod": 1, // epoch >= 1 ⇒ a rotation removed a recipient
		},
	}
	doctor := r4bRealRotationHistoryDoctor(t, probe)

	got, exit := r4bRunDoctorRotationHistory(t, mode.ModeAdmin, doctor)

	// (b) ⇄ (c): stdout contains the verbatim production constant.
	wantConst := rotate_ForwardSecrecyWarning()
	if !strings.Contains(got, wantConst) {
		t.Fatalf("R4b AC-R4b-1: doctor --rotation-history stdout does not contain the "+
			"verbatim ForwardSecrecyWarning constant.\nThis is release-blocking: an "+
			"operator inspecting rotation history of a project with a removed recipient "+
			"MUST see the forward-secrecy honesty warning, or they may believe rotation "+
			"retroactively protected pre-rotation ciphertext in git history.\n\n"+
			"want (substring):\n%q\n\ngot (full stdout):\n%q", wantConst, got)
	}

	// (a) ⇄ (c): the same emitted bytes also contain the independent fixture.
	if !strings.Contains(got, string(r4bForwardSecrecyWarningFixture)) {
		t.Fatalf("R4b AC-R4b-2: doctor --rotation-history stdout does not contain the "+
			"INDEPENDENT verbatim fixture. The constant and the emission agree but both "+
			"have drifted from the ADR-0016 §D9 source of truth.\n\n"+
			"want fixture (substring):\n%q\n\ngot (full stdout):\n%q",
			string(r4bForwardSecrecyWarningFixture), got)
	}

	// AC-R4b-4: warning emission alone does NOT set a non-zero exit (advisory
	// honesty). No FAIL-severity finding is produced by the rotation-history
	// path, so exit must be 0.
	if exit != 0 {
		t.Fatalf("R4b AC-R4b-4: warning emission must not set a non-zero exit "+
			"(advisory honesty), got exit=%d.\nstdout:\n%s", exit, got)
	}

	t.Logf("R4b AC-R4b-1/2/4: PASS — verbatim warning emitted (const + fixture), exit 0")
}

// TestR4b_DoctorRotationHistoryNoRemovalsNoWarningExitZero asserts AC-R4b-4
// (negative): `doctor --rotation-history` with NO removed recipient (all files
// at epoch 0) emits NO forward-secrecy warning and exits 0. This is the
// must-not-over-warn half of the advisory-honesty contract: a never-rotated
// project must not be told its ciphertext is compromised.
func TestR4b_DoctorRotationHistoryNoRemovalsNoWarningExitZero(t *testing.T) {
	t.Parallel()

	probe := &r4bFakeEpochProbe{
		epochs: map[string]uint64{
			"prod":    0,
			"staging": 0, // all at epoch 0 ⇒ never rotated ⇒ no removed recipient
		},
	}
	doctor := r4bRealRotationHistoryDoctor(t, probe)

	got, exit := r4bRunDoctorRotationHistory(t, mode.ModeAdmin, doctor)

	// No warning: neither the constant nor the fixture may appear.
	if strings.Contains(got, rotate_ForwardSecrecyWarning()) {
		t.Fatalf("R4b AC-R4b-4 (negative): the forward-secrecy warning was emitted "+
			"for a never-rotated project (all epochs 0). Over-warning is a release-"+
			"blocking honesty defect.\nstdout:\n%s", got)
	}
	if strings.Contains(got, string(r4bForwardSecrecyWarningFixture)) {
		t.Fatalf("R4b AC-R4b-4 (negative): fixture text appeared for a never-rotated "+
			"project.\nstdout:\n%s", got)
	}
	// And no partial-rotation finding (epochs agree).
	if strings.Contains(got, "partial-rotation-detected") {
		t.Fatalf("R4b AC-R4b-4 (negative): partial-rotation-detected surfaced when all "+
			"epochs agree.\nstdout:\n%s", got)
	}
	if exit != 0 {
		t.Fatalf("R4b AC-R4b-4 (negative): no-removal run must exit 0, got %d.\nstdout:\n%s", exit, got)
	}

	t.Logf("R4b AC-R4b-4 (negative): PASS — no warning, no partial finding, exit 0")
}

// TestR4b_DoctorRotationHistoryPartialRotationDetected asserts AC-R4b-5 (lock
// L23): GIVEN files in one project disagree on epoch, THEN the
// partial-rotation-detected finding is surfaced in stdout. Because at least one
// file is at epoch >= 1, the forward-secrecy warning is ALSO emitted (a partial
// rotation still removed a recipient from some files), and exit remains 0
// (advisory).
func TestR4b_DoctorRotationHistoryPartialRotationDetected(t *testing.T) {
	t.Parallel()

	probe := &r4bFakeEpochProbe{
		epochs: map[string]uint64{
			"prod":    2,
			"staging": 1, // divergent epochs ⇒ partial rotation
		},
	}
	doctor := r4bRealRotationHistoryDoctor(t, probe)

	got, exit := r4bRunDoctorRotationHistory(t, mode.ModeAdmin, doctor)

	if !strings.Contains(got, "partial-rotation-detected") {
		t.Fatalf("R4b AC-R4b-5: doctor --rotation-history stdout does not surface "+
			"partial-rotation-detected when files disagree on epoch (prod=2, "+
			"staging=1).\nThis is release-blocking (lock L23): an incomplete rotation "+
			"leaves some files encrypted to a removed recipient and the operator must "+
			"be told to finish it.\n\ngot (full stdout):\n%s", got)
	}
	// Forward-secrecy warning is still emitted (epoch >= 1 exists).
	if !strings.Contains(got, rotate_ForwardSecrecyWarning()) {
		t.Errorf("R4b AC-R4b-5: a partial rotation with epoch >= 1 must still emit the "+
			"forward-secrecy warning.\ngot:\n%s", got)
	}
	if exit != 0 {
		t.Fatalf("R4b AC-R4b-5: partial-rotation advisory must not set a non-zero exit, "+
			"got %d.\nstdout:\n%s", exit, got)
	}

	t.Logf("R4b AC-R4b-5: PASS — partial-rotation-detected surfaced, warning emitted, exit 0")
}

// TestR4b_DoctorRotationHistoryReachableInContributorMode asserts the BA-
// specified (command × mode) row: `doctor --rotation-history` is a diagnostic
// with NO mode gate on the flag, so it must be reachable in CONTRIBUTOR mode —
// NOT denied. A contributor running the diagnostic must reach the doctor use-
// case and (when the history reveals a removed recipient) see the same verbatim
// warning an admin sees. The exit code must NOT be the permission-denied code.
//
// This is the asymmetric-access guard for the diagnostic surface: read-only
// rotation-history diagnostics are intentionally C+A (no new mode constant);
// the asymmetry lives on the WRITE path (rotate), not on doctor.
func TestR4b_DoctorRotationHistoryReachableInContributorMode(t *testing.T) {
	t.Parallel()

	probe := &r4bFakeEpochProbe{
		epochs: map[string]uint64{"prod": 1},
	}
	doctor := r4bRealRotationHistoryDoctor(t, probe)

	got, exit := r4bRunDoctorRotationHistory(t, mode.ModeContributor, doctor)

	// NOT denied: the permission-denied exit code (2) must not be returned.
	const exitPermissionDenied = 2
	if exit == exitPermissionDenied {
		t.Fatalf("R4b (command×mode): contributor-mode doctor --rotation-history was "+
			"DENIED (exit %d). The flag is a diagnostic with no mode gate; denying it "+
			"in contributor mode is a release-blocking regression of the C+A reachability "+
			"contract.\nstdout:\n%s", exit, got)
	}
	if exit != 0 {
		t.Fatalf("R4b (command×mode): contributor-mode doctor --rotation-history must "+
			"exit 0 (diagnostic, advisory warning only), got %d.\nstdout:\n%s", exit, got)
	}

	// Reachability proof: the use-case actually ran and emitted the warning,
	// confirming the contributor reached the rotation-history report (not a
	// silent no-op) and sees the same honesty warning as an admin.
	if !strings.Contains(got, rotate_ForwardSecrecyWarning()) {
		t.Fatalf("R4b (command×mode): contributor-mode doctor --rotation-history did not "+
			"reach the report (no warning emitted). The diagnostic must be reachable and "+
			"honest in contributor mode.\nstdout:\n%s", got)
	}

	t.Logf("R4b (command×mode): PASS — contributor-mode doctor --rotation-history is " +
		"reachable (not denied), exit 0, verbatim warning emitted")
}
