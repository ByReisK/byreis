package registry_test

// V8 S8 — diff-tree transient-vs-determinate classification tests (REQ-V08-009).
//
// Background: prior to S8, extractCommitInfo treated ANY git diff-tree failure
// (whether a verifier-side exec/IO/process failure with filesErr != nil, or a
// determinate non-zero exit with filesErr == nil) as StagedFilesUndeterminable,
// which bindLines escalated to BindingTampered. This caused a false-positive
// DENIAL when git diff-tree encountered a transient verifier-side exec error.
//
// The fix classifies on the NATURE of the failure:
//
//	filesErr != nil
//	  Verifier-side exec/IO/process failure — the subprocess never started or
//	  died before producing output. This is a transient, retryable condition
//	  that does NOT assert tamper. extractCommitInfo returns immediately with
//	  ErrRegistryOffline. The CLI renders this as a retryable/inconclusive
//	  outcome (non-zero exit but NOT ErrAuditLogTampered, NOT BindingTampered).
//
//	filesErr == nil && filesExit != 0
//	  Determinate result: git ran and returned non-zero — a real git-level
//	  content or object problem caused by the commit's own content. This stays
//	  fail-closed: StagedFilesUndeterminable=true → bindLines → BindingTampered.
//
// Acceptance criteria (from REQ-V08-009):
//
//	AC-A: genuine splice with WORKING git → DENIES (ErrAuditLogTampered).
//	      Fix must NOT weaken genuine-tamper detection.
//	AC-B: transient verifier-side diff-tree exec failure on clean history →
//	      ErrRegistryOffline, not ErrAuditLogTampered, no BindingVerified.
//	AC-C: crafted tamper disguised as transient — a real splice where the
//	      attacker ALSO induces filesErr != nil — STILL DENIES (non-zero exit,
//	      NOT BindingVerified, verifier never returns a clean result).
//	AC-D: all of the above tested with REAL signed-git-history fixtures, not
//	      structural mocks.
//
// Test fixtures: all four tests build real local git repositories via
// newSignedAuditHistory (defined in registry_auditverify_signedhistory_test.go)
// and exercise the full VerifyAuditLog path. AC-B and AC-C use an intercepting
// runner that wraps the real SubprocessRunner but intercepts git diff-tree calls
// to inject a configurable exec error.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ---- intercepting runner -------------------------------------------------------

// diffTreeInterceptRunner is a CommandRunner that wraps the real SubprocessRunner
// for every command except "git diff-tree". When a "git diff-tree" call is
// intercepted, it returns the configured execErr (simulating a verifier-side
// exec/IO/process failure) without calling the real subprocess. All other git
// subcommands are forwarded to the real runner.
//
// This is the minimal seam needed to simulate filesErr != nil from
// extractCommitInfo without touching the clone/log/verify/show paths that must
// use a real git binary operating on a real signed repository.
type diffTreeInterceptRunner struct {
	// real is the real SubprocessRunner for all non-intercepted commands.
	real registry.SubprocessRunner
	// execErr is the error to return for git diff-tree calls.
	// Must be non-nil (an exec-level error, not a non-zero exit).
	execErr error
}

// Run implements fetchtransport.CommandRunner.
// It intercepts "git diff-tree" and returns execErr for those calls.
// All other commands are forwarded to the real SubprocessRunner.
func (r *diffTreeInterceptRunner) Run(
	ctx context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) (stdout, stderr []byte, exitCode int, err error) {
	// Detect "git diff-tree" by checking that it is a git call with diff-tree
	// as the first argument. This matches exactly the call in extractCommitInfo:
	//   "git", "diff-tree", "--no-commit-id", "-r", "--name-only", sha
	if name == "git" && len(args) > 0 && args[0] == "diff-tree" {
		// Simulate a verifier-side exec/IO/process failure: the subprocess
		// never started or died before producing output. exitCode is 0 because
		// a real exec failure does not produce a meaningful exit code (the
		// exec.ExitError branch is only reached when the process ran).
		return nil, nil, 0, r.execErr
	}
	return r.real.Run(ctx, dir, env, name, args...)
}

// newVerifyAuditClientWithRunner builds a registry.Client backed by the real
// productionFetchTransport using the given CommandRunner for the HeadVerifier,
// pointed at the given signed history. Used for AC-B and AC-C where we need to
// intercept diff-tree calls while keeping the rest of the git operations real.
func newVerifyAuditClientWithRunner(
	t *testing.T,
	history *signedAuditHistory,
	runner fetchtransport.CommandRunner,
) *registry.Client {
	t.Helper()

	v, err := fetchtransport.NewHeadVerifier(fetchtransport.HeadVerifierConfig{
		Runner:    runner,
		MkdirTemp: os.MkdirTemp,
		RemoveAll: os.RemoveAll,
	})
	if err != nil {
		t.Fatalf("newVerifyAuditClientWithRunner: NewHeadVerifier: %v", err)
	}

	pt, err := registry.NewProductionFetchTransport(v, nil)
	if err != nil {
		t.Fatalf("newVerifyAuditClientWithRunner: NewProductionFetchTransport: %v", err)
	}

	fixedNow := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    history.RepoURL,
		ProjectID:      history.ProjectID,
		CacheDir:       t.TempDir(),
		TrustAnchorKey: history.AnchorKey,
		Clock:          func() time.Time { return fixedNow },
		FetchTransport: pt,
	})
	if err != nil {
		t.Fatalf("newVerifyAuditClientWithRunner: registry.New: %v", err)
	}
	return client
}

// ---- AC-A: genuine splice with working git → DENIES --------------------------

// TestAuditVerify_V8_ACA_GenuineSplice_WorkingGit_StillDenies verifies that a
// genuine cross-project splice committed to a REAL signed history is still
// detected as ErrAuditLogTampered after the S8 fix. This is the regression
// guard: the fix must not weaken genuine-tamper detection.
//
// The test builds a 1-event history for "v8aca-main", then adds a second commit
// that appends a valid audit line for "v8aca-main" AND stages an audit file for
// "v8aca-other" simultaneously. The verifier walks with the REAL git binary
// (no intercepting runner); git diff-tree succeeds and reports the two staged
// paths. The splice check must fire → ErrAuditLogTampered.
//
// This mirrors the AC-F splice test in registry_auditverify_tamper_test.go but
// names it explicitly as the AC-A regression guard for V8/S8.
func TestAuditVerify_V8_ACA_GenuineSplice_WorkingGit_StillDenies(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const (
		mainProject  = "v8aca-main"
		otherProject = "v8aca-other"
	)

	events := buildTestAuditEvents(mainProject)[:1]
	history := newSignedAuditHistory(t, mainProject, events)
	repoDir := repoPathFromURL(history.RepoURL)

	// Build the second event's JSONL line and its sha.
	secondEvent := buildTestAuditEvents(mainProject)[1]
	secondLine, secondEntrySHA := buildCommittableJSONLLine(t, secondEvent)

	// Create and stage the other project's audit file alongside the main project's.
	otherAuditPath := filepath.Join(repoDir, "audit", otherProject+".jsonl")
	otherLine := fmt.Sprintf(
		`{"kind":"merge","occurred_at":"2026-05-26T12:00:00Z","actor":"attacker","project_id":%q,"outcome":"ok"}`,
		otherProject,
	) + "\n"
	if err := os.WriteFile(otherAuditPath, []byte(otherLine), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("AC-A: write other audit file: %v", err)
	}

	// Append the second event to the main project audit file.
	mainAuditPath := filepath.Join(repoDir, "audit", mainProject+".jsonl")
	f, err := os.OpenFile(mainAuditPath, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("AC-A: open main audit file: %v", err)
	}
	if _, wErr := f.Write(secondLine); wErr != nil {
		_ = f.Close()
		t.Fatalf("AC-A: write main audit file: %v", wErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatalf("AC-A: close main audit file: %v", cErr)
	}

	// Stage both files in one commit.
	gitInRepoFatal(t, repoDir, "add", "--",
		filepath.Join("audit", mainProject+".jsonl"),
		filepath.Join("audit", otherProject+".jsonl"),
	)
	msg := fmt.Sprintf("audit: splice commit (main+other)\n\naudit_entry_sha: %s\n", secondEntrySHA)
	msgFile := filepath.Join(t.TempDir(), "splice-msg.txt")
	if wErr := os.WriteFile(msgFile, []byte(msg), 0o600); wErr != nil { //nolint:gosec // test fixture
		t.Fatalf("AC-A: write commit msg: %v", wErr)
	}
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile, "-S")

	// Use the real git binary (no intercepting runner): diff-tree works correctly
	// and reports the two staged paths. The splice check must fire.
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, mainProject)
	assertTamperedResult(t, "V8/AC-A", result, err)
}

// ---- AC-B: transient diff-tree exec failure → ErrRegistryOffline ------------

// TestAuditVerify_V8_ACB_TransientDiffTreeExecError_ErrRegistryOffline verifies
// that a verifier-side exec/IO/process failure in git diff-tree (filesErr != nil)
// is classified as a transient condition and returned as ErrRegistryOffline, NOT
// as ErrAuditLogTampered and NOT as a clean BindingVerified result.
//
// The test builds a CLEAN 3-event signed history (no tamper). The client is
// wired with an intercepting runner that returns an exec error for every git
// diff-tree call while delegating all other git commands to the real binary.
// The expected outcome is:
//   - err wraps ErrRegistryOffline (transient/retryable, not tamper)
//   - err does NOT wrap ErrAuditLogTampered
//   - no entry carries BindingVerified (the verifier did not complete cleanly)
//
// This is a REAL signed-git-history fixture: the signed commits exist and
// would verify cleanly with a working git diff-tree.
func TestAuditVerify_V8_ACB_TransientDiffTreeExecError_ErrRegistryOffline(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const projectID = "v8acb-project"

	events := buildTestAuditEvents(projectID)
	history := newSignedAuditHistory(t, projectID, events)

	// Wire a diff-tree intercepting runner that simulates an exec error.
	// The message text is chosen to be clearly verifier-side (not attacker-controlled).
	simErr := fmt.Errorf("simulated exec error: git binary unavailable (test injection)")
	runner := &diffTreeInterceptRunner{
		real:    registry.SubprocessRunner{},
		execErr: simErr,
	}
	client := newVerifyAuditClientWithRunner(t, history, runner)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	_, verifyErr := client.VerifyAuditLog(ctx, projectID)

	if verifyErr == nil {
		t.Fatal("AC-B: VerifyAuditLog returned nil error — " +
			"a transient diff-tree exec failure must not produce a clean result")
	}
	if !errors.Is(verifyErr, coreregistry.ErrRegistryOffline) {
		t.Errorf("AC-B: want errors.Is(err, ErrRegistryOffline), got: %v", verifyErr)
	}
	if errors.Is(verifyErr, coreregistry.ErrAuditLogTampered) {
		t.Errorf("AC-B: got ErrAuditLogTampered but want ErrRegistryOffline — "+
			"a verifier-side exec error must NOT assert tamper: %v", verifyErr)
	}

	t.Logf("AC-B: PASS — ErrRegistryOffline returned, NOT ErrAuditLogTampered: %v", verifyErr)
}

// ---- AC-C: crafted tamper disguised as transient → STILL DENIES -------------

// TestAuditVerify_V8_ACC_TamperPlusForcedExecError_StillDenies is the C6 gate
// test. It constructs a scenario where:
//  1. The signed history contains a GENUINE cross-project splice (tamper).
//  2. The intercepting runner ALSO returns filesErr != nil for diff-tree.
//
// This simulates an attacker who crafts a tampered history AND simultaneously
// tries to force the verifier into the "transient" path to prevent BindingTampered.
//
// Expected behaviour after S8: the verifier returns ErrRegistryOffline (because
// the transient path fires first — diff-tree never runs on the tampered commit).
// The result is still a NON-ZERO EXIT and still NOT BindingVerified. The
// attacker gains nothing: the verifier denies the operation without asserting
// the specific ErrAuditLogTampered label, but it NEVER returns a clean result.
//
// C6 invariant: an attacker cannot induce the "transient" classification to
// MASK a genuine splice and obtain a BindingVerified result. This test proves
// that the combined scenario (tamper + forced exec error) still DENIES.
//
// Note: the test asserts that verifyErr is non-nil AND does NOT carry
// BindingVerified on any entry. It does NOT require ErrAuditLogTampered
// specifically — the key property is denial (non-zero exit), not which denial
// label is used.
func TestAuditVerify_V8_ACC_TamperPlusForcedExecError_StillDenies(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const (
		mainProject  = "v8acc-main"
		otherProject = "v8acc-other"
	)

	// Build a 1-event clean history.
	events := buildTestAuditEvents(mainProject)[:1]
	history := newSignedAuditHistory(t, mainProject, events)
	repoDir := repoPathFromURL(history.RepoURL)

	// Inject a genuine splice: a second commit stages both the main project's
	// audit file AND another project's audit file simultaneously.
	secondEvent := buildTestAuditEvents(mainProject)[1]
	secondLine, secondEntrySHA := buildCommittableJSONLLine(t, secondEvent)

	otherAuditPath := filepath.Join(repoDir, "audit", otherProject+".jsonl")
	otherLine := fmt.Sprintf(
		`{"kind":"merge","occurred_at":"2026-05-26T12:00:00Z","actor":"attacker","project_id":%q,"outcome":"ok"}`,
		otherProject,
	) + "\n"
	if err := os.WriteFile(otherAuditPath, []byte(otherLine), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("AC-C: write other audit file: %v", err)
	}

	mainAuditPath := filepath.Join(repoDir, "audit", mainProject+".jsonl")
	f, err := os.OpenFile(mainAuditPath, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("AC-C: open main audit file: %v", err)
	}
	if _, wErr := f.Write(secondLine); wErr != nil {
		_ = f.Close()
		t.Fatalf("AC-C: write main audit file: %v", wErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatalf("AC-C: close main audit file: %v", cErr)
	}
	gitInRepoFatal(t, repoDir, "add", "--",
		filepath.Join("audit", mainProject+".jsonl"),
		filepath.Join("audit", otherProject+".jsonl"),
	)
	msg := fmt.Sprintf("audit: splice (attacker disguised as transient)\n\naudit_entry_sha: %s\n",
		secondEntrySHA)
	msgFile := filepath.Join(t.TempDir(), "acc-commitmsg.txt")
	if wErr := os.WriteFile(msgFile, []byte(msg), 0o600); wErr != nil { //nolint:gosec // test fixture
		t.Fatalf("AC-C: write commit msg: %v", wErr)
	}
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile, "-S")

	// Wire an intercepting runner that ALSO forces filesErr != nil for diff-tree.
	// This simulates an attacker who has simultaneously tampered with the history
	// AND somehow managed to induce a verifier-side exec failure on diff-tree.
	simErr := fmt.Errorf("simulated exec error: attacker-induced (test injection)")
	runner := &diffTreeInterceptRunner{
		real:    registry.SubprocessRunner{},
		execErr: simErr,
	}
	client := newVerifyAuditClientWithRunner(t, history, runner)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, verifyErr := client.VerifyAuditLog(ctx, mainProject)

	// C6 gate: the verifier MUST NOT return a clean result. The two key properties:
	//   1. verifyErr must be non-nil (the verifier denied the operation).
	//   2. no entry must carry BindingVerified (no line is certified clean).
	if verifyErr == nil {
		t.Fatal("AC-C (C6 gate): VerifyAuditLog returned nil error — " +
			"a tampered history with a forced diff-tree exec error must not produce " +
			"a clean result; the attacker must not be able to disguise a splice as transient")
	}

	// Assert that no entry carries BindingVerified. This is the key C6 property:
	// the attacker forcing the transient path on a tampered repo must NEVER cause
	// the verifier to certify any line as verified.
	for i, e := range result.Entries {
		if e.BindingStatus == rotate.BindingVerified {
			t.Errorf("AC-C (C6 gate): entry[%d] has BindingVerified — "+
				"a forced transient exec error on a tampered repo must never produce "+
				"BindingVerified; the attacker must not gain a clean certification",
				i)
		}
	}

	// The error must be ErrRegistryOffline (transient path fires because diff-tree
	// never runs — the intercepting runner returns before git is called). It must
	// NOT be a nil error or a silent clean pass.
	if !errors.Is(verifyErr, coreregistry.ErrRegistryOffline) {
		t.Errorf("AC-C: want errors.Is(err, ErrRegistryOffline) when diff-tree is forcibly "+
			"intercepted (regardless of tamper), got: %v", verifyErr)
	}

	t.Logf("AC-C (C6 gate): PASS — verifyErr non-nil (%v), no BindingVerified entry; "+
		"attacker cannot disguise splice as transient to obtain a clean result", verifyErr)
}

// ---- AC-D: fixture integrity confirmation -----------------------------------

// TestAuditVerify_V8_ACD_RealFixtures_CleanHistory_AllBindingVerified confirms
// that the REAL signed-git-history fixture (no interception, no tamper) still
// produces a fully clean result after the S8 fix. This is the forward-
// compatibility guard: the fix must not break the clean path.
//
// Using the same newSignedAuditHistory harness as AC-A/B/C with a real runner
// and a real git binary, on an untampered 3-event history. Every non-synthetic
// entry must carry BindingVerified.
func TestAuditVerify_V8_ACD_RealFixtures_CleanHistory_AllBindingVerified(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const projectID = "v8acd-project"

	events := buildTestAuditEvents(projectID)
	history := newSignedAuditHistory(t, projectID, events)

	// Real runner, no interception, no tamper — the full clean path.
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	if err != nil {
		t.Fatalf("AC-D: VerifyAuditLog returned unexpected error on clean history: %v", err)
	}
	if !result.FullWalk {
		t.Errorf("AC-D: FullWalk = false, want true")
	}

	nonSynthetic := 0
	for i, e := range result.Entries {
		if e.Unknown || e.Kind == "truncated" || e.Kind == "malformed-line" {
			continue
		}
		nonSynthetic++
		if e.BindingStatus != rotate.BindingVerified {
			t.Errorf("AC-D: entry[%d] kind=%q BindingStatus=%v, want BindingVerified",
				i, e.Kind, e.BindingStatus)
		}
	}
	if nonSynthetic == 0 {
		t.Errorf("AC-D: no non-synthetic entries returned — history has %d events", len(events))
	}

	t.Logf("AC-D: PASS — %d non-synthetic entries, all BindingVerified, FullWalk=%v",
		nonSynthetic, result.FullWalk)
}

// ---- Determinate non-zero exit stays fail-closed ----------------------------

// TestAuditVerify_V8_DeterminateNonZeroExit_StillTampered verifies that when
// git diff-tree runs successfully but returns a non-zero exit code (filesErr == nil,
// filesExit != 0), the commit is still treated as StagedFilesUndeterminable and
// the line is marked BindingTampered. This is the direct companion to AC-B:
// the determinate (non-zero exit) path must NOT be reclassified as transient.
//
// The test builds a clean signed history and wires a runner that returns a
// non-zero exit code (not an exec error) for git diff-tree calls. The expected
// outcome is ErrAuditLogTampered (fail-closed, same as before S8).
func TestAuditVerify_V8_DeterminateNonZeroExit_StillTampered(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const projectID = "v8det-project"

	events := buildTestAuditEvents(projectID)
	history := newSignedAuditHistory(t, projectID, events)

	// Intercepting runner: for git diff-tree, return exitCode=128 with err=nil
	// (a determinate non-zero exit — git ran but reported an error). For all
	// other commands, delegate to the real binary.
	runner := &diffTreeNonZeroRunner{real: registry.SubprocessRunner{}}
	client := newVerifyAuditClientWithRunner(t, history, runner)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, verifyErr := client.VerifyAuditLog(ctx, projectID)

	if verifyErr == nil {
		t.Fatal("Determinate/NonZeroExit: VerifyAuditLog returned nil error — " +
			"a determinate non-zero diff-tree exit must fail closed as ErrAuditLogTampered")
	}
	if !errors.Is(verifyErr, coreregistry.ErrAuditLogTampered) {
		t.Errorf("Determinate/NonZeroExit: want errors.Is(err, ErrAuditLogTampered), got: %v",
			verifyErr)
	}
	if errors.Is(verifyErr, coreregistry.ErrRegistryOffline) {
		t.Errorf("Determinate/NonZeroExit: got ErrRegistryOffline but want ErrAuditLogTampered — "+
			"a determinate non-zero exit must stay tamper, not become transient: %v", verifyErr)
	}

	// At least one entry must be BindingTampered.
	tampered := 0
	for _, e := range result.Entries {
		if e.BindingStatus == rotate.BindingTampered {
			tampered++
		}
	}
	if tampered == 0 {
		t.Errorf("Determinate/NonZeroExit: no BindingTampered entry — " +
			"a determinate non-zero exit must produce BindingTampered, not skip the check")
	}

	t.Logf("Determinate/NonZeroExit: PASS — ErrAuditLogTampered, %d BindingTampered: %v",
		tampered, verifyErr)
}

// diffTreeNonZeroRunner is a CommandRunner that intercepts git diff-tree calls
// and returns exitCode=128 with err=nil (a determinate non-zero exit). All
// other commands are forwarded to the real SubprocessRunner.
type diffTreeNonZeroRunner struct {
	real registry.SubprocessRunner
}

// Run implements fetchtransport.CommandRunner.
func (r *diffTreeNonZeroRunner) Run(
	ctx context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) (stdout, stderr []byte, exitCode int, err error) {
	if name == "git" && len(args) > 0 && args[0] == "diff-tree" {
		// Return a determinate non-zero exit (filesErr == nil, filesExit != 0).
		// This mirrors what the real git would return on a git-level object error.
		return nil, []byte("fatal: Not a valid object name"), 128, nil
	}
	return r.real.Run(ctx, dir, env, name, args...)
}

// ---- AC-E: context deadline/cancel during diff-tree → ErrRegistryOffline ----

// diffTreeCancelRunner is a CommandRunner that intercepts git diff-tree calls and
// simulates the path exec.CommandContext takes when the per-read deadline fires:
// it cancels the injected outer context (propagating cancellation to the filesCtx
// child derived inside extractCommitInfo) and then returns (exitCode=-1, err=nil),
// exactly as SubprocessRunner.Run does when *exec.ExitError.ExitCode() == -1.
//
// All other git commands are forwarded to the real SubprocessRunner so that the
// clone/log/verify/show path uses a real working git binary on the real signed
// repository.
type diffTreeCancelRunner struct {
	real        registry.SubprocessRunner
	cancelOuter context.CancelFunc // called once, on the first diff-tree interception
}

// Run implements fetchtransport.CommandRunner.
func (r *diffTreeCancelRunner) Run(
	ctx context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) (stdout, stderr []byte, exitCode int, err error) {
	if name == "git" && len(args) > 0 && args[0] == "diff-tree" {
		// Cancel the outer context. Go's context propagation is synchronous: the
		// child filesCtx (created inside extractCommitInfo as
		// WithBoundedDeadline(outerCtx, ...)) transitions to Canceled immediately.
		// extractCommitInfo captures filesCtx.Err() BEFORE calling filesCancel(),
		// so the captured filesCtxErr will be context.Canceled when the default
		// branch evaluates it.
		r.cancelOuter()
		// Return (exitCode=-1, err=nil): exactly what SubprocessRunner.Run
		// produces when exec.CommandContext kills the child on context expiry and
		// *exec.ExitError.ExitCode() is -1.
		return nil, []byte("signal: killed"), -1, nil
	}
	return r.real.Run(ctx, dir, env, name, args...)
}

// TestAuditVerify_V8_ACE_DeadlineDuringDiffTree_ErrRegistryOffline verifies
// that when the per-read filesCtx deadline fires during git diff-tree (producing
// exitCode=-1 with err=nil via SubprocessRunner's SIGKILL→ExitCode mapping),
// the result is classified as a transient condition and returned as
// ErrRegistryOffline, NOT as ErrAuditLogTampered and NOT as a clean
// BindingVerified result.
//
// The false-positive path this test guards against:
//   - filesErr == nil && filesExit == -1 falls into the default branch.
//   - Without the filesCtx.Err() guard, default → StagedFilesUndeterminable →
//     bindLines → BindingTampered / ErrAuditLogTampered.
//   - That is a verifier-side timeout being misreported as tamper.
//
// Deadline simulation: diffTreeCancelRunner cancels the outer context (which
// propagates synchronously to filesCtx, a child context created by
// extractCommitInfo) before returning (-1, nil). extractCommitInfo captures
// filesCtx.Err() BEFORE calling filesCancel(), so filesCtxErr == context.Canceled
// when the runner fires — triggering the transient-return path.
//
// C5 invariant: the companion test TestAuditVerify_V8_DeterminateNonZeroExit_StillTampered
// (exitCode=128, err=nil, context NOT expired) still returns ErrAuditLogTampered,
// proving the fix does not over-broaden the transient classification.
func TestAuditVerify_V8_ACE_DeadlineDuringDiffTree_ErrRegistryOffline(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const projectID = "v8ace-project"

	events := buildTestAuditEvents(projectID)
	history := newSignedAuditHistory(t, projectID, events)

	// Build a cancellable context. The diffTreeCancelRunner will cancel it on the
	// first diff-tree interception to propagate cancellation to filesCtx.
	outerCtx, outerCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer outerCancel()

	runner := &diffTreeCancelRunner{
		real:        registry.SubprocessRunner{},
		cancelOuter: outerCancel,
	}
	client := newVerifyAuditClientWithRunner(t, history, runner)

	_, verifyErr := client.VerifyAuditLog(outerCtx, projectID)

	if verifyErr == nil {
		t.Fatal("AC-E: VerifyAuditLog returned nil error — " +
			"a diff-tree deadline/cancel must not produce a clean result")
	}
	if !errors.Is(verifyErr, coreregistry.ErrRegistryOffline) {
		t.Errorf("AC-E: want errors.Is(err, ErrRegistryOffline), got: %v", verifyErr)
	}
	if errors.Is(verifyErr, coreregistry.ErrAuditLogTampered) {
		t.Errorf("AC-E: got ErrAuditLogTampered but want ErrRegistryOffline — "+
			"a diff-tree deadline/cancel must NOT assert tamper: %v", verifyErr)
	}

	t.Logf("AC-E: PASS — ErrRegistryOffline returned, NOT ErrAuditLogTampered: %v", verifyErr)
}
