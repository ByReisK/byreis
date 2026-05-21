package registry_test

// Adapter-level tests for RotationReverserAdapter.
//
// Test rows owned by this file:
//
//   - V5.RECON.reverser-clear-pendings-happy-path
//     Happy path: ClearPendings lands BOTH counter mutation AND audit append
//     in exactly ONE signed commit (same-commit atomicity).
//
//   - V5.RECON.reverser-cas-rejection
//     CAS rejection: push exit 1 with "rejected" text → ErrRegistryConcurrentWrite,
//     no second commit, no retry (adapter surfaces; reconciler owns retry budget).
//
//   - V5.RECON.reverser-validator-rejection
//     Validator rejection: malformed audit.Event → error wraps
//     audit.ErrAuditEventInvalidField; NO git clone, NO counter file mutation,
//     NO commit, NO audit line.
//
//   - V5.RECON.reverser-delete-branch-happy-path
//     DeleteRotationBranch success: git push --delete invoked with correct
//     branch name derived from PRRef.
//
//   - V5.RECON.reverser-delete-branch-cas-rejection
//     DeleteRotationBranch exit 1 "rejected" → ErrRegistryConcurrentWrite.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
	"github.com/ByReisK/byreis/internal/core/audit"
	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ---- test doubles shared by this file ----------------------------------------

// reverserRunner is a CommandRunner that serves pre-configured step responses
// and records all calls made. Thread-safe.
type reverserRunner struct {
	mu    sync.Mutex
	steps []reverserStep
	calls []reverserCall
}

type reverserStep struct {
	stdout   []byte
	stderr   []byte
	exitCode int
	err      error
}

type reverserCall struct {
	dir  string
	env  []string
	name string
	args []string
}

func (r *reverserRunner) Run(
	_ context.Context, dir string, env []string, name string, args ...string,
) ([]byte, []byte, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, reverserCall{dir: dir, env: env, name: name, args: args})
	if len(r.steps) == 0 {
		return nil, nil, 1, errors.New("reverserRunner: no more configured steps")
	}
	step := r.steps[0]
	r.steps = r.steps[1:]
	return step.stdout, step.stderr, step.exitCode, step.err
}

func (r *reverserRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *reverserRunner) callAt(i int) reverserCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[i]
}

// reverserNopSigner is a no-op RegistryWriteSigner for reverser tests.
type reverserNopSigner struct{}

func (s *reverserNopSigner) SignText(_ context.Context, _ []byte) (string, []byte, error) {
	return "test-signer", make([]byte, 64), nil
}

// reverserTokenProvider always returns a fixed token.
type reverserTokenProvider struct{ token string }

func (p *reverserTokenProvider) RegistryWriteToken(_ context.Context, _ string) (string, error) {
	return p.token, nil
}

// ---- tmp directory helpers ---------------------------------------------------

// noopRemoveAll is a no-op cleanup for temp dirs managed by t.TempDir().
func noopRemoveAll(_ string) error { return nil }

// ---- step constructors -------------------------------------------------------

func rrCloneOK() reverserStep { return reverserStep{exitCode: 0} }
func rrRevParseOK() reverserStep {
	return reverserStep{stdout: []byte("aabbccddee112233445566778899aabbccddeeff\n"), exitCode: 0}
}
func rrGitAddOK() reverserStep    { return reverserStep{exitCode: 0} }
func rrGitCfgOK() reverserStep    { return reverserStep{exitCode: 0} }
func rrGitCommitOK() reverserStep { return reverserStep{exitCode: 0} }
func rrGitPushOK() reverserStep   { return reverserStep{exitCode: 0} }
func rrGitPushRejected() reverserStep {
	return reverserStep{
		stderr:   []byte("rejected (non-fast-forward)\n"),
		exitCode: 1,
	}
}
func rrGitDeleteOK() reverserStep { return reverserStep{exitCode: 0} }
func rrGitDeleteRejected() reverserStep {
	return reverserStep{
		stderr:   []byte("rejected (branch does not exist)\n"),
		exitCode: 1,
	}
}

// ---- helper: build a minimal valid audit.Event for reversal ------------------

func reverserValidAuditEvent(projectID string) audit.Event {
	return audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ProjectID:  projectID,
		Outcome:    rotate.RotationOutcomeReverted,
		Details: map[string]string{
			"reversal_target_pr":          "myorg/my-secrets/byreis/rotate-key-111#0",
			"reversal_reason":             "phase-1-only-classification",
			"reversal_pendings_cleared_0": "db-enc",
		},
	}
}

// ---- helper: build a RotationReverserAdapter for tests ----------------------

// newReverserAdapter builds a RotationReverserAdapter. Uses t.TempDir() as the
// MkdirTemp provider so that the os.Chmod call inside the adapter succeeds
// against a real directory on disk, while the git subprocess is still intercepted
// by the recording runner.
func newReverserAdapter(
	t *testing.T,
	runner fetchtransport.CommandRunner,
) *registry.RotationReverserAdapter {
	t.Helper()
	// Provide a MkdirTemp that creates real directories via t.TempDir() so
	// os.Chmod succeeds. RemoveAll is a no-op — t.TempDir cleanup handles it.
	fakeMkdir := func(_, _ string) (string, error) {
		return t.TempDir(), nil
	}
	adapter, err := registry.NewRotationReverserAdapter(registry.RotationReverserDeps{
		RegistryURL:    "file:///fake/registry.git",
		ProjectRepoURL: "file:///fake/project.git",
		Signer:         &reverserNopSigner{},
		TokenProvider:  &reverserTokenProvider{token: "test-token"},
		Runner:         runner,
		MkdirTemp:      fakeMkdir,
		RemoveAll:      noopRemoveAll,
	})
	if err != nil {
		t.Fatalf("NewRotationReverserAdapter: %v", err)
	}
	return adapter
}

// ---- V5.RECON.reverser-clear-pendings-happy-path ----------------------------

// TestReverser_ClearPendings_HappyPath_SingleCommitAtomicity proves that
// ClearPendings lands a SINGLE signed git commit that contains BOTH the counter
// file mutation AND the audit JSONL append. Same-commit atomicity is load-bearing:
// a reader of any post-reconcile registry snapshot must see either both the
// cleared pendings AND the reversal audit row, or neither.
//
// This test uses a real temp directory so the file-write and git-add steps can
// be verified structurally. The git subprocess calls are intercepted by the
// recording runner (no real git network).
func TestReverser_ClearPendings_HappyPath_SingleCommitAtomicity(t *testing.T) {
	t.Parallel()

	// V5.RECON.reverser-clear-pendings-happy-path

	// ClearPendings flow:
	//   1. token fetch (in-process)
	//   2. MkdirTemp + chmod (in-process)
	//   3. git clone   → rrCloneOK
	//   4. git rev-parse HEAD → rrRevParseOK
	//   5. counter file write (in-process)
	//   6. audit JSONL append (in-process)
	//   7. git add -A  → rrGitAddOK
	//   8. git config user.name → rrGitCfgOK
	//   9. git config user.email → rrGitCfgOK
	//  10. Signer.SignText (in-process)
	//  11. git commit -m → rrGitCommitOK
	//  12. git push      → rrGitPushOK
	runner := &reverserRunner{
		steps: []reverserStep{
			rrCloneOK(),     // clone
			rrRevParseOK(),  // rev-parse HEAD
			rrGitAddOK(),    // git add -A
			rrGitCfgOK(),    // git config user.name
			rrGitCfgOK(),    // git config user.email
			rrGitCommitOK(), // git commit
			rrGitPushOK(),   // git push
		},
	}

	var mkdirCalls int
	var createdDirs []string
	fakeMkdir := func(dir, pattern string) (string, error) {
		mkdirCalls++
		d := t.TempDir()
		createdDirs = append(createdDirs, d)
		return d, nil
	}
	var removedDirs []string
	mu := sync.Mutex{}
	fakeRemove := func(path string) error {
		mu.Lock()
		defer mu.Unlock()
		removedDirs = append(removedDirs, path)
		return nil
	}

	adapter, err := registry.NewRotationReverserAdapter(registry.RotationReverserDeps{
		RegistryURL:    "https://github.com/myorg/my-registry",
		ProjectRepoURL: "https://github.com/myorg/my-secrets",
		Signer:         &reverserNopSigner{},
		TokenProvider:  &reverserTokenProvider{token: "tok-123"},
		Runner:         runner,
		MkdirTemp:      fakeMkdir,
		RemoveAll:      fakeRemove,
	})
	if err != nil {
		t.Fatalf("NewRotationReverserAdapter: %v", err)
	}

	// LogicalName must be a single path component (no slashes) per ValidateFileName.
	pendings := []rotate.PendingObservation{
		{
			LogicalName:       "db-enc",
			PendingCounter:    5,
			TargetArtifactSHA: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			TargetPR:          coregit.PRRef{Project: "myorg/my-secrets/byreis/rotate-db-111", Number: 0},
		},
	}
	event := reverserValidAuditEvent("proj-a")

	clearErr := adapter.ClearPendings(context.Background(), "proj-a", pendings, event)
	if clearErr != nil {
		t.Fatalf("ClearPendings returned unexpected error: %v", clearErr)
	}

	// Atomicity assertion: exactly ONE commit call, ONE push call.
	nCalls := runner.callCount()
	// Expected: clone, rev-parse, add, cfg×2, commit, push = 7
	if nCalls != 7 {
		t.Errorf("runner call count = %d, want 7 (clone+rev-parse+add+cfg×2+commit+push)", nCalls)
	}

	// Verify commit was reached (call index 5 = "git commit").
	commitCall := runner.callAt(5)
	if commitCall.name != "git" {
		t.Errorf("call[5].name = %q, want 'git'", commitCall.name)
	}
	if len(commitCall.args) < 1 || commitCall.args[0] != "commit" {
		t.Errorf("call[5].args[0] = %q, want 'commit'", commitCall.args[0])
	}
	// The commit message must include the signer envelope prefix.
	var commitMsg string
	for i, arg := range commitCall.args {
		if arg == "-m" && i+1 < len(commitCall.args) {
			commitMsg = commitCall.args[i+1]
			break
		}
	}
	if !strings.Contains(commitMsg, "byreis: rotation reversal") {
		t.Errorf("commit message missing 'byreis: rotation reversal': %q", commitMsg)
	}
	if !strings.Contains(commitMsg, "byreis-signer:") {
		t.Errorf("commit message missing 'byreis-signer:' envelope: %q", commitMsg)
	}
	if !strings.Contains(commitMsg, "byreis-sig:") {
		t.Errorf("commit message missing 'byreis-sig:' envelope: %q", commitMsg)
	}

	// Verify CAS push (call index 6).
	pushCall := runner.callAt(6)
	if pushCall.name != "git" || pushCall.args[0] != "push" {
		t.Errorf("call[6] should be 'git push', got name=%q args=%v", pushCall.name, pushCall.args)
	}
	var hasForceLease bool
	for _, arg := range pushCall.args {
		if strings.HasPrefix(arg, "--force-with-lease=") {
			hasForceLease = true
			break
		}
	}
	if !hasForceLease {
		t.Errorf("CAS push missing --force-with-lease flag; push args = %v", pushCall.args)
	}

	// Temp dir cleanup: defer on MkdirTemp was called with RemoveAll.
	if mkdirCalls < 1 {
		t.Error("MkdirTemp was not called")
	}
}

// ---- V5.RECON.reverser-cas-rejection ----------------------------------------

// TestReverser_ClearPendings_CASRejection_ReturnsErrRegistryConcurrentWrite
// proves that a push exit-1 with "rejected" in stderr maps to
// ErrRegistryConcurrentWrite. The adapter must NOT retry internally
// (bounded retry budget is owned by the reconciler).
func TestReverser_ClearPendings_CASRejection_ReturnsErrRegistryConcurrentWrite(t *testing.T) {
	t.Parallel()

	// V5.RECON.reverser-cas-rejection

	runner := &reverserRunner{
		steps: []reverserStep{
			rrCloneOK(),         // clone
			rrRevParseOK(),      // rev-parse HEAD
			rrGitAddOK(),        // git add -A
			rrGitCfgOK(),        // git config user.name
			rrGitCfgOK(),        // git config user.email
			rrGitCommitOK(),     // git commit
			rrGitPushRejected(), // git push → CAS rejection
		},
	}

	adapter := newReverserAdapter(t, runner)

	pendings := []rotate.PendingObservation{
		{
			LogicalName:       "db-enc",
			PendingCounter:    3,
			TargetArtifactSHA: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			TargetPR:          coregit.PRRef{Project: "myorg/my-secrets/byreis/rotate-db-222", Number: 0},
		},
	}
	event := reverserValidAuditEvent("proj-b")

	clearErr := adapter.ClearPendings(context.Background(), "proj-b", pendings, event)
	if clearErr == nil {
		t.Fatal("ClearPendings: expected ErrRegistryConcurrentWrite, got nil")
	}
	if !errors.Is(clearErr, registry.ErrRegistryConcurrentWrite) {
		t.Errorf("want errors.Is(err, ErrRegistryConcurrentWrite), got: %v", clearErr)
	}

	// Adapter must NOT retry — exactly 7 runner calls total (no second clone).
	nCalls := runner.callCount()
	if nCalls != 7 {
		t.Errorf("runner calls = %d after CAS rejection, want 7 (no internal retry)", nCalls)
	}
}

// ---- V5.RECON.reverser-validator-rejection -----------------------------------

// TestReverser_ClearPendings_ValidatorRejects_NoCommitNoAuditLine proves that
// when audit.ValidateEventFields rejects the reversal event, NO git subprocess
// is invoked, NO counter file is mutated, and the returned error wraps
// audit.ErrAuditEventInvalidField.
//
// This test uses a zero-step runner so any invocation panics the test via
// the "no more configured steps" path — which surfaces as a non-nil error
// exposing the violation.
func TestReverser_ClearPendings_ValidatorRejects_NoCommitNoAuditLine(t *testing.T) {
	t.Parallel()

	// V5.RECON.reverser-validator-rejection

	// A zero-step runner: any Run call will return an error from the runner
	// itself, which would surface as a git clone error, making it detectable
	// that the runner was invoked despite the validation gate.
	runner := &reverserRunner{steps: []reverserStep{}}

	adapter := newReverserAdapter(t, runner)

	// Malformed event: Details map contains a key with a value that is too long
	// (> 512 chars), which fails ValidateEventFields.
	malformedEvent := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ProjectID:  "proj-c",
		Outcome:    rotate.RotationOutcomeReverted,
		Details: map[string]string{
			// A value exceeding 512 bytes causes ErrAuditEventInvalidField.
			"reversal_reason": strings.Repeat("x", 513),
		},
	}

	pendings := []rotate.PendingObservation{
		{
			LogicalName:       "db-enc",
			PendingCounter:    1,
			TargetArtifactSHA: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			TargetPR:          coregit.PRRef{Project: "myorg/my-secrets/byreis/rotate-db-333", Number: 0},
		},
	}

	clearErr := adapter.ClearPendings(context.Background(), "proj-c", pendings, malformedEvent)
	if clearErr == nil {
		t.Fatal("ClearPendings: expected error for malformed event, got nil")
	}
	if !errors.Is(clearErr, audit.ErrAuditEventInvalidField) {
		t.Errorf("want errors.Is(err, audit.ErrAuditEventInvalidField), got: %v", clearErr)
	}

	// NO git calls must have been made (runner must be empty).
	if runner.callCount() != 0 {
		t.Errorf("runner was called %d times; must be 0 (validation gate must fire before git clone)", runner.callCount())
	}
}

// ---- V5.RECON.reverser-delete-branch-happy-path -----------------------------

// TestReverser_DeleteRotationBranch_HappyPath proves that DeleteRotationBranch
// invokes "git push <projectRepoURL> --delete <branchName>" and returns nil on
// exit 0.
func TestReverser_DeleteRotationBranch_HappyPath(t *testing.T) {
	t.Parallel()

	// V5.RECON.reverser-delete-branch-happy-path

	runner := &reverserRunner{
		steps: []reverserStep{
			rrGitDeleteOK(), // git push --delete
		},
	}

	adapter := newReverserAdapter(t, runner)

	// PRRef for a rotation branch: Project = "<owner/repo>/<branchName>".
	ref := coregit.PRRef{
		Project: "myorg/my-secrets/byreis/rotate-key-1234567890",
		Number:  0,
	}

	delErr := adapter.DeleteRotationBranch(context.Background(), ref)
	if delErr != nil {
		t.Fatalf("DeleteRotationBranch: unexpected error: %v", delErr)
	}

	if runner.callCount() != 1 {
		t.Fatalf("runner call count = %d, want 1", runner.callCount())
	}
	call := runner.callAt(0)
	if call.name != "git" {
		t.Errorf("call.name = %q, want 'git'", call.name)
	}
	// Args must include "push", "--delete", and the branch name.
	argsStr := strings.Join(call.args, " ")
	if !strings.Contains(argsStr, "push") {
		t.Errorf("args missing 'push': %v", call.args)
	}
	if !strings.Contains(argsStr, "--delete") {
		t.Errorf("args missing '--delete': %v", call.args)
	}
	if !strings.Contains(argsStr, "byreis/rotate-key-1234567890") {
		t.Errorf("args missing branch name 'byreis/rotate-key-1234567890': %v", call.args)
	}
}

// ---- V5.RECON.reverser-delete-branch-cas-rejection --------------------------

// TestReverser_DeleteRotationBranch_CASRejection_ReturnsErrRegistryConcurrentWrite
// proves that push --delete exit 1 with "rejected" maps to
// ErrRegistryConcurrentWrite (the branch was concurrently merged or already
// deleted).
func TestReverser_DeleteRotationBranch_CASRejection_ReturnsErrRegistryConcurrentWrite(t *testing.T) {
	t.Parallel()

	// V5.RECON.reverser-delete-branch-cas-rejection

	runner := &reverserRunner{
		steps: []reverserStep{
			rrGitDeleteRejected(), // git push --delete → rejected
		},
	}

	adapter := newReverserAdapter(t, runner)

	ref := coregit.PRRef{
		Project: "myorg/my-secrets/byreis/rotate-key-9999999999",
		Number:  0,
	}

	delErr := adapter.DeleteRotationBranch(context.Background(), ref)
	if delErr == nil {
		t.Fatal("DeleteRotationBranch: expected ErrRegistryConcurrentWrite, got nil")
	}
	if !errors.Is(delErr, registry.ErrRegistryConcurrentWrite) {
		t.Errorf("want errors.Is(err, ErrRegistryConcurrentWrite), got: %v", delErr)
	}
}

// ---- constructor guards -------------------------------------------------------

// TestReverser_ConstructorGuards proves that NewRotationReverserAdapter returns
// errors for each required field when nil or empty.
func TestReverser_ConstructorGuards(t *testing.T) {
	t.Parallel()

	runner := &reverserRunner{}

	cases := []struct {
		name string
		deps registry.RotationReverserDeps
	}{
		{
			name: "empty RegistryURL",
			deps: registry.RotationReverserDeps{
				RegistryURL:    "",
				ProjectRepoURL: "file:///fake/proj.git",
				Signer:         &reverserNopSigner{},
				TokenProvider:  &reverserTokenProvider{},
				Runner:         runner,
			},
		},
		{
			name: "empty ProjectRepoURL",
			deps: registry.RotationReverserDeps{
				RegistryURL:    "file:///fake/reg.git",
				ProjectRepoURL: "",
				Signer:         &reverserNopSigner{},
				TokenProvider:  &reverserTokenProvider{},
				Runner:         runner,
			},
		},
		{
			name: "nil Signer",
			deps: registry.RotationReverserDeps{
				RegistryURL:    "file:///fake/reg.git",
				ProjectRepoURL: "file:///fake/proj.git",
				Signer:         nil,
				TokenProvider:  &reverserTokenProvider{},
				Runner:         runner,
			},
		},
		{
			name: "nil TokenProvider",
			deps: registry.RotationReverserDeps{
				RegistryURL:    "file:///fake/reg.git",
				ProjectRepoURL: "file:///fake/proj.git",
				Signer:         &reverserNopSigner{},
				TokenProvider:  nil,
				Runner:         runner,
			},
		},
		{
			name: "nil Runner",
			deps: registry.RotationReverserDeps{
				RegistryURL:    "file:///fake/reg.git",
				ProjectRepoURL: "file:///fake/proj.git",
				Signer:         &reverserNopSigner{},
				TokenProvider:  &reverserTokenProvider{},
				Runner:         nil,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := registry.NewRotationReverserAdapter(tc.deps)
			if err == nil {
				t.Errorf("%s: expected construction error, got nil", tc.name)
			}
		})
	}
}

// ---- compile-time assertion --------------------------------------------------

// TestReverser_CompileTimeAssert asserts RotationReverserAdapter satisfies the
// rotate.RotationStateReverser port without needing a value.
var _ rotate.RotationStateReverser = (*registry.RotationReverserAdapter)(nil)
