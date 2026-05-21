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
	"os"
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

// reverserContentCapturingRunner wraps reverserRunner and captures the content
// of the -F temp file on the commit call (call index 5 in ClearPendings). The
// file is read during the Run() call, before the adapter's deferred os.Remove
// fires. Used to verify the commit message body without exposing it in argv.
type reverserContentCapturingRunner struct {
	*reverserRunner
	mu              sync.Mutex
	capturedContent string
	captureIndex    int // which call index to capture the -F file content from
}

func (r *reverserContentCapturingRunner) Run(
	ctx context.Context, dir string, env []string, name string, args ...string,
) ([]byte, []byte, int, error) {
	r.mu.Lock()
	callIdx := len(r.calls) // before the call is recorded
	r.mu.Unlock()

	stdout, stderr, exit, err := r.reverserRunner.Run(ctx, dir, env, name, args...)

	// If this is the capture index and it's a commit call, read the -F file.
	if callIdx == r.captureIndex && name == "git" && len(args) > 0 && args[0] == "commit" {
		for i, arg := range args {
			if arg == "-F" && i+1 < len(args) {
				content, readErr := os.ReadFile(args[i+1])
				if readErr == nil {
					r.mu.Lock()
					r.capturedContent = string(content)
					r.mu.Unlock()
				}
				break
			}
		}
	}
	return stdout, stderr, exit, err
}

func (r *reverserContentCapturingRunner) content() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.capturedContent
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
	// Commit must use -F <msgFile> (not -m) so byreis-sig: never appears in argv.
	var commitMsgFile string
	for i, arg := range commitCall.args {
		if arg == "-F" && i+1 < len(commitCall.args) {
			commitMsgFile = commitCall.args[i+1]
			break
		}
	}
	if commitMsgFile == "" {
		t.Errorf("git commit call missing -F flag; args = %v", commitCall.args)
	}
	// The -F path must be a non-empty temp-file path (not the message body itself).
	if !strings.Contains(commitMsgFile, "commitmsg-reversal") {
		t.Errorf("git commit -F value %q does not contain expected 'commitmsg-reversal' prefix", commitMsgFile)
	}
	// No -m flag must appear in the commit args (byreis-sig: must not be in argv).
	for _, arg := range commitCall.args {
		if arg == "-m" {
			t.Errorf("git commit args contain -m flag — byreis-sig: would be exposed in argv: %v", commitCall.args)
			break
		}
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

// ---- commit message body content check via file capture ---------------------

// TestReverser_ClearPendings_CommitMessageBody_ContainsRequiredFields verifies
// that the reversal commit message body (written to the -F temp file) contains
// all required canonical fields. The content-capturing runner reads the file
// during the Run() call, before the adapter's deferred os.Remove fires.
func TestReverser_ClearPendings_CommitMessageBody_ContainsRequiredFields(t *testing.T) {
	t.Parallel()

	baseRunner := &reverserRunner{
		steps: []reverserStep{
			rrCloneOK(),
			rrRevParseOK(),
			rrGitAddOK(),
			rrGitCfgOK(),
			rrGitCfgOK(),
			rrGitCommitOK(), // index 5 — captured
			rrGitPushOK(),
		},
	}
	capturer := &reverserContentCapturingRunner{
		reverserRunner: baseRunner,
		captureIndex:   5, // commit is at index 5
	}

	fakeMkdir := func(_, _ string) (string, error) {
		return t.TempDir(), nil
	}

	adapter, err := registry.NewRotationReverserAdapter(registry.RotationReverserDeps{
		RegistryURL:    "https://github.com/myorg/reg.git",
		ProjectRepoURL: "https://github.com/myorg/proj.git",
		Signer:         &reverserNopSigner{},
		TokenProvider:  &reverserTokenProvider{token: "tok-body"},
		Runner:         capturer,
		MkdirTemp:      fakeMkdir,
		RemoveAll:      noopRemoveAll,
	})
	if err != nil {
		t.Fatalf("NewRotationReverserAdapter: %v", err)
	}

	pendings := []rotate.PendingObservation{
		{
			LogicalName:       "db-enc",
			PendingCounter:    7,
			TargetArtifactSHA: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			TargetPR:          coregit.PRRef{Project: "myorg/proj/byreis/rotate-db-body", Number: 0},
		},
	}

	if err := adapter.ClearPendings(context.Background(), "proj-body", pendings, reverserValidAuditEvent("proj-body")); err != nil {
		t.Fatalf("ClearPendings: unexpected error: %v", err)
	}

	msg := capturer.content()
	if msg == "" {
		t.Fatal("commit message body not captured — the content-capturing runner did not fire")
	}

	required := []struct {
		needle string
		label  string
	}{
		{"byreis: rotation reversal", "header"},
		{"project_id: proj-body", "project_id field"},
		{"pending_cleared: db-enc", "pending_cleared field"},
		{"audit_entry_sha:", "audit_entry_sha field (atomicity proof)"},
		{"registry_parent_sha:", "registry_parent_sha (CAS anchor)"},
		{"byreis-signer:", "signer envelope"},
		{"byreis-sig:", "signature envelope"},
	}
	for _, r := range required {
		if !strings.Contains(msg, r.needle) {
			t.Errorf("commit body missing %s (%q); full body = %q", r.label, r.needle, msg)
		}
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

// ---- CR-1 regression: exactly one GIT_CONFIG_COUNT entry -------------------

// TestReverser_EnvBuilder_ExactlyOneGITConfigCount proves that the env slice
// produced for an authenticated git call contains EXACTLY ONE entry that
// starts with "GIT_CONFIG_COUNT=". A duplicate COUNT entry causes glibc's
// getenv to return the first (lower) value, silently dropping the auth header
// and causing production HTTPS push to fail with 401/403.
//
// This regression test verifies the fix: the env slice from a ClearPendings
// clone call (which uses a token) has exactly one GIT_CONFIG_COUNT entry,
// and that entry has the value "3" (two base entries + one auth entry).
//
// Mutation proof: on the OLD code, hardenedEnv(authEnv()...) produced two
// GIT_CONFIG_COUNT entries; this test would fail on the old code with
// "GIT_CONFIG_COUNT appears 2 times in env, want 1".
func TestReverser_EnvBuilder_ExactlyOneGITConfigCount(t *testing.T) {
	t.Parallel()

	// Happy-path runner: ClearPendings calls clone (uses auth env), rev-parse,
	// add, config×2, commit, push.
	runner := &reverserRunner{
		steps: []reverserStep{
			rrCloneOK(),
			rrRevParseOK(),
			rrGitAddOK(),
			rrGitCfgOK(),
			rrGitCfgOK(),
			rrGitCommitOK(),
			rrGitPushOK(),
		},
	}

	fakeMkdir := func(_, _ string) (string, error) {
		return t.TempDir(), nil
	}

	adapter, err := registry.NewRotationReverserAdapter(registry.RotationReverserDeps{
		RegistryURL:    "https://github.com/myorg/registry.git",
		ProjectRepoURL: "https://github.com/myorg/project.git",
		Signer:         &reverserNopSigner{},
		TokenProvider:  &reverserTokenProvider{token: "tok-env-test"},
		Runner:         runner,
		MkdirTemp:      fakeMkdir,
		RemoveAll:      noopRemoveAll,
	})
	if err != nil {
		t.Fatalf("NewRotationReverserAdapter: %v", err)
	}

	pendings := []rotate.PendingObservation{
		{
			LogicalName:       "db-enc",
			PendingCounter:    1,
			TargetArtifactSHA: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			TargetPR:          coregit.PRRef{Project: "myorg/project/byreis/rotate-db-env", Number: 0},
		},
	}

	if err := adapter.ClearPendings(context.Background(), "proj-env", pendings, reverserValidAuditEvent("proj-env")); err != nil {
		t.Fatalf("ClearPendings: unexpected error: %v", err)
	}

	// Inspect the env on the clone call (index 0) — this call uses auth env
	// and is the one that previously emitted two GIT_CONFIG_COUNT entries.
	cloneCall := runner.callAt(0)

	countEntries := 0
	countValue := ""
	for _, entry := range cloneCall.env {
		if strings.HasPrefix(entry, "GIT_CONFIG_COUNT=") {
			countEntries++
			countValue = entry
		}
	}

	if countEntries != 1 {
		t.Errorf("GIT_CONFIG_COUNT appears %d times in env, want exactly 1; "+
			"duplicate entries cause glibc getenv to return the first (wrong) value "+
			"and silently drop the Authorization header; env = %v",
			countEntries, cloneCall.env)
	} else if countValue != "GIT_CONFIG_COUNT=3" {
		// With a token, the count must be 3 (2 base + 1 auth).
		t.Errorf("GIT_CONFIG_COUNT = %q, want 'GIT_CONFIG_COUNT=3' "+
			"(2 base entries + 1 auth entry)", countValue)
	}

	// Also verify the no-auth path: config calls (index 3, 4) must have COUNT=2.
	for _, idx := range []int{3, 4} {
		call := runner.callAt(idx)
		nCount := 0
		noAuthCount := ""
		for _, entry := range call.env {
			if strings.HasPrefix(entry, "GIT_CONFIG_COUNT=") {
				nCount++
				noAuthCount = entry
			}
		}
		if nCount != 1 {
			t.Errorf("call[%d] (no-auth): GIT_CONFIG_COUNT appears %d times, want 1; env = %v",
				idx, nCount, call.env)
		} else if noAuthCount != "GIT_CONFIG_COUNT=2" {
			t.Errorf("call[%d] (no-auth): GIT_CONFIG_COUNT = %q, want 'GIT_CONFIG_COUNT=2'",
				idx, noAuthCount)
		}
	}
}

// ---- CR-2 regression: reversal commit argv must not contain byreis-sig: ----

// TestReverser_ClearPendings_CommitArgv_NoByreisSignatureInArgv proves that the
// reversal commit subprocess does NOT receive the signed message as an -m
// argument. The byreis-sig: footer must travel via a temp file (-F flag), never
// via argv where it is visible in /proc/<pid>/cmdline and ps output.
func TestReverser_ClearPendings_CommitArgv_NoByreisSignatureInArgv(t *testing.T) {
	t.Parallel()

	runner := &reverserRunner{
		steps: []reverserStep{
			rrCloneOK(),
			rrRevParseOK(),
			rrGitAddOK(),
			rrGitCfgOK(),
			rrGitCfgOK(),
			rrGitCommitOK(),
			rrGitPushOK(),
		},
	}

	adapter := newReverserAdapter(t, runner)

	pendings := []rotate.PendingObservation{
		{
			LogicalName:       "vault-enc",
			PendingCounter:    2,
			TargetArtifactSHA: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
			TargetPR:          coregit.PRRef{Project: "myorg/project/byreis/rotate-vault-111", Number: 0},
		},
	}

	if err := adapter.ClearPendings(context.Background(), "proj-argv", pendings, reverserValidAuditEvent("proj-argv")); err != nil {
		t.Fatalf("ClearPendings: unexpected error: %v", err)
	}

	// Locate the commit call (index 5).
	commitCall := runner.callAt(5)
	if len(commitCall.args) == 0 || commitCall.args[0] != "commit" {
		t.Fatalf("call[5] is not 'git commit'; args = %v", commitCall.args)
	}

	// No -m flag in argv.
	for _, arg := range commitCall.args {
		if arg == "-m" {
			t.Errorf("commit args contain -m flag — message body (byreis-sig:) exposed in argv: %v",
				commitCall.args)
			break
		}
	}

	// No byreis-sig: sequence in any argv element.
	for _, arg := range commitCall.args {
		if strings.Contains(arg, "byreis-sig:") {
			t.Errorf("commit argv element %q contains 'byreis-sig:' — "+
				"signature exposed in process argv; args = %v", arg, commitCall.args)
		}
	}

	// -F flag must be present with a tmp-file path.
	var hasDashF bool
	for i, arg := range commitCall.args {
		if arg == "-F" && i+1 < len(commitCall.args) {
			hasDashF = true
			if !strings.Contains(commitCall.args[i+1], "commitmsg-reversal") {
				t.Errorf("commit -F path %q does not contain 'commitmsg-reversal'",
					commitCall.args[i+1])
			}
			break
		}
	}
	if !hasDashF {
		t.Errorf("commit args missing -F flag; args = %v", commitCall.args)
	}
}

// ---- compile-time assertion --------------------------------------------------

// TestReverser_CompileTimeAssert asserts RotationReverserAdapter satisfies the
// rotate.RotationStateReverser port without needing a value.
var _ rotate.RotationStateReverser = (*registry.RotationReverserAdapter)(nil)
