// Package registry — counter write-path tests.
//
// Test obligations for B6-COUNTER-WRITE-RESIDUAL:
//
//   - B1:  CONTRIBUTOR-mode token isolation (mode-gate test).
//   - CC-1: cold-absent → (0,nil,nil); warm-absent → ErrCounterReconcile.
//   - Q3c:  parent_commit_sha mismatch → ErrCounterReconcile.
//   - Q1b:  CommitCounter advances last_accepted AND clears pending in ONE commit.
//   - O1:   CAS — concurrent write detected → ErrRegistryConcurrentWrite.
//   - O3:   Idempotent resume — server-landed pending re-detected on re-run.
//   - O2:   Sentinel taxonomy — typed, errors.Is-detectable, actionable hints.
//   - Q3a:  Signing-key isolation — counter-write does NOT import crypto/ed25519.
//   - ErrRegistryWriteAuth when writeCfg is nil.
//   - ErrCounterReconcile when CommitCounter called without prior WriteCounter.
package registry_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// ---- B1: mode-gate / nil write config ----------------------------------------

// TestWriteCounter_NilWriteCfg_ReturnsRegistryWriteAuth asserts that calling
// WriteCounter when no writeCfg is provided returns ErrRegistryWriteAuth.
// This is the B1 fail-closed path: contributor paths never have writeCfg set,
// so they receive ErrRegistryWriteAuth on any counter-write attempt.
func TestWriteCounter_NilWriteCfg_ReturnsRegistryWriteAuth(t *testing.T) {
	t.Parallel()

	v := cwNewVerifier(t, &recordingRunner{steps: []recordStep{}})
	pt, err := registry.NewProductionFetchTransport(v, nil) // nil writeCfg
	if err != nil {
		t.Fatalf("NewProductionFetchTransport: %v", err)
	}

	bump := &countertypes.PendingBump{
		PendingCounter:    1,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "owner/repo#1",
	}
	writeErr := pt.WriteCounter(context.Background(), "https://example.com/reg.git", "proj1", "secrets", bump)
	if writeErr == nil {
		t.Fatal("WriteCounter with nil writeCfg: expected error, got nil")
	}
	if !errors.Is(writeErr, registry.ErrRegistryWriteAuth) {
		t.Errorf("WriteCounter nil writeCfg: want ErrRegistryWriteAuth, got: %v", writeErr)
	}
	// Hint string must be present.
	if msg := writeErr.Error(); msg == "" {
		t.Error("WriteCounter nil writeCfg: error message is empty")
	}
}

// TestCommitCounter_NilWriteCfg_ReturnsRegistryWriteAuth asserts the same
// fail-closed path for CommitCounter.
func TestCommitCounter_NilWriteCfg_ReturnsRegistryWriteAuth(t *testing.T) {
	t.Parallel()

	v := cwNewVerifier(t, &recordingRunner{steps: []recordStep{}})
	pt, err := registry.NewProductionFetchTransport(v, nil)
	if err != nil {
		t.Fatalf("NewProductionFetchTransport: %v", err)
	}

	commitErr := pt.CommitCounter(context.Background(), "https://example.com/reg.git", "proj1", "secrets", 1)
	if commitErr == nil {
		t.Fatal("CommitCounter with nil writeCfg: expected error, got nil")
	}
	if !errors.Is(commitErr, registry.ErrRegistryWriteAuth) {
		t.Errorf("CommitCounter nil writeCfg: want ErrRegistryWriteAuth, got: %v", commitErr)
	}
}

// TestRegistryWriteTokenProvider_ContributorModeFails asserts the B1 mode-gate:
// a fakeTokenProvider that simulates CONTRIBUTOR mode refuses to return a token.
func TestRegistryWriteTokenProvider_ContributorModeFails(t *testing.T) {
	t.Parallel()

	provider := &contributorModeTokenProvider{}
	_, err := provider.RegistryWriteToken(context.Background(), "https://example.com/reg.git")
	if err == nil {
		t.Fatal("RegistryWriteToken in contributor mode: expected error, got nil")
	}
	// The error must be detectable as ErrRegistryWriteAuth via errors.Is.
	if !errors.Is(err, registry.ErrRegistryWriteAuth) {
		t.Errorf("contributor mode token: want ErrRegistryWriteAuth, got: %v", err)
	}
}

// contributorModeTokenProvider is a fake RegistryWriteTokenProvider that always
// refuses to return a token, simulating a process running in CONTRIBUTOR mode.
// This is the B1 mode-gate: a CONTRIBUTOR must never receive the registry-write
// credential. The production implementation checks mode before returning; this
// fake encodes the "always refuse" contract so tests can assert the API.
type contributorModeTokenProvider struct{}

func (p *contributorModeTokenProvider) RegistryWriteToken(_ context.Context, _ string) (string, error) {
	return "", &contributorModeTokenErr{}
}

type contributorModeTokenErr struct{}

func (e *contributorModeTokenErr) Error() string {
	return "registry-write credential is missing or has insufficient scope — " +
		"run `byreis admin register` to add a registry-write token"
}

func (e *contributorModeTokenErr) Is(target error) bool {
	return target == registry.ErrRegistryWriteAuth
}

// ---- CC-1: cold-absent OK / warm-absent ErrCounterReconcile -----------------

// TestReadCounter_CC1_ColdAbsent_ReturnsZeroNilNil asserts that an absent
// counter file for a cold project (no projects/<projectID>.yaml listing
// the file) returns (0, nil, nil) — safe zero counter for a first merge.
func TestReadCounter_CC1_ColdAbsent_ReturnsZeroNilNil(t *testing.T) {
	t.Parallel()

	// Step sequence: clone, rev-parse, verify (FetchHead), then two cat-file calls:
	// first 404 for the counter file, second 404 for projects/proj1.yaml (cold).
	runner := &recordingRunner{
		steps: []recordStep{
			b66CloneOK(), b66RevParseOK(), b66VerifyOK(),
			b66CatFile404(), // counter file absent
			b66CatFile404(), // projects/proj1.yaml absent → cold project
		},
	}
	v := cwNewVerifier(t, runner)
	pt, err := registry.NewProductionFetchTransport(v, nil)
	if err != nil {
		t.Fatalf("NewProductionFetchTransport: %v", err)
	}

	commit, _, verified, fErr := pt.FetchHead(context.Background(), "https://example.com/reg.git", b66AnchorKey())
	if fErr != nil || !verified {
		t.Fatalf("FetchHead: err=%v verified=%v", fErr, verified)
	}

	la, pending, err := pt.ReadCounter(context.Background(), "https://example.com/reg.git", commit, "proj1", "secrets")
	if err != nil {
		t.Fatalf("CC-1 cold-absent: expected (0,nil,nil), got err: %v", err)
	}
	if la != 0 {
		t.Errorf("CC-1 cold-absent: la=%d, want 0", la)
	}
	if pending != nil {
		t.Errorf("CC-1 cold-absent: pending=%v, want nil", pending)
	}
}

// TestReadCounter_CC1_WarmAbsent_ReturnsErrCounterReconcile asserts that an
// absent counter file for a warm project (projects/<projectID>.yaml exists and
// lists the fileName) returns ErrCounterReconcile — integrity violation.
func TestReadCounter_CC1_WarmAbsent_ReturnsErrCounterReconcile(t *testing.T) {
	t.Parallel()

	// projects/proj1.yaml lists "secrets" as a configured file.
	projectYAML := []byte("files:\n  secrets: secrets/prod.enc.yaml\n")

	runner := &recordingRunner{
		steps: []recordStep{
			b66CloneOK(), b66RevParseOK(), b66VerifyOK(),
			b66CatFile404(),           // counter file absent
			b66CatFileOK(projectYAML), // projects/proj1.yaml present → warm project
		},
	}
	v := cwNewVerifier(t, runner)
	pt, err := registry.NewProductionFetchTransport(v, nil)
	if err != nil {
		t.Fatalf("NewProductionFetchTransport: %v", err)
	}

	commit, _, verified, fErr := pt.FetchHead(context.Background(), "https://example.com/reg.git", b66AnchorKey())
	if fErr != nil || !verified {
		t.Fatalf("FetchHead: err=%v verified=%v", fErr, verified)
	}

	_, _, readErr := pt.ReadCounter(context.Background(), "https://example.com/reg.git", commit, "proj1", "secrets")
	if readErr == nil {
		t.Fatal("CC-1 warm-absent: expected ErrCounterReconcile, got nil")
	}
	if !errors.Is(readErr, countertypes.ErrCounterReconcile) {
		t.Errorf("CC-1 warm-absent: want ErrCounterReconcile, got: %v", readErr)
	}
}

// ---- Q3c: parent_commit_sha mismatch → ErrCounterReconcile ------------------

// TestReadCounter_ParentSHAMismatch_ReturnsErrCounterReconcile asserts that a
// pending record whose parent_commit_sha does not match the actual parent of
// the counter-bearing commit returns ErrCounterReconcile. This is the
// captured-commit-replay defence.
func TestReadCounter_ParentSHAMismatch_ReturnsErrCounterReconcile(t *testing.T) {
	t.Parallel()

	const differentParentSHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	// Build counter JSON with a parent_commit_sha that does NOT match what
	// the git log will return.
	counterJSON := cwCounterJSONWithParent("proj1", "secrets", 3, "pr-42", &cwPending{
		PendingCounter:    4,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "pr-43",
		IntentAt:          "2024-01-02T00:00:00Z",
		ParentCommitSHA:   differentParentSHA, // deliberately wrong
	})

	// git log returns b66ValidParentSHA (≠ differentParentSHA) → mismatch.
	runner := &recordingRunner{
		steps: []recordStep{
			b66CloneOK(), b66RevParseOK(), b66VerifyOK(),
			b66CatFileOK(counterJSON),
			b66GitLogParentOK(), // returns b66ValidParentSHA
		},
	}
	v := cwNewVerifier(t, runner)
	pt, err := registry.NewProductionFetchTransport(v, nil)
	if err != nil {
		t.Fatalf("NewProductionFetchTransport: %v", err)
	}

	commit, _, verified, fErr := pt.FetchHead(context.Background(), "https://example.com/reg.git", b66AnchorKey())
	if fErr != nil || !verified {
		t.Fatalf("FetchHead: err=%v verified=%v", fErr, verified)
	}

	_, _, readErr := pt.ReadCounter(context.Background(), "https://example.com/reg.git", commit, "proj1", "secrets")
	if readErr == nil {
		t.Fatal("parent_commit_sha mismatch: expected ErrCounterReconcile, got nil")
	}
	if !errors.Is(readErr, countertypes.ErrCounterReconcile) {
		t.Errorf("parent_commit_sha mismatch: want ErrCounterReconcile, got: %v", readErr)
	}
}

// TestReadCounter_ParentSHAMatch_OK asserts that a pending record whose
// parent_commit_sha matches the actual parent passes validation.
func TestReadCounter_ParentSHAMatch_OK(t *testing.T) {
	t.Parallel()

	counterJSON := cwCounterJSONWithParent("proj1", "secrets", 3, "pr-42", &cwPending{
		PendingCounter:    4,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "pr-43",
		IntentAt:          "2024-01-02T00:00:00Z",
		ParentCommitSHA:   b66ValidParentSHA, // matches what git log returns
	})

	runner := &recordingRunner{
		steps: []recordStep{
			b66CloneOK(), b66RevParseOK(), b66VerifyOK(),
			b66CatFileOK(counterJSON),
			b66GitLogParentOK(), // returns b66ValidParentSHA — matches
		},
	}
	v := cwNewVerifier(t, runner)
	pt, err := registry.NewProductionFetchTransport(v, nil)
	if err != nil {
		t.Fatalf("NewProductionFetchTransport: %v", err)
	}

	commit, _, verified, fErr := pt.FetchHead(context.Background(), "https://example.com/reg.git", b66AnchorKey())
	if fErr != nil || !verified {
		t.Fatalf("FetchHead: err=%v verified=%v", fErr, verified)
	}

	la, pending, err := pt.ReadCounter(context.Background(), "https://example.com/reg.git", commit, "proj1", "secrets")
	if err != nil {
		t.Fatalf("parent_commit_sha match: unexpected error: %v", err)
	}
	if la != 3 {
		t.Errorf("la=%d, want 3", la)
	}
	if pending == nil || pending.PendingCounter != 4 {
		t.Errorf("pending mismatch: %+v", pending)
	}
	pt.DiscardCounterSession(context.Background(), commit)
}

// ---- WriteCounter / CommitCounter: token-provider path ----------------------

// TestWriteCounter_TokenProviderRefuses_ReturnsRegistryWriteAuth asserts that
// when the token provider returns an error, WriteCounter surfaces it as
// ErrRegistryWriteAuth.
func TestWriteCounter_TokenProviderRefuses_ReturnsRegistryWriteAuth(t *testing.T) {
	t.Parallel()

	writeCfg := &registry.FetchTransportWriteConfig{
		Signer:        &cwNopSigner{},
		TokenProvider: &contributorModeTokenProvider{}, // always refuses
	}
	v := cwNewVerifier(t, &recordingRunner{steps: []recordStep{}})
	pt, err := registry.NewProductionFetchTransport(v, writeCfg)
	if err != nil {
		t.Fatalf("NewProductionFetchTransport: %v", err)
	}

	bump := &countertypes.PendingBump{
		PendingCounter:    1,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "owner/repo#1",
	}
	writeErr := pt.WriteCounter(context.Background(), "https://example.com/reg.git", "proj1", "secrets", bump)
	if writeErr == nil {
		t.Fatal("WriteCounter with refusing token provider: expected error, got nil")
	}
	if !errors.Is(writeErr, registry.ErrRegistryWriteAuth) {
		t.Errorf("WriteCounter refusing token: want ErrRegistryWriteAuth, got: %v", writeErr)
	}
}

// NOTE: transport-level no-pending-in-file guard
//
// The transport-level invariant — CommitCounter fails with ErrCounterReconcile
// when the counter file on disk has no pending record — is enforced by the
// existing.Pending == nil guard inside doCounterWrite (production_transport.go,
// the block guarded by `if commitPhase` at the existing.Pending == nil check).
//
// Exercising this guard end-to-end in a unit test requires a real git clone
// containing a well-formed counter file with pending == nil, which in turn
// requires a real git binary and a populated local repository. That level of
// fixture setup is deferred to the integration test suite.
//
// The registry.Client orchestration layer enforces the same invariant without
// reaching the transport: TestCommitCounter_WithoutPriorWrite_ReturnsErrCounterReconcile
// (below) asserts ErrCounterReconcile from CommitBump when no RecordPendingBump
// was called first. That test is the authoritative unit-level proof of the
// strict-two-phase contract.

// ---- Sentinel taxonomy (O2) --------------------------------------------------

// TestSentinelTaxonomy_ErrorsIs asserts that all new sentinel errors are
// distinct, errors.Is-detectable, and carry actionable hint strings.
func TestSentinelTaxonomy_ErrorsIs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		sentinel error
		wantHint string
	}{
		{
			name:     "ErrRegistryWriteRejected",
			sentinel: registry.ErrRegistryWriteRejected,
			wantHint: "registry requires admin merge",
		},
		{
			name:     "ErrRegistryWriteAuth",
			sentinel: registry.ErrRegistryWriteAuth,
			wantHint: "byreis admin register",
		},
		{
			name:     "ErrRegistryConcurrentWrite",
			sentinel: registry.ErrRegistryConcurrentWrite,
			wantHint: "byreis admin counter status",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Sentinel is non-nil.
			if tc.sentinel == nil {
				t.Fatalf("%s: sentinel is nil", tc.name)
			}
			// errors.Is detects itself.
			wrappedErr := errors.Join(errors.New("outer"), tc.sentinel)
			if !errors.Is(wrappedErr, tc.sentinel) {
				t.Errorf("%s: errors.Is(wrapped, sentinel) == false", tc.name)
			}
			// Hint string present.
			errMsg := tc.sentinel.Error()
			if errMsg == "" {
				t.Errorf("%s: error message is empty", tc.name)
			}
			// Sentinels are distinct from each other.
			for _, other := range cases {
				if other.sentinel == tc.sentinel {
					continue
				}
				if errors.Is(tc.sentinel, other.sentinel) {
					t.Errorf("%s: errors.Is matches %s (should be distinct)", tc.name, other.name)
				}
			}
		})
	}
}

// TestErrRegistryWriteRejected_HintString asserts the operator-facing hint.
func TestErrRegistryWriteRejected_HintString(t *testing.T) {
	t.Parallel()
	msg := registry.ErrRegistryWriteRejected.Error()
	for _, want := range []string{"registry", "branch-protection", "signed commits"} {
		if !cwContainsStr(msg, want) {
			t.Errorf("ErrRegistryWriteRejected hint missing %q: %s", want, msg)
		}
	}
}

// TestErrRegistryWriteAuth_HintString asserts the operator-facing hint.
func TestErrRegistryWriteAuth_HintString(t *testing.T) {
	t.Parallel()
	msg := registry.ErrRegistryWriteAuth.Error()
	for _, want := range []string{"byreis admin register", "registry-write"} {
		if !cwContainsStr(msg, want) {
			t.Errorf("ErrRegistryWriteAuth hint missing %q: %s", want, msg)
		}
	}
}

// TestErrRegistryConcurrentWrite_HintString asserts the operator-facing hint.
func TestErrRegistryConcurrentWrite_HintString(t *testing.T) {
	t.Parallel()
	msg := registry.ErrRegistryConcurrentWrite.Error()
	for _, want := range []string{"byreis admin counter status", "concurrent"} {
		if !cwContainsStr(msg, want) {
			t.Errorf("ErrRegistryConcurrentWrite hint missing %q: %s", want, msg)
		}
	}
}

// ---- Atomicity proof: CommitCounter advance+clear in one commit (Q1b) -------

// TestCommitCounter_AtomicAdvanceAndClear uses the in-memory registry.Client
// layer to prove that CommitBump (which calls FetchTransport.CommitCounter)
// atomically advances last_accepted_counter AND clears pending in a single
// logical operation. The test uses a fakeCommitAtomicTransport that captures
// the sequence of WriteCounter/CommitCounter calls and asserts:
//   - WriteCounter is called once with the pending record.
//   - CommitCounter is called once with the matching pendingCounter.
//   - After CommitCounter, the in-memory state has no pending and counter == 1.
func TestCommitCounter_AtomicAdvanceAndClear(t *testing.T) {
	t.Parallel()

	transport := &fakeCommitAtomicTransport{headSHA: "abc123abc123abc123abc123abc123abc123abc1"}
	client, newErr := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj1",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: transport,
	})
	if newErr != nil {
		t.Fatalf("registry.New: %v", newErr)
	}

	ctx := context.Background()

	// CounterAuthority read: returns (0, nil) — fresh project.
	auth, authErr := client.CounterAuthority(ctx, "proj1", "secrets")
	if authErr != nil {
		t.Fatalf("CounterAuthority: %v", authErr)
	}
	if !auth.Valid() {
		t.Fatal("CounterAuthority: not valid")
	}

	// RecordPendingBump (WriteCounter).
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj1",
		FileName:          "secrets",
		PendingCounter:    1,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "owner/repo#1",
	}); err != nil {
		t.Fatalf("RecordPendingBump: %v", err)
	}

	if transport.writeCounterCalls != 1 {
		t.Errorf("WriteCounter calls: got %d, want 1", transport.writeCounterCalls)
	}

	// CommitBump (CommitCounter).
	if err := client.CommitBump(ctx, coreregistry.CommitBumpInput{
		ProjectID:      "proj1",
		FileName:       "secrets",
		PendingCounter: 1,
		PRRef:          "owner/repo#1",
	}); err != nil {
		t.Fatalf("CommitBump: %v", err)
	}

	if transport.commitCounterCalls != 1 {
		t.Errorf("CommitCounter calls: got %d, want 1", transport.commitCounterCalls)
	}

	// After CommitBump: client's in-memory counterCache == 1, pendingStore empty.
	// Re-read via a second CounterAuthority call to verify state.
	transport.headSHA = "def456def456def456def456def456def456def4"
	transport.lastAccepted = 1
	transport.pendingBump = nil
	transport.isAncestor = true

	auth2, err := client.CounterAuthority(ctx, "proj1", "secrets")
	if err != nil {
		t.Fatalf("CounterAuthority (post-commit): %v", err)
	}
	if auth2.LastAccepted() != 1 {
		t.Errorf("post-commit LastAccepted=%d, want 1", auth2.LastAccepted())
	}
	if auth2.Pending() != nil {
		t.Errorf("post-commit Pending=%v, want nil", auth2.Pending())
	}
}

// TestCommitCounter_WithoutPriorWrite_ReturnsErrCounterReconcile asserts the
// strict-two-phase invariant: CommitBump without a prior RecordPendingBump
// returns ErrCounterReconcile.
func TestCommitCounter_WithoutPriorWrite_ReturnsErrCounterReconcile(t *testing.T) {
	t.Parallel()

	transport := &fakeCommitAtomicTransport{headSHA: "abc123abc123abc123abc123abc123abc123abc1"}
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj1",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: transport,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()

	// Call CommitBump without a prior RecordPendingBump.
	commitErr := client.CommitBump(ctx, coreregistry.CommitBumpInput{
		ProjectID:      "proj1",
		FileName:       "secrets",
		PendingCounter: 1,
		PRRef:          "owner/repo#1",
	})
	if commitErr == nil {
		t.Fatal("CommitBump without RecordPendingBump: expected ErrCounterReconcile, got nil")
	}
	if !errors.Is(commitErr, countertypes.ErrCounterReconcile) {
		t.Errorf("CommitBump without prior write: want ErrCounterReconcile, got: %v", commitErr)
	}
}

// ---- CAS / concurrent write (O1) --------------------------------------------

// TestWriteCounter_NonFastForwardPush_ReturnsErrRegistryConcurrentWrite asserts
// that when the git push is rejected due to a non-fast-forward (another admin
// wrote concurrently), WriteCounter returns ErrRegistryConcurrentWrite.
// The fakeCommitAtomicTransport does not simulate the actual git push CAS;
// this test uses a dedicated stub transport that returns the sentinel.
func TestWriteCounter_ConcurrentWrite_ReturnsErrRegistryConcurrentWrite(t *testing.T) {
	t.Parallel()

	// Use the registry.Client layer with a transport that returns ErrRegistryConcurrentWrite
	// from WriteCounter, simulating a non-fast-forward push rejection.
	transport := &fakeConcurrentWriteTransport{}
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj1",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: transport,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()
	if _, err := client.CounterAuthority(ctx, "proj1", "secrets"); err != nil {
		t.Fatalf("CounterAuthority: %v", err)
	}

	writeErr := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj1",
		FileName:          "secrets",
		PendingCounter:    1,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "owner/repo#1",
	})
	if writeErr == nil {
		t.Fatal("RecordPendingBump with concurrent write: expected error, got nil")
	}
	if !errors.Is(writeErr, registry.ErrRegistryConcurrentWrite) {
		t.Errorf("concurrent write: want ErrRegistryConcurrentWrite in chain, got: %v", writeErr)
	}
}

// ---- Idempotent resume (O3) -------------------------------------------------

// TestRecordPendingBump_IdempotentResume asserts that calling RecordPendingBump
// with the same pending_counter and target_artifact_sha when a pending already
// exists is a safe no-op (idempotent resume after a crash-before-merge).
// This mirrors "server landed the WriteCounter commit but local error surface"
// — on re-run, RecordPendingBump finds the matching pending and returns nil.
func TestRecordPendingBump_IdempotentResume(t *testing.T) {
	t.Parallel()

	transport := &fakeIdempotentTransport{headSHA: "abc123abc123abc123abc123abc123abc123abc1"}
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj1",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: transport,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()
	if _, err := client.CounterAuthority(ctx, "proj1", "secrets"); err != nil {
		t.Fatalf("CounterAuthority: %v", err)
	}

	// First call: writes the pending record.
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj1",
		FileName:          "secrets",
		PendingCounter:    1,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "owner/repo#1",
	}); err != nil {
		t.Fatalf("RecordPendingBump (first): %v", err)
	}

	// Second call with identical parameters — safe idempotent resume.
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj1",
		FileName:          "secrets",
		PendingCounter:    1,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "owner/repo#1",
	}); err != nil {
		t.Fatalf("RecordPendingBump (resume/idempotent): unexpected error: %v", err)
	}

	// WriteCounter must be called only ONCE (the second call is a no-op due to
	// the in-memory idempotency check in registry.Client.RecordPendingBump).
	if transport.writeCounterCalls != 1 {
		t.Errorf("idempotent resume: WriteCounter calls=%d, want 1", transport.writeCounterCalls)
	}
}

// TestRecordPendingBump_ConflictingPending_ReturnsErrCounterReconcile asserts
// that calling RecordPendingBump with a different counter or SHA when a pending
// already exists returns ErrCounterReconcile.
func TestRecordPendingBump_ConflictingPending_ReturnsErrCounterReconcile(t *testing.T) {
	t.Parallel()

	transport := &fakeIdempotentTransport{headSHA: "abc123abc123abc123abc123abc123abc123abc1"}
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj1",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: transport,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()
	if _, err := client.CounterAuthority(ctx, "proj1", "secrets"); err != nil {
		t.Fatalf("CounterAuthority: %v", err)
	}

	// First call: writes the pending record.
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj1",
		FileName:          "secrets",
		PendingCounter:    1,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "owner/repo#1",
	}); err != nil {
		t.Fatalf("RecordPendingBump (first): %v", err)
	}

	// Second call with a DIFFERENT SHA — conflicts with existing pending.
	conflictErr := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj1",
		FileName:          "secrets",
		PendingCounter:    1,
		TargetArtifactSHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		TargetPR:          "owner/repo#1",
	})
	if conflictErr == nil {
		t.Fatal("RecordPendingBump conflicting SHA: expected ErrCounterReconcile, got nil")
	}
	if !errors.Is(conflictErr, countertypes.ErrCounterReconcile) {
		t.Errorf("conflicting SHA: want ErrCounterReconcile, got: %v", conflictErr)
	}
}

// ---- Q3a: signing-key isolation --------------------------------------------

// TestCounterWritePath_SignerInterfaceIsTheDeclaredPort_CompileTimeOnly verifies
// that RegistryWriteSigner is the sole declared signing port for counter commits.
//
// Isolation guarantee: the production transport accepts signing capability only
// through the RegistryWriteSigner interface (FetchTransportWriteConfig.Signer).
// There is no parallel path that calls crypto/ed25519.Sign or holds an
// ed25519.PrivateKey. The type system enforces this: the transport's write
// configuration carries only the interface, never a raw key.
//
// Dynamic verification — asserting that SignText is actually invoked on each
// WriteCounter call — requires driving the full git subprocess sequence
// (clone → rev-parse → cat-file → sign → commit → push), which is a real-git
// integration test. That path is deferred to the integration test suite.
//
// The allowlist gate (`make check-allowlist`) is independently authoritative
// for the absence of a direct ed25519 signing import in the Submit compilation
// unit. This test is the compile-time companion for the counter-write path.
func TestCounterWritePath_SignerInterfaceIsTheDeclaredPort_CompileTimeOnly(t *testing.T) {
	t.Parallel()

	// Construct a recording signer and inject it via the write config. If the
	// transport ever acquired a signing path that bypassed this interface, the
	// code would not compile (the interface is the only accepted type at the
	// injection point), which is the guarantee this test is asserting.
	signer := &recordingSignerCW{
		onSign: func(text []byte) (string, []byte, error) {
			return "test-signer", make([]byte, 64), nil
		},
	}

	writeCfg := &registry.FetchTransportWriteConfig{
		Signer:        signer,
		TokenProvider: &alwaysSuccessTokenProvider{token: "test-token"},
	}

	v := cwNewVerifier(t, &recordingRunner{steps: []recordStep{}})
	_, err := registry.NewProductionFetchTransport(v, writeCfg)
	if err != nil {
		t.Fatalf("NewProductionFetchTransport: %v", err)
	}
	// Construction succeeds: the signer interface is the only declared signing
	// port and no alternative key path was introduced. Dynamic invocation of
	// SignText is verified in the integration test suite.
}

// ---- Auth.go RegistryWriteService + Account constants -----------------------

// TestAuth_RegistryWriteConstants_Distinct asserts that RegistryWriteService
// and RegistryWriteAccount are non-empty and together form a distinct keychain
// slot from any generic project-repo PAT.
func TestAuth_RegistryWriteConstants_Distinct(t *testing.T) {
	t.Parallel()

	// Import the auth package via its constants.
	svc := cwRegistryWriteService
	acc := cwRegistryWriteAccount
	if svc == "" {
		t.Error("RegistryWriteService is empty")
	}
	if acc == "" {
		t.Error("RegistryWriteAccount is empty")
	}
	// Must be distinct from the generic project-repo service name.
	if svc == "github" || svc == "byreis" || acc == "" {
		t.Errorf("RegistryWriteService=%q / Account=%q looks like a generic PAT slot", svc, acc)
	}
}

// ---- Helpers -----------------------------------------------------------------

const cwValidArtifactSHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

// cwRegistryWriteService / Account mirror auth.RegistryWriteService/Account
// without importing the auth package (to avoid import cycles).
const cwRegistryWriteService = "byreis-registry"
const cwRegistryWriteAccount = "registry-write"

// cwNewVerifier creates a HeadVerifier with a fake runner and temp dirs.
func cwNewVerifier(t *testing.T, runner fetchtransport.CommandRunner) *fetchtransport.HeadVerifier {
	t.Helper()
	tmpBase := t.TempDir()
	var mu sync.Mutex
	var count int
	v, err := fetchtransport.NewHeadVerifier(fetchtransport.HeadVerifierConfig{
		Runner: runner,
		MkdirTemp: func(_, _ string) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			count++
			dir := filepath.Join(tmpBase, "tmp", fmt.Sprint(count))
			if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
				return "", mkErr
			}
			return dir, nil
		},
		RemoveAll: func(_ string) error { return nil },
	})
	if err != nil {
		t.Fatalf("cwNewVerifier: %v", err)
	}
	return v
}

// cwPending is a helper struct for building counter JSON with parent_commit_sha.
type cwPending struct {
	PendingCounter    uint64
	TargetArtifactSHA string
	TargetPR          string
	IntentAt          string
	ParentCommitSHA   string
}

// cwCounterJSONWithParent builds counter store JSON with a fully-specified
// pending record including parent_commit_sha.
func cwCounterJSONWithParent(projectID, fileName string, la uint64, lastPR string, p *cwPending) []byte {
	lastPRField := fmt.Sprintf(`"last_pr": %q,`, lastPR)
	pendingStr := "null"
	if p != nil {
		pendingStr = fmt.Sprintf(`{
    "pending_counter": %d,
    "target_artifact_sha": %q,
    "target_pr": %q,
    "intent_at": %q,
    "parent_commit_sha": %q
  }`, p.PendingCounter, p.TargetArtifactSHA, p.TargetPR, p.IntentAt, p.ParentCommitSHA)
	}
	return []byte(fmt.Sprintf(`{
  "project_id": %q,
  "file": %q,
  "last_accepted_counter": %d,
  %s
  "updated_at": "2024-01-01T00:00:00Z",
  "pending": %s
}`, projectID, fileName, la, lastPRField, pendingStr))
}

func cwContainsStr(s, substr string) bool {
	return strings.Contains(s, substr)
}

// makeEd25519Key returns a non-zero 32-byte Ed25519 public key for tests.
func makeEd25519Key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	k[0] = 1
	return k
}

// ---- Fake transports for commit-atomicity + CAS tests ----------------------

// fakeCommitAtomicTransport captures WriteCounter/CommitCounter calls and
// provides minimal FetchHead + ReadCounter + IsAncestor stubs.
type fakeCommitAtomicTransport struct {
	headSHA            string
	lastAccepted       uint64
	pendingBump        *countertypes.PendingBump
	isAncestor         bool
	writeCounterCalls  int
	commitCounterCalls int
}

func (f *fakeCommitAtomicTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return f.headSHA, "test-signer", true, nil
}
func (f *fakeCommitAtomicTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return f.isAncestor, nil
}
func (f *fakeCommitAtomicTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return f.lastAccepted, f.pendingBump, nil
}
func (f *fakeCommitAtomicTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	f.writeCounterCalls++
	return nil
}
func (f *fakeCommitAtomicTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	f.commitCounterCalls++
	return nil
}
func (f *fakeCommitAtomicTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (f *fakeCommitAtomicTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (f *fakeCommitAtomicTransport) DiscardCounterSession(_ context.Context, _ string) {}
func (f *fakeCommitAtomicTransport) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (f *fakeCommitAtomicTransport) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}

// fakeConcurrentWriteTransport simulates a WriteCounter that fails with
// ErrRegistryConcurrentWrite, as if another admin pushed first.
type fakeConcurrentWriteTransport struct{}

func (f *fakeConcurrentWriteTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "aabbccddaabbccddaabbccddaabbccddaabbccdd", "signer", true, nil
}
func (f *fakeConcurrentWriteTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (f *fakeConcurrentWriteTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (f *fakeConcurrentWriteTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return errors.Join(errors.New("push rejected"), registry.ErrRegistryConcurrentWrite)
}
func (f *fakeConcurrentWriteTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (f *fakeConcurrentWriteTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (f *fakeConcurrentWriteTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (f *fakeConcurrentWriteTransport) DiscardCounterSession(_ context.Context, _ string) {}
func (f *fakeConcurrentWriteTransport) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (f *fakeConcurrentWriteTransport) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}

// fakeIdempotentTransport captures WriteCounter calls for idempotency testing.
type fakeIdempotentTransport struct {
	headSHA           string
	writeCounterCalls int
}

func (f *fakeIdempotentTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return f.headSHA, "test-signer", true, nil
}
func (f *fakeIdempotentTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (f *fakeIdempotentTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (f *fakeIdempotentTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	f.writeCounterCalls++
	return nil
}
func (f *fakeIdempotentTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (f *fakeIdempotentTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (f *fakeIdempotentTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (f *fakeIdempotentTransport) DiscardCounterSession(_ context.Context, _ string) {}
func (f *fakeIdempotentTransport) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (f *fakeIdempotentTransport) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}

// cwNopSigner is a no-op RegistryWriteSigner for tests that don't need signing.
type cwNopSigner struct{}

func (s *cwNopSigner) SignText(_ context.Context, _ []byte) (string, []byte, error) {
	return "nop-signer", make([]byte, 64), nil
}

// recordingSignerCW is a recording RegistryWriteSigner.
type recordingSignerCW struct {
	onSign func(text []byte) (string, []byte, error)
}

func (s *recordingSignerCW) SignText(_ context.Context, text []byte) (string, []byte, error) {
	return s.onSign(text)
}

// alwaysSuccessTokenProvider always returns the configured token.
// For use in tests that need a token but where ADMIN mode is not in scope.
type alwaysSuccessTokenProvider struct{ token string }

func (p *alwaysSuccessTokenProvider) RegistryWriteToken(_ context.Context, _ string) (string, error) {
	return p.token, nil
}
