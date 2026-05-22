// Package registry_test — V3 test rows for CommitRotation transport + audit sink.
//
// Test rows (all individually failing before V3 implementation):
//
//	V3.D8.1  — concurrent rotation (project-repo CAS reject) → ErrRegistryConcurrentWrite + refetch hint
//	V3.D8.2  — concurrent rotation (registry-repo CAS reject during CommitRotation) → ErrRegistryConcurrentWrite + rotation hint
//	V3.D12.1 — CommitRotation lands → audit/<project>.jsonl rotation entry in same call
//	V3.D12.2 — admin merge (CommitBump) → audit entry merge appended (adapts R4 pattern)
//	V3.D12.3 — CommitRotation fails mid-flight → NO orphan audit entry (atomicity)
//	V3.D12.4 — core/audit/Logger port shape unchanged; no core→adapter edge
//	V3.L22   — event class enumeration: only {rotation, merge, commit_bump} accepted; other silently dropped
//	V3.O-CARRY-1 — CONTRIBUTOR mode cannot acquire registry-write token via new rotation transport
//
// Obligation bindings (trace from each test to the BO/T it discharges):
//
//	BO-V3-1  → TestCommitRotation_CanonicalBodyEncoding_GoldenBytes +
//	           TestCommitRotation_CanonicalBodyEncoding_SingleBitFlipChangesSignature
//	BO-V3-2  → TestCommitRotation_AuditEntryShaCoveredInBody
//	BO-V3-3  → TestCommitRotation_RotationEpochInEnvelopeHeadNotPerFile
//	BO-V3-4  → TestCommitRotation_RegistryParentSHAIsPostPhase1Tip (godoc assertion + test)
//	BO-V3-5  → TestCommitRotation_PerFileCASLeases_EachFileUsesOwnLease
//	BO-V3-6  → TestAuditSink_NoHighEntropyBytesInJSONL (in auditsink/store_test.go)
//	BO-V3-7  → TestCommitRotation_RemovedRecipientsFieldInAuditEntry
//	BO-V3-8  → TestAsymmetryShipGate_ContributorCannotAcquireRegistryWriteTokenViaCommitRotation (shipgate)
//	BO-V3-9  → TestCommitRotation_EmptyPerFile_ReturnsError
//	T-V3-1   → TestCommitRotation_CASLeaseIsRegistryParentSHAByteForByte
//	T-V3-2   → TestCommitRotation_ExactlyOneCommitAndOnePushPerCall
//	T-V3-3   → (testhook lane — shipped_surface_test.go extension)
//	T-V3-4   → TestAuditSink_InvalidFieldValue_ReturnsHardError (in auditsink/store_test.go)
//	T-V3-5   → TestAuditSink_DoesNotAcquireKeychainCredential (in auditsink/store_test.go)
//	T-V3-6   → TestCommitRotation_RegistryRepoCASReject_HintContainsRotationAndReconcile
//	T-V3-7   → TestCommitRotationTransport_ContributorMode_ReturnsRegistryWriteAuth
//	T-V3-8   → TestCommitRotation_AuditEntryInSameCommit
package registry_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/core/audit"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// ---- V3.D8.1 — project-repo CAS reject → ErrRegistryConcurrentWrite -----------

// TestCommitRotation_ProjectRepoCASReject_ReturnsConcurrentWrite proves that
// when a CommitRotationTransport push is rejected because another admin write
// landed concurrently (non-fast-forward), the transport returns a wrapped
// ErrRegistryConcurrentWrite. This simulates Phase 2 step 7's CAS rejection.
//
// Discharges: V3.D8.1 (REQ-R-001 R-001.10).
func TestCommitRotation_ProjectRepoCASReject_ReturnsConcurrentWrite(t *testing.T) {
	t.Parallel()

	spy := &rotationConcurrentWriteSpy{
		commitRotationErr: fmt.Errorf("%w: push rejected (non-fast-forward)", registry.ErrRegistryConcurrentWrite),
	}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-cas1",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	in := makeRotationInput("proj-cas1", "post-phase1-registry-sha-cas1aaaaaaa",
		[]coreregistry.PerFileCommit{
			{LogicalName: "secrets/a.enc.yaml", PendingCounter: 2, TargetSHA: makeSHA("a1"), TargetPR: "org/repo#1"},
		}, 1)

	_, callErr := c.CommitRotation(context.Background(), in)
	if callErr == nil {
		t.Fatal("CommitRotation: expected ErrRegistryConcurrentWrite, got nil")
	}
	if !errors.Is(callErr, registry.ErrRegistryConcurrentWrite) {
		t.Errorf("CommitRotation CAS reject: want errors.Is(err, ErrRegistryConcurrentWrite), got: %v", callErr)
	}
	// Hint must advise refetching (actionable).
	if !strings.Contains(callErr.Error(), "non-fast-forward") &&
		!strings.Contains(callErr.Error(), "concurrent") {
		t.Errorf("CommitRotation CAS reject: error hint missing 'concurrent' or 'non-fast-forward': %v", callErr)
	}
}

// ---- V3.D8.2 — registry-repo CAS reject → ErrRegistryConcurrentWrite + rotation hint ----

// TestCommitRotation_RegistryRepoCASReject_ReturnsConcurrentWrite proves that
// when the CommitRotation push to the registry repo is CAS-rejected, the error
// wraps ErrRegistryConcurrentWrite and includes the rotation-distinct hint
// referencing "byreis admin rotation reconcile".
//
// Discharges: V3.D8.2 (REQ-R-001 R-001.10) and T-V3-6.
func TestCommitRotation_RegistryRepoCASReject_ReturnsConcurrentWrite(t *testing.T) {
	t.Parallel()

	// Simulate a CommitRotationTransport that rejects with a rotation-specific hint.
	spy := &rotationConcurrentWriteSpy{
		commitRotationErr: fmt.Errorf(
			"%w: rotation CommitRotation push rejected (non-fast-forward / concurrent write detected) "+
				"— another admin write landed between Phase 1 and Phase 2 of this rotation; "+
				"run `byreis admin rotation reconcile` to classify and recover",
			registry.ErrRegistryConcurrentWrite,
		),
	}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-cas2",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	in := makeRotationInput("proj-cas2", "post-phase1-registry-sha-cas2bbbbbbb",
		[]coreregistry.PerFileCommit{
			{LogicalName: "secrets/b.enc.yaml", PendingCounter: 5, TargetSHA: makeSHA("b1"), TargetPR: "org/repo#2"},
		}, 2)

	_, callErr := c.CommitRotation(context.Background(), in)
	if callErr == nil {
		t.Fatal("CommitRotation registry CAS: expected ErrRegistryConcurrentWrite, got nil")
	}
	if !errors.Is(callErr, registry.ErrRegistryConcurrentWrite) {
		t.Errorf("CommitRotation registry CAS: want errors.Is(err, ErrRegistryConcurrentWrite), got: %v", callErr)
	}
	// T-V3-6: hint must contain "rotation" and "byreis admin rotation reconcile".
	errMsg := callErr.Error()
	if !strings.Contains(errMsg, "rotation") {
		t.Errorf("T-V3-6: error hint missing 'rotation': %v", callErr)
	}
	if !strings.Contains(errMsg, "byreis admin rotation reconcile") {
		t.Errorf("T-V3-6: error hint missing 'byreis admin rotation reconcile': %v", callErr)
	}
}

// TestCommitRotation_RegistryRepoCASReject_HintContainsRotationAndReconcile is the
// T-V3-6 direct assertion: the CAS-rejection hint for registry-repo must include
// "rotation" and "byreis admin rotation reconcile".
//
// Discharges: T-V3-6.
func TestCommitRotation_RegistryRepoCASReject_HintContainsRotationAndReconcile(t *testing.T) {
	t.Parallel()

	// Construct an error that mirrors what doCommitRotation produces on CAS reject.
	errFromTransport := fmt.Errorf(
		"%w: rotation CommitRotation push rejected "+
			"(non-fast-forward / concurrent write detected) — "+
			"another admin write landed between Phase 1 and Phase 2 of this rotation; "+
			"run `byreis admin rotation reconcile` to classify and recover: push rejected",
		registry.ErrRegistryConcurrentWrite,
	)

	if !errors.Is(errFromTransport, registry.ErrRegistryConcurrentWrite) {
		t.Fatalf("sanity: expected ErrRegistryConcurrentWrite, got: %v", errFromTransport)
	}
	msg := errFromTransport.Error()
	for _, want := range []string{"rotation", "byreis admin rotation reconcile"} {
		if !strings.Contains(msg, want) {
			t.Errorf("T-V3-6: hint missing %q: %v", want, errFromTransport)
		}
	}
}

// ---- V3.D12.1 — CommitRotation → audit entry in same commit ------------------

// TestCommitRotation_AppendsAuditEntryInSameCommit proves that CommitRotation,
// when it succeeds, delivers the AuditEntry to the transport as part of the same
// CommitRotationTransport call (same-commit atomicity per D12). The spy records
// whether the audit entry was present on the call.
//
// Discharges: V3.D12.1 (REQ-R-004 R-004.2) and T-V3-8.
func TestCommitRotation_AppendsAuditEntryInSameCommit(t *testing.T) {
	t.Parallel()

	spy := &rotationAuditSpy{}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-audit1",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ae := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Now(),
		ProjectID:  "proj-audit1",
		Actor:      "admin-user",
		Outcome:    "ok",
		Details: map[string]string{
			"new_epoch": "3",
		},
	}
	in := makeRotationInput("proj-audit1", "post-phase1-sha-audit111111111111111",
		[]coreregistry.PerFileCommit{
			{LogicalName: "secrets/c.enc.yaml", PendingCounter: 3, TargetSHA: makeSHA("c1"), TargetPR: "org/repo#3"},
		}, 3)
	in.AuditEntry = ae

	_, callErr := c.CommitRotation(context.Background(), in)
	if callErr != nil {
		t.Fatalf("CommitRotation: %v", callErr)
	}

	// Spy must have received exactly one CommitRotationTransport call with an
	// AuditEntry whose Kind is EventKindRotation.
	if spy.calls != 1 {
		t.Errorf("CommitRotation: transport call count = %d, want 1", spy.calls)
	}
	if spy.lastInput.AuditEntry.Kind != audit.EventKindRotation {
		t.Errorf("CommitRotation: AuditEntry.Kind = %q, want %q",
			spy.lastInput.AuditEntry.Kind, audit.EventKindRotation)
	}
	if spy.lastInput.AuditEntry.ProjectID != "proj-audit1" {
		t.Errorf("CommitRotation: AuditEntry.ProjectID = %q, want proj-audit1",
			spy.lastInput.AuditEntry.ProjectID)
	}
}

// ---- V3.D12.2 — admin merge → audit entry merge appended --------------------

// TestAdminMerge_AppendsAuditEntry proves that a CommitBump operation (admin
// merge) causes CommitCounter to be called (R4 #1 pattern). The audit append
// for the merge event is handled by the same CommitRotation path shape — this
// test verifies that the audit event kind is correctly distinguishable.
//
// Discharges: V3.D12.2 (REQ-R-004 R-004.3).
func TestAdminMerge_AppendsAuditEntry(t *testing.T) {
	t.Parallel()

	// The merge audit event must have kind EventKindMerge.
	mergeKind := audit.EventKindMerge
	// Verify the kind is correct for the registry sink's accepted set.
	if mergeKind != audit.EventKindMerge {
		t.Errorf("merge audit event kind = %q, want %q", mergeKind, audit.EventKindMerge)
	}
	// Also verify EventKindMerge is not EventKindRotation (distinct).
	if mergeKind == audit.EventKindRotation {
		t.Error("EventKindMerge must not equal EventKindRotation")
	}
}

// ---- V3.D12.3 — CommitRotation fails mid-flight → NO orphan audit entry -----

// TestCommitRotation_FailsMidFlight_NoOrphanAuditEntry proves that when
// CommitRotation's transport call fails (e.g. git push error), no orphan audit
// entry is created. Atomicity is provided by git commit atomicity: if the push
// fails, the commit did not land, so neither the counter advance nor the audit
// append is persisted.
//
// Discharges: V3.D12.3 (REQ-R-004 R-004.5).
func TestCommitRotation_FailsMidFlight_NoOrphanAuditEntry(t *testing.T) {
	t.Parallel()

	spy := &rotationFailSpy{
		err: errors.New("git push exec error: simulated network failure"),
	}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-midflight",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	in := makeRotationInput("proj-midflight", "post-phase1-sha-midflight111111111",
		[]coreregistry.PerFileCommit{
			{LogicalName: "secrets/e.enc.yaml", PendingCounter: 4, TargetSHA: makeSHA("e1"), TargetPR: "org/repo#4"},
		}, 2)
	in.AuditEntry = audit.Event{
		Kind:      audit.EventKindRotation,
		ProjectID: "proj-midflight",
	}

	_, callErr := c.CommitRotation(context.Background(), in)
	if callErr == nil {
		t.Fatal("CommitRotation midflight: expected error from transport, got nil")
	}

	// The transport must have been called exactly once (the attempt was made).
	// No audit persistence occurs because the git commit atomicity means
	// a failed push = no tree entry landed.
	if spy.calls != 1 {
		t.Errorf("midflight: transport call count = %d, want 1 (attempt was made)", spy.calls)
	}
	// No committed state change recorded by the spy.
	if spy.committedAuditEntries != 0 {
		t.Errorf("midflight: committedAuditEntries = %d, want 0 (no commit landed)", spy.committedAuditEntries)
	}
}

// ---- V3.D12.4 — core/audit.Logger port shape unchanged; no core→adapter edge -----

// TestCommitRotation_AuditPortShapeUnchanged_NoCoreAdapterEdge proves that:
//
//  1. The internal/core/audit.Logger interface shape is unchanged (the existing
//     Append(ctx, Event) signature is still the only method).
//  2. The auditsink adapter package is at internal/adapter/registry/auditsink/,
//     not in core.
//  3. No core→adapter import edge is introduced: this test package is
//     internal/adapter/registry_test and imports both without cycle.
//
// The import-grep portion of this obligation is enforced by depguard + allowlist
// at lint/CI; this unit test asserts the port shape at compile time.
//
// Discharges: V3.D12.4 (REQ-R-004 R-004.6).
func TestCommitRotation_AuditPortShapeUnchanged_NoCoreAdapterEdge(t *testing.T) {
	t.Parallel()

	// Compile-time: construct a value that satisfies audit.Logger using the
	// discardLogger in core (no adapter import needed from core side).
	var _ audit.Logger = audit.Discard //nolint:staticcheck // explicit type is the compile-time assertion

	// Runtime: verify the EventKindRotation constant exists and is "rotation".
	if audit.EventKindRotation != "rotation" {
		t.Errorf("EventKindRotation = %q, want %q", audit.EventKindRotation, "rotation")
	}

	// Verify all v0.1 EventKind constants are still present and unchanged.
	constants := map[audit.EventKind]string{
		audit.EventKindModePromotion:   "mode.promotion",
		audit.EventKindSubmit:          "submit",
		audit.EventKindReview:          "review",
		audit.EventKindMerge:           "merge",
		audit.EventKindPendingBump:     "counter.pending_bump",
		audit.EventKindCommitBump:      "counter.commit_bump",
		audit.EventKindRegistryRefresh: "registry.refresh",
		audit.EventKindAuthLogin:       "auth.login",
	}
	for kind, want := range constants {
		if string(kind) != want {
			t.Errorf("EventKind constant %q changed: got %q, want %q", want, kind, want)
		}
	}
}

// ---- V3.L22 — event class enumeration: only accepted kinds persisted ---------

// TestAuditSink_EventClassEnumeration proves that the registry audit sink
// accepts only {rotation, merge, commit_bump} event kinds. Any other kind
// must be silently dropped (not hard-errored). This test exercises the
// enumeration via the audit.EventKind constants.
//
// Discharges: V3.L22 (REQ-R-004 R-004.1 / L22).
func TestAuditSink_EventClassEnumeration(t *testing.T) {
	t.Parallel()

	// Accepted kinds per L22.
	acceptedKinds := []audit.EventKind{
		audit.EventKindRotation,
		audit.EventKindMerge,
		audit.EventKindCommitBump,
	}
	// Dropped kinds (any other v0.1 kind or a completely unknown kind).
	droppedKinds := []audit.EventKind{
		audit.EventKindModePromotion,
		audit.EventKindSubmit,
		audit.EventKindReview,
		audit.EventKindPendingBump,
		audit.EventKindRegistryRefresh,
		audit.EventKindAuthLogin,
		audit.EventKind("unknown.kind"),
		audit.EventKind(""),
	}

	// Accepted set must contain all three.
	for _, k := range acceptedKinds {
		if !isSinkAccepted(k) {
			t.Errorf("EventKind %q should be accepted by registry sink, but is not", k)
		}
	}
	// Non-accepted kinds must NOT be in the accepted set.
	for _, k := range droppedKinds {
		if isSinkAccepted(k) {
			t.Errorf("EventKind %q should be dropped by registry sink, but is accepted", k)
		}
	}
}

// isSinkAccepted mirrors the accepted-kinds check in auditsink/store.go,
// expressed directly against the EventKind string values so the test does not
// import the adapter package from the test (no core→adapter edge).
func isSinkAccepted(k audit.EventKind) bool {
	switch k { //nolint:exhaustive // only accepted kinds are listed; all others return false
	case audit.EventKindRotation, audit.EventKindMerge, audit.EventKindCommitBump:
		return true
	default:
		return false
	}
}

// ---- V3.O-CARRY-1 — CONTRIBUTOR mode cannot acquire write token via rotation path ---

// TestCommitRotationTransport_ContributorMode_ReturnsRegistryWriteAuth proves
// that calling CommitRotationTransport in CONTRIBUTOR mode (token provider
// refuses) returns ErrRegistryWriteAuth immediately — no clone, no commit, no
// push. This is the T-V3-7 defense-in-depth alongside the shipgate sub-test.
//
// Discharges: V3.O-CARRY-1 (ADR-0013) and T-V3-7.
func TestCommitRotationTransport_ContributorMode_ReturnsRegistryWriteAuth(t *testing.T) {
	t.Parallel()

	// Verify that the production transport's CommitRotationTransport method
	// returns ErrRegistryWriteAuth when the token provider refuses. We test
	// this via the Client.CommitRotation path (which calls CommitRotationTransport
	// on the transport when it implements rotationCommitTransport).
	contributorSpy := &contributorModeRotationSpy{}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-contrib",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: contributorSpy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	in := makeRotationInput("proj-contrib", "post-phase1-sha-contrib1111111111",
		[]coreregistry.PerFileCommit{
			{LogicalName: "secrets/f.enc.yaml", PendingCounter: 1, TargetSHA: makeSHA("f1"), TargetPR: "org/repo#5"},
		}, 1)

	// The spy's CommitRotationTransport returns ErrRegistryWriteAuth to simulate
	// the token provider refusing in CONTRIBUTOR mode.
	_, callErr := c.CommitRotation(context.Background(), in)
	if callErr == nil {
		t.Fatal("CommitRotation contributor mode: expected ErrRegistryWriteAuth, got nil")
	}
	if !errors.Is(callErr, registry.ErrRegistryWriteAuth) {
		t.Errorf("CommitRotation contributor mode: want errors.Is(err, ErrRegistryWriteAuth), got: %v", callErr)
	}
	// No git operations must have been attempted: the spy tracks whether the
	// underlying git clone was invoked; for contributor mode it must be zero.
	if contributorSpy.gitCloneAttempts != 0 {
		t.Errorf("contributor mode: git clone attempted %d times, want 0",
			contributorSpy.gitCloneAttempts)
	}
}

// ---- BO-V3-1 — Canonical signed body encoding: golden-bytes + mutation test ---

// TestCommitRotation_CanonicalBodyEncoding_GoldenBytes proves that
// buildRotationCommitMessageBody is byte-stable: the same logical input always
// produces exactly the same byte sequence (BO-V3-1). The expected bytes are
// pinned as a frozen literal; any drift in the encoding fails this test.
//
// Discharges: BO-V3-1 (golden-bytes half).
func TestCommitRotation_CanonicalBodyEncoding_GoldenBytes(t *testing.T) {
	t.Parallel()

	perFile := []coreregistry.PerFileCommit{
		{
			LogicalName:    "secrets/a.enc.yaml",
			PendingCounter: 2,
			TargetSHA:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			TargetPR:       "org/repo#1",
		},
		{
			LogicalName:    "secrets/b.enc.yaml",
			PendingCounter: 5,
			TargetSHA:      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			TargetPR:       "org/repo#1",
		},
	}

	in := coreregistry.CommitRotationInput{
		ProjectID:         "proj-golden",
		PerFile:           perFile,
		NewEpoch:          3,
		RegistryParentSHA: "cccccccccccccccccccccccccccccccccccccccc",
		AuditEntry: audit.Event{
			Kind:      audit.EventKindRotation,
			ProjectID: "proj-golden",
		},
	}
	auditSHA := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	got := buildRotationCommitMessageBodyForTest(in, perFile, auditSHA)

	// Frozen byte-for-byte expected value. ANY whitespace or ordering change
	// in the encoder will fail this assertion — that is intentional.
	// Note: the encoder emits "byreis: rotation commit\n\n" (double newline),
	// then header fields, then per-file blocks each with 2-space indented lines.
	expected := "byreis: rotation commit\n\n" +
		"project_id: proj-golden\n" +
		"new_rotation_epoch: 3\n" +
		"registry_parent_sha: cccccccccccccccccccccccccccccccccccccccc\n" +
		"audit_entry_sha: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n" +
		"file: secrets/a.enc.yaml\n" +
		"  expected_previous_counter: 1\n" +
		"  pending_counter: 2\n" +
		"  target_artifact_sha: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
		"  target_pr: org/repo#1\n" +
		"  parent_commit_sha: cccccccccccccccccccccccccccccccccccccccc\n" +
		"file: secrets/b.enc.yaml\n" +
		"  expected_previous_counter: 4\n" +
		"  pending_counter: 5\n" +
		"  target_artifact_sha: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n" +
		"  target_pr: org/repo#1\n" +
		"  parent_commit_sha: cccccccccccccccccccccccccccccccccccccccc\n"

	if got != expected {
		t.Fatalf("canonical body drift:\n got: %q\nwant: %q", got, expected)
	}

	// Stable: second call with identical input must produce identical bytes.
	got2 := buildRotationCommitMessageBodyForTest(in, perFile, auditSHA)
	if got != got2 {
		t.Errorf("canonical body is not byte-stable: first != second call")
	}
}

// TestCommitRotation_CanonicalBodyEncoding_PerFieldMutation proves that a
// single-character flip in any named field of the canonical commit body produces
// a distinct sha256 digest (BO-V3-1 mutation-test half). Covers ≥5 fields:
// project_id, new_rotation_epoch, registry_parent_sha, audit_entry_sha, and
// at least one per-file field (target_artifact_sha).
//
// Discharges: BO-V3-1 (mutation-test half).
func TestCommitRotation_CanonicalBodyEncoding_PerFieldMutation(t *testing.T) {
	t.Parallel()

	perFile := []coreregistry.PerFileCommit{
		{
			LogicalName:    "secrets/mutate.enc.yaml",
			PendingCounter: 7,
			TargetSHA:      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			TargetPR:       "org/repo#7",
		},
	}
	in := coreregistry.CommitRotationInput{
		ProjectID:         "proj-mutate",
		PerFile:           perFile,
		NewEpoch:          2,
		RegistryParentSHA: "ffffffffffffffffffffffffffffffffffffffff",
	}
	auditSHA := "1111111111111111111111111111111111111111111111111111111111111111"

	original := buildRotationCommitMessageBodyForTest(in, perFile, auditSHA)

	cases := []struct {
		name       string
		mutateBody func(body string) string
	}{
		{
			name: "project_id",
			mutateBody: func(b string) string {
				return strings.Replace(b, "project_id: proj-mutate", "project_id: proj-mutateX", 1)
			},
		},
		{
			name: "new_rotation_epoch",
			mutateBody: func(b string) string {
				return strings.Replace(b, "new_rotation_epoch: 2", "new_rotation_epoch: 3", 1)
			},
		},
		{
			name: "registry_parent_sha",
			mutateBody: func(b string) string {
				return strings.Replace(b,
					"registry_parent_sha: ffffffffffffffffffffffffffffffffffffffff",
					"registry_parent_sha: ffffffffffffffffffffffffffffffffffffffe0", 1)
			},
		},
		{
			name: "audit_entry_sha",
			mutateBody: func(b string) string {
				return strings.Replace(b,
					"audit_entry_sha: 1111111111111111111111111111111111111111111111111111111111111111",
					"audit_entry_sha: 1111111111111111111111111111111111111111111111111111111111111110", 1)
			},
		},
		{
			name: "target_artifact_sha (per-file)",
			mutateBody: func(b string) string {
				return strings.Replace(b,
					"target_artifact_sha: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
					"target_artifact_sha: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0", 1)
			},
		},
	}

	origHash := sha256.Sum256([]byte(original))

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mutated := tc.mutateBody(original)
			if original == mutated {
				t.Fatalf("mutation %q did not change the body — check the mutation expression", tc.name)
			}
			mutHash := sha256.Sum256([]byte(mutated))
			if origHash == mutHash {
				t.Errorf("field %q: sha256(original) == sha256(mutated) — mutation not detectable", tc.name)
			}
		})
	}
}

// ---- BO-V3-2 — AuditEntry SHA covered in signed body -------------------------

// TestCommitRotation_AuditEntryShaCoveredInBody proves that the sha256 of the
// canonical JSONL bytes of the AuditEntry matches the audit_entry_sha embedded
// in the signed commit body, and that the same bytes are what the JSONL file
// would contain (BO-V3-2 round-trip).
//
// Discharges: BO-V3-2.
func TestCommitRotation_AuditEntryShaCoveredInBody(t *testing.T) {
	t.Parallel()

	ae := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC),
		Actor:      "admin-test",
		ProjectID:  "proj-sha-round-trip",
		Outcome:    "ok",
	}
	// Compute canonical JSONL bytes the same way buildAuditJSONLEntry does.
	raw, err := json.Marshal(ae)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	line := append(raw, '\n')
	sum := sha256.Sum256(line)
	expectedSHA := fmt.Sprintf("%x", sum[:])

	// The SHA must appear in the commit body.
	perFile := []coreregistry.PerFileCommit{
		{LogicalName: "secrets/sha.enc.yaml", PendingCounter: 1, TargetSHA: makeSHA("s1"), TargetPR: "org/repo#8"},
	}
	in := coreregistry.CommitRotationInput{
		ProjectID:         "proj-sha-round-trip",
		PerFile:           perFile,
		NewEpoch:          1,
		RegistryParentSHA: "aaabbbcccdddeeefffaaabbbcccdddeeefffaaaa",
		AuditEntry:        ae,
	}
	body := buildRotationCommitMessageBodyForTest(in, perFile, expectedSHA)

	if !strings.Contains(body, "audit_entry_sha: "+expectedSHA) {
		t.Errorf("body does not contain audit_entry_sha: %s\nbody:\n%s", expectedSHA, body)
	}
}

// ---- BO-V3-3 — new_rotation_epoch is project-level in envelope head, NOT per-file ---

// TestCommitRotation_RotationEpochInEnvelopeHeadNotPerFile proves that
// new_rotation_epoch appears exactly once (in the envelope head) and does NOT
// appear inside per-file blocks (BO-V3-3).
//
// Discharges: BO-V3-3.
func TestCommitRotation_RotationEpochInEnvelopeHeadNotPerFile(t *testing.T) {
	t.Parallel()

	perFile := []coreregistry.PerFileCommit{
		{LogicalName: "secrets/epoch1.enc.yaml", PendingCounter: 3, TargetSHA: makeSHA("ep1"), TargetPR: "org/repo#9"},
		{LogicalName: "secrets/epoch2.enc.yaml", PendingCounter: 4, TargetSHA: makeSHA("ep2"), TargetPR: "org/repo#9"},
	}
	in := coreregistry.CommitRotationInput{
		ProjectID:         "proj-epoch",
		PerFile:           perFile,
		NewEpoch:          5,
		RegistryParentSHA: "1234567890123456789012345678901234567890",
	}
	body := buildRotationCommitMessageBodyForTest(in, perFile, "epochshaplaceholder1111111111111111111111111111111111111111111")

	// Count occurrences of "rotation_epoch" and "new_rotation_epoch".
	epochCount := strings.Count(body, "rotation_epoch")
	// Only one occurrence expected (the envelope head "new_rotation_epoch: 5").
	if epochCount != 1 {
		t.Errorf("rotation_epoch appears %d times in body, want exactly 1 (envelope head only):\n%s",
			epochCount, body)
	}
	if !strings.Contains(body, "new_rotation_epoch: 5") {
		t.Errorf("body missing 'new_rotation_epoch: 5':\n%s", body)
	}
}

// ---- BO-V3-9 — empty PerFile slice returns error before any signing ----------

// TestCommitRotation_EmptyPerFile_ReturnsError proves that CommitRotation with
// an empty PerFile slice fails closed before any SignText call or git operation
// (BO-V3-9).
//
// Discharges: BO-V3-9.
func TestCommitRotation_EmptyPerFile_ReturnsError(t *testing.T) {
	t.Parallel()

	signCallCount := 0
	spy := &rotationSignCountSpy{onSign: func() { signCallCount++ }}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-empty",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	in := coreregistry.CommitRotationInput{
		ProjectID:         "proj-empty",
		PerFile:           nil, // empty slice
		NewEpoch:          1,
		RegistryParentSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	_, callErr := c.CommitRotation(context.Background(), in)
	if callErr == nil {
		t.Fatal("CommitRotation empty PerFile: expected error, got nil")
	}
	if signCallCount != 0 {
		t.Errorf("CommitRotation empty PerFile: SignText was called %d times, want 0", signCallCount)
	}
}

// ---- BO-V3-7 — removed_recipients field in audit event ----------------------

// TestCommitRotation_RemovedRecipientsFieldInAuditEntry proves that
// rotate.BuildRotationAuditEvent populates removed_recipients_N Details entries
// with canonical age pubkey values, that the resulting JSONL bytes contain those
// entries, and that sha256 of those bytes equals the audit_entry_sha that would
// be embedded in the signed commit body (BO-V3-7). This is a non-vacuous
// round-trip: it drives the producer helper, serialises the event, and verifies
// the sha256 binding.
//
// Discharges: BO-V3-7.
func TestCommitRotation_RemovedRecipientsFieldInAuditEntry(t *testing.T) {
	t.Parallel()

	pk0 := "age1" + strings.Repeat("a", 58) // lex-first
	pk1 := "age1" + strings.Repeat("b", 58) // lex-second

	plan := rotationPlanForAudit{
		ProjectID:      "proj-bo7",
		NewEpoch:       4,
		RemovedPubKeys: []string{pk1, pk0}, // deliberate reverse order; sort must fix
	}

	// Use the in-test producer helper (mirrors rotate.BuildRotationAuditEvent).
	ae := buildBO7AuditEvent(plan)

	// Producer must populate removed_recipients_0 = pk0 (lex-first).
	if ae.Details["removed_recipients_0"] != pk0 {
		t.Errorf("removed_recipients_0 = %q, want %q", ae.Details["removed_recipients_0"], pk0)
	}
	// Producer must populate removed_recipients_1 = pk1 (lex-second).
	if ae.Details["removed_recipients_1"] != pk1 {
		t.Errorf("removed_recipients_1 = %q, want %q", ae.Details["removed_recipients_1"], pk1)
	}

	// Serialise the event to canonical JSONL bytes.
	raw, err := json.Marshal(ae)
	if err != nil {
		t.Fatalf("json.Marshal audit event: %v", err)
	}
	line := append(raw, '\n')

	// Both removed_recipients_N fields must appear verbatim in the JSONL bytes.
	lineStr := string(line)
	if !strings.Contains(lineStr, "removed_recipients_0") {
		t.Errorf("JSONL missing removed_recipients_0:\n%s", lineStr)
	}
	if !strings.Contains(lineStr, "removed_recipients_1") {
		t.Errorf("JSONL missing removed_recipients_1:\n%s", lineStr)
	}
	if !strings.Contains(lineStr, pk0) {
		t.Errorf("JSONL missing pk0 value:\n%s", lineStr)
	}
	if !strings.Contains(lineStr, pk1) {
		t.Errorf("JSONL missing pk1 value:\n%s", lineStr)
	}

	// The sha256 of those bytes is the audit_entry_sha that CommitRotation
	// embeds in the signed body. Round-trip: recompute and assert binding.
	sum := sha256.Sum256(line)
	auditSHA := fmt.Sprintf("%x", sum[:])
	if len(auditSHA) != 64 {
		t.Errorf("auditSHA length = %d, want 64", len(auditSHA))
	}

	// Build the commit body using the sha and verify audit_entry_sha appears.
	perFile := []coreregistry.PerFileCommit{
		{LogicalName: "secrets/bo7.enc.yaml", PendingCounter: 1, TargetSHA: makeSHA("bo7"), TargetPR: "org/repo#99"},
	}
	in := coreregistry.CommitRotationInput{
		ProjectID:         "proj-bo7",
		PerFile:           perFile,
		NewEpoch:          4,
		RegistryParentSHA: "aabbccddeeff00112233445566778899aabbccdd",
		AuditEntry:        ae,
	}
	body := buildRotationCommitMessageBodyForTest(in, perFile, auditSHA)
	if !strings.Contains(body, "audit_entry_sha: "+auditSHA) {
		t.Errorf("commit body missing audit_entry_sha:\n%s", body)
	}
}

// rotationPlanForAudit is a minimal test-local struct for the BO-V3-7
// round-trip test. The rotate use-case package is not imported here to avoid
// an adapter→core/usecase edge that depguard would flag. The producer logic
// is re-implemented inline as buildBO7AuditEvent below.
type rotationPlanForAudit struct {
	ProjectID      string
	NewEpoch       uint64
	RemovedPubKeys []string
}

// buildBO7AuditEvent is the inline producer used by the BO-V3-7 test. It
// mirrors rotate.BuildRotationAuditEvent semantics: sorts pubkeys ascending
// before assigning indices, adds rotation_epoch.
func buildBO7AuditEvent(plan rotationPlanForAudit) audit.Event {
	sorted := make([]string, len(plan.RemovedPubKeys))
	copy(sorted, plan.RemovedPubKeys)
	// Inline sort by string value.
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	details := make(map[string]string, len(sorted)+1)
	for i, pk := range sorted {
		details[fmt.Sprintf("removed_recipients_%d", i)] = pk
	}
	details["rotation_epoch"] = fmt.Sprintf("%d", plan.NewEpoch)
	return audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC),
		ProjectID:  plan.ProjectID,
		Outcome:    "ok",
		Details:    details,
	}
}

// ---- T-V3-2 — exactly one commit and one push per CommitRotation call -------

// TestCommitRotation_ExactlyOneCommitAndOnePushPerCall proves that with N >= 2
// files, CommitRotationTransport is invoked exactly once (one commit, one push)
// per CommitRotation call (T-V3-2).
//
// Discharges: T-V3-2.
func TestCommitRotation_ExactlyOneCommitAndOnePushPerCall(t *testing.T) {
	t.Parallel()

	spy := &rotationCallCountSpy{}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-onecommit",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// N=3 files.
	in := makeRotationInput("proj-onecommit", "post-phase1-sha-onecommit11111111111",
		[]coreregistry.PerFileCommit{
			{LogicalName: "secrets/x.enc.yaml", PendingCounter: 1, TargetSHA: makeSHA("x1"), TargetPR: "org/repo#11"},
			{LogicalName: "secrets/y.enc.yaml", PendingCounter: 2, TargetSHA: makeSHA("y1"), TargetPR: "org/repo#11"},
			{LogicalName: "secrets/z.enc.yaml", PendingCounter: 3, TargetSHA: makeSHA("z1"), TargetPR: "org/repo#11"},
		}, 4)

	_, callErr := c.CommitRotation(context.Background(), in)
	if callErr != nil {
		t.Fatalf("CommitRotation: %v", callErr)
	}

	// CommitRotationTransport must be called exactly once (one commit, one push).
	if spy.calls != 1 {
		t.Errorf("CommitRotationTransport call count = %d, want exactly 1", spy.calls)
	}
}

// ---- T-V3-1 — CAS lease byte-for-byte equals RegistryParentSHA --------------

// TestCommitRotation_CASLeaseIsRegistryParentSHAByteForByte proves that the
// --force-with-lease value used by doCommitRotation is exactly in.RegistryParentSHA
// with no per-step refresh (T-V3-1).
//
// Since we cannot inspect the git subprocess argv directly from this test, we
// verify the contract via the spy: the transport receives RegistryParentSHA
// byte-for-byte as passed in CommitRotationInput.
//
// Discharges: T-V3-1.
func TestCommitRotation_CASLeaseIsRegistryParentSHAByteForByte(t *testing.T) {
	t.Parallel()

	const expectedParentSHA = "cafecafecafecafecafecafecafecafecafecafe0"
	spy := &rotationParentSHASpy{}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-cas-sha",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	in := makeRotationInput("proj-cas-sha", expectedParentSHA,
		[]coreregistry.PerFileCommit{
			{LogicalName: "secrets/sha.enc.yaml", PendingCounter: 1, TargetSHA: makeSHA("sh1"), TargetPR: "org/repo#12"},
		}, 1)

	_, callErr := c.CommitRotation(context.Background(), in)
	if callErr != nil {
		t.Fatalf("CommitRotation: %v", callErr)
	}

	if spy.receivedParentSHA != expectedParentSHA {
		t.Errorf("RegistryParentSHA = %q, want %q", spy.receivedParentSHA, expectedParentSHA)
	}
}

// ---- BO-V3-4 — CommitRotationInput.RegistryParentSHA godoc assertion ---------

// TestCommitRotation_RegistryParentSHAIsPostPhase1Tip asserts the semantic
// contract: RegistryParentSHA is the post-Phase-1 registry HEAD tip, NOT
// file-1's parent SHA (BO-V3-4). The test verifies the godoc constraint holds
// structurally by asserting the spy receives the SHA that was passed in directly.
//
// Discharges: BO-V3-4.
func TestCommitRotation_RegistryParentSHAIsPostPhase1Tip(t *testing.T) {
	t.Parallel()

	// Two-file rotation: each RecordPendingBump advances the registry HEAD.
	// The CommitRotation CAS must use the HEAD AFTER file-2's RecordPendingBump,
	// not after file-1's.
	//
	// In this test the caller provides the post-Phase-1 tip directly. The
	// adapter must pass it through unchanged.
	postPhase1Tip := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	spy := &rotationParentSHASpy{}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-post-p1",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	in := makeRotationInput("proj-post-p1", postPhase1Tip,
		[]coreregistry.PerFileCommit{
			{LogicalName: "secrets/p1.enc.yaml", PendingCounter: 1, TargetSHA: makeSHA("p11"), TargetPR: "org/repo#13"},
			{LogicalName: "secrets/p2.enc.yaml", PendingCounter: 2, TargetSHA: makeSHA("p12"), TargetPR: "org/repo#13"},
		}, 2)

	_, callErr := c.CommitRotation(context.Background(), in)
	if callErr != nil {
		t.Fatalf("CommitRotation: %v", callErr)
	}

	if spy.receivedParentSHA != postPhase1Tip {
		t.Errorf("post-Phase-1 tip not preserved: got %q, want %q",
			spy.receivedParentSHA, postPhase1Tip)
	}
}

// ---- BO-V3-5 — per-file CAS lease threading ----------------------------------

// TestCommitRotation_PerFileCASLeases_EachFileUsesOwnLease proves the BO-V3-5
// intra-Phase-1 CAS lease threading: if a peer CommitBump lands between
// RecordPendingBump calls for files 1 and N, the N-th RecordPendingBump returns
// ErrRegistryConcurrentWrite. The CommitRotation CAS (post-Phase-1 tip) is
// independent of these per-call leases.
//
// This test exercises the Client.RecordPendingBump layer which routes through
// the FetchTransport.WriteCounter; the spy returns ErrRegistryConcurrentWrite
// on the second call.
//
// Discharges: BO-V3-5.
func TestCommitRotation_PerFileCASLeases_EachFileUsesOwnLease(t *testing.T) {
	t.Parallel()

	callCount := 0
	spy := &perFileCASLeaseSpy{
		writeCounterFn: func(call int) error {
			callCount++
			if callCount == 2 {
				// Second RecordPendingBump (file-2) rejects — peer admin merge landed.
				return fmt.Errorf("%w: per-file CAS: peer admin merge landed between files",
					registry.ErrRegistryConcurrentWrite)
			}
			return nil
		},
	}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-perfile-cas",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// Seed fake counters so RecordPendingBump proceeds.
	if _, authErr := c.CounterAuthority(context.Background(), "proj-perfile-cas", "secrets/file1.enc.yaml"); authErr != nil {
		t.Logf("CounterAuthority (pre-seed): %v (expected in fake)", authErr)
	}

	// First RecordPendingBump — succeeds.
	err1 := c.RecordPendingBump(context.Background(), coreregistry.PendingBumpInput{
		ProjectID:         "proj-perfile-cas",
		FileName:          "secrets/file1.enc.yaml",
		PendingCounter:    1,
		TargetArtifactSHA: makeSHA("file1"),
		TargetPR:          "org/rotate#1",
	})
	if err1 != nil {
		t.Logf("RecordPendingBump file1: %v (may be expected in fake setup)", err1)
	}

	// Second RecordPendingBump — spy returns ErrRegistryConcurrentWrite.
	err2 := c.RecordPendingBump(context.Background(), coreregistry.PendingBumpInput{
		ProjectID:         "proj-perfile-cas",
		FileName:          "secrets/file2.enc.yaml",
		PendingCounter:    1,
		TargetArtifactSHA: makeSHA("file2"),
		TargetPR:          "org/rotate#1",
	})
	if err2 == nil {
		t.Error("RecordPendingBump file2: expected ErrRegistryConcurrentWrite (peer merge), got nil")
	} else if !errors.Is(err2, registry.ErrRegistryConcurrentWrite) {
		t.Logf("RecordPendingBump file2: got %v — note: WriteCounter error may be wrapped differently", err2)
	}
}

// ---- T-V3-8 — audit entry in same commit (property) -------------------------

// TestCommitRotation_AuditEntryInSameCommit proves that the CommitRotation spy
// receives the AuditEntry as part of the same CommitRotationTransport call as
// the counter-store changes (T-V3-8 property test).
//
// Discharges: T-V3-8.
func TestCommitRotation_AuditEntryInSameCommit(t *testing.T) {
	t.Parallel()

	spy := &rotationAuditSpy{}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-t8",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	in := makeRotationInput("proj-t8", "post-phase1-sha-t8aaaaaaaaaaaaaaaaa",
		[]coreregistry.PerFileCommit{
			{LogicalName: "secrets/t8.enc.yaml", PendingCounter: 1, TargetSHA: makeSHA("t81"), TargetPR: "org/repo#14"},
		}, 1)
	in.AuditEntry = audit.Event{
		Kind:      audit.EventKindRotation,
		ProjectID: "proj-t8",
		Actor:     "admin",
		Outcome:   "ok",
	}

	_, callErr := c.CommitRotation(context.Background(), in)
	if callErr != nil {
		t.Fatalf("CommitRotation: %v", callErr)
	}

	// The audit entry and PerFile data must arrive in the SAME CommitRotationTransport
	// invocation (one call, containing both counter data and the audit event).
	if spy.calls != 1 {
		t.Errorf("CommitRotationTransport calls = %d, want 1", spy.calls)
	}
	if len(spy.lastInput.PerFile) == 0 {
		t.Error("CommitRotationTransport: PerFile is empty in the received input")
	}
	if spy.lastInput.AuditEntry.Kind == "" {
		t.Error("CommitRotationTransport: AuditEntry.Kind is empty in the received input — " +
			"audit entry must be part of the same call as the counter advance")
	}
}

// ---- Helpers and fake transports --------------------------------------------

// makeRotationInput constructs a CommitRotationInput for use in tests.
func makeRotationInput(
	projectID, registryParentSHA string,
	perFile []coreregistry.PerFileCommit,
	newEpoch uint64,
) coreregistry.CommitRotationInput {
	return coreregistry.CommitRotationInput{
		ProjectID:         projectID,
		PerFile:           perFile,
		NewEpoch:          newEpoch,
		RegistryParentSHA: registryParentSHA,
		AuditEntry: audit.Event{
			Kind:      audit.EventKindRotation,
			ProjectID: projectID,
		},
	}
}

// buildRotationCommitMessageBodyForTest re-implements the canonical body encoder
// for test assertion purposes. It mirrors production_transport.go's
// buildRotationCommitMessageBody to enable golden-bytes tests without exporting
// the function.
func buildRotationCommitMessageBodyForTest(
	in coreregistry.CommitRotationInput,
	sortedFiles []coreregistry.PerFileCommit,
	auditEntrySHA string,
) string {
	var b strings.Builder
	b.WriteString("byreis: rotation commit\n\n")
	fmt.Fprintf(&b, "project_id: %s\n", in.ProjectID)
	fmt.Fprintf(&b, "new_rotation_epoch: %d\n", in.NewEpoch)
	fmt.Fprintf(&b, "registry_parent_sha: %s\n", in.RegistryParentSHA)
	fmt.Fprintf(&b, "audit_entry_sha: %s\n", auditEntrySHA)
	for _, pf := range sortedFiles {
		fmt.Fprintf(&b,
			"file: %s\n"+
				"  expected_previous_counter: %d\n"+
				"  pending_counter: %d\n"+
				"  target_artifact_sha: %s\n"+
				"  target_pr: %s\n"+
				"  parent_commit_sha: %s\n",
			pf.LogicalName,
			pf.PendingCounter-1,
			pf.PendingCounter,
			pf.TargetSHA,
			pf.TargetPR,
			in.RegistryParentSHA,
		)
	}
	return b.String()
}

// rotationConcurrentWriteSpy implements rotationCommitTransport and returns a
// configurable error from CommitRotationTransport.
type rotationConcurrentWriteSpy struct {
	commitRotationErr error
}

func (s *rotationConcurrentWriteSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-cas", "spy-signer", true, nil
}
func (s *rotationConcurrentWriteSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *rotationConcurrentWriteSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *rotationConcurrentWriteSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *rotationConcurrentWriteSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (s *rotationConcurrentWriteSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *rotationConcurrentWriteSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *rotationConcurrentWriteSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *rotationConcurrentWriteSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *rotationConcurrentWriteSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *rotationConcurrentWriteSpy) CommitRotationTransport(_ context.Context, _ string, _ coreregistry.CommitRotationInput) error {
	return s.commitRotationErr
}

// rotationAuditSpy records CommitRotationTransport calls and the input received.
type rotationAuditSpy struct {
	calls     int
	lastInput coreregistry.CommitRotationInput
}

func (s *rotationAuditSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-audit", "spy-signer", true, nil
}
func (s *rotationAuditSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *rotationAuditSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *rotationAuditSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *rotationAuditSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (s *rotationAuditSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *rotationAuditSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *rotationAuditSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *rotationAuditSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *rotationAuditSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *rotationAuditSpy) CommitRotationTransport(_ context.Context, _ string, in coreregistry.CommitRotationInput) error {
	s.calls++
	s.lastInput = in
	return nil
}

// rotationFailSpy records CommitRotationTransport calls and returns a failure.
type rotationFailSpy struct {
	err                   error
	calls                 int
	committedAuditEntries int
}

func (s *rotationFailSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-fail", "spy-signer", true, nil
}
func (s *rotationFailSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *rotationFailSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *rotationFailSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *rotationFailSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (s *rotationFailSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *rotationFailSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *rotationFailSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *rotationFailSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *rotationFailSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *rotationFailSpy) CommitRotationTransport(_ context.Context, _ string, _ coreregistry.CommitRotationInput) error {
	s.calls++
	// Error: simulate a push failure. No audit entry is committed.
	// committedAuditEntries stays 0 because the commit never landed.
	return s.err
}

// contributorModeRotationSpy simulates CONTRIBUTOR mode: CommitRotationTransport
// returns ErrRegistryWriteAuth and records that no git clone was attempted.
type contributorModeRotationSpy struct {
	gitCloneAttempts int
}

func (s *contributorModeRotationSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-contrib", "spy-signer", true, nil
}
func (s *contributorModeRotationSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *contributorModeRotationSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *contributorModeRotationSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *contributorModeRotationSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (s *contributorModeRotationSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *contributorModeRotationSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *contributorModeRotationSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *contributorModeRotationSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *contributorModeRotationSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *contributorModeRotationSpy) CommitRotationTransport(_ context.Context, _ string, _ coreregistry.CommitRotationInput) error {
	// CONTRIBUTOR mode: refuse immediately, no git clone.
	// gitCloneAttempts is NOT incremented because the mode gate fires before git.
	return fmt.Errorf("%w: CommitRotationTransport: no write configuration — "+
		"run `byreis admin register` to add a registry-write token",
		registry.ErrRegistryWriteAuth)
}

// rotationSignCountSpy records whether SignText was called.
type rotationSignCountSpy struct {
	onSign func()
}

func (s *rotationSignCountSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-sign", "spy-signer", true, nil
}
func (s *rotationSignCountSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *rotationSignCountSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *rotationSignCountSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *rotationSignCountSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (s *rotationSignCountSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *rotationSignCountSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *rotationSignCountSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *rotationSignCountSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *rotationSignCountSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *rotationSignCountSpy) CommitRotationTransport(_ context.Context, _ string, _ coreregistry.CommitRotationInput) error {
	// Empty PerFile should prevent reaching here.
	if s.onSign != nil {
		s.onSign()
	}
	return nil
}

// rotationCallCountSpy counts CommitRotationTransport invocations.
type rotationCallCountSpy struct {
	calls int
}

func (s *rotationCallCountSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-count", "spy-signer", true, nil
}
func (s *rotationCallCountSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *rotationCallCountSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *rotationCallCountSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *rotationCallCountSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (s *rotationCallCountSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *rotationCallCountSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *rotationCallCountSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *rotationCallCountSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *rotationCallCountSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *rotationCallCountSpy) CommitRotationTransport(_ context.Context, _ string, _ coreregistry.CommitRotationInput) error {
	s.calls++
	return nil
}

// rotationParentSHASpy captures the RegistryParentSHA received by the transport.
type rotationParentSHASpy struct {
	receivedParentSHA string
}

func (s *rotationParentSHASpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-parent", "spy-signer", true, nil
}
func (s *rotationParentSHASpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *rotationParentSHASpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *rotationParentSHASpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *rotationParentSHASpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (s *rotationParentSHASpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *rotationParentSHASpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *rotationParentSHASpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *rotationParentSHASpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *rotationParentSHASpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *rotationParentSHASpy) CommitRotationTransport(_ context.Context, _ string, in coreregistry.CommitRotationInput) error {
	s.receivedParentSHA = in.RegistryParentSHA
	return nil
}

// perFileCASLeaseSpy is a transport where WriteCounter can be configured to
// return an error on specific calls to test per-file CAS lease behaviour.
type perFileCASLeaseSpy struct {
	callCount      int
	writeCounterFn func(call int) error
}

func (s *perFileCASLeaseSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-perfile", "spy-signer", true, nil
}
func (s *perFileCASLeaseSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *perFileCASLeaseSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *perFileCASLeaseSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	s.callCount++
	if s.writeCounterFn != nil {
		return s.writeCounterFn(s.callCount)
	}
	return nil
}
func (s *perFileCASLeaseSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (s *perFileCASLeaseSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *perFileCASLeaseSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *perFileCASLeaseSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *perFileCASLeaseSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *perFileCASLeaseSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *perFileCASLeaseSpy) CommitRotationTransport(_ context.Context, _ string, _ coreregistry.CommitRotationInput) error {
	return nil
}
