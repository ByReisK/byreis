package rotate_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// TestBuildRotationAuditEvent_ZeroRemovedRecipients proves that a plan with no
// removed recipients produces an event with only the rotation_epoch details
// field and no removed_recipients_N entries. Discharges BO-V3-7 (zero case).
func TestBuildRotationAuditEvent_ZeroRemovedRecipients(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	plan := rotate.RotationPlan{
		ProjectID:         "proj-zero",
		NewEpoch:          7,
		RemovedRecipients: nil,
	}

	ev := rotate.BuildRotationAuditEvent(plan, "proj-zero", when)

	if ev.Kind != audit.EventKindRotation {
		t.Errorf("Kind = %q, want %q", ev.Kind, audit.EventKindRotation)
	}
	if ev.ProjectID != "proj-zero" {
		t.Errorf("ProjectID = %q, want proj-zero", ev.ProjectID)
	}
	if !ev.OccurredAt.Equal(when) {
		t.Errorf("OccurredAt = %v, want %v", ev.OccurredAt, when)
	}
	if ev.Outcome != "ok" {
		t.Errorf("Outcome = %q, want ok", ev.Outcome)
	}

	// No removed_recipients_N keys must be present.
	for k := range ev.Details {
		if k != "rotation_epoch" {
			t.Errorf("unexpected Details key %q (no removed recipients in plan)", k)
		}
	}
	if ev.Details["rotation_epoch"] != "7" {
		t.Errorf("rotation_epoch = %q, want 7", ev.Details["rotation_epoch"])
	}
}

// TestBuildRotationAuditEvent_OneRemovedRecipient proves that a plan with one
// removed recipient produces Details["removed_recipients_0"] = that pubkey.
// Discharges BO-V3-7 (one case).
func TestBuildRotationAuditEvent_OneRemovedRecipient(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	pubkey := "age1" + strRepeat("q", 58)
	plan := rotate.RotationPlan{
		ProjectID: "proj-one",
		NewEpoch:  3,
		RemovedRecipients: []rectypes.Recipient{
			{AgePubKey: pubkey, Label: "removed-admin"},
		},
	}

	ev := rotate.BuildRotationAuditEvent(plan, "proj-one", when)

	if ev.Details["removed_recipients_0"] != pubkey {
		t.Errorf("removed_recipients_0 = %q, want %q", ev.Details["removed_recipients_0"], pubkey)
	}
	if ev.Details["rotation_epoch"] != "3" {
		t.Errorf("rotation_epoch = %q, want 3", ev.Details["rotation_epoch"])
	}
	// Exactly 2 details keys: removed_recipients_0 + rotation_epoch.
	if len(ev.Details) != 2 {
		t.Errorf("Details len = %d, want 2; map: %v", len(ev.Details), ev.Details)
	}
}

// TestBuildRotationAuditEvent_NRemovedRecipients proves that with N removed
// recipients the indices 0..N-1 are assigned in ascending AgePubKey order,
// and the mapping is deterministic regardless of the order the planner
// populated RemovedRecipients. Discharges BO-V3-7 (N case + ordering).
func TestBuildRotationAuditEvent_NRemovedRecipients(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)

	// Three pubkeys; pass them in non-sorted order to verify sort-before-index.
	pkB := "age1" + strRepeat("b", 58)
	pkA := "age1" + strRepeat("a", 58)
	pkC := "age1" + strRepeat("c", 58)

	plan := rotate.RotationPlan{
		ProjectID: "proj-n",
		NewEpoch:  5,
		RemovedRecipients: []rectypes.Recipient{
			{AgePubKey: pkB, Label: "b"},
			{AgePubKey: pkA, Label: "a"},
			{AgePubKey: pkC, Label: "c"},
		},
	}

	ev := rotate.BuildRotationAuditEvent(plan, "proj-n", when)

	// Sorted ascending: pkA < pkB < pkC.
	if ev.Details["removed_recipients_0"] != pkA {
		t.Errorf("removed_recipients_0 = %q, want pkA (%q)", ev.Details["removed_recipients_0"], pkA)
	}
	if ev.Details["removed_recipients_1"] != pkB {
		t.Errorf("removed_recipients_1 = %q, want pkB (%q)", ev.Details["removed_recipients_1"], pkB)
	}
	if ev.Details["removed_recipients_2"] != pkC {
		t.Errorf("removed_recipients_2 = %q, want pkC (%q)", ev.Details["removed_recipients_2"], pkC)
	}
	if ev.Details["rotation_epoch"] != "5" {
		t.Errorf("rotation_epoch = %q, want 5", ev.Details["rotation_epoch"])
	}
	// 4 keys total: 3 recipients + rotation_epoch.
	if len(ev.Details) != 4 {
		t.Errorf("Details len = %d, want 4; map: %v", len(ev.Details), ev.Details)
	}

	// Second call with same plan must produce identical event (deterministic).
	ev2 := rotate.BuildRotationAuditEvent(plan, "proj-n", when)
	if ev2.Details["removed_recipients_0"] != ev.Details["removed_recipients_0"] ||
		ev2.Details["removed_recipients_1"] != ev.Details["removed_recipients_1"] ||
		ev2.Details["removed_recipients_2"] != ev.Details["removed_recipients_2"] {
		t.Error("BuildRotationAuditEvent is not deterministic for same input")
	}
}

// TestBuildRotationAuditEvent_ProjectIDPropagates proves that the projectID
// argument (not plan.ProjectID) populates Event.ProjectID. This allows the
// caller to provide a canonical project ID even when the plan was built with a
// display-only project name.
func TestBuildRotationAuditEvent_ProjectIDPropagates(t *testing.T) {
	t.Parallel()

	plan := rotate.RotationPlan{
		ProjectID: "plan-pid",
		NewEpoch:  1,
	}
	ev := rotate.BuildRotationAuditEvent(plan, "canonical-pid", time.Now())
	if ev.ProjectID != "canonical-pid" {
		t.Errorf("ProjectID = %q, want canonical-pid", ev.ProjectID)
	}
}

// TestBuildRotationAuditEvent_OccurredAtSetFromClock proves that the OccurredAt
// field is set from the injected `when` argument (clock injection contract).
func TestBuildRotationAuditEvent_OccurredAtSetFromClock(t *testing.T) {
	t.Parallel()

	frozen := time.Date(2026, 1, 15, 12, 30, 0, 0, time.UTC)
	plan := rotate.RotationPlan{ProjectID: "proj-clk", NewEpoch: 2}
	ev := rotate.BuildRotationAuditEvent(plan, "proj-clk", frozen)
	if !ev.OccurredAt.Equal(frozen) {
		t.Errorf("OccurredAt = %v, want %v", ev.OccurredAt, frozen)
	}
}

// strRepeat returns a string of c repeated n times (test helper).
func strRepeat(c string, n int) string {
	result := make([]byte, n)
	for i := range result {
		result[i] = c[0]
	}
	return string(result)
}

// --- BuildRotationReversalAuditEvent (V5.AUDIT.* rows) ---
//
// Row IDs (audit-trail anchors permitted in _test.go ONLY):
//   - V5.AUDIT.reversal.happy-path
//   - V5.AUDIT.reversal.empty-branch-ref-sentinel
//   - V5.AUDIT.reversal.unsorted-input-sorted-output
//   - V5.AUDIT.reversal.zero-pendings-no-N-keys
//   - V5.AUDIT.reversal.no-recipient-keys-emitted
//   - V5.AUDIT.reversal.outcome-constant-value
//
// Discharges BO-V5-7 (producer added + V1 fake updated), BO-V5-PORT-CRYPTO-1
// (outcome constant), BO-V5-PORT-CRYPTO-5 (absence-of-recipient-fields).

// reversalObsViaGit builds a Phase-1-only PartialStateObservation for the
// V5.AUDIT.* rows: one pending per logical name supplied, plus the supplied
// project/PR-number rotation branch ref. With zero names, the resulting
// observation has zero pendings and a non-empty branch ref (defensive path
// row coverage).
func reversalObsViaGit(project string, prNumber int, names ...string) rotate.PartialStateObservation {
	branchRef := git.PRRef{Project: project, Number: prNumber}
	ps := make([]rotate.PendingObservation, len(names))
	for i, n := range names {
		ps[i] = rotate.PendingObservation{
			LogicalName:       n,
			PendingCounter:    uint64(i + 1),
			TargetArtifactSHA: "sha-" + n,
			TargetPR:          branchRef,
		}
	}
	return rotate.PartialStateObservation{
		PendingsTaggedRotation: ps,
		RotationBranchExists:   true,
		RotationBranchMerged:   false,
		RotationBranchRef:      branchRef,
	}
}

// keyForReversalPending returns the canonical Details key for the N-th
// reversal pending (ascending LogicalName order index N=0,1,...).
func keyForReversalPending(n int) string {
	return fmt.Sprintf("reversal_pendings_cleared_%d", n)
}

// V5.AUDIT.reversal.happy-path — non-empty branch ref + 3 pendings (already in
// ascending LogicalName order) produces an event with the correct shape:
// Kind=audit.EventKindRotation, Outcome=RotationOutcomeReverted, ProjectID
// propagated, OccurredAt set from the injected clock, reversal_target_pr is
// the rotation branch PR ref canonical string, reversal_pendings_cleared_<N>
// keys present in ascending order, reversal_reason pinned.
func TestBuildRotationReversalAuditEvent_HappyPath(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, 5, 21, 11, 30, 0, 0, time.UTC)
	obs := reversalObsViaGit("myorg/proj", 99, "prod-a", "prod-b", "prod-c")

	ev, err := rotate.BuildRotationReversalAuditEvent(obs, "myorg/proj", when)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Kind != audit.EventKindRotation {
		t.Errorf("Kind = %q, want %q", ev.Kind, audit.EventKindRotation)
	}
	if ev.Outcome != rotate.RotationOutcomeReverted {
		t.Errorf("Outcome = %q, want %q (RotationOutcomeReverted)",
			ev.Outcome, rotate.RotationOutcomeReverted)
	}
	if ev.ProjectID != "myorg/proj" {
		t.Errorf("ProjectID = %q, want myorg/proj", ev.ProjectID)
	}
	if !ev.OccurredAt.Equal(when) {
		t.Errorf("OccurredAt = %v, want %v", ev.OccurredAt, when)
	}
	// reversal_target_pr must equal the rotation branch PR ref canonical
	// string. The exact canonical form is "<project>#<number>" — we assert
	// containment so a future formatting tweak does not silently regress.
	if ev.Details["reversal_target_pr"] == "" {
		t.Fatal("Details[reversal_target_pr] must be present")
	}
	if !containsSubstr(ev.Details["reversal_target_pr"], "myorg/proj") ||
		!containsSubstr(ev.Details["reversal_target_pr"], "99") {
		t.Errorf("reversal_target_pr = %q, want canonical form referencing both project and PR number",
			ev.Details["reversal_target_pr"])
	}
	for i, name := range []string{"prod-a", "prod-b", "prod-c"} {
		k := keyForReversalPending(i)
		if ev.Details[k] != name {
			t.Errorf("Details[%s] = %q, want %q", k, ev.Details[k], name)
		}
	}
	if ev.Details["reversal_reason"] != "phase-1-only-classification" {
		t.Errorf("Details[reversal_reason] = %q, want phase-1-only-classification",
			ev.Details["reversal_reason"])
	}
}

// V5.AUDIT.reversal.empty-branch-ref-sentinel — an observation with an empty
// RotationBranchRef must surface ErrRotationReversalNoBranchRef; NO partial
// event may be returned. The producer fails closed.
func TestBuildRotationReversalAuditEvent_EmptyBranchRefSentinel(t *testing.T) {
	t.Parallel()

	obs := rotate.PartialStateObservation{
		PendingsTaggedRotation: []rotate.PendingObservation{
			{LogicalName: "prod", PendingCounter: 1, TargetArtifactSHA: "sha"},
		},
		RotationBranchExists: true,
		// RotationBranchRef intentionally zero-value.
	}
	ev, err := rotate.BuildRotationReversalAuditEvent(obs, "myorg/proj", time.Now())
	if !errors.Is(err, rotate.ErrRotationReversalNoBranchRef) {
		t.Fatalf("expected ErrRotationReversalNoBranchRef, got %v", err)
	}
	// Absence: no partial event must be emitted. Every meaningful field on
	// the zero-value event must be its zero value.
	if ev.Kind != "" || ev.Outcome != "" || ev.ProjectID != "" || len(ev.Details) != 0 {
		t.Errorf("partial event leaked on sentinel return: %+v", ev)
	}
}

// V5.AUDIT.reversal.unsorted-input-sorted-output — pendings supplied in
// non-sorted order produce reversal_pendings_cleared_<N> keys in ascending
// LogicalName order regardless of input ordering.
func TestBuildRotationReversalAuditEvent_UnsortedInputSortedOutput(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, 5, 21, 11, 30, 0, 0, time.UTC)
	// Pendings supplied B, A, C; producer must emit A, B, C at indices 0,1,2.
	obs := reversalObsViaGit("myorg/proj", 7, "prod-b", "prod-a", "prod-c")

	ev, err := rotate.BuildRotationReversalAuditEvent(obs, "myorg/proj", when)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Details[keyForReversalPending(0)] != "prod-a" {
		t.Errorf("index 0 = %q, want prod-a", ev.Details[keyForReversalPending(0)])
	}
	if ev.Details[keyForReversalPending(1)] != "prod-b" {
		t.Errorf("index 1 = %q, want prod-b", ev.Details[keyForReversalPending(1)])
	}
	if ev.Details[keyForReversalPending(2)] != "prod-c" {
		t.Errorf("index 2 = %q, want prod-c", ev.Details[keyForReversalPending(2)])
	}
	// Determinism: a second call with the same input produces an identical
	// Details map (sort discipline is not flaky).
	ev2, err := rotate.BuildRotationReversalAuditEvent(obs, "myorg/proj", when)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	for i := 0; i < 3; i++ {
		k := keyForReversalPending(i)
		if ev.Details[k] != ev2.Details[k] {
			t.Errorf("non-deterministic sort at index %d: first=%q second=%q",
				i, ev.Details[k], ev2.Details[k])
		}
	}
}

// V5.AUDIT.reversal.zero-pendings-no-N-keys — an observation with zero
// pendings produces an event with NO reversal_pendings_cleared_<N> keys at
// all (not even _0); the other Details fields remain present. Reconcile may
// surface this path if a probe race observed an empty pending set on the
// reversal attempt (defensive coverage; not the normal path).
func TestBuildRotationReversalAuditEvent_ZeroPendingsNoNKeys(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, 5, 21, 11, 30, 0, 0, time.UTC)
	obs := reversalObsViaGit("myorg/proj", 99) // zero pendings, branch ref present.

	ev, err := rotate.BuildRotationReversalAuditEvent(obs, "myorg/proj", when)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for k := range ev.Details {
		if k == "reversal_target_pr" || k == "reversal_reason" {
			continue
		}
		// Any other key must not be a reversal_pendings_cleared_* key.
		if len(k) >= len("reversal_pendings_cleared_") &&
			k[:len("reversal_pendings_cleared_")] == "reversal_pendings_cleared_" {
			t.Errorf("unexpected reversal_pendings_cleared key %q with zero pendings", k)
		}
	}
	if ev.Details["reversal_target_pr"] == "" {
		t.Error("reversal_target_pr must still be present with zero pendings")
	}
	if ev.Details["reversal_reason"] != "phase-1-only-classification" {
		t.Errorf("reversal_reason = %q, want phase-1-only-classification",
			ev.Details["reversal_reason"])
	}
}

// V5.AUDIT.reversal.no-recipient-keys-emitted — absence assertion per the
// BO-V5-PORT-CRYPTO-5 obligation: a reversal event never carries
// removed_recipients_* or added_recipients_* keys. The rotation reversal is
// classification-only; it makes no recipient-set assertion.
func TestBuildRotationReversalAuditEvent_NoRecipientKeysEmitted(t *testing.T) {
	t.Parallel()

	when := time.Date(2026, 5, 21, 11, 30, 0, 0, time.UTC)
	obs := reversalObsViaGit("myorg/proj", 99, "prod-a", "prod-b")

	ev, err := rotate.BuildRotationReversalAuditEvent(obs, "myorg/proj", when)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for k := range ev.Details {
		if len(k) >= len("removed_recipients_") &&
			k[:len("removed_recipients_")] == "removed_recipients_" {
			t.Errorf("reversal event must NOT emit %q (removed_recipients_*)", k)
		}
		if len(k) >= len("added_recipients_") &&
			k[:len("added_recipients_")] == "added_recipients_" {
			t.Errorf("reversal event must NOT emit %q (added_recipients_*)", k)
		}
	}
}

// V5.AUDIT.reversal.outcome-constant-value — proves the named outcome
// constant value is exactly "reverted". The audit-sink consumers (V5 docgate
// row + production registry-side append) key on this literal; a typo in the
// constant is a deliberate review event.
func TestBuildRotationReversalAuditEvent_OutcomeConstantValue(t *testing.T) {
	t.Parallel()

	if rotate.RotationOutcomeReverted != "reverted" {
		t.Errorf("RotationOutcomeReverted = %q, want %q",
			rotate.RotationOutcomeReverted, "reverted")
	}
	// Echo via a producer call: the event surface uses the constant verbatim.
	when := time.Date(2026, 5, 21, 11, 30, 0, 0, time.UTC)
	obs := reversalObsViaGit("myorg/proj", 99, "prod")
	ev, err := rotate.BuildRotationReversalAuditEvent(obs, "myorg/proj", when)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Outcome != rotate.RotationOutcomeReverted {
		t.Errorf("event.Outcome = %q, want %q (RotationOutcomeReverted)",
			ev.Outcome, rotate.RotationOutcomeReverted)
	}
	if ev.Outcome != "reverted" {
		t.Errorf("event.Outcome = %q, want literal \"reverted\" (constant value pin)",
			ev.Outcome)
	}
}
