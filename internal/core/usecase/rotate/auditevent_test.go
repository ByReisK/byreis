package rotate_test

import (
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
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
