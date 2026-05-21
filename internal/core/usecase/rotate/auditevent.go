package rotate

import (
	"fmt"
	"sort"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
)

// RotationOutcomeReverted is the audit.Event.Outcome value emitted when a
// rotation transaction is reversed by the reconciler under a PHASE_1_ONLY
// classification. Consumers (registry-side audit sink, docgate row asserting
// the literal value, CLI render layer surfacing reversal results) key on
// this literal — a change here is a deliberate review event.
const RotationOutcomeReverted = "reverted"

// BuildRotationAuditEvent constructs the audit.Event for a rotation
// transaction. The event carries the project ID, the rotation epoch, the
// timestamp, and a canonical-typed Details map enumerating the recipients
// removed by this rotation.
//
// Field shape (Details map):
//   - "removed_recipients_<N>": canonical age recipient string, for
//     N = 0..len(plan.RemovedRecipients)-1, sorted ascending by AgePubKey so
//     the index assignment is deterministic across runs.
//   - "rotation_epoch": the new epoch as a decimal string.
//
// Ordering: removed recipients are sorted ascending by AgePubKey before
// index assignment, so the mapping is reproducible regardless of the order
// in which the planner computed RemovedRecipients.
//
// This helper is consumed by the rotate use-case orchestrator; tests exercise
// it directly so the producer is covered in its owning package rather than
// only at the registry-adapter boundary.
func BuildRotationAuditEvent(plan RotationPlan, projectID string, when time.Time) audit.Event {
	details := make(map[string]string, len(plan.RemovedRecipients)+1)

	// Sort removed recipients ascending by AgePubKey for deterministic N
	// assignment. Copy to avoid mutating the plan's slice.
	sorted := make([]string, len(plan.RemovedRecipients))
	for i, r := range plan.RemovedRecipients {
		sorted[i] = r.AgePubKey
	}
	sort.Strings(sorted)

	for i, pk := range sorted {
		details[fmt.Sprintf("removed_recipients_%d", i)] = pk
	}
	details["rotation_epoch"] = fmt.Sprintf("%d", plan.NewEpoch)

	return audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: when,
		ProjectID:  projectID,
		Outcome:    "ok",
		Details:    details,
	}
}

// BuildRotationReversalAuditEvent constructs the audit.Event for a rotation
// reversal: the reconciler's PHASE_1_ONLY reversal path emits this event
// alongside the ClearPendings signed registry commit. The event captures
// which pendings were cleared and which rotation branch they were tied to,
// but makes NO recipient-set assertion: a reversal is a classification-only
// undo of an in-flight Phase-1, not a rotation outcome.
//
// Producer contract:
//
//   - reversal_target_pr: the rotation branch PR ref's canonical string. This
//     is the ROTATION BRANCH PR ref (the byreis/rotate-* PR opened in
//     Phase-1), NOT a contributor submission PR ref. Joining this event back
//     to the failed rotation requires the rotation branch ref, not the
//     unrelated contributor flow's PR ref.
//   - reversal_pendings_cleared_<N>: one Details key per pending in the
//     observation's PendingsTaggedRotation slice, indices N=0,1,2,...
//     assigned by ascending LogicalName. The sort discipline is load-bearing:
//     audit consumers diff event Details across reversal events and a
//     non-deterministic index assignment would make those diffs noisy and
//     untrustworthy.
//   - reversal_reason: pinned at "phase-1-only-classification" for V5. Future
//     reversal triggers (post-V5) would extend this enumeration; the value
//     pin makes V5 reversal events distinguishable from future ones.
//
// Absence contract:
//
//   - NO removed_recipients_* keys are emitted (the reversal does not change
//     the recipient set; the rotation that would have changed it never
//     landed).
//   - NO added_recipients_* keys are emitted (same rationale).
//
// Failure mode: BuildRotationReversalAuditEvent REFUSES on an empty
// RotationBranchRef and returns ErrRotationReversalNoBranchRef wrapped via
// the package's sentinel-with-hint convention. No partial event is emitted —
// the caller (the reconciler) treats this as a probe defect and surfaces a
// terminal error. The function never panics.
func BuildRotationReversalAuditEvent(observation PartialStateObservation, projectID string, when time.Time) (audit.Event, error) {
	// Empty-branch-ref sentinel: an observation without a populated branch ref
	// cannot anchor a reversal audit trail. Fail closed; no partial event.
	if observation.RotationBranchRef.Project == "" && observation.RotationBranchRef.Number == 0 {
		return audit.Event{}, ErrRotationReversalNoBranchRef
	}

	// Sort pendings ascending by LogicalName for deterministic N assignment.
	// Copy to avoid mutating the caller's slice.
	names := make([]string, len(observation.PendingsTaggedRotation))
	for i, p := range observation.PendingsTaggedRotation {
		names[i] = p.LogicalName
	}
	sort.Strings(names)

	details := make(map[string]string, len(names)+2)
	details["reversal_target_pr"] = fmt.Sprintf("%s#%d",
		observation.RotationBranchRef.Project,
		observation.RotationBranchRef.Number)
	details["reversal_reason"] = "phase-1-only-classification"
	for i, name := range names {
		details[fmt.Sprintf("reversal_pendings_cleared_%d", i)] = name
	}

	return audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: when,
		ProjectID:  projectID,
		Outcome:    RotationOutcomeReverted,
		Details:    details,
	}, nil
}
