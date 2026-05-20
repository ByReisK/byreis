package rotate

import (
	"fmt"
	"sort"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
)

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
