package rotate

import (
	"context"
	"errors"
	"fmt"

	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// reconcileMaxRetries is the bounded retry budget for the reconciler: a CAS
// rejection during pending-clear triggers a re-classification + retry; after
// this many retries the reconciler surfaces ErrRotationReconcile (terminal).
const reconcileMaxRetries = 3

// ReconcilerDeps carries the constructor-injected ports for the reconciler.
// All collaborators are consumer-defined ports here in the rotate package.
type ReconcilerDeps struct {
	// Probe observes the registry+project partial-state shape under a
	// SourceVerified registry fetch.
	Probe RotationStateProbe
	// Reverser acts on a PHASE_1_ONLY classification: clear pendings + delete
	// the unmerged rotation branch.
	Reverser RotationStateReverser
	// Clock supplies the OccurredAt timestamp for the rotation-reversal audit
	// event emitted alongside ClearPendings. Required: no real clock is used
	// in tests; production wires a system clock at composition.
	Clock Clock
}

// NewReconciler returns a RotationReconciler with the given dependencies.
// All ports are required; a nil port returns an error (no nil-port silent
// downgrade — security paths fail closed).
func NewReconciler(d ReconcilerDeps) (RotationReconciler, error) {
	if d.Probe == nil || d.Reverser == nil || d.Clock == nil {
		return nil, errors.New(
			"rotate.NewReconciler: a required port is nil — " +
				"wire RotationStateProbe, RotationStateReverser, and Clock")
	}
	return &reconciler{d: d}, nil
}

type reconciler struct {
	d ReconcilerDeps
}

// Classify is the read-only classification entry point: it observes the
// partial-state shape under a SourceVerified registry fetch and returns the
// classification only. No writes.
func (r *reconciler) Classify(ctx context.Context, projectID string) (PartialStateClassification, error) {
	if err := ctx.Err(); err != nil {
		return NoPartialState, fmt.Errorf("rotation classify cancelled: %w", err)
	}
	obs, err := r.d.Probe.FetchPartialState(ctx, projectID)
	if err != nil {
		return NoPartialState, fmt.Errorf("rotation classify: %w", err)
	}
	return classifyObservation(obs), nil
}

// Reconcile classifies the partial state, then acts on the classification
// with bounded retries on CAS rejection during the pending-clear path AND
// the branch-delete path. The retry budget is uniform across the two steps:
// each CAS failure costs one retry; the budget caps at reconcileMaxRetries
// regardless of which step burned it.
//
// Branch-delete-pending discipline: once ClearPendings has succeeded for an
// observation, the reconciler must NOT re-probe or re-classify on a
// branch-delete failure. Re-probing after the clear succeeded would risk
// (a) racing a fresh rotation start that has not yet observed the clear,
// classifying the live partial-state as something other than Phase1Only,
// and (b) re-running ClearPendings against the already-cleared registry
// state. Instead, the loop snapshots the rotation branch ref and the
// cleared-pendings count from the observation that drove the successful
// ClearPendings, and on subsequent iterations goes DIRECTLY to
// DeleteRotationBranch using the snapshot.
func (r *reconciler) Reconcile(ctx context.Context, projectID string) (ReconcileResult, error) {
	if err := ctx.Err(); err != nil {
		return ReconcileResult{}, fmt.Errorf("rotation reconcile cancelled: %w", err)
	}

	var (
		retries             int
		branchDeletePending bool
		snapshotBranchRef   = git.PRRef{}
		snapshotCleared     int
	)
	for {
		if err := ctx.Err(); err != nil {
			return ReconcileResult{Retries: retries}, fmt.Errorf("rotation reconcile cancelled: %w", err)
		}

		// Branch-delete-pending fast path: skip probe + classify + clear,
		// retry the delete directly against the snapshotted branch ref.
		if branchDeletePending {
			if err := r.d.Reverser.DeleteRotationBranch(ctx, snapshotBranchRef); err != nil {
				retries++
				if retries >= reconcileMaxRetries {
					return ReconcileResult{
							Classification:  Phase1Only,
							PendingsCleared: snapshotCleared,
							Retries:         retries,
						}, fmt.Errorf(
							"%w: branch-delete CAS rejected after %d retries; "+
								"manual cleanup required via `git push origin --delete %s`: %v",
							ErrRotationReconcile, retries, formatBranchRef(snapshotBranchRef), err)
				}
				continue
			}
			return ReconcileResult{
				Classification:  Phase1Only,
				BranchDeleted:   true,
				PendingsCleared: snapshotCleared,
				Retries:         retries,
			}, nil
		}

		obs, err := r.d.Probe.FetchPartialState(ctx, projectID)
		if err != nil {
			return ReconcileResult{Retries: retries}, fmt.Errorf("rotation reconcile: %w", err)
		}
		cls := classifyObservation(obs)
		switch cls {
		case NoPartialState:
			return ReconcileResult{Classification: NoPartialState, Retries: retries}, nil

		case Phase2Midflight:
			return ReconcileResult{Classification: Phase2Midflight, Retries: retries},
				fmt.Errorf("%w: rotation branch merged to project main but CommitRotation did not land",
					ErrRotationReconcile)

		case InconsistentPartial:
			return ReconcileResult{Classification: InconsistentPartial, Retries: retries},
				fmt.Errorf("%w: rotation state shape does not match any protocol-supported partial state",
					ErrRotationReconcile)

		case Phase1Only:
			// Build the rotation-reversal audit event for this observation
			// against the injected clock. An empty branch ref surfaces
			// ErrRotationReversalNoBranchRef as a probe defect — terminal.
			ev, evErr := BuildRotationReversalAuditEvent(obs, projectID, r.d.Clock.Now())
			if evErr != nil {
				return ReconcileResult{Classification: Phase1Only, Retries: retries},
					fmt.Errorf("rotation reconcile: %w", evErr)
			}

			// Apply the PHASE_1_ONLY reversal: clear pendings (same-commit
			// audit append per the port contract). A CAS rejection triggers a
			// re-classification + retry up to the bounded budget.
			if err := r.d.Reverser.ClearPendings(ctx, projectID, obs.PendingsTaggedRotation, ev); err != nil {
				// Counter-authority reconcile errors are terminal — surface them
				// directly (the registry's counter authority demands operator
				// reconciliation, never an auto-retry).
				if errors.Is(err, countertypes.ErrCounterReconcile) {
					return ReconcileResult{Classification: Phase1Only, Retries: retries},
						fmt.Errorf("rotation reconcile: %w", err)
				}
				retries++
				if retries >= reconcileMaxRetries {
					return ReconcileResult{Classification: Phase1Only, Retries: retries},
						fmt.Errorf("%w: pending-clear CAS rejected after %d retries: %v",
							ErrRotationReconcile, retries, err)
				}
				continue
			}

			// Clear succeeded — snapshot the branch ref and the cleared count
			// so the subsequent delete-retry path does not re-derive them
			// from a fresh probe (which could race a concurrent rotation
			// start and mis-classify).
			branchDeletePending = true
			snapshotBranchRef = obs.RotationBranchRef
			snapshotCleared = len(obs.PendingsTaggedRotation)

			if err := r.d.Reverser.DeleteRotationBranch(ctx, snapshotBranchRef); err != nil {
				retries++
				if retries >= reconcileMaxRetries {
					return ReconcileResult{
							Classification:  Phase1Only,
							PendingsCleared: snapshotCleared,
							Retries:         retries,
						}, fmt.Errorf(
							"%w: branch-delete CAS rejected after %d retries; "+
								"manual cleanup required via `git push origin --delete %s`: %v",
							ErrRotationReconcile, retries, formatBranchRef(snapshotBranchRef), err)
				}
				continue
			}
			return ReconcileResult{
				Classification:  Phase1Only,
				BranchDeleted:   true,
				PendingsCleared: snapshotCleared,
				Retries:         retries,
			}, nil

		default:
			return ReconcileResult{Retries: retries},
				fmt.Errorf("%w: unrecognised classification %q",
					ErrRotationReconcile, cls)
		}
	}
}

// formatBranchRef returns a short, runbook-readable rendering of a PRRef for
// use in the branch-delete error message. The format is
// "<project>#<number>"; an empty PRRef renders as a sentinel "<unknown-ref>"
// so the operator notices the gap in the runbook hint.
func formatBranchRef(ref git.PRRef) string {
	if ref.Project == "" && ref.Number == 0 {
		return "<unknown-ref>"
	}
	return fmt.Sprintf("%s#%d", ref.Project, ref.Number)
}

// classifyObservation applies the reconcile classification logic to a single
// PartialStateObservation.
//
// The table rows in column order are:
//
//	(P_set, B_exists, B_merged, M_set==P_set)
//
//	(empty,     false,  false,   _)      → NO_PARTIAL_STATE
//	(non-empty, true,   false,   _)      → PHASE_1_ONLY
//	(non-empty, false,  true,    true)   → PHASE_2_MIDFLIGHT
//	(non-empty, false,  true,    false)  → INCONSISTENT_PARTIAL (split-brain artifact)
//	(non-empty, true,   true,    _)      → INCONSISTENT_PARTIAL (branch present AND merged)
//	(empty,     true,   _,       _)      → INCONSISTENT_PARTIAL (branch with no pendings)
//
// Anything outside the table falls into INCONSISTENT_PARTIAL.
func classifyObservation(obs PartialStateObservation) PartialStateClassification {
	pSetEmpty := len(obs.PendingsTaggedRotation) == 0
	mMatchesP := len(obs.MatchingPendings) == len(obs.PendingsTaggedRotation) && !pSetEmpty

	switch {
	case pSetEmpty && !obs.RotationBranchExists && !obs.RotationBranchMerged:
		return NoPartialState
	case !pSetEmpty && obs.RotationBranchExists && !obs.RotationBranchMerged:
		return Phase1Only
	case !pSetEmpty && !obs.RotationBranchExists && obs.RotationBranchMerged && mMatchesP:
		return Phase2Midflight
	case !pSetEmpty && !obs.RotationBranchExists && obs.RotationBranchMerged && !mMatchesP:
		return InconsistentPartial
	case !pSetEmpty && obs.RotationBranchExists && obs.RotationBranchMerged:
		return InconsistentPartial
	case pSetEmpty && obs.RotationBranchExists:
		return InconsistentPartial
	default:
		return InconsistentPartial
	}
}
