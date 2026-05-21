package rotate_test

// V5.RECON.* rows — reconciler's PHASE_1_ONLY reversal under the V5
// branch-delete-pending discipline.
//
// Row IDs (audit-trail anchors permitted in _test.go ONLY):
//   - V5.RECON.transient-retry-success            (BO-V5-T8)
//   - V5.RECON.transient-exhausts-budget          (BO-V5-T8)
//   - V5.RECON.cold-empty-pset-stays-inconsistent (classifier purity)
//   - V5.RECON.budget-uniform-across-clear-and-delete (BO-V5-RECON-CRYPTO-1)
//
// The new fakes here parallel the V1 fakes in rotate_test.go but take the
// updated ClearPendings signature (audit.Event arg per BO-V5-PORT-CRYPTO-2/4
// + RULING-V5-PORT (a)) and drive the V5 branch-delete-pending retry loop.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// v5FakeReverser tracks Clear/Delete call counts and per-call error programs,
// and captures the audit.Event passed to each ClearPendings call so the V5
// rows can assert producer integration.
type v5FakeReverser struct {
	clearCalls      atomic.Int32
	deleteCalls     atomic.Int32
	clearErrs       []error
	deleteErrs      []error
	clearedEvents   []audit.Event
	clearedPendings [][]rotate.PendingObservation
}

func (f *v5FakeReverser) ClearPendings(_ context.Context, _ string, ps []rotate.PendingObservation, ev audit.Event) error {
	idx := f.clearCalls.Add(1) - 1
	f.clearedPendings = append(f.clearedPendings, ps)
	f.clearedEvents = append(f.clearedEvents, ev)
	if int(idx) < len(f.clearErrs) {
		return f.clearErrs[idx]
	}
	return nil
}

func (f *v5FakeReverser) DeleteRotationBranch(_ context.Context, _ git.PRRef) error {
	idx := f.deleteCalls.Add(1) - 1
	if int(idx) < len(f.deleteErrs) {
		return f.deleteErrs[idx]
	}
	return nil
}

// v5FakeProbe is identical in shape to the V1 fakeProbe but lives in this
// file so the V5 reconciler tests are self-contained and unaffected by any
// future refactor of the V1 fake.
type v5FakeProbe struct {
	mu  atomic.Int32
	seq []rotate.PartialStateObservation
	err error
}

func (f *v5FakeProbe) FetchPartialState(_ context.Context, _ string) (rotate.PartialStateObservation, error) {
	idx := f.mu.Add(1) - 1
	if f.err != nil {
		return rotate.PartialStateObservation{}, f.err
	}
	if int(idx) >= len(f.seq) {
		return f.seq[len(f.seq)-1], nil
	}
	return f.seq[idx], nil
}

// v5Phase1OnlyObs returns a Phase-1-only observation with one pending and a
// non-empty rotation branch ref.
func v5Phase1OnlyObs() rotate.PartialStateObservation {
	pr := git.PRRef{Project: "myorg/proj", Number: 99}
	return rotate.PartialStateObservation{
		PendingsTaggedRotation: []rotate.PendingObservation{
			{
				LogicalName:       "prod",
				PendingCounter:    1,
				TargetArtifactSHA: "sha-prod",
				TargetPR:          pr,
			},
		},
		MatchingPendings:     nil,
		RotationBranchExists: true,
		RotationBranchMerged: false,
		RotationBranchRef:    pr,
	}
}

// v5InconsistentColdObs returns the (empty P_set, branch exists) shape that
// must classify as InconsistentPartial. Used by the classifier-purity row.
func v5InconsistentColdObs() rotate.PartialStateObservation {
	return rotate.PartialStateObservation{
		PendingsTaggedRotation: nil,
		MatchingPendings:       nil,
		RotationBranchExists:   true,
		RotationBranchMerged:   false,
		RotationBranchRef:      git.PRRef{Project: "myorg/proj", Number: 77},
	}
}

// v5Clock is a deterministic injected clock for the reconciler tests.
type v5Clock struct{ now time.Time }

func (c v5Clock) Now() time.Time { return c.now }

func v5NewClock() v5Clock {
	return v5Clock{now: time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)}
}

// V5.RECON.transient-retry-success — clear succeeds first try; delete fails
// once then succeeds on the second try. Branch-delete-pending discipline:
// the loop must NOT re-probe / re-classify / re-call ClearPendings on the
// delete retry. Result: BranchDeleted=true, Retries=1.
func TestReconcile_V5_TransientRetrySuccess(t *testing.T) {
	probe := &v5FakeProbe{seq: []rotate.PartialStateObservation{
		v5Phase1OnlyObs(),
		// Any subsequent FetchPartialState call would indicate the reconciler
		// re-probed during the branch-delete-pending phase — wrong per
		// RULING-V5-RECON (a).
	}}
	rev := &v5FakeReverser{
		// clear: ok on first call.
		// delete: fail once then succeed.
		deleteErrs: []error{errors.New("CAS rejected: branch ref moved")},
	}
	rec, err := rotate.NewReconciler(rotate.ReconcilerDeps{
		Probe: probe, Reverser: rev, Clock: v5NewClock(),
	})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	res, err := rec.Reconcile(context.Background(), "myorg/proj")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.Classification != rotate.Phase1Only {
		t.Errorf("Classification = %s, want Phase1Only", res.Classification)
	}
	if !res.BranchDeleted {
		t.Error("BranchDeleted must be true after a successful delete retry")
	}
	if res.Retries != 1 {
		t.Errorf("Retries = %d, want 1", res.Retries)
	}
	// Clear was called exactly ONCE (not on the delete retry).
	if rev.clearCalls.Load() != 1 {
		t.Errorf("ClearPendings calls = %d, want 1 (no re-clear on delete retry)",
			rev.clearCalls.Load())
	}
	if rev.deleteCalls.Load() != 2 {
		t.Errorf("DeleteRotationBranch calls = %d, want 2 (first fails, second succeeds)",
			rev.deleteCalls.Load())
	}
	// FetchPartialState was called ONCE (no re-probe during branch-delete-pending).
	if probe.mu.Load() != 1 {
		t.Errorf("FetchPartialState calls = %d, want 1 (no re-probe in branch-delete-pending)",
			probe.mu.Load())
	}
	// Producer integration: ClearPendings received a non-zero audit.Event
	// with the expected outcome constant.
	if len(rev.clearedEvents) != 1 {
		t.Fatalf("captured audit events = %d, want 1", len(rev.clearedEvents))
	}
	if rev.clearedEvents[0].Outcome != rotate.RotationOutcomeReverted {
		t.Errorf("captured event Outcome = %q, want %q",
			rev.clearedEvents[0].Outcome, rotate.RotationOutcomeReverted)
	}
}

// V5.RECON.transient-exhausts-budget — clear succeeds; delete fails on every
// attempt. Bounded budget (3) exhausts; reconcile returns ErrRotationReconcile
// with a BRANCH-DELETE-specific message (not pending-clear).
// res.PendingsCleared > 0 because the clear DID land before delete-budget
// exhaustion.
func TestReconcile_V5_TransientExhaustsBudget(t *testing.T) {
	probe := &v5FakeProbe{seq: []rotate.PartialStateObservation{v5Phase1OnlyObs()}}
	rev := &v5FakeReverser{
		deleteErrs: []error{
			errors.New("CAS rejected 1"),
			errors.New("CAS rejected 2"),
			errors.New("CAS rejected 3"),
			errors.New("CAS rejected 4"),
		},
	}
	rec, _ := rotate.NewReconciler(rotate.ReconcilerDeps{
		Probe: probe, Reverser: rev, Clock: v5NewClock(),
	})
	res, err := rec.Reconcile(context.Background(), "myorg/proj")
	if !errors.Is(err, rotate.ErrRotationReconcile) {
		t.Fatalf("expected ErrRotationReconcile (budget exhausted), got %v", err)
	}
	if !containsSubstr(err.Error(), "branch-delete") {
		t.Errorf("error message must be branch-delete specific; got: %s", err.Error())
	}
	if res.PendingsCleared <= 0 {
		t.Errorf("PendingsCleared = %d, want > 0 (clear DID land before delete exhaustion)",
			res.PendingsCleared)
	}
	if rev.clearCalls.Load() != 1 {
		t.Errorf("ClearPendings calls = %d, want 1 (no re-clear during delete retry storm)",
			rev.clearCalls.Load())
	}
	if rev.deleteCalls.Load() < 1 {
		t.Errorf("DeleteRotationBranch calls = %d, want >= 1", rev.deleteCalls.Load())
	}
}

// V5.RECON.cold-empty-pset-stays-inconsistent — defends classifier purity.
// A cold-observed (empty P_set, branch exists) — i.e. WITHOUT a preceding
// in-loop ClearPendings — MUST classify as InconsistentPartial and yield a
// terminal ErrRotationReconcile. The V5 branch-delete-pending flag is an
// in-loop bookkeeping flag; it must NOT leak into the classifier.
func TestReconcile_V5_ColdEmptyPSetStaysInconsistent(t *testing.T) {
	probe := &v5FakeProbe{seq: []rotate.PartialStateObservation{v5InconsistentColdObs()}}
	rev := &v5FakeReverser{}
	rec, _ := rotate.NewReconciler(rotate.ReconcilerDeps{
		Probe: probe, Reverser: rev, Clock: v5NewClock(),
	})
	res, err := rec.Reconcile(context.Background(), "myorg/proj")
	if !errors.Is(err, rotate.ErrRotationReconcile) {
		t.Fatalf("expected terminal ErrRotationReconcile, got %v", err)
	}
	if res.Classification != rotate.InconsistentPartial {
		t.Errorf("Classification = %s, want InconsistentPartial", res.Classification)
	}
	if rev.clearCalls.Load() != 0 || rev.deleteCalls.Load() != 0 {
		t.Errorf("inconsistent-partial must NOT invoke reverser; got clear=%d delete=%d",
			rev.clearCalls.Load(), rev.deleteCalls.Load())
	}
}

// V5.RECON.budget-uniform-across-clear-and-delete — BO-V5-RECON-CRYPTO-1:
// the retry budget is uniformly applied across ClearPendings and
// DeleteRotationBranch failures. Program: clear fails 1x (retry=1) → clear
// succeeds (no retry bump) → delete fails 2x (retry=2 then retry=3) → budget
// exhausts on retries=3. Terminal ErrRotationReconcile with branch-delete
// message; res.Retries == 3; ClearPendings called exactly 2x;
// DeleteRotationBranch called exactly 2x; res.PendingsCleared > 0.
func TestReconcile_V5_BudgetUniformAcrossClearAndDelete(t *testing.T) {
	// The probe must be ready for the re-classification triggered by the
	// clear-side retry — supply Phase-1-only repeatedly.
	probe := &v5FakeProbe{seq: []rotate.PartialStateObservation{
		v5Phase1OnlyObs(),
		v5Phase1OnlyObs(),
	}}
	rev := &v5FakeReverser{
		clearErrs: []error{errors.New("CAS rejected on clear (#1)")},
		deleteErrs: []error{
			errors.New("CAS rejected on delete (#1)"),
			errors.New("CAS rejected on delete (#2)"),
		},
	}
	rec, _ := rotate.NewReconciler(rotate.ReconcilerDeps{
		Probe: probe, Reverser: rev, Clock: v5NewClock(),
	})
	res, err := rec.Reconcile(context.Background(), "myorg/proj")
	if !errors.Is(err, rotate.ErrRotationReconcile) {
		t.Fatalf("expected ErrRotationReconcile, got %v", err)
	}
	if !containsSubstr(err.Error(), "branch-delete") {
		t.Errorf("error message must be branch-delete specific (budget exhausted on delete), got: %s",
			err.Error())
	}
	if containsSubstr(err.Error(), "pending-clear") {
		t.Errorf("error message must NOT be pending-clear (budget exhausted on delete, not clear), got: %s",
			err.Error())
	}
	if res.Retries != 3 {
		t.Errorf("Retries = %d, want 3 (1 clear + 2 delete; uniform budget)", res.Retries)
	}
	if rev.clearCalls.Load() != 2 {
		t.Errorf("ClearPendings calls = %d, want 2 (first fails, second succeeds; no further re-clear)",
			rev.clearCalls.Load())
	}
	if rev.deleteCalls.Load() != 2 {
		t.Errorf("DeleteRotationBranch calls = %d, want 2 (both fail, budget exhausts)",
			rev.deleteCalls.Load())
	}
	if res.PendingsCleared <= 0 {
		t.Errorf("PendingsCleared = %d, want > 0 (clear DID succeed before delete exhaustion)",
			res.PendingsCleared)
	}
}
