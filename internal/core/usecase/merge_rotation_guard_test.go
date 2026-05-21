package usecase

// T-V6-FL1 — isolated unit test for the rotation-guard consultation contract.
//
// Row IDs (audit-trail anchors permitted in _test.go ONLY):
//   - V6.FL1.merge.guard-nil-allows
//   - V6.FL1.merge.guard-in-flight-refuses
//   - V6.FL1.merge.guard-not-in-flight-proceeds
//   - V6.FL1.merge.guard-error-fail-closed
//   - V6.FL1.merge.guard-context-propagates
//   - V6.FL1.merge.synthetic-mutation-always-true
//
// The merge.go step-6 rotation-in-flight check is factored to the package-
// private helper checkRotationGuardBeforeCommitBump; this test exercises it
// directly. The merge_test.go integration row in V5b's shipgate already
// exercises the call end-to-end; this unit-level row pins the contract so a
// future regression that breaks the consultation pattern is caught without
// the cost of standing up the full merge pipeline.
//
// Discharges T-V6-FL1 / FL-V6-THREAT-1 (merge.go rotation-guard unit-test
// coverage gap surfaced at V5b POST-impl).

import (
	"context"
	"errors"
	"testing"

	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// stubGuard is a minimal RotationGuard implementation tests configure to
// return the (inFlight, err) pair the row asserts against. The recordedCalls
// counter doubles as proof-of-consultation: a test that expects the predicate
// to fire BEFORE any CommitBump observes a non-zero call count.
type stubGuard struct {
	inFlight     bool
	err          error
	calls        int
	lastProject  string
	lastFileName string
}

func (s *stubGuard) RotationInFlight(_ context.Context, projectID, fileName string) (bool, error) {
	s.calls++
	s.lastProject = projectID
	s.lastFileName = fileName
	return s.inFlight, s.err
}

// TestCheckRotationGuard_NilGuardAllows — V6.FL1.merge.guard-nil-allows.
// A nil RotationGuard (legacy / pre-rotation deployments without the rotation
// adapter wired) is treated as inFlight=false. The check returns nil and the
// merge step-6 CommitBump proceeds.
func TestCheckRotationGuard_NilGuardAllows(t *testing.T) {
	t.Parallel()

	if err := checkRotationGuardBeforeCommitBump(context.Background(), nil, "proj", "file.enc.yaml"); err != nil {
		t.Errorf("nil guard must allow CommitBump; got err = %v", err)
	}
}

// TestCheckRotationGuard_InFlightRefuses — V6.FL1.merge.guard-in-flight-refuses.
// inFlight=true wraps the sentinel and refuses; project + file are named in
// the surfaced error so the operator can identify which pair is blocked.
func TestCheckRotationGuard_InFlightRefuses(t *testing.T) {
	t.Parallel()

	g := &stubGuard{inFlight: true}
	err := checkRotationGuardBeforeCommitBump(context.Background(), g, "proj-x", "secrets/prod.enc.yaml")
	if !errors.Is(err, rotate.ErrCommitBumpRejectedRotationInFlight) {
		t.Fatalf("inFlight=true must wrap ErrCommitBumpRejectedRotationInFlight; got %v", err)
	}
	if g.calls != 1 {
		t.Errorf("guard predicate consultation count = %d, want 1", g.calls)
	}
	if g.lastProject != "proj-x" || g.lastFileName != "secrets/prod.enc.yaml" {
		t.Errorf("guard called with (%q, %q); want (proj-x, secrets/prod.enc.yaml)",
			g.lastProject, g.lastFileName)
	}
}

// TestCheckRotationGuard_NotInFlightProceeds — V6.FL1.merge.guard-not-in-flight-proceeds.
// inFlight=false + nil error returns nil; the merge step-6 CommitBump proceeds.
func TestCheckRotationGuard_NotInFlightProceeds(t *testing.T) {
	t.Parallel()

	g := &stubGuard{inFlight: false}
	if err := checkRotationGuardBeforeCommitBump(context.Background(), g, "proj", "f"); err != nil {
		t.Errorf("inFlight=false must allow CommitBump; got err = %v", err)
	}
	if g.calls != 1 {
		t.Errorf("guard predicate consultation count = %d, want 1", g.calls)
	}
}

// TestCheckRotationGuard_ErrorFailsClosed — V6.FL1.merge.guard-error-fail-closed.
// A probe error is treated as "rotation possibly in flight" and refuses. The
// surfaced error wraps ErrCommitBumpRejectedRotationInFlight (fail-closed on
// uncertainty) — uncertainty NEVER falls through to a CommitBump that could
// race the rotation's N-file atomic commit.
func TestCheckRotationGuard_ErrorFailsClosed(t *testing.T) {
	t.Parallel()

	probeErr := errors.New("network timeout")
	g := &stubGuard{err: probeErr}
	err := checkRotationGuardBeforeCommitBump(context.Background(), g, "proj", "f")
	if !errors.Is(err, rotate.ErrCommitBumpRejectedRotationInFlight) {
		t.Fatalf("probe error must wrap ErrCommitBumpRejectedRotationInFlight; got %v", err)
	}
}

// TestCheckRotationGuard_ContextPropagates — V6.FL1.merge.guard-context-propagates.
// The supplied context is forwarded to the guard so cancellation in the
// caller surfaces in the predicate's RPC. A cancelled context is still
// permissible to pass through — the guard implementation owns the response
// shape; what matters here is that the context value reaches the call.
func TestCheckRotationGuard_ContextPropagates(t *testing.T) {
	t.Parallel()

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "marker")
	calledCtx := func() context.Context { return ctx }()

	g := &contextCapturingGuard{}
	if err := checkRotationGuardBeforeCommitBump(calledCtx, g, "p", "f"); err != nil {
		t.Errorf("happy path: unexpected error %v", err)
	}
	if v, _ := g.capturedCtx.Value(ctxKey{}).(string); v != "marker" {
		t.Errorf("context value did not propagate to guard; got %q", v)
	}
}

// TestCheckRotationGuard_SyntheticMutation — V6.FL1.merge.synthetic-mutation-always-true.
// A guard wired to always return inFlight=true unconditionally MUST refuse
// the bump. This row is the live-mutation check the threat-modeler ack
// requires: it proves the helper observes the guard's verdict on every call
// rather than caching a prior result or short-circuiting on identity-equal
// inputs. A future refactor that introduced memoisation without invalidation
// would be caught here.
func TestCheckRotationGuard_SyntheticMutation(t *testing.T) {
	t.Parallel()

	g := &alwaysInFlightGuard{}
	// First call with one (project, file) pair: refuse.
	if err := checkRotationGuardBeforeCommitBump(context.Background(), g, "p1", "f1"); !errors.Is(err, rotate.ErrCommitBumpRejectedRotationInFlight) {
		t.Errorf("first call: expected sentinel, got %v", err)
	}
	// Second call with a different pair: still refuse (the guard's verdict
	// is the authority; the helper must not cache).
	if err := checkRotationGuardBeforeCommitBump(context.Background(), g, "p2", "f2"); !errors.Is(err, rotate.ErrCommitBumpRejectedRotationInFlight) {
		t.Errorf("second call: expected sentinel, got %v", err)
	}
	if g.calls != 2 {
		t.Errorf("guard called %d times, want 2 (no memoisation)", g.calls)
	}
}

// contextCapturingGuard records the ctx value passed by the helper so the
// context-propagation row can assert the supplied context reaches the guard.
type contextCapturingGuard struct {
	capturedCtx context.Context
}

func (g *contextCapturingGuard) RotationInFlight(ctx context.Context, _, _ string) (bool, error) {
	g.capturedCtx = ctx
	return false, nil
}

// alwaysInFlightGuard returns inFlight=true on every invocation and counts
// calls. The synthetic-mutation row uses this to detect any memoisation /
// caching regression in the helper.
type alwaysInFlightGuard struct {
	calls int
}

func (g *alwaysInFlightGuard) RotationInFlight(_ context.Context, _, _ string) (bool, error) {
	g.calls++
	return true, nil
}
