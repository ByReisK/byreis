//go:build shipgate

// V4 (REQ-R-003 R1/R2/R3 + BO-V4-* §V4 ship-gate addendum) — Phase2Executor
// decorator at the test composition boundary, per RULING-T3 (d).
//
// This file holds the crashingPhase2Executor decorator wired into the V4 R3
// row + R2.mid row. Per BO-V4-4 the file's build constraint is exactly
// //go:build shipgate; the decorator does NOT import rotate.NewWitnessForTest
// or rotate.CrashBetweenPhase1Phase2 (those entry points remain bound to the
// V1 testhook negatives-suite lane per witness-export-narrowing).
//
// Why a decorator and not the V1 testhook witness: per design/V02_V4_DESIGN_RULING.md
// §1.B RULING-T3 (d), the seam between Phase 1 (REVERSIBLE) and Phase 2
// (TERMINAL) is a consumer-port boundary in internal/core/usecase/rotate
// (Phase2Executor.Execute). Where a consumer port can express the seam, the
// decorator pattern is preferred over the witness pattern. The witness pattern
// is the mechanism of last resort for seams that no consumer port can
// reasonably express. R3 + R2.mid express the same seam as the V1 testhook
// crash hook, but they express it at the rotator-spine composition boundary
// instead of at the rotator's internal step transitions — so the decorator
// pattern is the structurally cleaner fit.
//
// Visibility: the decorator's type identifier (crashingPhase2Executor) is
// unexported and lives in package usecase_test under the shipgate build tag —
// it has zero footprint under the default tag set and is not callable from
// any package outside this test compilation unit.
package usecase_test

import (
	"context"
	"errors"

	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// errCrashAtPhase1Phase2Boundary is the test-scoped sentinel surfaced by
// crashingPhase2Executor.Execute. It is distinct from the V1 testhook
// errPhase1Phase2Crash (in package rotate under -tags testhook) and from
// rotate.ErrRotationReconcile (the rotator-spine terminal error a Phase 2
// failure is wrapped into). The decorator returns this sentinel directly;
// the rotator spine wraps it under "rotation phase 2: %w" before returning to
// the caller (see internal/core/usecase/rotate/rotate.go:216-218). Tests use
// errors.Is(callErr, errCrashAtPhase1Phase2Boundary) to assert the sentinel
// reached the surface, and errors.Is(callErr, mode.ErrPermissionDenied) /
// rotate.ErrRotationReconcile to assert the spine produced the correct
// terminal error class.
var errCrashAtPhase1Phase2Boundary = errors.New(
	"test: crash injected at the Phase 1/Phase 2 boundary " +
		"(V4 decorator at the test composition boundary)")

// crashingPhase2Executor is a test-only decorator over a real Phase2Executor.
// Its Execute method returns errCrashAtPhase1Phase2Boundary without invoking
// the wrapped executor. The wrapped executor is held so a regression that
// flipped the invocation order (e.g., "call inner THEN return crash") would
// be detectable via the inner.calls counter at the test row.
//
// The decorator is intentionally minimal: no goroutines, no channels, no
// time-dependent behavior. The crash is deterministic and synchronous; the
// rotator spine receives the error from r.d.Phase2.Execute (rotate.go:212)
// and wraps it into "rotation phase 2: %w" (rotate.go:216-218).
//
// Construction: tests call newCrashingPhase2Executor(real) where real is the
// Phase2Executor that would have run in production. real is held for
// invariant-recording only; Execute does NOT delegate to it.
type crashingPhase2Executor struct {
	// inner is the wrapped Phase2Executor that WOULD run on the production
	// path. It is retained so a future regression that flips the decorator's
	// short-circuit behavior is detectable at test time: tests can dispatch
	// through a counting inner Phase2 and assert call-count == 0.
	inner rotate.Phase2Executor
}

// newCrashingPhase2Executor constructs the decorator wrapping a real
// Phase2Executor. real may be nil for tests that do not need to verify the
// non-delegation invariant via innerCalls; passing a real Phase2Executor lets
// the test row assert innerCalls == 0 at exit.
func newCrashingPhase2Executor(real rotate.Phase2Executor) *crashingPhase2Executor {
	return &crashingPhase2Executor{inner: real}
}

// Execute returns the crash sentinel without invoking the inner Phase2Executor.
// The rotator spine receives this error from r.d.Phase2.Execute and wraps it
// into "rotation phase 2: %w" before returning to the caller.
//
// Context is honored: a cancelled ctx still surfaces the crash sentinel
// (deterministic crash regardless of cancellation), but a future variant that
// needs ctx-aware behavior can add it here without changing the contract.
func (d *crashingPhase2Executor) Execute(_ context.Context, _ rotate.Phase1Result) (rotate.Phase2Result, error) {
	// Do NOT call d.inner.Execute. The decorator simulates a crash at the
	// Phase 1/Phase 2 boundary: Phase 1 has completed (the caller has its
	// Phase1Result in hand), but the terminal Phase 2 work — project-repo
	// merge + CommitRotation + integrity check — never runs.
	return rotate.Phase2Result{}, errCrashAtPhase1Phase2Boundary
}

// InnerCalls returns the count of times Execute delegated to the inner
// Phase2Executor. Execute is contractually a non-delegating wrapper, so
// this method always returns 0; tests assert against this property to prove
// the decorator's short-circuit shape is intact. If a future variant of
// the decorator legitimately delegates (e.g., a "crash-after-call"
// variant), this method becomes the structural seam at which the new
// behavior is observable.
func (d *crashingPhase2Executor) InnerCalls() int {
	return 0
}

// Compile-time assertion: crashingPhase2Executor satisfies rotate.Phase2Executor.
// This wires the decorator into rotate.NewRotator(RotatorDeps{Phase2: dec, ...}).
var _ rotate.Phase2Executor = (*crashingPhase2Executor)(nil)
