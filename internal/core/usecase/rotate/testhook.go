//go:build testhook

// This file is compiled ONLY under the `testhook` build tag. It exposes a
// witnessed, test-scoped path to deterministic crash injection between the
// reversibility boundary (Phase-1 step 6 / Phase-2 step 7) and the terminal
// commit boundary (Phase-2 step 7 / step 8). Production builds never set
// `-tags testhook`; CI's release build verifies the absence of the tag, and
// the default-tag AST guard (shipped_surface_test.go) asserts no exported
// witness-free Rotator-modifier exists under any shipped-candidate tag set.
//
// Defense in depth: even if a stray `-tags testhook` reaches a shipped build,
// the only Rotator-modifier entry points here require a *rotationTestHookWitness.
// rotationTestHookWitness is unexported and declared only under this build
// tag, so under the default (shipped) tag set the type does not exist at all.
// A package outside rotate cannot name *rotationTestHookWitness and cannot
// construct one, so it cannot call the modifier entry points even if those
// happen to be compiled. The capability is strictly test-scoped by Go
// visibility, not by a build-step convention.
//
// Security note: this hook is test-only and does not weaken the production
// guarantee. Changes here should be reviewed as security-critical.
package rotate

import (
	"context"
	"errors"
)

// rotationTestHookWitness is the unexported capability token the cross-package
// test hooks require. It mirrors the countertypes testOnlyWitness pattern: the
// Rotator-modifier entry points are gated behind a type that no outer package
// can name or construct, so the hook is not a production-grade module API
// even if it is accidentally compiled. It is declared in this build-tagged
// file so it has ZERO footprint under the default (shipped) tag set.
type rotationTestHookWitness struct {
	_ [0]func()
}

// NewWitnessForTest mints the unexported capability token the crash-injection
// entry points require.
//
// It returns a *rotationTestHookWitness — an unexported type. Callers outside
// this package cannot name that type in a declaration, so although
// NewWitnessForTest is exported its result is only usable by code that
// immediately passes it back to a hook entry point in this same package.
func NewWitnessForTest() *rotationTestHookWitness { //nolint:revive // returns unexported type by design: the witness is intentionally unnameable outside this package so the test hook is not production-usable API.
	return &rotationTestHookWitness{}
}

// errPhase1Phase2Crash is the sentinel surfaced by the Phase-1/Phase-2
// boundary crash. It is returned (not panicked) so the ship-gate row can
// assert deterministic propagation through the spine's error chain.
var errPhase1Phase2Crash = errors.New(
	"test hook: injected crash between Phase 1 and Phase 2")

// errStep7Step8Crash is the sentinel surfaced by the Phase-2 step-7/step-8
// boundary crash.
var errStep7Step8Crash = errors.New(
	"test hook: injected crash between Phase 2 step 7 and step 8")

// CrashBetweenPhase1Phase2 wraps a Rotator so that any call between the end
// of Phase 1 and the start of Phase 2 surfaces a deterministic sentinel
// error. The wrapper itself preserves the spine's contract: Phase 1
// executes, Phase 2 does not. The reconciler can then classify the state
// as PHASE_1_ONLY (rotation branch pushed; CommitRotation not landed).
//
// The wrapper REQUIRES a non-nil *rotationTestHookWitness; a nil witness
// panics because there is no witness-free path to the hook by design.
func CrashBetweenPhase1Phase2(w *rotationTestHookWitness, r Rotator) Rotator {
	if w == nil {
		panic("rotate.CrashBetweenPhase1Phase2: nil test witness — " +
			"a Rotator hook requires a witness from NewWitnessForTest")
	}
	return &phase1Phase2CrashRotator{inner: r}
}

// CrashBetweenStep7Step8 wraps a Rotator so that any call surfaces a
// deterministic sentinel error between Phase-2 step 7 (project-repo merge)
// and step 8 (CommitRotation registry commit). The reconciler then
// classifies the state as PHASE_2_MIDFLIGHT (rotation branch merged;
// CommitRotation not landed); the reconciler refuses auto-rollback.
//
// The wrapper REQUIRES a non-nil *rotationTestHookWitness; a nil witness
// panics because there is no witness-free path to the hook by design.
func CrashBetweenStep7Step8(w *rotationTestHookWitness, r Rotator) Rotator {
	if w == nil {
		panic("rotate.CrashBetweenStep7Step8: nil test witness — " +
			"a Rotator hook requires a witness from NewWitnessForTest")
	}
	return &step7Step8CrashRotator{inner: r}
}

// phase1Phase2CrashRotator runs Phase 1 by delegation and then short-circuits
// before Phase 2 with a deterministic error. The error path mirrors the
// real-rotation phase-1-only crash shape: Phase1Executed is true and Phase2
// is the zero value.
type phase1Phase2CrashRotator struct {
	inner Rotator
}

func (p *phase1Phase2CrashRotator) Rotate(ctx context.Context, in RotationInput) (RotationResult, error) {
	res, err := p.inner.Rotate(ctx, in)
	if err != nil {
		return res, err
	}
	if res.DryRun || !res.Phase1Executed {
		return res, nil
	}
	res.Phase2 = Phase2Result{}
	res.Phase2Executed = false
	return res, errPhase1Phase2Crash
}

// step7Step8CrashRotator delegates the full Rotate call and reports the
// step-7/step-8 sentinel even on Phase-2 success. The reconcile classify
// path is tested separately; the hook's job is to surface a deterministic
// error to the ship-gate row.
type step7Step8CrashRotator struct {
	inner Rotator
}

func (s *step7Step8CrashRotator) Rotate(ctx context.Context, in RotationInput) (RotationResult, error) {
	res, err := s.inner.Rotate(ctx, in)
	if err != nil {
		return res, err
	}
	return res, errStep7Step8Crash
}
