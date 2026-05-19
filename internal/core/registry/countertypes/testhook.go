//go:build testhook

// This file is compiled ONLY under the `testhook` build tag. It exposes a
// witnessed, test-scoped path to a Valid() CounterAuthority for the in-repo
// tests that must exercise the verify-time counter-decision table.
//
// It is NOT compiled into any production binary: production builds never set
// `-tags testhook`. The default (no-tag) build keeps the type-shape constraint
// fully operative, and the visibility_boundary_test.go assertions run WITHOUT
// this tag and continue to prove no exported Valid()-producer exists in the
// shipped surface.
//
// Defense in depth — why a stray `-tags testhook` on a shipped build still does
// not weaken the production guarantee: the only Valid()-producing entry here is
// NewForTest, and its signature requires a *testOnlyWitness. testOnlyWitness is
// unexported and is itself declared ONLY in this build-tagged file, so under
// the default (shipped) tag set the type does not exist at all. It has no
// exported constructor; the sole producer is ForTestWitness below, behind this
// same tag. A package outside countertypes (verify/mode/usecase/cli) cannot
// name *testOnlyWitness and cannot construct one, so it cannot call NewForTest
// even if NewForTest is accidentally compiled. The capability is strictly
// test-scoped by Go visibility, not by a build-step convention. CI additionally
// asserts mechanically that no shipped/release build carries this tag and that
// no exported Valid()-producer is reachable under the default tag set.
//
// Security note: this hook is test-only and does not weaken the production
// guarantee (the sole production producer remains the registry adapter via
// capmint). The arrangement is security-relevant and is not self-certified.
package countertypes

// testOnlyWitness is the unexported capability token the cross-package test
// hook requires. It mirrors the capmint pattern: the Valid()-producing entry
// point is gated behind a type that no outer package can name or construct, so
// the hook is not a production-grade module API even if it is accidentally
// compiled. It is declared in this build-tagged file so it has ZERO footprint
// under the default (shipped) tag set.
type testOnlyWitness struct {
	// _ signals "no usable fields" and keeps the zero value inert: trust still
	// flows only through newCounterAuthority, never through this token.
	_ [0]func()
}

// ForTestWitness mints the unexported capability token NewForTest requires.
//
// It returns a *testOnlyWitness — an unexported type. Callers outside this
// package cannot name that type in a declaration, so although ForTestWitness is
// exported its result is only usable by code that immediately passes it to
// NewForTest. This keeps the witnessed Valid()-producer test-scoped: there is
// no production-grade, independently usable API surface added by this file.
func ForTestWitness() *testOnlyWitness { //nolint:revive // returns unexported type by design: the witness is intentionally unnameable outside this package so the test hook is not production-usable API.
	return &testOnlyWitness{}
}

// NewForTest constructs a Valid() CounterAuthority for tests only. It is present
// only under the `testhook` build tag and is absent from production builds.
//
// It requires a non-nil *testOnlyWitness produced by ForTestWitness. The
// witness type is unexported, so verify/mode/usecase/cli cannot satisfy this
// signature even if this file is compiled — the function is uncallable from any
// package that cannot name testOnlyWitness. A nil witness panics: there is no
// witness-free path to a Valid() authority.
func NewForTest(w *testOnlyWitness, lastAccepted uint64, pending *PendingBump) CounterAuthority {
	if w == nil {
		panic("countertypes.NewForTest: nil test witness — " +
			"a Valid() CounterAuthority requires a witness from ForTestWitness")
	}
	return newCounterAuthority(lastAccepted, pending)
}
