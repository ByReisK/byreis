// Package capmint is the sole capability-mint for CounterAuthority values.
//
// # Visibility constraint
//
// This package lives under internal/adapter/registry/internal/, so Go's
// internal/ package rule makes it importable only by code whose import path is
// rooted at github.com/ByReisK/byreis/internal/adapter/registry. Any attempt to
// import it from internal/core/crypto/verify, internal/core/mode,
// internal/core/usecase, internal/cli, cmd/, or any other package outside that
// subtree is a compile error — not a runtime check, not a policy doc. The
// exported Mint function below is the only module-reachable path to a
// Valid()==true CounterAuthority, and it is reachable only from the registry
// adapter subtree. This is what makes counter authority unforgeable by the
// contributor code paths.
//
// # Wiring
//
// Until the real implementation lands, Mint panics. The registry adapter calls
// Mint; once the adapter is fully wired, Mint must call
// countertypes.newCounterAuthority.
//
// Open design question: countertypes.newCounterAuthority is unexported, so
// capmint cannot call it directly today. Bridging it requires one of:
//
//	a. countertypes exports a restricted-by-name constructor (e.g. New or Mint)
//	   and the visibility test adds a source-scan assertion that the constructor
//	   is not called from verify/mode/usecase (defense-in-depth alongside the
//	   capmint internal/ rule).
//	b. countertypes exposes newCounterAuthority via a package-level var set by an
//	   explicit non-init() registration call driven by the adapter's wiring
//	   code — a one-shot set-once guarded by sync.Once, never a global mutable
//	   open to any caller (this option needs careful review).
//	c. Another reviewed mechanism.
//
// Until then, Mint panics and the type-shape constraint is operative.
//
// Security note: this package is security-relevant. The visibility boundary and
// any chosen bridging mechanism require crypto and threat-model sign-off before
// release; it is not self-certified.
package capmint

import "github.com/ByReisK/byreis/internal/core/registry/countertypes"

// Mint constructs a Valid()==true CounterAuthority for the registry adapter.
//
// This function is the sole module-reachable constructor for CounterAuthority
// values with Valid()==true. It is importable only from packages rooted at
// internal/adapter/registry (Go internal/ rule — see package-level doc).
//
// The panic body is replaced with the real construction once the bridge to
// countertypes.newCounterAuthority is in place (see the open design question in
// the package doc). All registry adapter code that needs a CounterAuthority
// must call this function, never construct one directly.
func Mint(lastAccepted uint64, pending *countertypes.PendingBump) countertypes.CounterAuthority {
	// Real body, once the bridge is in place:
	//   return countertypes.newCounterAuthority(lastAccepted, pending)
	// This path is currently unreachable in practice (the registry adapter stub
	// also panics before calling Mint), so panicking here is safe for the gate.
	panic("not implemented: wire to countertypes.newCounterAuthority via the approved bridge")
}
