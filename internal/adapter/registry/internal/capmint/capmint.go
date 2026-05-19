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
// Mint delegates to countertypes.MintFromAdapter, passing an untyped nil as the
// witness argument. The witness type (*countertypes.adapterWitness) is
// unexported in countertypes and therefore cannot be named from this package.
// Passing the untyped nil is correct and Go-safe: MintFromAdapter accepts a nil
// witness in production and does not panic on it. The load-bearing guarantee is
// the Go internal/ import rule on this package plus the AST surface classifier
// in countertypes; the witness parameter is defense-in-depth for
// accident-prevention and classifier purposes only.
//
// Security note: this package is security-relevant. The visibility boundary and
// the bridge mechanism require crypto and threat-model sign-off before release;
// it is not self-certified.
package capmint

import "github.com/ByReisK/byreis/internal/core/registry/countertypes"

// Mint constructs a Valid()==true CounterAuthority for the registry adapter.
//
// It is the sole module-reachable constructor for Valid()==true CounterAuthority
// values and is importable only from packages rooted at internal/adapter/registry
// (Go internal/ rule — see package-level doc). All registry adapter code that
// needs a CounterAuthority must call this function. The adapter must ensure all
// preconditions (SourceVerified fetch provenance, anti-rollback cache check,
// fail-closed ancestry check) are satisfied before calling Mint.
func Mint(lastAccepted uint64, pending *countertypes.PendingBump) countertypes.CounterAuthority {
	// capmint cannot name *countertypes.adapterWitness (unexported type), so the
	// only witness value it can pass is the untyped nil — Go converts this to
	// (*countertypes.adapterWitness)(nil). MintFromAdapter accepts a nil witness
	// in production (no panic here; the nil-panic guard is test-only).
	return countertypes.MintFromAdapter(nil, lastAccepted, pending)
}
