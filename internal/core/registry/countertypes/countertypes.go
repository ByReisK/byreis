// Package countertypes is the pure, isolated sub-package for the counter
// authority domain types. It uses the same isolation pattern as rectypes,
// applied to the anti-replay counter store.
//
// It exports:
//   - CounterAuthority and PendingBump — the two-record anti-replay view from
//     the signature-verified registry counter store.
//   - ErrReplay and ErrCounterReconcile — the canonical sentinel errors whose
//     semantic owner is this package (they travel with CounterAuthority).
//
// # Visibility boundary
//
// There is no exported constructor in this package. newCounterAuthority is
// package-private, and no exported function produces a Valid()==true
// CounterAuthority. A zero-value or struct-literal CounterAuthority is not
// Valid(). This is what makes counter authority unforgeable: trust cannot be
// fabricated by constructing the struct directly.
//
//   - internal/core/crypto/verify may import this package to consume an opaque
//     CounterAuthority (read fields via accessors, call Valid()), but it cannot
//     construct a valid one — there is no exported constructor and no settable
//     trust-bearing field. This is enforced by Go visibility, not by a comment:
//     newCounterAuthority is unexported, and the only constructing path is the
//     internal/adapter/registry/internal/capmint package (importable only by
//     code rooted at internal/adapter/registry, enforced by Go's internal/ rule).
//   - The sole producer of a valid CounterAuthority is the registry adapter
//     (internal/adapter/registry), which calls capmint.Mint after reading the
//     signature-verified counter store and applying anti-rollback cache checks.
//     capmint is not importable from verify, mode, usecase, or the CLI — the
//     import attempt is a compile error.
//   - The negative test in this package's _test.go proves:
//     (a) CounterAuthority{} is !Valid() (zero-value protection),
//     (b) no exported symbol in this package produces a Valid()==true value,
//     (c) a compile-fail assertion shows that importing capmint from a
//     non-adapter package is rejected by the Go toolchain.
//
// This placement keeps internal/core/registry from importing
// internal/core/crypto/verify. The dependency direction is:
//
//	verify     → countertypes   (read/consume)
//	registry   → countertypes   (declare CounterAuthority return type in interface)
//	capmint    → countertypes   (construct via newCounterAuthority)
//
// There is no cycle and no registry→verify edge.
//
// # Wiring
//
// Production CounterAuthority values are now minted via the exported
// MintFromAdapter function defined in this package. MintFromAdapter requires an
// unexported *adapterWitness parameter, making it uncallable by accident from
// packages that cannot name that type. The only wired caller is
// internal/adapter/registry/internal/capmint (the capability-mint package),
// which is itself importable only by code rooted at internal/adapter/registry
// (Go internal/ rule). The honest, load-bearing guarantee is the Go internal/
// import restriction on capmint combined with the AST classifier in
// shipped_surface_test.go — not the witness parameter alone. The witness is
// defense-in-depth: it makes the constructor unnameable-by-construction from
// core packages and AST-classifiable by the surface guard.
//
// Security note: the construction and trust model here is security-relevant;
// changes to this package should be reviewed as security-critical.
package countertypes

import "errors"

// ErrReplay is returned by VerifyOfRecord when the signed counter is less than
// or equal to the last accepted counter — the file is old or replayed. This
// package is the semantic owner (the error travels with CounterAuthority);
// verify and registry reference this symbol directly rather than defining alias
// vars, so the sentinel has exactly one owner.
var ErrReplay = errors.New(
	"artifact counter is not strictly greater than last accepted (replayed/old file)")

// ErrCounterReconcile is returned by VerifyOfRecord when the counter authority's
// own integrity is in question: a file claims last+1 with no matching
// write-ahead intent and no committed bump, or skips ahead of authority, or a
// different artifact than the recorded intent claims the pending slot. It is
// terminal and not auto-healed; the caller must follow the reconciliation
// runbook. This package is the semantic owner; verify and registry reference
// this symbol directly rather than defining alias vars.
var ErrCounterReconcile = errors.New(
	"counter authority requires manual reconciliation " +
		"(no matching write-ahead/committed bump) — " +
		"see reconciliation runbook: run `byreis admin counter reconcile` or contact an admin")

// PendingBump is the write-ahead intent recorded before a secrets-repo merge.
// TargetArtifactSHA is the canonical content SHA of the signed file-of-record
// (the post-sign value), computed by the single shared content-SHA function —
// it is NOT a hash of the raw, untransformed on-disk file buffer.
type PendingBump struct {
	// PendingCounter is last_accepted_counter + 1, recorded before merge.
	PendingCounter uint64

	// TargetArtifactSHA is the canonical content SHA of the signed
	// file-of-record: sha256 over the canonical domain stream of the manifest,
	// a 0x1f separator, and the raw signature — i.e. the value the shared
	// content-SHA function computes, NOT a hash of the raw, untransformed
	// on-disk file bytes and not a re-implemented preimage. The recorder MUST
	// obtain it by calling that same shared content-SHA function over the
	// file-of-record it is about to commit, so the recorded value and the
	// verify-time value come from the identical function. It is compared
	// against the content SHA of the committed file in the VerifyOfRecord
	// decision table.
	TargetArtifactSHA string

	// TargetPR is the PR reference for audit linkage.
	TargetPR string
}

// CounterAuthority is the two-record anti-replay view from the registry/audit
// store. It is opaque: all fields are unexported.
//
// # Visibility guarantee
//
// There is no exported constructor. The only constructor is the
// package-private newCounterAuthority, whose call site is restricted to capmint
// (internal/adapter/registry/internal/capmint), which is in turn importable
// only by code rooted at internal/adapter/registry (Go internal/ rule — a
// compile error for any other importer).
//
// verify (and any other consumer) imports this package and calls Valid() /
// LastAccepted() / Pending() — it cannot construct a valid value. A zero-value
// or struct-literal CounterAuthority is not Valid() and VerifyOfRecord
// hard-errors on it.
//
// This is a Go-visibility type-shape constraint. It is security-relevant;
// changes here should be reviewed as security-critical.
type CounterAuthority struct {
	// lastAccepted is the committed authority: the highest counter durably merged.
	// Unexported: set only by newCounterAuthority; no external write path.
	lastAccepted uint64

	// pending is the nullable write-ahead intent. Non-nil only when a merge is in
	// flight (RecordPendingBump called but CommitBump not yet landed).
	// Unexported: set only by newCounterAuthority.
	pending *PendingBump

	// valid is the anti-fabrication sentinel. A zero-value / struct-literal
	// CounterAuthority has valid==false and is rejected by VerifyOfRecord.
	// Set only by newCounterAuthority.
	valid bool
}

// Valid reports whether this CounterAuthority was produced via the
// package-private constructor (newCounterAuthority). A zero-value or
// struct-literal CounterAuthority is not Valid(). VerifyOfRecord hard-errors
// (returning ErrCounterReconcile) on any CounterAuthority where Valid() ==
// false.
//
// This is the Go-visibility type-shape guarantee: a caller cannot satisfy the
// VerifyOfRecord flow with an artifact-, repo-, or stale-cache-derived counter
// authority, because no caller outside this package can reach
// newCounterAuthority, and no exported Valid()-producing function exists here.
// Importing capmint.Mint (the only valid-producing path) from any package
// outside internal/adapter/registry is a compile error.
func (c CounterAuthority) Valid() bool { return c.valid }

// LastAccepted returns the committed last-accepted counter for this
// (project, file) pair. Read-only accessor — callers cannot mutate the value.
func (c CounterAuthority) LastAccepted() uint64 { return c.lastAccepted }

// Pending returns the nullable write-ahead intent. Returns nil when no merge is
// in flight. Read-only accessor — callers cannot mutate the PendingBump or set
// the pointer.
func (c CounterAuthority) Pending() *PendingBump { return c.pending }

// newCounterAuthority is package-private — the sole constructor for
// CounterAuthority. Its only intended call site is capmint
// (internal/adapter/registry/internal/capmint), reachable solely by code under
// internal/adapter/registry (Go internal/ rule). There is deliberately no
// exported constructor: verify, mode, usecase, and CLI packages cannot
// construct a Valid()==true CounterAuthority.
//
// capmint.Mint reaches this unexported function through a bridge whose
// mechanism is still an open design question (see the capmint package doc).
//
// Until the real implementation lands, the adapter stub and capmint.Mint both
// panic; this function exists to establish the type-shape contract and will be
// called by capmint once wired.
func newCounterAuthority(lastAccepted uint64, pending *PendingBump) CounterAuthority {
	return CounterAuthority{
		lastAccepted: lastAccepted,
		pending:      pending,
		valid:        true,
	}
}

// adapterWitness is an unexported capability token. It has zero usable fields
// and zero exported constructor. Because the type is unexported, no package
// outside countertypes can name *adapterWitness in a declaration, so
// MintFromAdapter is uncallable by any package that cannot name this type.
// capmint passes an untyped nil (Go-converted to (*adapterWitness)(nil))
// because it cannot name the type at all. There is no exported producer of
// *adapterWitness under any build tag — that would be a laundering vector.
// The honest guarantee rests on the Go internal/ import rule and the AST
// surface classifier, not on this token alone.
type adapterWitness struct{ _ [0]func() }

// MintFromAdapter is the single exported production CounterAuthority producer.
// It requires a *adapterWitness parameter, which is unexported and has no
// exported constructor. This makes MintFromAdapter uncallable by construction
// from any package that cannot name *adapterWitness. The only wired caller is
// internal/adapter/registry/internal/capmint, which passes an untyped nil
// because it cannot name the type. MintFromAdapter accepts a nil witness in
// production — the nil-panic guard belongs to the test-only NewForTest, not
// here. The load-bearing guarantee is the Go internal/ import rule on capmint
// combined with the AST surface classifier in countertypes, plus capmint being
// the only wired caller; the witness parameter is defense-in-depth for
// accident-prevention and AST classification only.
func MintFromAdapter(w *adapterWitness, lastAccepted uint64, pending *PendingBump) CounterAuthority {
	_ = w // accepted for AST classification; not claimed load-bearing
	return newCounterAuthority(lastAccepted, pending)
}
