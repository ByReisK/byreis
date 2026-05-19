// Package rectypes is the pure value-type sub-package for registry public-key
// domain objects. It exports only Recipient and Fingerprint — no identity
// material, no SignerKey, no CounterStore, no ed25519.
//
// This is the only registry-side package on the contributor-path import
// allowlist for internal/core/crypto/encrypt and usecase/Submit. The parent
// package internal/core/registry carries SignerKey = ed25519.PublicKey and
// CounterStore, which transitively import crypto/ed25519, placing the parent
// off that allowlist. Recipient and Fingerprint live here precisely so the
// package-scoped transitive-subset test enforces the rule mechanically, without
// relying on prose.
//
// Invariant: no field (exported or unexported) and no method reachable from a
// Recipient value is assignable to or yields age.Identity, age.X25519Identity,
// an X25519/Ed25519 private key, or a byte buffer typed or named as private-key
// material. This keeps the contributor path provably free of decrypt capability
// and is re-asserted by a reflection test on any change to Recipient.
package rectypes

// Fingerprint is the full 32-byte SHA-256 digest of an age recipient public-key
// string. A truncated digest is forbidden: the full 32 bytes are required to
// keep the recipient binding collision-resistant.
type Fingerprint [32]byte

// Recipient is a public-key-only domain value type. It carries no private-key
// material — that invariant is enforced by the import allowlist gate and by the
// reflection test. Label is diagnostic only and is never security-relevant;
// AgePubKey is an opaque "age1…" string; Fingerprint is sha256(AgePubKey).
type Recipient struct {
	// Label is a human-readable identifier for diagnostics. NOT used in any
	// security decision. MUST NOT carry private-key material.
	Label string

	// AgePubKey is the "age1…" public-key string (opaque to core). Used as the
	// encryption target; never a private key.
	AgePubKey string

	// Fingerprint is sha256(AgePubKey), full 32 bytes. Used in the signed
	// manifest recipient-fingerprint set.
	Fingerprint Fingerprint
}
