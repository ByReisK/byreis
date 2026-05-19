// Package identity holds admin identity material: the age X25519 private key.
// It is imported by crypto/decrypt only. It is never imported by
// crypto/encrypt or by any usecase reachable from the contributor submit path;
// the import allowlist enforces this so the contributor path cannot reach
// private-key material.
package identity

import (
	"context"
	"errors"
	"fmt"

	"filippo.io/age"
)

// ErrParseIdentity is returned when an age private key string cannot be parsed.
var ErrParseIdentity = errors.New("could not parse age identity (admin private key)")

// Identity represents an admin's age X25519 private key. The private-key
// material is held inside an age.X25519Identity; callers obtain the age
// identity only via AgeIdentity, used by the admin decrypt path.
type Identity interface {
	// Recipient returns the corresponding age recipient public key string
	// ("age1…"). Safe to log/display — it is public-key material only.
	Recipient() string

	// AgeIdentity returns the underlying age X25519 identity for decryption.
	// Only the admin decrypt path calls this; the contributor path cannot
	// reach this package (import allowlist).
	AgeIdentity() *age.X25519Identity
}

// x25519Identity is the concrete admin identity. It wraps an age X25519
// identity. The age library holds the scalar internally; we keep no extra copy
// of the private bytes in this struct.
type x25519Identity struct {
	id *age.X25519Identity
}

func (x *x25519Identity) Recipient() string { return x.id.Recipient().String() }

func (x *x25519Identity) AgeIdentity() *age.X25519Identity { return x.id }

// Parse builds an Identity from an "AGE-SECRET-KEY-1…" string. The string is a
// private key and MUST NOT be logged. Parsing failure is ErrParseIdentity
// without echoing the input.
func Parse(secret string) (Identity, error) {
	parsed, err := age.ParseX25519Identity(secret)
	if err != nil {
		// Deliberately do NOT include `secret` in the error — it is private.
		return nil, fmt.Errorf("%w", ErrParseIdentity)
	}
	return &x25519Identity{id: parsed}, nil
}

// Loader loads an admin identity from a source (keychain, file, env) behind a
// context for cancellation. Never used in the contributor path.
type Loader interface {
	Load(ctx context.Context) (Identity, error)
}
