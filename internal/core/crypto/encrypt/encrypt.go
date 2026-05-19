// Package encrypt is the contributor encrypt path. It is public-key only: it
// can never sign and never decrypt.
//
// Closed-world import allowlist: the full transitive dependency set of this
// package must be a subset of an explicit allowlist. This package must not
// import:
//   - internal/core/crypto/identity  (admin private key)
//   - internal/core/crypto/decrypt   (admin decrypt)
//   - internal/core/registry         (parent — transitively reaches
//     crypto/ed25519 via SignerKey/CounterStore)
//   - filippo.io/age identity types  (X25519Identity, etc.)
//   - crypto/ed25519
//
// Permitted imports: internal/core/crypto/manifest,
// internal/core/registry/rectypes (the pure value-type sub-package only),
// filippo.io/age (recipient/encrypt surface), and a stdlib subset (io, bytes,
// errors, fmt, crypto/sha256).
//
// The allowlist test (allowlist_test.go) is the single authoritative gate and
// enforces this mechanically: any transitive dependency not on the allowlist
// fails the build.
package encrypt

import (
	"context"
	"errors"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// Sentinel errors owned by this package.
var (
	// ErrNoRecipients is returned when Recipients is empty. Encrypting to nobody
	// is a hard error with a hint ("registry returned zero admin recipients").
	ErrNoRecipients = errors.New(
		"refusing to encrypt to zero recipients: registry returned zero admin recipients")

	// ErrFormatVersion is returned when a format_version field is invalid.
	ErrFormatVersion = errors.New(
		"unsupported or malformed artifact format version")

	// ErrManifestMismatch is returned when the manifest does not match artifact.
	ErrManifestMismatch = errors.New("manifest does not match artifact contents")
)

// EncryptInput carries all inputs for Encryptor.Encrypt. Recipients must be
// non-empty (ErrNoRecipients) and must be sourced from a signature-verified
// registry fetch. The caller is responsible for that sourcing; this package
// cannot enforce it at runtime, but the import allowlist ensures the recipient
// types come only from rectypes, never from identity-bearing code.
type EncryptInput struct {
	// ProjectID and LogicalFileName are bound into the signed manifest so an
	// artifact cannot be replayed under a different project or file identity.
	ProjectID       string
	LogicalFileName string

	// Counter is the claimed counter value. The registry/audit store is the
	// acceptance authority; Encrypt does not validate it.
	Counter uint64

	// Recipients is the set of age recipient public keys. Must be non-empty and
	// must originate from a signature-verified registry fetch. Uses the pure
	// rectypes sub-package, never the parent registry package, so the
	// contributor path stays off any private-key-bearing code.
	Recipients []rectypes.Recipient

	// Values maps secret key names to plaintext values. The plaintext is
	// encrypted into independent per-value age ciphertexts (one fresh
	// age.Encrypt per value, for AEAD nonce freshness).
	Values map[string]string
}

// Encryptor builds an unsigned contributor artifact from plaintext values using
// only recipient public keys. It can never sign and never decrypt.
//
// The interface is defined here, in the consumer package, per the Clean
// Architecture consumer-defines-interface rule. The concrete implementation
// lives in this same package — the package itself is the adapter boundary, so
// no separate adapter is needed.
type Encryptor interface {
	// Encrypt produces an unsigned artifact: each value is an independent fresh
	// multi-recipient age ciphertext to all recipients (for AEAD nonce
	// freshness). The artifact carries the digest-committed manifest without a
	// signature.
	//
	// recipients must be non-empty, otherwise ErrNoRecipients (with a hint).
	// Returns a wrapped age error with a hint on encryption failure.
	Encrypt(ctx context.Context, in EncryptInput) (artifact.Unsigned, error)
}

// New returns the concrete Encryptor implementation.
func New() Encryptor {
	return &encryptor{}
}

type encryptor struct{}

func (e *encryptor) Encrypt(_ context.Context, _ EncryptInput) (artifact.Unsigned, error) {
	panic("not implemented") // stub: real implementation pending
}
