// Package manifestsigner provides the production usecase.ManifestSigner adapter.
// It signs the canonical manifest encoding using the admin's registry-attested
// Ed25519 signing key, delegating the signing operation entirely to the existing
// internal/core/crypto/sign package (no re-implementation of canonical encoding).
//
// Key design invariants enforced here:
//
//   - The Ed25519 signing key is DISTINCT from the age X25519 decryption identity.
//     Cross-role reuse is structurally impossible: the adapter accepts raw []byte
//     via the Ed25519KeySource port, and validates the byte length against
//     ed25519.PrivateKeySize (64 bytes) — a Curve25519 scalar (32 bytes) or any
//     other wrong-length buffer is rejected before any signing attempt.
//
//   - The signerID is the registry-attested admin id resolved from the injected
//     TrustedSigners map at sign time by matching the public half of the loaded
//     private key. The signer never self-declares a signerID and never reads one
//     from the artifact being signed.
//
//   - A key whose public half is not in the registry-attested TrustedSigners map
//     cannot produce a usable signerID: ErrKeyNotAttested is returned and no
//     signature byte is produced.
//
//   - A malformed manifest (bad format_version, separator injection) fails closed
//     BEFORE any signature byte is produced, because sign.Sign re-validates the
//     manifest via manifest.Encode.
//
//   - The raw Ed25519 private-key buffer returned by Ed25519KeySource.ProvideKey
//     is explicitly zeroed via ZeroizeBuffer (the same discipline as
//     internal/adapter/identity) immediately after the signing operation, before
//     the buffer is dropped.
package manifestsigner

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ErrKeyNotAttested is returned when the public half of the loaded Ed25519
// private key is not present in the registry-attested TrustedSigners map. A
// non-attested key cannot produce a usable signerID — fail closed.
var ErrKeyNotAttested = errors.New(
	"ed25519 signing key is not registry-attested: public key not found in verified TrustedSigners — " +
		"ensure the admin key is registered in the registry")

// ErrWrongKeySize is returned when the Ed25519KeySource returns a buffer whose
// length is not ed25519.PrivateKeySize (64 bytes). This also rejects age X25519
// private scalars (32 bytes), enforcing the distinct-key / no-cross-role-reuse
// invariant at the type boundary.
var ErrWrongKeySize = fmt.Errorf(
	"ed25519 private key must be exactly %d bytes (got wrong-length buffer — "+
		"ensure the Ed25519 signing key is not confused with the age X25519 decrypt identity)",
	ed25519.PrivateKeySize)

// Ed25519KeySource is the port for providing the raw Ed25519 private-key bytes
// to the signer. It is defined here (consumer = manifestsigner adapter) and
// implemented by the production key-loading adapter or by test fakes.
//
// Contract:
//   - ProvideKey returns a freshly-allocated []byte slice (not a sub-slice of a
//     shared buffer) so the signer can zero it safely after use.
//   - On success the returned slice has length ed25519.PrivateKeySize (64).
//   - On error the returned slice is nil and the error wraps the failure cause.
//   - The source MUST NOT retain a reference to the returned slice after
//     ProvideKey returns.
type Ed25519KeySource interface {
	ProvideKey(ctx context.Context) ([]byte, error)
}

// signer is the concrete usecase.ManifestSigner implementation. It holds the
// injected key source and the registry-attested TrustedSigners map. It stores no
// raw key material between calls.
type signer struct {
	keySource      Ed25519KeySource
	trustedSigners map[string]ed25519.PublicKey
}

// New constructs the ManifestSigner adapter. Both parameters are required:
//
//   - keySource must be non-nil and must return raw Ed25519 private-key bytes
//     exactly ed25519.PrivateKeySize bytes long.
//   - trustedSigners must be non-nil and non-empty: it is the registry-attested
//     signer map (admin id → Ed25519 public key) sourced from a
//     SourceVerified && !Stale registry fetch. A nil or empty map means no admin
//     key is attested, so no signerID can ever be resolved — fail closed.
//
// The constructor does NOT load the private key: key material is never held
// between Sign calls.
func New(keySource Ed25519KeySource, trustedSigners map[string]ed25519.PublicKey) (usecase.ManifestSigner, error) {
	if keySource == nil {
		return nil, errors.New("manifestsigner.New: keySource must not be nil")
	}
	if len(trustedSigners) == 0 {
		return nil, errors.New(
			"manifestsigner.New: trustedSigners must be non-nil and non-empty — " +
				"no registry-attested admin key is present; check the registry fetch")
	}
	// Defensive copy: the caller's map must not be mutated after New returns.
	ts := make(map[string]ed25519.PublicKey, len(trustedSigners))
	for k, v := range trustedSigners {
		ts[k] = v
	}
	return &signer{keySource: keySource, trustedSigners: ts}, nil
}

// Sign implements usecase.ManifestSigner. It:
//  1. Checks ctx cancellation first (fail fast).
//  2. Loads the Ed25519 private key from the injected source.
//  3. Validates the key length (rejects wrong-size buffers, including age scalars).
//  4. Derives the corresponding public key and looks it up in trustedSigners to
//     resolve the registry-attested signerID. If not found, zeroizes the buffer
//     and returns ErrKeyNotAttested — no signature byte is produced.
//  5. Delegates signing to sign.Sign, which re-validates the manifest via
//     manifest.Encode before signing. A malformed manifest (bad format_version,
//     separator injection) fails closed here, before any signature byte.
//  6. Zeroizes the private-key buffer unconditionally on every exit path.
//
// The signer holds no key material after Sign returns.
func (s *signer) Sign(ctx context.Context, m manifest.Manifest) (signerID string, sig []byte, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", nil, fmt.Errorf("manifestsigner: sign cancelled: %w", ctxErr)
	}

	// Load the Ed25519 private key bytes from the source.
	rawKey, err := s.keySource.ProvideKey(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("manifestsigner: loading Ed25519 signing key: %w", err)
	}

	// Zeroize unconditionally on all exit paths below this point.
	defer identity.ZeroizeBuffer(rawKey)

	// Validate byte length. This is the distinct-key / no-cross-role-reuse
	// gate: a Curve25519 scalar (32 bytes) or any other wrong-length value
	// cannot proceed, keeping the two admin key roles (Ed25519 sign, age decrypt)
	// structurally separate.
	if len(rawKey) != ed25519.PrivateKeySize {
		return "", nil, fmt.Errorf("%w: got %d bytes", ErrWrongKeySize, len(rawKey))
	}

	priv := ed25519.PrivateKey(rawKey)

	// Derive the public key and look it up in the registry-attested TrustedSigners.
	pub := priv.Public().(ed25519.PublicKey)
	resolvedID, ok := s.lookupSignerID(pub)
	if !ok {
		return "", nil, ErrKeyNotAttested
	}

	// Delegate to the existing canonical sign path. sign.Sign re-validates the
	// manifest via manifest.Encode before signing, so a malformed manifest
	// (bad format_version, separator injection) fails closed here.
	rawSig, err := sign.Sign(priv, m)
	if err != nil {
		return "", nil, fmt.Errorf("manifestsigner: signing canonical manifest: %w", err)
	}

	return resolvedID, rawSig, nil
}

// TextSigner is the port for raw-bytes signing using the same key-bearing path
// as ManifestSigner. It is defined here so writesigner can hold a narrow
// interface without widening the exported ManifestSigner surface or introducing
// a parallel ed25519 import.
//
// SignText returns the registry-attested signer identity and a raw Ed25519
// signature over text. The same key-length validation, zeroization, and
// attested-id-lookup disciplines apply as in Sign. No manifest encoding is
// performed; text is signed verbatim after domain-separation is applied by the
// caller.
type TextSigner interface {
	SignText(ctx context.Context, text []byte) (signerID string, sig []byte, err error)
}

// SignText signs arbitrary bytes using the same key-bearing path as Sign.
// Domain-separation is the caller's responsibility; writesigner applies the
// fixed "byreis-registry-write/v1\n" prefix before calling this method.
//
// Key-length validation, unconditional zeroization, and attested-id-lookup
// are identical to Sign. No manifest encoding is performed.
func (s *signer) SignText(ctx context.Context, text []byte) (signerID string, sig []byte, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", nil, fmt.Errorf("manifestsigner: SignText cancelled: %w", ctxErr)
	}

	rawKey, err := s.keySource.ProvideKey(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("manifestsigner: loading Ed25519 signing key for SignText: %w", err)
	}

	defer identity.ZeroizeBuffer(rawKey)

	if len(rawKey) != ed25519.PrivateKeySize {
		return "", nil, fmt.Errorf("%w: got %d bytes (SignText path)", ErrWrongKeySize, len(rawKey))
	}

	priv := ed25519.PrivateKey(rawKey)
	pub := priv.Public().(ed25519.PublicKey)
	resolvedID, ok := s.lookupSignerID(pub)
	if !ok {
		return "", nil, ErrKeyNotAttested
	}

	rawSig := ed25519.Sign(priv, text)
	return resolvedID, rawSig, nil
}

// lookupSignerID searches the trustedSigners map for an entry whose Ed25519
// public key matches pub. Because TrustedSigners is a map from id to pubkey, we
// iterate and compare by value (ed25519.PublicKey is []byte; we use
// ed25519.PublicKey.Equal for constant-time comparison to avoid timing leaks).
//
// Returns the matching admin id and true on success, or ("", false) if not found.
func (s *signer) lookupSignerID(pub ed25519.PublicKey) (string, bool) {
	for id, trusted := range s.trustedSigners {
		if pub.Equal(trusted) {
			return id, true
		}
	}
	return "", false
}
