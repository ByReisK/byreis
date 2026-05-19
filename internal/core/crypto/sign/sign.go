// Package sign produces and verifies the Ed25519 signature over the canonical
// manifest byte stream. It is deliberately SEPARATE from
// internal/core/crypto/manifest: the manifest package is the pure canonical
// encoder that the contributor encrypt path imports, so it must not
// transitively reach crypto/ed25519, or the contributor path would gain a
// route to private-key constructors and the asymmetric-access guarantee would
// be defeated. Signing is an admin-only capability and lives here instead.
//
// This package imports crypto/ed25519 and is therefore intentionally NOT
// reachable from the contributor encrypt path or the submit use-case spine.
package sign

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
)

// ErrBadSignerKeyLength is returned when a public key is not exactly 32 bytes.
// Wrong-length signer keys are caught here (and at the registry boundary)
// rather than producing a confusing signature-verification failure later.
var ErrBadSignerKeyLength = errors.New("ed25519 public key has wrong length (want 32 bytes)")

// ErrSignatureInvalid is returned when the Ed25519 signature does not verify
// over the recomputed canonical manifest stream. It is a fail-closed error: the
// caller MUST NOT treat a non-nil result as a downgrade-to-unsigned.
var ErrSignatureInvalid = errors.New("ed25519 signature verification failed over canonical manifest stream")

// Sign produces the Ed25519 signature over the canonical manifest encoding. It
// re-validates the manifest via manifest.Encode, so a malformed manifest (bad
// format_version / separator injection) fails closed BEFORE any signature is
// produced, never after.
func Sign(priv ed25519.PrivateKey, m manifest.Manifest) ([]byte, error) {
	stream, err := manifest.Encode(m)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, stream), nil
}

// Verify recomputes the canonical stream from m and checks the Ed25519
// signature against pub. It returns nil ONLY on a valid signature; any
// mismatch (tampered manifest, wrong key, bad/short signature, malformed
// input, wrong-length key) is a non-nil error and the caller MUST treat it as
// fail-closed (no downgrade path).
func Verify(pub ed25519.PublicKey, m manifest.Manifest, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: got %d", ErrBadSignerKeyLength, len(pub))
	}
	stream, err := manifest.Encode(m)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, stream, sig) {
		return ErrSignatureInvalid
	}
	return nil
}
