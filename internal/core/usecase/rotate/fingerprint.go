package rotate

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// RecipientFingerprintFull returns the hex-encoded SHA-256 of a recipient's
// age public-key string. The full 64-character hex digest is the single
// source of truth for the typed-fingerprint operator confirm on rotation's
// --remove and --replace paths.
//
// The full digest is load-bearing: a truncated fingerprint (e.g. first 8
// chars) admits a shoulder-surfed visual-only attack where the operator
// types a few characters they remember seeing, and the CLI accepts a
// recipient they never meant to confirm. By requiring the operator to type
// the full 64-char value, the confirm path forces a deliberate
// copy/transcribe action against the exact recipient the CLI displayed.
//
// The helper is pure: deterministic, no I/O, no allocations beyond the hex
// buffer. It is the SAME computation the CLI uses to print fingerprints, so
// the displayed value and the compared value are always byte-equal.
func RecipientFingerprintFull(r rectypes.Recipient) string {
	digest := sha256.Sum256([]byte(r.AgePubKey))
	return hex.EncodeToString(digest[:])
}
