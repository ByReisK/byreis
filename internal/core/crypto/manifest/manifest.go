// Package manifest implements the canonical encoding for the Ed25519-signed
// manifest bytes. It is pure: bytes in, bytes out. No age. No network. No
// filesystem. No identity types.
//
// Imported by crypto/encrypt, crypto/verify, and the signing path in the
// decrypt package. Not imported by external adapters or CLI packages.
package manifest

import "errors"

// Sentinel errors returned by this package.
var (
	// ErrFormatVersion is returned when format_version does not match the
	// required regex ^byreis\.native\.v[0-9]+$ or contains a separator byte
	// (0x1e or 0x1f).
	ErrFormatVersion = errors.New(
		"unsupported or malformed artifact format version: must match ^byreis\\.native\\.v[0-9]+$")

	// ErrSeparatorInjection is returned when any signed field (project_id,
	// logical_file_name, or a key name) contains the RS (0x1e) or US (0x1f)
	// separator byte, which would let an attacker shift field boundaries in the
	// signed stream.
	ErrSeparatorInjection = errors.New(
		"manifest field contains reserved separator byte (0x1e or 0x1f)")
)

// Manifest is the domain type capturing the data that participates in the
// canonical signing stream. It is produced by crypto/encrypt and consumed by
// crypto/verify and crypto/sign.
//
// Note: the YAML on-disk representation lives in crypto/artifact; the mapping
// from artifact bytes to Manifest values is the caller's responsibility.
type Manifest struct {
	// FormatVersion must match ^byreis\.native\.v[0-9]+$.
	FormatVersion string

	// ProjectID and LogicalFileName bind the artifact to its identity. An
	// artifact signed for (projX, prod) but presented as (projY, prod) or
	// (projX, staging) fails ErrIdentityMismatch at verify.
	ProjectID       string
	LogicalFileName string

	// Counter is the monotonic anti-replay value. Its authority is the
	// registry/audit store; the encoder merely binds whatever value the signed
	// file claims so a replayed file is detected against registry authority.
	Counter uint64

	// Values maps key name → age ciphertext bytes (the canonical encoding uses
	// sha256(key_name ‖ 0x00 ‖ ciphertext) per key). Map iteration order must
	// never reach the encoder; the encoder sorts internally so the output is
	// deterministic.
	Values map[string][]byte

	// RecipientFingerprints is the set of 64-char lowercase hex fingerprints
	// (full 32-byte sha256 of each age recipient public-key string).
	// The encoder sorts internally.
	RecipientFingerprints []string
}

// Encode produces the canonical byte stream that Ed25519 signs. It is
// deterministic: map iteration order is irrelevant because the encoder sorts
// all variable-length fields internally.
//
// Returns ErrFormatVersion if FormatVersion is invalid or contains separator
// bytes. Returns ErrSeparatorInjection if any key name, ProjectID, or
// LogicalFileName contains a separator byte. Panics are never used.
func Encode(m Manifest) ([]byte, error) {
	panic("not implemented") // stub: real implementation pending
}

// FormatVersionValid reports whether v matches ^byreis\.native\.v[0-9]+$ and
// contains no 0x1e or 0x1f bytes.
func FormatVersionValid(v string) bool {
	panic("not implemented") // stub: real implementation pending
}
