// Package manifest implements the canonical encoding for the Ed25519-signed
// manifest bytes. It is pure: bytes in, bytes out. No age. No network. No
// filesystem. No identity types.
//
// Imported by crypto/encrypt, crypto/verify, and the signing path in the
// decrypt package. Not imported by external adapters or CLI packages.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// Separator bytes. RS delimits list elements / sub-fields of a record; US
// delimits top-level fields. Both are control characters that cannot occur in
// armored age ciphertext, hex digests, fingerprints, or printable-ASCII ids —
// any signed field containing one is rejected before a byte is emitted, so an
// attacker cannot shift the framing of subsequent signed fields.
const (
	sepRS = 0x1e // record separator
	sepUS = 0x1f // unit separator
)

// formatVersionRE constrains the first signed field. A free-form first field
// would be a separator-injection / framing-ambiguity surface, so the version
// is a fixed enum, not an arbitrary string.
var formatVersionRE = regexp.MustCompile(`^byreis\.native\.v[0-9]+$`)

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

// containsSeparator reports whether s holds an RS or US byte. These bytes are
// the framing of the signed stream; smuggling one into any field would shift
// the boundary of every subsequent field, so it is rejected before encoding.
func containsSeparator(s string) bool {
	return bytes.IndexByte([]byte(s), sepRS) >= 0 ||
		bytes.IndexByte([]byte(s), sepUS) >= 0
}

// FormatVersionValid reports whether v matches ^byreis\.native\.v[0-9]+$ and
// contains no 0x1e or 0x1f bytes. The separator check is applied before the
// regex so a smuggled control byte can never reach the encoder even if the
// regex engine were somehow permissive.
func FormatVersionValid(v string) bool {
	if containsSeparator(v) {
		return false
	}
	return formatVersionRE.MatchString(v)
}

// perKeyDigest is the per-key digest: sha256(key_name ‖ 0x00 ‖ ciphertext).
// The 0x00 domain separator prevents name‖ct ambiguity; binding the ciphertext
// to the NAME (not sha256(ct) alone) defeats ciphertext-swap-between-keys.
func perKeyDigest(name string, ciphertext []byte) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x00})
	h.Write(ciphertext)
	return hex.EncodeToString(h.Sum(nil))
}

// Encode produces the canonical byte stream that Ed25519 signs.
// It is deterministic: map iteration order is irrelevant because the encoder
// sorts all variable-length fields internally over a private copy, so the
// caller's map order is never observed by the signer.
//
// Field order (US between top-level fields, RS within list/records):
//
//  1. format_version (constrained)              US
//  2. registry_project_id                       US
//  3. logical_file_name                         US
//  4. counter (8 bytes big-endian)              US
//  5. for each SORTED key: name RS digest_hex (records RS-joined)  US
//  6. for each SORTED fingerprint: fp_hex (RS-joined, NO trailing US)
//
// Returns ErrFormatVersion if FormatVersion is invalid or carries a separator
// byte. Returns ErrSeparatorInjection if ProjectID, LogicalFileName, a key
// name, or a fingerprint carries a separator byte. Never panics.
func Encode(m Manifest) ([]byte, error) {
	if !FormatVersionValid(m.FormatVersion) {
		return nil, fmt.Errorf("%w: %q", ErrFormatVersion, m.FormatVersion)
	}
	// ProjectID / LogicalFileName are signed identity fields; a separator byte
	// here would let an attacker re-frame the stream.
	if containsSeparator(m.ProjectID) || containsSeparator(m.LogicalFileName) {
		return nil, fmt.Errorf("%w: project_id or logical_file_name", ErrSeparatorInjection)
	}

	var buf bytes.Buffer
	buf.WriteString(m.FormatVersion)
	buf.WriteByte(sepUS)
	buf.WriteString(m.ProjectID)
	buf.WriteByte(sepUS)
	buf.WriteString(m.LogicalFileName)
	buf.WriteByte(sepUS)

	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], m.Counter)
	buf.Write(counter[:])
	buf.WriteByte(sepUS)

	// Field 5: sorted key records. Sort a private copy of the key names so the
	// input map's iteration order is never observed by the signer (defeats a
	// key-reorder attack — a reordered map must not change the signed bytes).
	keys := make([]string, 0, len(m.Values))
	for k := range m.Values {
		if containsSeparator(k) {
			return nil, fmt.Errorf("%w: key name %q", ErrSeparatorInjection, k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys) // bytewise ascending on the UTF-8 key name
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(sepRS)
		}
		buf.WriteString(k)
		buf.WriteByte(sepRS)
		buf.WriteString(perKeyDigest(k, m.Values[k]))
	}
	buf.WriteByte(sepUS)

	// Field 6: sorted recipient fingerprints, RS-joined, NO trailing US.
	fps := make([]string, len(m.RecipientFingerprints))
	copy(fps, m.RecipientFingerprints)
	for _, fp := range fps {
		if containsSeparator(fp) {
			return nil, fmt.Errorf("%w: fingerprint %q", ErrSeparatorInjection, fp)
		}
	}
	sort.Strings(fps) // bytewise ascending on the lowercase-hex fingerprint
	for i, fp := range fps {
		if i > 0 {
			buf.WriteByte(sepRS)
		}
		buf.WriteString(fp)
	}

	return buf.Bytes(), nil
}
