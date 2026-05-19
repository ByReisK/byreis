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
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// formatVersion is the only format this v0.1 contributor path emits. It is
// bound into the signed manifest; a future field change is a version bump plus
// a new ADR (the manifest is signed, so it cannot change silently).
const formatVersion = "byreis.native.v1"

// ErrNoValues is returned when there is nothing to encrypt. Producing an empty
// artifact is a contributor mistake, surfaced eagerly with a hint.
var ErrNoValues = errors.New(
	"refusing to build an empty artifact: no secret values provided")

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

// Encrypt builds an UNSIGNED contributor artifact. Each value is an
// independent multi-recipient age ciphertext from a FRESH age.Encrypt call to
// the full recipient set, so every value gets its own file key and nonce and
// no ciphertext is ever reused. No private key is ever touched: the package's
// import allowlist (allowlist_test.go) proves the contributor path cannot
// reach identity/decrypt material.
func (e *encryptor) Encrypt(ctx context.Context, in EncryptInput) (artifact.Unsigned, error) {
	if len(in.Recipients) == 0 {
		return artifact.Unsigned{}, ErrNoRecipients
	}
	if len(in.Values) == 0 {
		return artifact.Unsigned{}, ErrNoValues
	}
	if err := ctx.Err(); err != nil {
		return artifact.Unsigned{}, fmt.Errorf("encrypt cancelled: %w", err)
	}

	// Parse all recipient public keys up front (public-key only — no identity
	// type is reachable here by construction).
	ageRecips := make([]age.Recipient, 0, len(in.Recipients))
	for _, r := range in.Recipients {
		pk, err := age.ParseX25519Recipient(r.AgePubKey)
		if err != nil {
			return artifact.Unsigned{}, fmt.Errorf(
				"invalid age recipient public key (label %q): %w — "+
					"the registry returned a malformed recipient; re-run after `byreis doctor`",
				r.Label, err)
		}
		ageRecips = append(ageRecips, pk)
	}

	values := make(map[string]artifact.EncryptedValue, len(in.Values))
	for name, plaintext := range in.Values {
		if err := ctx.Err(); err != nil {
			return artifact.Unsigned{}, fmt.Errorf("encrypt cancelled: %w", err)
		}
		ct, err := encryptValue(plaintext, ageRecips)
		if err != nil {
			// Never include the plaintext in the error.
			return artifact.Unsigned{}, fmt.Errorf(
				"encrypting value for key %q failed: %w", name, err)
		}
		values[name] = artifact.EncryptedValue(ct)
	}

	// Build the canonical manifest and validate it (separator / format-version
	// rejection) BEFORE returning an artifact, so a malformed identity field
	// fails closed at the contributor instead of at merge.
	man := manifest.Manifest{
		FormatVersion:         formatVersion,
		ProjectID:             in.ProjectID,
		LogicalFileName:       in.LogicalFileName,
		Counter:               in.Counter,
		Values:                make(map[string][]byte, len(values)),
		RecipientFingerprints: fingerprintHexes(in.Recipients),
	}
	for name, ct := range values {
		man.Values[name] = []byte(ct)
	}
	if _, err := manifest.Encode(man); err != nil {
		return artifact.Unsigned{}, mapManifestErr(err)
	}

	return artifact.Unsigned{
		Values: values,
		Byreis: artifact.Metadata{
			FormatVersion: formatVersion,
			ProjectID:     in.ProjectID,
			File:          in.LogicalFileName,
			Counter:       in.Counter,
			Recipients:    recipientEntries(in.Recipients),
		},
	}, nil
}

// encryptValue produces ONE independent armored age ciphertext via a FRESH
// age.Encrypt call (new file key + nonce per value). No prior ciphertext is
// ever spliced, re-wrapped, or carried forward, so a stale or replayed blob
// can never ride a later signature.
func encryptValue(plaintext string, recips []age.Recipient) (string, error) {
	var out bytes.Buffer
	armorW := armor.NewWriter(&out)
	w, err := age.Encrypt(armorW, recips...)
	if err != nil {
		return "", fmt.Errorf("age.Encrypt init: %w", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		return "", fmt.Errorf("age write: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("age close: %w", err)
	}
	if err := armorW.Close(); err != nil {
		return "", fmt.Errorf("armor close: %w", err)
	}
	return out.String(), nil
}

// fingerprintHexes returns the lowercase-hex of each recipient's full 32-byte
// fingerprint, for the signed manifest's recipient-fingerprint set.
func fingerprintHexes(rs []rectypes.Recipient) []string {
	hexes := make([]string, 0, len(rs))
	for _, r := range rs {
		hexes = append(hexes, hex.EncodeToString(r.Fingerprint[:]))
	}
	sort.Strings(hexes)
	return hexes
}

// recipientEntries builds the DISPLAY-ONLY recipient block. It is never trusted
// as the recipient authority: VerifyOfRecord/VerifySubmission compare against a
// signature-verified registry set, never this block.
func recipientEntries(rs []rectypes.Recipient) []artifact.RecipientEntry {
	out := make([]artifact.RecipientEntry, 0, len(rs))
	for _, fp := range fingerprintHexes(rs) {
		out = append(out, artifact.RecipientEntry{FP: fp})
	}
	return out
}

// mapManifestErr maps manifest sentinels into this package's sentinels so
// callers get a stable, actionable error at the contributor boundary.
func mapManifestErr(err error) error {
	switch {
	case errors.Is(err, manifest.ErrFormatVersion):
		return fmt.Errorf("%w: %v", ErrFormatVersion, err)
	case errors.Is(err, manifest.ErrSeparatorInjection):
		return fmt.Errorf("%w: a project id, file name, or key name contains a "+
			"reserved control byte: %v", ErrManifestMismatch, err)
	default:
		return fmt.Errorf("%w: %v", ErrManifestMismatch, err)
	}
}
