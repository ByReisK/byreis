// Package verify implements the two verification entry points. There is no
// nil-key downgrade path: a single VerifyArtifact(verifyKey) with a
// nil-means-skip branch is deliberately not offered, because it would let a
// missing key silently weaken verification.
//
// The two interfaces are separate so the submit path can depend on Encryptor
// (in package encrypt) without ever seeing a verify/identity type.
//
// Counter-authority types (CounterAuthority / PendingBump) and their sentinel
// errors (ErrReplay / ErrCounterReconcile) live in
// internal/core/registry/countertypes. This package imports countertypes to
// consume the opaque CounterAuthority value (reads fields via Valid() /
// LastAccepted() / Pending()). It cannot construct a valid CounterAuthority:
// countertypes exposes no exported constructor reachable from here, so counter
// authority cannot be forged on the verification path.
package verify

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// Sentinel errors owned by this package. ErrReplay and ErrCounterReconcile are
// owned by internal/core/registry/countertypes and are referenced from there
// directly; this package does not define alias vars for them, to avoid two
// packages owning the same sentinel.
var (
	// ErrFormatVersion: format_version does not match ^byreis\.native\.v[0-9]+$
	// or contains a separator byte.
	ErrFormatVersion = errors.New(
		"unsupported or malformed artifact format version: must match ^byreis\\.native\\.v[0-9]+$")

	// ErrManifestMismatch: manifest fields do not match artifact contents.
	ErrManifestMismatch = errors.New("manifest does not match artifact contents")

	// ErrIdentityMismatch: project_id or logical_file_name does not match
	// the caller's expected identity.
	ErrIdentityMismatch = errors.New(
		"artifact project/file identity does not match expected — possible cross-file/cross-project transplant")

	// ErrRecipientMismatch: artifact recipient set does not match the verified
	// registry. Hint: re-run `byreis merge` to re-encrypt to current admins.
	ErrRecipientMismatch = errors.New(
		"artifact recipient set does not match the verified registry: " +
			"run `byreis merge` to re-encrypt to the current admin set")

	// ErrUnsigned: file-of-record has no manifest_sig — a hard error for live
	// reads and CI deploys, because the file was never merged via `byreis
	// merge` and so was never reviewed.
	ErrUnsigned = errors.New(
		"file-of-record is unsigned: it was never merged via `byreis merge`; " +
			"a contributor submission must be reviewed and merged before live use")

	// ErrNoTrustedSigner: no trusted manifest signer key is available, or all
	// keys are invalid. This is a hard error and never a downgrade to unsigned.
	// This package is the semantic owner; the registry boundary returns this
	// same sentinel by reference rather than defining its own alias.
	ErrNoTrustedSigner = errors.New(
		"no trusted manifest signer key available — " +
			"run `byreis doctor` to check your trust anchor, or `byreis auth login`")

	// ErrSignatureInvalid: Ed25519 signature verification failed.
	ErrSignatureInvalid = errors.New("manifest signature verification failed")

	// ErrDecrypt: no available identity could decrypt the value.
	ErrDecrypt = errors.New(
		"no available identity could decrypt the value — " +
			"run `byreis auth login` or check that your admin key is present")

	// ErrNoRecipients mirrors the encrypt-side sentinel for use-cases that need it.
	ErrNoRecipients = errors.New(
		"refusing to encrypt to zero recipients: registry returned zero admin recipients")
)

// VerificationState distinguishes a structurally-checked submission from a fully
// verified file-of-record. A submission can never become StateOfRecord via
// VerifySubmission.
type VerificationState int

const (
	// StateUnverified is returned by VerifySubmission. It is structural-only;
	// it must never gate a prod decrypt/deploy. This value is not
	// trust-equivalent to StateOfRecord under any condition.
	StateUnverified VerificationState = iota

	// StateOfRecord is returned only by VerifyOfRecord on full success. It
	// implies: valid format, matching identity, valid counter authority,
	// matching recipient set, present and verified Ed25519 signature.
	StateOfRecord
)

// OfRecordInput carries all inputs for VerifierOfRecord.VerifyOfRecord.
// All fields are required; there is no nil/zero-value path that skips any
// verification step.
type OfRecordInput struct {
	// Artifact is the signed file-of-record to verify. An unsigned artifact is
	// ErrUnsigned.
	Artifact artifact.Signed

	// ExpectedProjectID and ExpectedFileName bind the artifact to its caller-
	// asserted identity. A mismatch is ErrIdentityMismatch before the signature
	// check.
	ExpectedProjectID string
	ExpectedFileName  string

	// ExpectedRecipients must come from a signature-verified registry fetch.
	// Feeding artifact-self-declared recipients here is disallowed by
	// construction: there is no API path that extracts artifact.Recipients and
	// passes them here.
	ExpectedRecipients []rectypes.Recipient

	// TrustedSigners is required and must be non-empty. Each entry is
	// length-validated to exactly 32 bytes at the registry boundary; a
	// wrong-length entry yields ErrNoTrustedSigner before reaching verify.
	TrustedSigners map[string]ed25519.PublicKey

	// Counter must be produced by RegistryClient.CounterAuthority from a
	// signature-verified fetch. A zero-value CounterAuthority (Valid()==false)
	// is rejected as countertypes.ErrCounterReconcile; there is no nil-skip
	// path. The type is opaque: this package imports countertypes to read the
	// value via Valid() / LastAccepted() / Pending(); it cannot construct one.
	Counter countertypes.CounterAuthority
}

// VerifierOfRecord checks a signed file-of-record for any live read, CI
// decrypt, or deploy. The signature is mandatory. The trusted Ed25519 key must
// be present; if it cannot be acquired (offline, cache miss, parse error) this
// is a hard error, never a downgrade to unsigned.
//
// The interface is defined here, in the inner core package that needs the
// capability (consumer-defined interface).
type VerifierOfRecord interface {
	VerifyOfRecord(ctx context.Context, in OfRecordInput) error
}

// SubmissionInput carries all inputs for VerifierOfSubmission.VerifySubmission.
type SubmissionInput struct {
	// Artifact is the unsigned contributor submission to check structurally.
	Artifact artifact.Unsigned

	// ExpectedProjectID and ExpectedFileName bind the artifact to its identity.
	ExpectedProjectID string
	ExpectedFileName  string

	// ExpectedRecipients is structural-equality only, but is still bound by the
	// sourcing rule: it must come from a signature-verified registry fetch.
	// Feeding artifact-self-declared recipients here is disallowed by
	// construction and is covered by a required negative test.
	ExpectedRecipients []rectypes.Recipient
}

// SubmissionResult is returned by VerifySubmission. State is always
// StateUnverified; this value must never gate a prod decrypt/deploy.
type SubmissionResult struct {
	// State is always StateUnverified. VerifySubmission cannot return StateOfRecord.
	State VerificationState

	// KeyNames lists the key names present in the artifact (not secret values —
	// key names are not secret; used to detect add vs. replace submissions).
	KeyNames []string

	// Reason is a human-readable summary of the structural check outcome.
	Reason string
}

// VerifierOfSubmission performs a structural-only check of an unsigned
// contributor submission. It returns an explicit Unverified result. Its output
// may never gate a prod decrypt/deploy. There is no key parameter and no
// "treat as trusted" branch.
//
// Consumer-defined interface.
type VerifierOfSubmission interface {
	VerifySubmission(ctx context.Context, in SubmissionInput) (SubmissionResult, error)
}

// New returns the concrete verifier implementing both interfaces.
func New() interface {
	VerifierOfRecord
	VerifierOfSubmission
} {
	return &verifier{}
}

type verifier struct{}

func (v *verifier) VerifyOfRecord(_ context.Context, _ OfRecordInput) error {
	panic("not implemented") // stub: real implementation pending
}

func (v *verifier) VerifySubmission(_ context.Context, _ SubmissionInput) (SubmissionResult, error) {
	panic("not implemented") // stub: real implementation pending
}
