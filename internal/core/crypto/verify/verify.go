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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
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

// ContentSHA is the core-side content hash for a signed file-of-record. It is
// sha256 over a DETERMINISTIC byte sequence derived from the signed artifact:
// the canonical manifest stream (the exact bytes Ed25519 signed) followed by a
// US separator and the raw signature bytes. It is the post-sign hash: adding
// the signature changes the file, and this hash binds exactly the signed-file
// identity the next reader pins when reconciling the counter authority.
// Adapters that hold the raw on-disk bytes hash that raw buffer at the
// boundary; this is the core equivalent over the deterministic domain
// representation, with zero normalization beyond the encoder's fixed framing.
//
// It returns the empty string if the manifest cannot be encoded (malformed
// input); callers treat an empty SHA as a non-match (fail closed).
func ContentSHA(s artifact.Signed) string {
	man, err := manifestFrom(s.Values, s.Byreis)
	if err != nil {
		return ""
	}
	stream, err := manifest.Encode(man)
	if err != nil {
		return ""
	}
	sig, err := hex.DecodeString(s.ManifestSig.Sig)
	if err != nil {
		// An unsigned / malformed-sig artifact still has a stable identity over
		// its canonical stream alone (used only for read-only comparison).
		sig = nil
	}
	h := sha256.New()
	h.Write(stream)
	h.Write([]byte{0x1f})
	h.Write(sig)
	return hex.EncodeToString(h.Sum(nil))
}

// manifestFrom maps the artifact body + metadata to the canonical Manifest.
// It does NOT trust the artifact's own recipient block as authority; the
// recipient comparison against the verified registry is a separate step.
func manifestFrom(
	values map[string]artifact.EncryptedValue, meta artifact.Metadata,
) (manifest.Manifest, error) {
	m := manifest.Manifest{
		FormatVersion:   meta.FormatVersion,
		ProjectID:       meta.ProjectID,
		LogicalFileName: meta.File,
		Counter:         meta.Counter,
		Values:          make(map[string][]byte, len(values)),
	}
	for k, v := range values {
		m.Values[k] = []byte(v)
	}
	for _, re := range meta.Recipients {
		m.RecipientFingerprints = append(m.RecipientFingerprints, re.FP)
	}
	return m, nil
}

// expectedFPSet returns the sorted lowercase-hex fingerprint set derived from
// the caller-supplied ExpectedRecipients. The caller MUST source these from a
// signature-verified registry fetch, never from the artifact's own block.
func expectedFPSet(rs []rectypes.Recipient) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, hex.EncodeToString(r.Fingerprint[:]))
	}
	sort.Strings(out)
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// structuralCheck runs the verification steps shared by both entry points, in
// fixed fail-closed order: format-version validity, canonical-encoding
// derivability, project/file identity match, non-empty value set, and
// recipient-set equality against the verified registry set. It returns the
// recomputed manifest so VerifyOfRecord can reuse it for the signature step
// without re-deriving it.
func structuralCheck(
	values map[string]artifact.EncryptedValue,
	meta artifact.Metadata,
	expectedProjectID, expectedFileName string,
	expectedRecipients []rectypes.Recipient,
) (manifest.Manifest, error) {
	// format_version must be constrained and separator-free.
	if !manifest.FormatVersionValid(meta.FormatVersion) {
		return manifest.Manifest{}, fmt.Errorf("%w: %q", ErrFormatVersion, meta.FormatVersion)
	}

	man, err := manifestFrom(values, meta)
	if err != nil {
		return manifest.Manifest{}, err
	}

	// The canonical encoding must be derivable (rejects separator injection in
	// ids/key names and any internal inconsistency).
	if _, err := manifest.Encode(man); err != nil {
		if errors.Is(err, manifest.ErrFormatVersion) {
			return manifest.Manifest{}, fmt.Errorf("%w: %v", ErrFormatVersion, err)
		}
		return manifest.Manifest{}, fmt.Errorf("%w: %v", ErrManifestMismatch, err)
	}

	// project_id and file must match the caller's expected identity BEFORE any
	// signature work — defeats cross-file/cross-project transplant.
	if meta.ProjectID != expectedProjectID || meta.File != expectedFileName {
		return manifest.Manifest{}, fmt.Errorf(
			"%w: artifact is (%q,%q), caller expected (%q,%q)",
			ErrIdentityMismatch, meta.ProjectID, meta.File,
			expectedProjectID, expectedFileName)
	}

	// Each per-key digest and the key set are enforced implicitly: the
	// canonical stream is recomputed from the artifact values, so any
	// swapped/deleted/tampered ciphertext or key changes a per-key digest and
	// therefore the stream the signature must cover.
	if len(values) == 0 {
		return manifest.Manifest{}, fmt.Errorf(
			"%w: artifact has no values", ErrManifestMismatch)
	}

	// The recipient set must equal the caller's verified-registry set (NEVER
	// the artifact's self-declared block as authority). The artifact's display
	// block is compared too, so a recipient-strip is detected.
	wantFPs := expectedFPSet(expectedRecipients)
	gotFPs := sortedCopy(man.RecipientFingerprints)
	if !equalStringSets(gotFPs, wantFPs) {
		return manifest.Manifest{}, fmt.Errorf(
			"%w: artifact recipient set has %d entries, verified registry has %d",
			ErrRecipientMismatch, len(gotFPs), len(wantFPs))
	}

	return man, nil
}

// counterDecision implements the exhaustive verify-time counter decision. It
// is pure and total: every (signed-counter, last-accepted, pending)
// combination maps to exactly one outcome. A non-Valid() authority is a hard
// ErrCounterReconcile — there is NO nil/zero-value path that skips this step,
// so a forged or stale-cache counter authority can never pass.
func counterDecision(sc uint64, ca countertypes.CounterAuthority, contentSHA string) error {
	if !ca.Valid() {
		return fmt.Errorf("%w: counter authority is not from a signature-verified "+
			"registry fetch (zero-value/forged)", countertypes.ErrCounterReconcile)
	}
	la := ca.LastAccepted()
	p := ca.Pending()

	switch {
	case sc < la:
		return fmt.Errorf("%w: signed counter %d <= last accepted %d",
			countertypes.ErrReplay, sc, la)
	case sc == la:
		// Steady-state live read of the committed file.
		return nil
	case sc == la+1:
		switch {
		case p != nil && p.PendingCounter == sc && p.TargetArtifactSHA == contentSHA:
			// Legitimate in-flight: the merged-but-unbumped file whose
			// commit-bump has not yet landed. Verify SUCCEEDS for this exact
			// pinned artifact; a read-only caller does NOT drive CommitBump.
			return nil
		case p != nil && p.PendingCounter == sc && p.TargetArtifactSHA != contentSHA:
			return fmt.Errorf("%w: a different artifact than the recorded "+
				"write-ahead intent claims the pending counter %d",
				countertypes.ErrCounterReconcile, sc)
		default:
			// p == nil OR p.PendingCounter != sc: the merged-but-unbumped /
			// forged-advance / intent-lost state. Terminal, NOT auto-heal,
			// and explicitly NOT ErrReplay (these two must stay distinct: a
			// lost-intent advance is an integrity question, not an old file).
			return fmt.Errorf("%w: signed counter %d claims last+1 with no "+
				"matching write-ahead intent and no committed bump",
				countertypes.ErrCounterReconcile, sc)
		}
	default: // sc > la+1
		return fmt.Errorf("%w: signed counter %d skips ahead of authority "+
			"(last accepted %d)", countertypes.ErrCounterReconcile, sc, la)
	}
}

// VerifyOfRecord runs the full fail-closed ordered verification. The signature
// is MANDATORY; there is no nil/empty input that skips the counter or
// signature steps. It never writes anything (read-only): an in-flight
// OK-resume outcome is reported as success and the caller — never this
// method — drives any counter commit-bump.
func (v *verifier) VerifyOfRecord(ctx context.Context, in OfRecordInput) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verify cancelled: %w", err)
	}

	// Shared structural gate (format, identity, recipient set).
	man, err := structuralCheck(
		in.Artifact.Values, in.Artifact.Byreis,
		in.ExpectedProjectID, in.ExpectedFileName, in.ExpectedRecipients)
	if err != nil {
		return err
	}

	// Counter decision vs the registry counter authority. The opaque value is
	// consumed read-only; a zero-value/forged one is !Valid() and hard-errors.
	// This package has no constructor for it, so it cannot be fabricated here.
	if cErr := counterDecision(man.Counter, in.Counter, ContentSHA(in.Artifact)); cErr != nil {
		return cErr
	}

	// The manifest MUST be signed. There is no downgrade-to-unsigned path.
	if in.Artifact.ManifestSig.Signer == "" || in.Artifact.ManifestSig.Sig == "" {
		return fmt.Errorf("%w", ErrUnsigned)
	}

	// The signer id must resolve in the non-empty, length-validated trusted
	// signer set. An empty set or an unknown signer is terminal — never a
	// downgrade to unsigned.
	if len(in.TrustedSigners) == 0 {
		return fmt.Errorf("%w: TrustedSigners is empty", ErrNoTrustedSigner)
	}
	pub, ok := in.TrustedSigners[in.Artifact.ManifestSig.Signer]
	if !ok {
		return fmt.Errorf("%w: signer id %q not in the verified registry signer set",
			ErrNoTrustedSigner, in.Artifact.ManifestSig.Signer)
	}
	if len(pub) != ed25519.PublicKeySize {
		// A wrong-length signer key is an unusable/absent signer, surfaced as
		// ErrNoTrustedSigner (not a confusing ErrSignatureInvalid later).
		return fmt.Errorf("%w: signer %q key is %d bytes (want 32)",
			ErrNoTrustedSigner, in.Artifact.ManifestSig.Signer, len(pub))
	}

	// Ed25519 verify over the recomputed canonical stream.
	sig, err := hexDecodeSig(in.Artifact.ManifestSig.Sig)
	if err != nil {
		return fmt.Errorf("%w: signature is not valid hex", ErrSignatureInvalid)
	}
	if err := sign.Verify(pub, man, sig); err != nil {
		if errors.Is(err, sign.ErrBadSignerKeyLength) {
			return fmt.Errorf("%w: %v", ErrNoTrustedSigner, err)
		}
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}

func hexDecodeSig(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// VerifySubmission runs the structural gate only on an UNSIGNED contributor
// submission. It NEVER runs the counter or signature steps and can NEVER
// return StateOfRecord. The recipient check still binds: ExpectedRecipients
// MUST be sourced from a signature-verified registry fetch.
func (v *verifier) VerifySubmission(
	ctx context.Context, in SubmissionInput,
) (SubmissionResult, error) {
	if err := ctx.Err(); err != nil {
		return SubmissionResult{}, fmt.Errorf("verify cancelled: %w", err)
	}
	if _, err := structuralCheck(
		in.Artifact.Values, in.Artifact.Byreis,
		in.ExpectedProjectID, in.ExpectedFileName, in.ExpectedRecipients,
	); err != nil {
		return SubmissionResult{State: StateUnverified}, err
	}
	keyNames := make([]string, 0, len(in.Artifact.Values))
	for k := range in.Artifact.Values {
		keyNames = append(keyNames, k)
	}
	sort.Strings(keyNames)
	// State is ALWAYS StateUnverified. There is no code path to StateOfRecord:
	// a submission carries no signature and the registry decides the counter at
	// merge — VerifySubmission proves structure + recipient-set shape ONLY.
	return SubmissionResult{
		State:    StateUnverified,
		KeyNames: keyNames,
		Reason:   "structural check passed; submission is unsigned and not trust-equivalent",
	}, nil
}
