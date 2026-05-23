package usecase

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/logging"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// Sentinel errors owned by the review/merge use-cases. Each wraps with %w and
// carries an actionable hint for the CLI layer to surface. No error ever
// contains plaintext, ciphertext, or key material.
var (
	// ErrReviewDecode is returned when the fetched artifact bytes cannot be
	// decoded into a domain artifact. Review never falls back to the PR
	// description: an undecodable artifact is a hard refusal.
	ErrReviewDecode = errors.New(
		"submission artifact could not be decoded — the PR branch may be " +
			"malformed; ask the contributor to re-run `byreis submit`")

	// ErrReviewNoIdentity is returned when no admin decrypting identity is
	// available. Review must decrypt the artifact to show plaintext; without an
	// identity it fails closed rather than approving from the PR description.
	ErrReviewNoIdentity = errors.New(
		"no admin identity available to decrypt the submission for review — " +
			"run `byreis auth login` or check that your admin key is present")
)

// ReviewInput carries the inputs for a single Review call.
type ReviewInput struct {
	// Ref identifies the submission PR.
	Ref git.PRRef
	// ExpectedProjectID and ExpectedFileName are the caller-asserted identity
	// the artifact's signed/embedded ids are checked against (display only at
	// review; the binding identity check is enforced at merge/verify).
	ExpectedProjectID string
	ExpectedFileName  string
}

// KeyReviewLine is the per-key review display line for one submitted key. It
// carries the key's own add-vs-replace action (from the submission metadata)
// and the result of a per-key value-validation pass. It never carries the
// plaintext value, and its ValidationMsg never includes plaintext.
type KeyReviewLine struct {
	// Key is the submitted key name. Not secret.
	Key string
	// Action is this key's own action ("add" or "replace").
	Action string
	// ValidationOK reports whether the per-key validation pass accepted the
	// decrypted value. When no validator is wired, it is true (not asserted).
	ValidationOK bool
	// ValidationMsg is a non-secret, human-readable reason when ValidationOK is
	// false; empty otherwise. It never contains the plaintext value.
	ValidationMsg string
}

// ReviewResult is the rendered, decrypted review surface. PinnedSHA is the
// S_unsigned content pin the admin passes to `merge --expect`.
type ReviewResult struct {
	Ref           git.PRRef
	Author        string
	Justification string
	// Action and Key are the single-key (schema_version 1) scalar fields, kept
	// for back-compat with single-key submissions. For a bulk submission read
	// PerKey instead.
	Action      string
	Key         string
	SecretsPath string
	// PerKey is the ordered per-key review view, in the contributor's file
	// order, for both single-key and bulk submissions (a single-key submission
	// yields a one-element list). Each line carries its own action and a
	// per-key validation result.
	PerKey []KeyReviewLine
	// Plaintext maps key name → decrypted plaintext value, decrypted from the
	// fetched ARTIFACT bytes (never the PR diff/description). The caller must
	// zeroize these after rendering.
	Plaintext map[string]string
	// KeyNames is the sorted set of key names present in the artifact (not
	// secret; used for ADD/REPLACE rendering).
	KeyNames []string
	// PinnedSHA is the content pin of exactly the reviewed (unsigned) artifact
	// bytes: the value the admin passes to `merge --expect`. A branch re-push
	// between review and merge changes this and merge fails closed.
	PinnedSHA string
	// ProjectID is the logical project identifier embedded in the artifact. It
	// is the value the admin passes to `merge --project` (or the TUI approve
	// action passes as MergeInput.ExpectedProjectID). Not secret; sourced from
	// the artifact's Byreis.ProjectID field.
	ProjectID string
	// FileName is the logical file name embedded in the artifact. It is the
	// value the admin passes to `merge --file` (or the TUI approve action
	// passes as MergeInput.ExpectedFileName). Not secret; sourced from the
	// artifact's Byreis.File field.
	FileName string
}

// ValueValidator is the consumer-defined per-key value-validation port for the
// review per-key display. It is optional: when nil, each key reports OK (the
// content is simply not asserted at review time). Defined here so Review does
// not depend on the validator package directly and the rule is unit-mockable.
type ValueValidator interface {
	// ValidateValue returns a non-nil error if the decrypted value is
	// unacceptable. The returned error must not contain the plaintext value.
	ValidateValue(value string) error
}

// ReviewDeps bundles the injected ports for the Review use-case.
type ReviewDeps struct {
	Git           git.GitProvider
	Decryptor     decrypt.Decryptor
	IDLoader      IDLoader
	ArtifactCodec ArtifactCodec
	Mode          ModeGate
	// Validator is the optional per-key value-validation port for the per-key
	// review display. When nil, each key reports OK (content not asserted).
	Validator ValueValidator
	Audit     audit.Logger
	Log       logging.Logger
}

// Reviewer is the consumer-defined interface for the admin Review use-case.
type Reviewer interface {
	// Review fetches the submission, decrypts the value(s) from the ARTIFACT
	// bytes (never the PR diff/description), and returns the rendered surface
	// plus the pinned S_unsigned content SHA. ADMIN-only: denied by the mode
	// gate in CONTRIBUTOR mode before any fetch or decrypt.
	Review(ctx context.Context, in ReviewInput) (ReviewResult, error)
}

type reviewUseCase struct {
	d ReviewDeps
}

// NewReviewer returns a Reviewer. All collaborators are injected; nil optional
// sinks fall back to the no-op discard so core never panics on a missing sink.
func NewReviewer(d ReviewDeps) (Reviewer, error) {
	if d.Git == nil || d.Decryptor == nil || d.IDLoader == nil ||
		d.ArtifactCodec == nil || d.Mode == nil {
		return nil, errors.New(
			"usecase.NewReviewer: a required port is nil — wire Git, " +
				"Decryptor, IDLoader, ArtifactCodec and Mode")
	}
	if d.Audit == nil {
		d.Audit = audit.Discard
	}
	if d.Log == nil {
		d.Log = logging.Discard
	}
	return &reviewUseCase{d: d}, nil
}

// Review is ADMIN-only and decrypts from the artifact bytes, never the PR diff.
//
// Order:
//  1. Mode gate — denied in CONTRIBUTOR before any git fetch or decrypt.
//  2. Fetch the submission (artifact bytes + meta).
//  3. Decode the artifact from the EXACT fetched bytes.
//  4. Load the admin identity and decrypt the value(s) from the artifact.
//  5. Emit the pinned S_unsigned content SHA over the fetched artifact bytes.
func (r *reviewUseCase) Review(ctx context.Context, in ReviewInput) (ReviewResult, error) {
	if err := ctx.Err(); err != nil {
		return ReviewResult{}, fmt.Errorf("review cancelled: %w", err)
	}

	// (1) Mode gate FIRST: a contributor is denied by policy, not
	// attempted-then-failed. No git fetch or decrypt happens on denial.
	if err := r.d.Mode.Allow(mode.CommandReview); err != nil {
		return ReviewResult{}, fmt.Errorf("review not permitted: %w", err)
	}

	// (2) Fetch the submission. GetSubmission returns the EXACT fetched bytes
	// and the parsed SubmissionMeta from the PR body.
	sub, err := r.d.Git.GetSubmission(ctx, in.Ref)
	if err != nil {
		return ReviewResult{}, fmt.Errorf("fetching submission failed: %w", err)
	}

	// (3) Decode the artifact from the EXACT fetched bytes. Review NEVER reads
	// the value from the PR diff/description: an undecodable artifact is a hard
	// refusal, not a fall-back to the body.
	art, err := r.d.ArtifactCodec.DecodeSigned(sub.ArtifactBytes)
	if err != nil {
		// A submission may legitimately be unsigned; decode as unsigned and
		// promote to a Signed shell (no manifest_sig) so the decrypt path is
		// uniform. The recipient/identity material is unchanged.
		uns, uErr := r.d.ArtifactCodec.DecodeUnsigned(sub.ArtifactBytes)
		if uErr != nil {
			return ReviewResult{}, fmt.Errorf("%w: %v", ErrReviewDecode, err)
		}
		art = artifact.Signed{Values: uns.Values, Byreis: uns.Byreis}
	}

	// (4) Load the admin identity and decrypt the value(s) FROM THE ARTIFACT.
	id, err := r.d.IDLoader.Load(ctx)
	if err != nil {
		return ReviewResult{}, fmt.Errorf("%w: %v", ErrReviewNoIdentity, err)
	}
	if id == nil {
		return ReviewResult{}, fmt.Errorf("%w", ErrReviewNoIdentity)
	}
	plaintext, err := r.d.Decryptor.Decrypt(ctx, art, id)
	if err != nil {
		return ReviewResult{}, fmt.Errorf("decrypting submission for review failed: %w", err)
	}

	keyNames := make([]string, 0, len(art.Values))
	for k := range art.Values {
		keyNames = append(keyNames, k)
	}
	sort.Strings(keyNames)

	// Build the per-key view from the submission metadata's normalised key list
	// (file order, version-agnostic), running a per-key validation pass over the
	// decrypted value when a validator is wired. The validation message never
	// includes the plaintext value.
	perKey := r.buildPerKey(sub.Meta.NormalisedKeys(), plaintext)

	// (5) Pin EXACTLY the reviewed (unsigned) artifact bytes. The git adapter
	// computed this over the raw fetched buffer; review echoes it as the
	// `merge --expect` pin so a branch re-push between review and merge is
	// caught fail-closed at merge.
	pinned := string(sub.ArtifactSHA)

	// Audit the review (no secret material; key names only).
	if aErr := r.d.Audit.Append(ctx, audit.Event{
		Kind:      audit.EventKindReview,
		ProjectID: in.ExpectedProjectID,
		FileName:  in.ExpectedFileName,
		KeyName:   sub.Meta.Key,
		PRRef:     fmt.Sprintf("%s#%d", sub.Ref.Project, sub.Ref.Number),
		Outcome:   "ok",
		Details:   map[string]string{"action": sub.Meta.Action, "pinned_sha": pinned},
	}); aErr != nil {
		r.d.Log.Log(ctx, logging.LevelWarn,
			"review completed but audit append failed",
			"project", in.ExpectedProjectID, "pr", fmt.Sprintf("%d", sub.Ref.Number),
			"error", aErr.Error())
	}

	return ReviewResult{
		Ref:           sub.Ref,
		Author:        sub.Author,
		Justification: sub.Justification,
		Action:        sub.Meta.Action,
		Key:           sub.Meta.Key,
		SecretsPath:   sub.Meta.SecretsPath,
		PerKey:        perKey,
		Plaintext:     plaintext,
		KeyNames:      keyNames,
		PinnedSHA:     pinned,
		ProjectID:     art.Byreis.ProjectID,
		FileName:      art.Byreis.File,
	}, nil
}

// buildPerKey assembles the ordered per-key review view from the submission's
// normalised (key, action) list, validating each decrypted value when a
// validator is wired. A missing plaintext for a listed key is reported as a
// validation failure (the metadata and the artifact disagree) rather than
// silently OK. No plaintext value is ever placed in a ValidationMsg.
func (r *reviewUseCase) buildPerKey(keys []git.KeyAction, plaintext map[string]string) []KeyReviewLine {
	lines := make([]KeyReviewLine, 0, len(keys))
	for _, ka := range keys {
		line := KeyReviewLine{Key: ka.Key, Action: ka.Action, ValidationOK: true}

		value, present := plaintext[ka.Key]
		switch {
		case !present:
			line.ValidationOK = false
			line.ValidationMsg = "no decrypted value present for this key " +
				"(the submission metadata and the artifact disagree)"
		case r.d.Validator != nil:
			if err := r.d.Validator.ValidateValue(value); err != nil {
				line.ValidationOK = false
				line.ValidationMsg = err.Error()
			}
		}
		lines = append(lines, line)
	}
	return lines
}

// Compile-time assertions that the consumed core ports are satisfied by the
// canonical implementations (defense-in-depth against signature drift).
var (
	_ Reviewer                = (*reviewUseCase)(nil)
	_ verify.VerifierOfRecord = verify.New()
)
