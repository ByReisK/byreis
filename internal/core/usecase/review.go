package usecase

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
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

// ReviewResult is the rendered, decrypted review surface. PinnedSHA is the
// S_unsigned content pin the admin passes to `merge --expect`.
type ReviewResult struct {
	Ref           git.PRRef
	Author        string
	Justification string
	Action        string
	Key           string
	SecretsPath   string
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
}

// ReviewDeps bundles the injected ports for the Review use-case.
type ReviewDeps struct {
	Git           git.GitProvider
	Decryptor     decrypt.Decryptor
	IDLoader      identity.Loader
	ArtifactCodec ArtifactCodec
	Mode          ModeGate
	Audit         audit.Logger
	Log           logging.Logger
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
		Plaintext:     plaintext,
		KeyNames:      keyNames,
		PinnedSHA:     pinned,
	}, nil
}

// Compile-time assertions that the consumed core ports are satisfied by the
// canonical implementations (defense-in-depth against signature drift).
var (
	_ Reviewer                = (*reviewUseCase)(nil)
	_ verify.VerifierOfRecord = verify.New()
)
