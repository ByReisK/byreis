package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/logging"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// Sentinel errors owned by the Merge use-case.
var (
	// ErrMergeRecipientsNotVerified is returned when the admin recipient set
	// did not come from a signature-verified registry fetch (SourceVerified ==
	// false) or was served stale. Merge re-encrypts ONLY to a verified set; an
	// unverified/stale set is a hard refusal, never a downgrade.
	ErrMergeRecipientsNotVerified = errors.New(
		"refusing to merge: admin recipient set is not signature-verified " +
			"(stale or unsigned registry) — run `byreis doctor` and retry when " +
			"the registry is reachable and verified")

	// ErrMergePinMismatch is returned BEFORE any write when the review pin was
	// not supplied or does not match the on-PR artifact: the admin must re-run
	// review to re-pin before signing.
	ErrMergePinMismatch = errors.New(
		"refusing to merge: the review pin is missing or does not match the " +
			"on-PR artifact — re-run `byreis review --pr N` to re-pin the " +
			"current artifact before merging")

	// ErrMergePostIntegrity is the POST-merge terminal alarm: the live file is
	// already committed but failed VerifyOfRecord or the round-trip-all check.
	// This is NOT a silent pass — it is a loud alarm with a reconciliation
	// hint; the live file is committed by now and an operator must reconcile.
	ErrMergePostIntegrity = errors.New(
		"ALARM: the merged file-of-record failed its post-merge integrity " +
			"check — the file is already committed; do NOT assume the secret is " +
			"safe. Reconcile immediately: see `byreis admin counter reconcile` " +
			"and verify the live secrets file against the registry")

	// ErrMergeFilePathMismatch is returned BEFORE the write-ahead step when the
	// submission's declared write path does not resolve to the registry-
	// configured path for the SIGNED manifest's logical_file_name (or that
	// configured path cannot be resolved at all). The write target identity is
	// read from the verified, signed manifest — never from the submission's
	// self-declared metadata — so a tampered submission cannot redirect the
	// signed file-of-record to an attacker-chosen path. This is a pre-merge
	// structural-invalid abort: nothing is recorded and the live tree is
	// untouched.
	ErrMergeFilePathMismatch = errors.New(
		"refusing to merge: the submission's target secrets path does not " +
			"match the registry-configured path for the signed file — the " +
			"submission may be tampered or the project registry config is out " +
			"of date; verify the project config in the admin registry and " +
			"re-open the submission against the configured path")

	// ErrMergeReEncrypt is returned when the re-encrypt-at-merge could not
	// produce a fresh whole-file ciphertext. Fail-closed; no blind sign.
	ErrMergeReEncrypt = errors.New(
		"refusing to merge: re-encrypting the submission to the current " +
			"verified admin set failed — resolve the registry/recipient error " +
			"and retry; byreis will not sign a stale-recipient artifact")
)

// MergeInput carries the inputs for a single Merge call.
type MergeInput struct {
	Ref git.PRRef
	// ExpectSHA is the review pin (S_unsigned). Merge fails closed BEFORE any
	// write if the on-PR artifact SHA no longer equals this value.
	ExpectSHA string
	// ExpectedProjectID and ExpectedFileName bind the artifact identity.
	ExpectedProjectID string
	ExpectedFileName  string
	// CommitMessage is the protected-branch commit message for the
	// file-of-record. Never a secret.
	CommitMessage string
}

// MergeResult is returned by a successful (or resumed) Merge.
type MergeResult struct {
	MergedCommit        string
	LiveFileSHA         string
	SignedFileCommitted bool
	SignedFileCommitSHA string
	// AlreadyApplied is true iff this merge resumed a prior attempt's
	// already-committed signed file (same IdempotencyKey) instead of creating
	// a duplicate commit.
	AlreadyApplied bool
	// ReEncrypted is true iff the stale-recipient path produced a FRESH
	// whole-file re-encrypt of every value before signing.
	ReEncrypted bool
	// FinalCounter is the counter the signed file-of-record carries (== last
	// accepted + 1).
	FinalCounter uint64
}

// MergeDeps bundles the injected ports for the Merge use-case.
type MergeDeps struct {
	Git           git.GitProvider
	Decryptor     decrypt.Decryptor
	Encryptor     encrypt.Encryptor
	IDLoader      IDLoader
	ArtifactCodec ArtifactCodec
	Recipients    RecipientSource
	Counter       CounterStore
	Signer        ManifestSigner
	Verifier      verify.VerifierOfRecord
	Mode          ModeGate
	Audit         audit.Logger
	Log           logging.Logger
	// RotationGuard is optional. When non-nil, Merge consults it before each
	// CommitBump: if a rotation is in flight for the (project, file) pair, the
	// CommitBump is refused with rotate.ErrCommitBumpRejectedRotationInFlight
	// so the operator can retry after the rotation completes. When nil the
	// check is skipped (backwards-compatible with pre-rotation deployments).
	RotationGuard RotationGuard
}

// Merger is the consumer-defined interface for the admin Merge use-case.
type Merger interface {
	// Merge runs the strictly-ordered write-ahead merge sequence (steps 1-7).
	// ADMIN-only: denied by the mode gate in CONTRIBUTOR mode before any fetch,
	// decrypt, sign, or write.
	Merge(ctx context.Context, in MergeInput) (MergeResult, error)
}

type mergeUseCase struct {
	d MergeDeps
}

// NewMerger returns a Merger. All collaborators are injected; nil optional
// sinks fall back to the no-op discard.
func NewMerger(d MergeDeps) (Merger, error) {
	if d.Git == nil || d.Decryptor == nil || d.Encryptor == nil ||
		d.IDLoader == nil || d.ArtifactCodec == nil || d.Recipients == nil ||
		d.Counter == nil || d.Signer == nil || d.Verifier == nil || d.Mode == nil {
		return nil, errors.New(
			"usecase.NewMerger: a required port is nil — wire Git, Decryptor, " +
				"Encryptor, IDLoader, ArtifactCodec, RecipientSource, " +
				"CounterStore, ManifestSigner, VerifierOfRecord and Mode")
	}
	if d.Audit == nil {
		d.Audit = audit.Discard
	}
	if d.Log == nil {
		d.Log = logging.Discard
	}
	return &mergeUseCase{d: d}, nil
}

// deriveIdempotencyKey is the deterministic, content-bound resume token. It is
// a stable hash over (project, PR number, ExpectSHA, post-sign content SHA) —
// NOT random and NOT wall-clock. A retry of the SAME merge re-derives the SAME
// key (so the adapter detects-before-write and resumes); a DIFFERENT artifact
// yields a different key and is never confused with a resume.
func deriveIdempotencyKey(ref git.PRRef, expectSHA, signedContentSHA string) string {
	h := sha256.New()
	h.Write([]byte(ref.Project))
	h.Write([]byte{0x1f})
	h.Write([]byte(strconv.Itoa(ref.Number)))
	h.Write([]byte{0x1f})
	h.Write([]byte(expectSHA))
	h.Write([]byte{0x1f})
	h.Write([]byte(signedContentSHA))
	return hex.EncodeToString(h.Sum(nil))
}

func fingerprintSet(rs []rectypes.Recipient) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, hex.EncodeToString(r.Fingerprint[:]))
	}
	sort.Strings(out)
	return out
}

// checkRotationGuardBeforeCommitBump runs the rotation-in-flight consultation
// contract: nil guard (legacy / pre-rotation deployment) returns nil and lets
// CommitBump proceed; a non-nil guard is consulted exactly once and any error
// OR an inFlight=true verdict refuses the bump with
// rotate.ErrCommitBumpRejectedRotationInFlight wrapped via %w. Fail-closed on
// uncertainty: a probe error is treated as "rotation possibly in flight" and
// refuses, preserving the rotation's N-file atomic counter commit.
//
// Factored out of the Merger step-6 path so the contract can be exercised by
// a focused unit test without driving the full merge pipeline; the production
// semantics are identical to the inline form they replaced.
func checkRotationGuardBeforeCommitBump(ctx context.Context, g RotationGuard, projectID, fileName string) error {
	if g == nil {
		return nil
	}
	inFlight, rgErr := g.RotationInFlight(ctx, projectID, fileName)
	if rgErr != nil {
		return fmt.Errorf(
			"%w: rotation-in-flight check failed before CommitBump for "+
				"project=%q file=%q: %v — run `byreis admin rotation reconcile` "+
				"to inspect state",
			rotate.ErrCommitBumpRejectedRotationInFlight,
			projectID, fileName, rgErr)
	}
	if inFlight {
		return fmt.Errorf(
			"%w: project=%q file=%q",
			rotate.ErrCommitBumpRejectedRotationInFlight,
			projectID, fileName)
	}
	return nil
}

func equalSets(a, b []string) bool {
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

// Merge executes the strictly-ordered write-ahead transactional merge. Each
// step is a hard gate; none may be reordered.
//
//  1. Mode gate (ADMIN-only) + review-pin confirm (ExpectSHA present,
//     matches the on-PR artifact) — else abort, live file UNTOUCHED.
//  2. Fresh SourceVerified registry fetch; recompute expectedRecipients.
//  3. If the submission's recipient set != current verified set, re-encrypt
//     at merge — a FRESH whole-file age.Encrypt of EVERY value from plaintext
//     (zero prior ciphertext reused); the admin re-pins + re-confirms the new
//     artifact, never signs blindly.
//  4. CounterAuthority (SourceVerified only); next = LastAccepted + 1.
//     4a. Build the signed bytes (Ed25519 sign over the pinned post-step-3
//     artifact); compute S_signed via the SHARED ContentSHA. Cross-check the
//     submission's declared write path against the registry-configured path
//     for the SIGNED logical file (fail-closed pre-merge abort on mismatch or
//     an unresolvable configured path). Then RecordPendingBump (write-ahead)
//     BEFORE the merge. A matching open pending => resume; any other mismatch
//     => ErrCounterReconcile (terminal).
//  5. MergeSubmission(--expect, SignedBytes) — fails closed ErrArtifactMoved
//     if the on-PR SHA moved. On the step-5-done/step-6-failed window the
//     rollback DRIVER acts only via a registry-pending-bound RollbackInput.
//  6. CommitBump (advance + clear, atomic) ONLY after the merge lands.
//  7. Post-merge mandatory VerifyOfRecord + round-trip-all; failure is a LOUD
//     terminal alarm (the live file is already committed) — never a silent
//     pass. This is DISTINCT from the pre-merge structural abort (step 1/2/3),
//     which leaves the live file UNTOUCHED.
func (m *mergeUseCase) Merge(ctx context.Context, in MergeInput) (MergeResult, error) {
	if err := ctx.Err(); err != nil {
		return MergeResult{}, fmt.Errorf("merge cancelled: %w", err)
	}

	// (1) Mode gate FIRST — a contributor is denied by policy, not
	// attempted-then-failed. No fetch, decrypt, sign, or write on denial.
	if err := m.d.Mode.Allow(mode.CommandMerge); err != nil {
		return MergeResult{}, fmt.Errorf("merge not permitted: %w", err)
	}

	// (1) Review-pin confirm. A missing pin is a hard pre-merge refusal: the
	// admin must have reviewed and pinned. The live file is UNTOUCHED.
	if in.ExpectSHA == "" {
		return MergeResult{}, fmt.Errorf("%w: no --expect pin supplied", ErrMergePinMismatch)
	}

	sub, err := m.d.Git.GetSubmission(ctx, in.Ref)
	if err != nil {
		return MergeResult{}, fmt.Errorf("fetching submission failed: %w", err)
	}

	// Pre-merge structural-invalid abort: the on-PR artifact moved since
	// review. Live file UNTOUCHED, no write attempted (this is the pre-merge
	// row, distinct from the post-merge alarm).
	if string(sub.ArtifactSHA) != in.ExpectSHA {
		return MergeResult{}, fmt.Errorf("%w", ErrMergePinMismatch)
	}

	// Pre-merge structural-invalid abort: the artifact cannot even be decoded.
	// Live file UNTOUCHED.
	uns, err := m.d.ArtifactCodec.DecodeUnsigned(sub.ArtifactBytes)
	if err != nil {
		return MergeResult{}, fmt.Errorf("%w: %v", ErrReviewDecode, err)
	}

	// (2) Fresh SourceVerified registry fetch; recompute expectedRecipients.
	rec, err := m.d.Recipients.ExpectedRecipients(ctx, in.ExpectedProjectID)
	if err != nil {
		return MergeResult{}, fmt.Errorf("resolving verified admin recipients failed: %w", err)
	}
	if len(rec.Set) == 0 || !rec.SourceVerified || rec.Stale {
		return MergeResult{}, fmt.Errorf("%w", ErrMergeRecipientsNotVerified)
	}
	if len(rec.TrustedSigners) == 0 {
		return MergeResult{}, fmt.Errorf(
			"%w: the verified registry returned no trusted signer keys",
			ErrMergeRecipientsNotVerified)
	}

	// Load the admin identity once: it is needed for the post-merge
	// round-trip-all and (conditionally) the re-encrypt decrypt.
	idForRoundTrip, err := m.d.IDLoader.Load(ctx)
	if err != nil {
		return MergeResult{}, fmt.Errorf("%w: %v", ErrReviewNoIdentity, err)
	}
	if idForRoundTrip == nil {
		return MergeResult{}, fmt.Errorf("%w", ErrReviewNoIdentity)
	}

	// (3) Re-encrypt-at-merge IFF the submission's recipient set != the
	// current verified set. The re-encrypt is a FRESH whole-file age.Encrypt
	// of EVERY value from plaintext — zero prior ciphertext is spliced,
	// re-wrapped, or carried forward. The admin re-pins + re-confirms; it
	// never signs the carried-forward artifact blindly.
	submittedFPs := submittedRecipientFPs(uns)
	verifiedFPs := fingerprintSet(rec.Set)
	body := artifact.Signed{Values: uns.Values, Byreis: uns.Byreis}
	reEncrypted := false
	if !equalSets(submittedFPs, verifiedFPs) {
		fresh, rErr := m.reEncryptWholeFile(ctx, uns, rec, idForRoundTrip)
		if rErr != nil {
			return MergeResult{}, fmt.Errorf("%w: %v", ErrMergeReEncrypt, rErr)
		}
		body = fresh
		reEncrypted = true
	}

	// Write-target identity cross-check, GATING the write-ahead. The signed
	// file-of-record's path identity is read from the VERIFIED manifest body
	// (body.Byreis.File) — NEVER from the submission's self-declared
	// sub.Meta.SecretsPath. The submission's declared write path MUST resolve to
	// the registry-configured path for that signed logical file, scoped to the
	// verified project, where the configured map arrives on the SAME
	// signature-verified registry fetch as the recipient set. An unresolvable
	// configured path or any mismatch is a fail-closed pre-merge structural
	// abort: no signature produced, no pending recorded, no merge, the live tree
	// untouched. This denies a tampered submission the ability to redirect the
	// signed file-of-record to an attacker-chosen path.
	configuredPath, ok := rec.ConfiguredFiles[body.Byreis.File]
	if !ok || configuredPath == "" {
		return MergeResult{}, fmt.Errorf(
			"%w: the signed logical file %q has no registry-configured path in "+
				"the verified project config",
			ErrMergeFilePathMismatch, body.Byreis.File)
	}
	if sub.Meta.SecretsPath != configuredPath {
		return MergeResult{}, fmt.Errorf(
			"%w: submission declared %q but the signed logical file %q is "+
				"configured to %q",
			ErrMergeFilePathMismatch, sub.Meta.SecretsPath,
			body.Byreis.File, configuredPath)
	}

	// (4) CounterAuthority — SourceVerified only; next = LastAccepted + 1. A
	// non-Valid() authority is fail-closed at step 4a via the shared decision.
	auth, err := m.d.Counter.CounterAuthority(ctx, in.ExpectedProjectID, in.ExpectedFileName)
	if err != nil {
		return MergeResult{}, fmt.Errorf("reading counter authority failed: %w", err)
	}
	if !auth.Valid() {
		return MergeResult{}, fmt.Errorf(
			"%w: counter authority is not from a signature-verified registry fetch",
			ErrMergeRecipientsNotVerified)
	}
	next := auth.LastAccepted() + 1

	// (4b conceptually, then 4a) Build the canonical manifest over the pinned
	// post-step-3 body, set the next counter, and Ed25519-sign it. The signed
	// file-of-record is the bytes the next reader pins.
	body.Byreis.Counter = next
	man := manifestFromSigned(body)
	signerID, sig, err := m.d.Signer.Sign(ctx, man)
	if err != nil {
		return MergeResult{}, fmt.Errorf("signing the file-of-record failed: %w", err)
	}
	body.ManifestSig = artifact.ManifestSig{
		Signer: signerID,
		Sig:    hex.EncodeToString(sig),
	}

	// S_signed via the SHARED ContentSHA — the SAME function the registry
	// adapter records pending.target_artifact_sha with and VerifyOfRecord
	// compares at step 4. A raw-buffer / re-impl here makes the OK-resume row
	// unreachable; we deliberately call the one shared function.
	sSigned := verify.ContentSHA(body)
	if sSigned == "" {
		return MergeResult{}, fmt.Errorf("%w: signed file-of-record is not encodable", ErrMergeReEncrypt)
	}

	signedBytes, err := m.d.ArtifactCodec.EncodeSigned(body)
	if err != nil {
		return MergeResult{}, fmt.Errorf("serialising the signed file-of-record failed: %w", err)
	}

	prRef := fmt.Sprintf("%s#%d", in.Ref.Project, in.Ref.Number)

	// (4a) WRITE-AHEAD: record the post-sign S_signed BEFORE the merge. A
	// matching open pending (same counter + same S_signed) is a safe resume;
	// any other mismatch is countertypes.ErrCounterReconcile (terminal,
	// surfaced by the port). The live file is UNTOUCHED if this fails.
	if err := m.d.Counter.RecordPendingBump(ctx, PendingBumpInput{
		ProjectID:         in.ExpectedProjectID,
		FileName:          in.ExpectedFileName,
		PendingCounter:    next,
		TargetArtifactSHA: sSigned,
		TargetPR:          prRef,
	}); err != nil {
		return MergeResult{}, fmt.Errorf("recording the write-ahead pending bump failed: %w", err)
	}

	// IdempotencyKey: deterministic, content-bound. A retry of the SAME merge
	// re-derives the SAME key (detect-before-write resume); a DIFFERENT
	// artifact yields a different key and is never confused with a resume.
	idemKey := deriveIdempotencyKey(in.Ref, in.ExpectSHA, sSigned)

	// (5) MergeSubmission(--expect, SignedBytes). Fails closed
	// ErrArtifactMoved if the on-PR SHA moved between review and now. On a
	// non-merge failure the write-ahead pending is LEFT IN PLACE so a retry is
	// a safe resume; if a signed-file commit landed but the PR-merge did not,
	// the rollback driver acts ONLY via a registry-pending-bound RollbackInput.
	mr, mergeErr := m.d.Git.MergeSubmission(ctx, git.MergeInput{
		Ref:            in.Ref,
		ExpectSHA:      git.ArtifactSHA(in.ExpectSHA),
		SignedBytes:    signedBytes,
		CommitMessage:  in.CommitMessage,
		SecretsPath:    sub.Meta.SecretsPath,
		IdempotencyKey: idemKey,
	})
	if mergeErr != nil {
		// step-5-done / step-6-failed window: a signed-file commit landed but
		// the PR-merge did not. The merge-state authority is the registry
		// pending/CommitBump state (NOT a git-side PR-merged bool): since
		// CommitBump has NOT been recorded for this attempt, drive the
		// rollback bound to THIS attempt's pending identity.
		if mr.SignedFileCommitted && mr.SignedFileCommitSHA != "" {
			if rbErr := m.d.Git.RollbackSignedFile(ctx, git.RollbackInput{
				Ref:             in.Ref,
				CommitSHA:       mr.SignedFileCommitSHA,
				PendingIdentity: sSigned,
			}); rbErr != nil {
				// Ambiguous rollback is terminal-manual: surface it loudly,
				// do not auto-rewrite history. The pending is left in place.
				return MergeResult{}, fmt.Errorf(
					"merge failed and the orphaned signed-file commit could not "+
						"be safely rolled back: %w (original merge error: %v)",
					rbErr, mergeErr)
			}
		}
		return MergeResult{}, fmt.Errorf("merging the submission failed: %w", mergeErr)
	}

	// (6) COMMIT-BUMP — advance + clear pending atomically, ONLY after the
	// merge landed. If this cannot be durably committed the merge is NOT
	// final: a re-run resumes from the matching pending and completes the
	// bump. A read-only/VerifyOfRecord caller NEVER drives this — only this
	// merge path does, and only against the pre-existing matching pending.
	//
	// Rotation-in-flight guard: when a rotation is mid-flight for this
	// (project, file) pair, a single-file CommitBump would corrupt the
	// rotation's N-file atomic counter commit. Refuse before any write and
	// surface ErrCommitBumpRejectedRotationInFlight so the operator retries
	// after the rotation completes. Fail-closed: uncertainty → in-flight=true.
	// The check is factored to checkRotationGuardBeforeCommitBump so the
	// consultation contract is exercisable by a focused unit test without
	// driving the full merge pipeline; the production semantics are unchanged.
	if err := checkRotationGuardBeforeCommitBump(ctx, m.d.RotationGuard, in.ExpectedProjectID, in.ExpectedFileName); err != nil {
		return MergeResult{}, err
	}
	if err := m.d.Counter.CommitBump(ctx, CommitBumpInput{
		ProjectID:      in.ExpectedProjectID,
		FileName:       in.ExpectedFileName,
		PendingCounter: next,
		PRRef:          prRef,
	}); err != nil {
		return MergeResult{}, fmt.Errorf(
			"the secrets merge landed but the counter commit-bump failed — "+
				"re-run `byreis merge --pr %d` to resume and finalise; the "+
				"write-ahead pending is left in place: %w", in.Ref.Number, err)
	}

	// (7) POST-merge mandatory integrity check. The live file is committed by
	// now: a failure here is a LOUD terminal ALARM with a reconciliation hint,
	// NOT a silent pass and NOT the pre-merge untouched-abort.
	if pErr := m.postMergeIntegrity(ctx, body, rec, idForRoundTrip); pErr != nil {
		m.d.Log.Log(ctx, logging.LevelError,
			"POST-MERGE INTEGRITY ALARM: live file-of-record failed verification",
			"project", in.ExpectedProjectID, "file", in.ExpectedFileName,
			"pr", fmt.Sprintf("%d", in.Ref.Number), "error", pErr.Error())
		if aErr := m.d.Audit.Append(ctx, audit.Event{
			Kind:      audit.EventKindMerge,
			ProjectID: in.ExpectedProjectID,
			FileName:  in.ExpectedFileName,
			PRRef:     prRef,
			Outcome:   "error: post-merge integrity failed",
		}); aErr != nil {
			m.d.Log.Log(ctx, logging.LevelWarn,
				"post-merge alarm audit append also failed",
				"error", aErr.Error())
		}
		return MergeResult{
			MergedCommit:        mr.MergedCommit,
			LiveFileSHA:         mr.LiveFileSHA,
			SignedFileCommitted: mr.SignedFileCommitted,
			SignedFileCommitSHA: mr.SignedFileCommitSHA,
			AlreadyApplied:      mr.AlreadyApplied,
			ReEncrypted:         reEncrypted,
			FinalCounter:        next,
		}, fmt.Errorf("%w: %v", ErrMergePostIntegrity, pErr)
	}

	if aErr := m.d.Audit.Append(ctx, audit.Event{
		Kind:      audit.EventKindMerge,
		ProjectID: in.ExpectedProjectID,
		FileName:  in.ExpectedFileName,
		KeyName:   sub.Meta.Key,
		PRRef:     prRef,
		Outcome:   "ok",
		Details: map[string]string{
			"counter":      fmt.Sprintf("%d", next),
			"re_encrypted": fmt.Sprintf("%t", reEncrypted),
		},
	}); aErr != nil {
		m.d.Log.Log(ctx, logging.LevelWarn,
			"merge completed but audit append failed",
			"project", in.ExpectedProjectID, "error", aErr.Error())
	}

	return MergeResult{
		MergedCommit:        mr.MergedCommit,
		LiveFileSHA:         mr.LiveFileSHA,
		SignedFileCommitted: mr.SignedFileCommitted,
		SignedFileCommitSHA: mr.SignedFileCommitSHA,
		AlreadyApplied:      mr.AlreadyApplied,
		ReEncrypted:         reEncrypted,
		FinalCounter:        next,
	}, nil
}

// reEncryptWholeFile decrypts EVERY value from the submission and re-encrypts
// the WHOLE file to the current verified recipient set with a FRESH
// age.Encrypt per value (zero prior ciphertext reused). Re-encrypt is
// whole-file or not at all: a partial/spliced re-encrypt is never produced.
func (m *mergeUseCase) reEncryptWholeFile(
	ctx context.Context, uns artifact.Unsigned, rec VerifiedRecipients, id identity.Identity,
) (artifact.Signed, error) {
	// Decrypt every value from the submission artifact (NOT the PR diff).
	plain, err := m.d.Decryptor.Decrypt(ctx, artifact.Signed{
		Values: uns.Values, Byreis: uns.Byreis,
	}, id)
	if err != nil {
		return artifact.Signed{}, fmt.Errorf("decrypting submission for re-encrypt failed: %w", err)
	}
	// FRESH whole-file age.Encrypt of EVERY value to the current verified set.
	fresh, err := m.d.Encryptor.Encrypt(ctx, encrypt.EncryptInput{
		ProjectID:       uns.Byreis.ProjectID,
		LogicalFileName: uns.Byreis.File,
		Counter:         uns.Byreis.Counter,
		Recipients:      rec.Set,
		Values:          plain,
	})
	if err != nil {
		return artifact.Signed{}, fmt.Errorf("fresh whole-file re-encrypt failed: %w", err)
	}
	return artifact.Signed{Values: fresh.Values, Byreis: fresh.Byreis}, nil
}

// postMergeIntegrity runs the mandatory VerifyOfRecord on the live signed
// file AND a round-trip decrypt under the executing admin's own identity. A
// failure is the caller's LOUD terminal alarm.
//
// Division of guarantees: VerifyOfRecord proves the file-of-record is wrapped
// to every current verified recipient (it is recipient-set bound). The
// round-trip decrypt is the live proof that the freshly produced envelope is
// decryptable by the one identity available at this call site — the executing
// admin's own key. It does not, and at the merge call site cannot, decrypt
// under other admins' private keys; multi-actor decryptability is a
// CLI/CI-level concern, not something resolvable here.
//
// The counter authority is re-read fresh AFTER the commit-bump: in the
// steady state the committed counter now equals the signed counter, so the
// verify-time counter decision passes. The SAME shared ContentSHA function is
// used by the registry recorder (RecordPendingBump) and by VerifyOfRecord
// here, so the in-flight OK-resume row is reachable rather than spuriously
// reconciling.
func (m *mergeUseCase) postMergeIntegrity(
	ctx context.Context, signed artifact.Signed, rec VerifiedRecipients, id identity.Identity,
) error {
	auth, err := m.d.Counter.CounterAuthority(ctx, signed.Byreis.ProjectID, signed.Byreis.File)
	if err != nil {
		return fmt.Errorf("post-merge counter re-read failed: %w", err)
	}
	if err := m.d.Verifier.VerifyOfRecord(ctx, verify.OfRecordInput{
		Artifact:           signed,
		ExpectedProjectID:  signed.Byreis.ProjectID,
		ExpectedFileName:   signed.Byreis.File,
		ExpectedRecipients: rec.Set,
		TrustedSigners:     rec.TrustedSigners,
		Counter:            auth,
	}); err != nil {
		return fmt.Errorf("of-record verification failed: %w", err)
	}
	if err := m.d.Decryptor.RoundTripAll(ctx, signed, []identity.Identity{id}); err != nil {
		return fmt.Errorf("round-trip decrypt failed: %w", err)
	}
	return nil
}

// submittedRecipientFPs returns the sorted fingerprint set the submission
// artifact declares (display copy). It is used ONLY to decide whether a
// re-encrypt is required; it is never trusted as the recipient authority.
func submittedRecipientFPs(uns artifact.Unsigned) []string {
	out := make([]string, 0, len(uns.Byreis.Recipients))
	for _, re := range uns.Byreis.Recipients {
		out = append(out, re.FP)
	}
	sort.Strings(out)
	return out
}

// manifestFromSigned maps a signed artifact body to the canonical Manifest the
// admin Ed25519-signs. Map iteration order never reaches the signer (the
// manifest encoder sorts internally).
func manifestFromSigned(s artifact.Signed) manifest.Manifest {
	man := manifest.Manifest{
		FormatVersion:   s.Byreis.FormatVersion,
		ProjectID:       s.Byreis.ProjectID,
		LogicalFileName: s.Byreis.File,
		Counter:         s.Byreis.Counter,
		Values:          make(map[string][]byte, len(s.Values)),
	}
	for k, v := range s.Values {
		man.Values[k] = []byte(v)
	}
	for _, re := range s.Byreis.Recipients {
		man.RecipientFingerprints = append(man.RecipientFingerprints, re.FP)
	}
	return man
}

// Compile-time assertion.
var _ Merger = (*mergeUseCase)(nil)
