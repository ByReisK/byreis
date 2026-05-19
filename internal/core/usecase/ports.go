package usecase

import (
	"context"
	"crypto/ed25519"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// ArtifactCodec is the consumer-defined port that maps between on-disk artifact
// bytes and the domain artifact types. It is injected so review/merge never
// import a YAML library and the exact decode/encode is unit-mockable. The
// decode path MUST operate on the EXACT fetched bytes (no normalization) so the
// pinned content hash is meaningful.
type ArtifactCodec interface {
	// DecodeSigned decodes a signed file-of-record from its on-disk bytes.
	DecodeSigned(b []byte) (artifact.Signed, error)
	// DecodeUnsigned decodes an unsigned contributor submission from its bytes.
	DecodeUnsigned(b []byte) (artifact.Unsigned, error)
	// EncodeSigned serialises a signed file-of-record to its on-disk bytes.
	EncodeSigned(s artifact.Signed) ([]byte, error)
}

// ModeGate is the consumer-defined permission port. It carries the
// cryptographically-derived mode internally; the use-case passes only the
// command, so no flag/env/config channel can grant admin through this port.
// Review and Merge are ADMIN-only: the gate denies them in CONTRIBUTOR mode
// before any git fetch, decrypt, or signing is attempted.
type ModeGate interface {
	// Allow returns an error wrapping mode.ErrPermissionDenied when the
	// resolved mode may not run cmd.
	Allow(cmd mode.Command) error
}

// VerifiedRecipients is a trust-tagged admin recipient set. The use-case only
// proceeds when SourceVerified is true and Stale is false: the expected
// recipient set (and, at merge, the re-encrypt target) is never sourced from
// an artifact, the project repo, or a stale/expired cache.
type VerifiedRecipients struct {
	// Set is the age recipient public-key set (pure rectypes value type).
	Set []rectypes.Recipient
	// TrustedSigners maps admin id → Ed25519 manifest-signing public key,
	// sourced from the SAME signature-verified registry fetch as Set. It is
	// the trusted signer set the post-merge VerifyOfRecord checks against —
	// never a key embedded in the artifact.
	TrustedSigners map[string]ed25519.PublicKey
	// ConfiguredFiles maps a project's logical_file_name → its registry-
	// configured repo-relative path. It MUST be filled ONLY from the SAME
	// signature-verified registry fetch (the same SourceVerified HEAD) as Set
	// and TrustedSigners — never from the submission, the project repo, or a
	// stale/unsigned cache. The merge use-case cross-checks the submission's
	// declared write path against the entry keyed by the SIGNED manifest's
	// logical_file_name so a tampered submission cannot redirect the signed
	// file-of-record to an attacker-chosen path.
	ConfiguredFiles map[string]string
	// SourceVerified is true only when the registry HEAD commit signature was
	// verified against the client-pinned trust anchor.
	SourceVerified bool
	// Stale is true when the set was served from cache after a network failure.
	Stale bool
}

// RecipientSource yields the admin recipient set for a project. The concrete
// implementation wraps the registry adapter at the CLI layer; it MUST set
// SourceVerified only from a signature-verified registry HEAD and MUST NOT
// source recipients from an artifact or the project repo.
type RecipientSource interface {
	ExpectedRecipients(ctx context.Context, projectID string) (VerifiedRecipients, error)
}

// CounterStore is the consumer-defined write-ahead counter-authority port. It
// is the merge-state authority: the rollback decision is driven exclusively by
// the pending/CommitBump state surfaced here, never by a git-side PR-merged
// signal. The opaque CounterAuthority is consumed read-only; this package
// cannot construct a Valid() one.
type CounterStore interface {
	// CounterAuthority returns the per-(project,file) two-record anti-replay
	// view from a signature-verified registry fetch. A non-Valid() result
	// (zero-value/forged/unsourced) is fail-closed by the caller.
	CounterAuthority(ctx context.Context, projectID, fileName string) (countertypes.CounterAuthority, error)
	// RecordPendingBump write-ahead records the merge intent (the post-sign
	// content SHA) as a durable signed registry commit BEFORE the secrets
	// merge. A re-call with the same pending_counter AND the same
	// target_artifact_sha is a safe resume; any other mismatch must surface
	// countertypes.ErrCounterReconcile.
	RecordPendingBump(ctx context.Context, in PendingBumpInput) error
	// CommitBump finalises: it advances last_accepted to pending_counter AND
	// clears pending in a single atomic registry commit, ONLY after the
	// secrets merge has landed.
	CommitBump(ctx context.Context, in CommitBumpInput) error
}

// PendingBumpInput carries the write-ahead intent recorded before merge.
type PendingBumpInput struct {
	ProjectID         string
	FileName          string
	PendingCounter    uint64
	TargetArtifactSHA string // post-sign content SHA (the next reader's pin)
	TargetPR          string
}

// CommitBumpInput carries the finalize intent recorded only after merge lands.
type CommitBumpInput struct {
	ProjectID      string
	FileName       string
	PendingCounter uint64
	PRRef          string
}

// ManifestSigner is the consumer-defined admin Ed25519 signing port. The
// concrete implementation loads the admin's registry-attested signing key; the
// use-case never holds raw private-key bytes. It signs ONLY the canonical
// manifest stream the use-case recomputes from the pinned (post-re-encrypt)
// artifact — never the PR diff and never a blindly-trusted blob.
type ManifestSigner interface {
	// Sign returns the admin signer id and the raw Ed25519 signature over the
	// canonical encoding of m. A malformed manifest fails closed BEFORE any
	// signature is produced.
	Sign(ctx context.Context, m manifest.Manifest) (signerID string, sig []byte, err error)
}
