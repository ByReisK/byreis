// Package registry defines the RegistryClient interface (consumer-defined here)
// and the domain types that carry identity/counter types. Because this package
// defines SignerKey = ed25519.PublicKey and CounterStore, its own transitive
// set includes crypto/ed25519 — so this package is off the contributor-path
// import allowlist for internal/core/crypto/encrypt and usecase/Submit.
//
// The pure public-key-only value types (Recipient, Fingerprint) live in the
// sub-package internal/core/registry/rectypes, which has no identity-bearing
// dependencies and is on the allowlist.
//
// The counter authority types (CounterAuthority, PendingBump) and their
// sentinel errors (ErrReplay, ErrCounterReconcile) live in the sub-package
// internal/core/registry/countertypes, using the same isolation pattern as
// rectypes for the counter store. This package imports countertypes but does
// not import internal/core/crypto/verify, which keeps the dependency direction
// clean and avoids an import cycle.
//
// No go-git, no net/http here. Fetch/verify/cache implementation lives in
// internal/adapter/registry.
package registry

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// SignerKey is the Ed25519 public key type for registry commit-signers and
// admin manifest-signers. It is a type alias to ed25519.PublicKey, so the full
// crypto/ed25519 package is transitively reachable from this package — which is
// why this package is off the contributor-path allowlist.
type SignerKey = ed25519.PublicKey

// AdminSet is the resolved admin set for a project, sourced from the registry.
// SourceVerified must be true before this value is used for any security
// decision (expected recipients and counter authority both depend on it).
type AdminSet struct {
	// ProjectID is the registry-canonical project identifier.
	ProjectID string

	// Recipients is the age recipient set — the encryption targets for this
	// project. It is the trusted recipient source and is used as
	// ExpectedRecipients in verify calls only when SourceVerified == true; the
	// artifact's self-declared recipients are never trusted.
	Recipients []rectypes.Recipient

	// SignerKeys maps admin id → Ed25519 manifest-signing public key. Each key
	// is length-validated to exactly 32 bytes at the registry boundary.
	SignerKeys map[string]SignerKey

	// SourceVerified is true only if the registry HEAD commit signature was
	// verified against the client-pinned trusted signer set. A false value means
	// this AdminSet came from an unverified or stale cache and must not be used
	// for admin promotion or as the expected-recipients source.
	SourceVerified bool

	// Stale is true when the AdminSet was served from cache after a network failure.
	Stale       bool
	StaleReason string

	// ConfiguredFiles maps logical_file_name → registry-configured repo-relative
	// path for this project. It is filled ONLY from a SourceVerified registry
	// fetch and is consumed by the merge use-case's write-path cross-check. An
	// unverified/stale AdminSet must carry an empty or nil ConfiguredFiles so
	// the merge cross-check cannot proceed on an unverified path.
	ConfiguredFiles map[string]string

	FetchedAt  time.Time
	HeadCommit string
}

// Sentinel errors for the registry package.
//
// Each sentinel has exactly one owning package to avoid two packages owning the
// same error. ErrReplay and ErrCounterReconcile are owned by
// internal/core/registry/countertypes and are referenced from there directly
// (no alias vars). ErrNoTrustedSigner is owned by this package; the registry
// boundary adapter and the verify package both reference it from here directly
// rather than defining alias vars. This keeps the dependency direction clean:
// verify imports core/registry (for the sentinel) but core/registry never
// imports verify, so there is no import cycle.
var (
	// ErrUnsignedRegistry: the registry HEAD commit could not be
	// signature-verified. A hard error for admin promotion; a contributor
	// last-known-good cache read may still proceed.
	ErrUnsignedRegistry = errors.New(
		"registry HEAD commit is not signature-verified against the pinned trust anchor — " +
			"admin operations are blocked; run `byreis doctor` to diagnose")

	// ErrRegistryRollback: a fetched HEAD is not a fast-forward descendant of
	// the last-observed HEAD (anti-rollback protection).
	ErrRegistryRollback = errors.New(
		"registry HEAD has regressed (not a fast-forward of last observed HEAD) — " +
			"possible rollback attack; run `byreis doctor` to diagnose")

	// ErrRegistryOffline: network failure; carries the cache age in the wrapped
	// error message.
	ErrRegistryOffline = errors.New(
		"registry is offline — using cached data; run `byreis doctor` for cache age")

	// ErrCacheTampered: cached last_accepted_counter regressed vs last observed
	// (offline anti-rollback protection).
	ErrCacheTampered = errors.New(
		"registry cache integrity check failed (counter regressed) — possible tamper; " +
			"delete the cache and re-fetch: rm -rf ~/.cache/byreis/registry")

	// ErrNoTrustedSigner: no trusted manifest signer key is available, or all
	// keys are invalid. This package is the semantic owner; the adapter boundary
	// and the verify package both reference this sentinel directly rather than
	// defining alias vars, so the sentinel has exactly one owner.
	//
	// Returned at the registry boundary when a parsed SignerKey has wrong length
	// (not 32 bytes): a bad key at parse time surfaces this error before it
	// can cause a confusing ErrSignatureInvalid later at verify time.
	ErrNoTrustedSigner = errors.New(
		"no trusted manifest signer key available — " +
			"run `byreis doctor` to check your trust anchor, or `byreis auth login`")

	// ErrAdminSetUnreadable: the registry admin set is unreadable at the
	// signature-verified HEAD (absent, malformed, or empty admins.yaml) and
	// admin operations are blocked. This sentinel is owned by this package so
	// that the adapter references it here directly, keeping sentinel ownership
	// single-canonical per layer. The adapter wraps it with %w and an actionable
	// hint; callers inspect it via errors.Is.
	ErrAdminSetUnreadable = errors.New(
		"registry admin set is unreadable at the signature-verified HEAD " +
			"(absent/malformed/empty admins.yaml) — admin operations are blocked; " +
			"run `byreis doctor` to diagnose")

	// ErrCounterStoreUnreadable: the counter store file is unreadable at the
	// signature-verified HEAD. An absent file is not this error — absent returns
	// (0,nil,nil) meaning the counter has never been written. This sentinel
	// covers malformed, over-size, duplicate-key, schema-invalid, or
	// semantic-invariant-violated counter JSON where counter authority cannot
	// be established. The sentinel is owned here so the adapter can reference
	// it without the reverse-dependency violation of defining it in adapter code.
	ErrCounterStoreUnreadable = errors.New(
		"registry counter store is unreadable at the signature-verified HEAD " +
			"(malformed/over-size/schema-invalid counter JSON) — " +
			"counter authority cannot be established; run `byreis doctor` to diagnose")
)

// CounterCacheStore is the consumer-defined port for a durable counter+head
// cache that survives process restart. Implementations are supplied by outer
// adapters (e.g. countercache.Store).
//
// All methods are context-aware; all I/O is bounded; all errors are wrapped
// with %w. The port carries domain values only (string project id, string file
// name, uint64 counter, string HEAD SHA) — no SDK, transport, or YAML types
// cross this boundary.
type CounterCacheStore interface {
	// LoadHead returns the durably-persisted last observed HEAD SHA for a
	// project, or ("", nil) if no record exists. A tampered/unbindable record
	// is treated as "no record" after the cache has been securely deleted.
	// ErrCacheTampered is returned only when the file exists, is bound, and
	// yet the contained counter regressed (the existing semantics are unchanged).
	LoadHead(ctx context.Context, projectID string) (string, error)

	// StoreHead writes the observed HEAD SHA durably. On Windows returns
	// ErrCounterCacheWindowsUnsupported; the caller treats persistence as a
	// no-op for the rest of the process lifetime.
	StoreHead(ctx context.Context, projectID, commitSHA string) error

	// LoadCounter returns the durably-persisted last observed counter for the
	// given (projectID, fileName) pair, or (0, nil) if no record exists.
	LoadCounter(ctx context.Context, projectID, fileName string) (uint64, error)

	// StoreCounter writes the counter durably for the given (projectID, fileName) pair.
	StoreCounter(ctx context.Context, projectID, fileName string, counter uint64) error

	// LoadPending returns the durably-persisted pending bump for the given
	// (projectID, fileName) pair, or (nil, nil) if no record exists.
	LoadPending(ctx context.Context, projectID, fileName string) (*countertypes.PendingBump, error)

	// StorePending writes the pending bump durably for the given pair.
	StorePending(ctx context.Context, projectID, fileName string, pending *countertypes.PendingBump) error

	// ClearPending removes the pending bump for the given pair. A missing
	// record is not an error.
	ClearPending(ctx context.Context, projectID, fileName string) error

	// LoadRotationEpoch returns the durably-persisted rotation_epoch for the
	// given (projectID, fileName) pair, or (0, nil) if no record exists.
	// A missing field in an existing cache file is treated as 0 for
	// backwards-compatibility with v0.1-written cache files.
	LoadRotationEpoch(ctx context.Context, projectID, fileName string) (uint64, error)

	// StoreRotationEpoch writes the rotation_epoch durably for the given pair.
	StoreRotationEpoch(ctx context.Context, projectID, fileName string, epoch uint64) error
}

// PendingBumpInput carries the write-ahead intent recorded before a
// secrets-repo merge.
type PendingBumpInput struct {
	ProjectID      string
	FileName       string
	PendingCounter uint64 // == last_accepted_counter + 1
	// TargetArtifactSHA is sha256 over the exact signed file-of-record bytes
	// the admin is about to push.
	TargetArtifactSHA string
	TargetPR          string
}

// CommitBumpInput carries the finalize intent.
type CommitBumpInput struct {
	ProjectID      string
	FileName       string
	PendingCounter uint64 // must match the open pending's pending_counter
	PRRef          string // audit linkage
}

// ErrCommitRotationNotImplemented is returned by CommitRotation when the full
// rotation transport has not yet been wired (V3 ships the implementation).
// Callers must treat this as a typed not-implemented sentinel and surface an
// actionable hint: "rotation transport not available in this build".
var ErrCommitRotationNotImplemented = errors.New(
	"CommitRotation transport is not yet available in this build — " +
		"full rotation support lands in the next release")

// PerFileCommit is one entry in a CommitRotation call: the logical file name,
// the pending counter that was recorded at RecordPendingBump, the content SHA
// of the signed artifact that was pushed to the rotation branch, and the PR ref
// for audit linkage.
type PerFileCommit struct {
	LogicalName    string
	PendingCounter uint64
	TargetSHA      string
	TargetPR       string
}

// CommitRotationInput carries the atomic-N-file rotation commit intent.
// All N files advance last_accepted_counter, clear pending, and record
// the new rotation epoch in one signed registry commit.
//
// The AuditEntry is appended to audit/<project>.jsonl inside the same
// signed registry commit as the counter advance, providing structural
// atomicity: a CommitRotation that does not land also has no audit entry.
type CommitRotationInput struct {
	ProjectID string
	PerFile   []PerFileCommit // N entries — one per file in the rotation
	NewEpoch  uint64          // new rotation_epoch for all N files

	// RegistryParentSHA is the CAS lease for the CommitRotation push. It is the
	// registry repository HEAD tip after all N RecordPendingBump commits for
	// this rotation have landed — the post-Phase-1 registry tip, NOT the HEAD
	// captured before file-1's RecordPendingBump. Using the post-Phase-1 tip is
	// the only physically realisable CAS: each RecordPendingBump advances the
	// registry HEAD by one commit, so by the time Phase 2 starts the tip is N
	// commits ahead of where it was before Phase 1. The per-file CAS property
	// (all-or-nothing under a peer admin merge landing between files) is enforced
	// by each RecordPendingBump's own per-call CAS lease — this field is
	// independent of those per-call leases.
	RegistryParentSHA string

	// AuditEntry is the rotation audit event to persist in the same signed
	// registry commit. It must carry EventKindRotation. The adapter computes
	// sha256(canonical-JSONL-bytes-of-AuditEntry) and embeds the hex digest in
	// the signed commit message body as audit_entry_sha, so the audit append is
	// structurally inseparable from the counter advance.
	AuditEntry audit.Event
}

// CommitRotationResult is returned on a successful CommitRotation.
type CommitRotationResult struct {
	CommitSHA     string
	NewEpoch      uint64
	AdvancedFiles int // equals len(input.PerFile)
}

// RegistryClient is the consumer-defined port for registry operations. The
// concrete implementation lives in internal/adapter/registry.
//
// All methods honor context cancellation/deadlines. All errors wrap with %w and
// carry actionable hints. No go-git or net/http types appear here.
type RegistryClient interface {
	// FetchAdminSet returns the admin recipient + signer set for a project. It
	// must verify the registry HEAD commit signature against the client-pinned
	// trusted signer set before returning data with SourceVerified=true. On
	// signature failure → ErrUnsignedRegistry (a hard error for admin
	// promotion; a contributor last-known-good cache read may still proceed).
	// On network failure it falls back to cache and sets Stale+StaleReason, and
	// never silently grants admin from an expired cache.
	//
	// Every Ed25519 key parsed into SignerKeys is length-validated to exactly
	// 32 bytes at this boundary. A wrong-length entry returns ErrNoTrustedSigner
	// (this package's sentinel) rather than a confusing ErrSignatureInvalid
	// raised later at verify time.
	FetchAdminSet(ctx context.Context, projectID string) (AdminSet, error)

	// VerifyRegistryFreshness enforces anti-rollback: the fetched HEAD must be a
	// fast-forward of the last-observed HEAD. A regressed or non-ancestor HEAD
	// → ErrRegistryRollback.
	VerifyRegistryFreshness(ctx context.Context, projectID string) error

	// CounterAuthority returns the per-(project,file) two-record anti-replay
	// view from the registry/audit store — the sole acceptance authority. The
	// returned countertypes.CounterAuthority is produced by the registry
	// adapter via capmint.Mint, the only module-reachable Valid()-producing
	// constructor. capmint is importable only by code rooted at
	// internal/adapter/registry (Go internal/ rule), so counter authority
	// cannot be forged from outside that adapter. The value is bound to the
	// same SourceVerified anchor as FetchAdminSet; pending is nil if no merge
	// is in flight.
	//
	// No other API path constructs a CounterAuthority: countertypes exposes no
	// exported constructor, and capmint.Mint is a compile error to import from
	// verify/mode/usecase.
	CounterAuthority(ctx context.Context, projectID, fileName string) (countertypes.CounterAuthority, error)

	// RecordPendingBump write-ahead records merge intent as a signed commit in
	// the admin registry repo before the secrets-repo merge. TargetArtifactSHA
	// is sha256 over the exact signed file-of-record bytes.
	// Idempotent: a re-call with the same pending_counter and same
	// target_artifact_sha is a safe resume; any other mismatch →
	// countertypes.ErrCounterReconcile.
	RecordPendingBump(ctx context.Context, in PendingBumpInput) error

	// CommitBump finalizes: it sets last_accepted_counter = pending_counter and
	// clears pending in a single signed registry commit, after the secrets
	// merge has landed. It must be atomic (advance and clear together).
	// pendingCounter must equal the open pending's pending_counter, otherwise
	// countertypes.ErrCounterReconcile.
	CommitBump(ctx context.Context, in CommitBumpInput) error

	// FetchRotationEpochs returns the per-file rotation_epoch for all files in
	// a project, sourced from the registry counter store. The map is keyed by
	// logical file name (e.g. "secrets/prod.enc.yaml"). An empty map means no
	// rotation has occurred for any file in the project.
	//
	// Missing rotation_epoch field in a counter-store file is treated as 0
	// (backwards-compatible read of v0.1-produced counter files).
	//
	// If the registry is unreachable and a stale cache is available, the stale
	// cache value is returned. If neither is available, returns ErrRegistryOffline.
	FetchRotationEpochs(ctx context.Context, projectID string) (map[string]uint64, error)

	// CommitRotation atomically advances last_accepted_counter for all N files in
	// one signed registry commit, clears all N pending records, and increments the
	// rotation_epoch for all N files to in.NewEpoch. Returns the commit SHA on
	// success. CAS rejection returns ErrRegistryConcurrentWrite.
	//
	// V2 note: the full transport implementation lands in V3. V2 declares the
	// method signature and the adapter returns ErrCommitRotationNotImplemented
	// until V3 wires the transport.
	CommitRotation(ctx context.Context, in CommitRotationInput) (CommitRotationResult, error)

	// RotationInFlight reports whether a rotation transaction is currently
	// in flight for the given (project, file) — i.e., there is a pending
	// counter bump AND the file's rotation_epoch is non-zero. Read-only
	// callers must use this to refuse single-file CommitBump while a
	// rotation is mid-flight, routing the resume through CommitRotation
	// instead.
	//
	// Returns true on uncertainty (fail closed toward rotation protection:
	// if the registry cannot be reached or the source-verified gate fails,
	// callers MUST treat the project as in-flight to avoid corrupting a
	// partial rotation by advancing a single file's counter).
	RotationInFlight(ctx context.Context, projectID, fileName string) (bool, error)
}
