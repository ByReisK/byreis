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
}
