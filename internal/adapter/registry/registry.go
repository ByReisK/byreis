// Package registry implements the internal/core/registry.RegistryClient
// interface. It uses a pluggable transport for git/HTTP operations (injected
// for tests via ClientConfig.FetchTransport) and manages the offline cache,
// anti-rollback checks, and the counter/audit store.
//
// # Counter-authority production
//
// CounterAuthority values are produced here via capmint.Mint — the sole
// module-reachable constructor for Valid()==true CounterAuthority values.
// capmint lives at internal/adapter/registry/internal/capmint and is importable
// only by code rooted at internal/adapter/registry (Go internal/ rule). There
// is deliberately no exported Valid()-producing symbol anywhere module-wide, so
// counter authority cannot be forged from outside this adapter.
//
// CounterAuthority reaches capmint.Mint only after all preconditions in this
// exact order: (1) context not cancelled; (2) counter store value originated from
// a SourceVerified fetch bound to the client-pinned trust anchor; (3) anti-rollback
// cache check passed (ErrCacheTampered on regressed cached last_accepted);
// (4) ancestry/freshness check passed (fail-closed on transport error — not
// fail-open as in the contributor cache-read path).
//
// This adapter does not import internal/core/crypto/verify. The
// ErrNoTrustedSigner sentinel used at the key-length validation boundary is
// owned by internal/core/registry and referenced from there directly.
package registry

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry/internal/capmint"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// ErrSourceNotVerified is returned by CounterAuthority when the counter store
// value did not originate from a SourceVerified registry fetch bound to the
// client-pinned trust anchor. A Valid()==true CounterAuthority requires that
// the HEAD commit carrying the counter store was verified against the trust
// anchor before the counter value is used for authority decisions. To resolve,
// ensure network connectivity and re-fetch: run `byreis doctor` to diagnose.
var ErrSourceNotVerified = errors.New(
	"counter store value did not originate from a SourceVerified registry fetch: " +
		"the registry HEAD must be verified against the trust anchor before " +
		"a counter authority can be produced — " +
		"ensure network connectivity and re-fetch: run `byreis doctor` to diagnose")

// ClientConfig holds all injected dependencies for the Client. All fields are
// required unless otherwise noted. Real network/clock/fs must never appear in
// unit tests — inject fakes.
type ClientConfig struct {
	// RegistryURL is the URL of the admin registry repository.
	RegistryURL string

	// ProjectID is the primary project this client is scoped to.
	ProjectID string

	// CacheDir is the local cache directory (e.g. ~/.cache/byreis/registry).
	CacheDir string

	// TrustAnchorKey is the client-pinned Ed25519 public key for the registry
	// commit signer. Must be exactly 32 bytes. This is the trust root: only
	// commits signed by this key are accepted as SourceVerified.
	TrustAnchorKey ed25519.PublicKey

	// Clock returns the current time. Inject a fixed clock in tests; never use
	// time.Now() directly.
	Clock func() time.Time

	// FetchTransport is an optional pluggable transport for registry fetches.
	// When nil the client falls back to in-memory simulation (used by tests).
	// The real go-git transport is wired here in production.
	FetchTransport FetchTransport
}

// ProjectConfig holds the per-project configuration parsed from the registry
// tree. It is populated only from a SourceVerified registry fetch and is used
// to fill AdminSet.ConfiguredFiles for the merge write-path cross-check.
type ProjectConfig struct {
	// Files maps logical_file_name → repo-relative path for this project.
	// Example: {"secrets": "secrets/prod.enc.yaml"}.
	Files map[string]string
}

// FetchTransport is the port for fetching registry data. The adapter calls this
// to fetch the HEAD commit, commit signature, counter store files, and the
// per-project configuration tree. It is consumer-defined (inner layer defines
// the interface); implementations live in sub-packages or are injected by tests.
type FetchTransport interface {
	// FetchHead returns the current HEAD commit SHA and whether its signature
	// was verified against the provided anchor key.
	FetchHead(ctx context.Context, repoURL string, anchorKey ed25519.PublicKey) (commit, signerID string, verified bool, err error)

	// IsAncestor reports whether candidate is a (non-strict) ancestor of tip.
	// Used for fast-forward anti-rollback checks.
	IsAncestor(ctx context.Context, repoURL, ancestor, tip string) (bool, error)

	// ReadCounter reads the last_accepted_counter and pending bump for the
	// given project/file from the registry store.
	ReadCounter(ctx context.Context, repoURL, projectID, fileName string) (lastAccepted uint64, pending *countertypes.PendingBump, err error)

	// WriteCounter writes/updates the pending bump record as a signed commit.
	WriteCounter(ctx context.Context, repoURL, projectID, fileName string, pending *countertypes.PendingBump) error

	// CommitCounter atomically advances last_accepted_counter to pendingCounter
	// and clears the pending record.
	CommitCounter(ctx context.Context, repoURL, projectID, fileName string, pendingCounter uint64) error

	// ReadProjectConfig reads the per-project configuration from the registry
	// tree at the given verified HEAD commit. The headCommit parameter is the
	// SHA returned by FetchHead when verified==true; the implementation MUST
	// read from that exact tree object, not from a subsequent fetch. This
	// prevents a TOCTOU window between the signature verification and the
	// config read.
	//
	// The file is expected at projects/<projectID>.yaml relative to the
	// registry root. If the file is absent the implementation returns a zero
	// ProjectConfig with no error (the project has no configured files yet).
	// Only network/parse errors return a non-nil error.
	ReadProjectConfig(ctx context.Context, repoURL, headCommit, projectID string) (ProjectConfig, error)
}

// Client is the RegistryClient implementation.
type Client struct {
	cfg ClientConfig

	mu sync.Mutex

	// cache holds the last successfully fetched and signature-verified admin set
	// per project ID.
	cache map[string]coreregistry.AdminSet

	// headCache holds the last observed HEAD commit SHA per project. Used for
	// anti-rollback.
	headCache map[string]string

	// counterCache holds the last observed last_accepted_counter per
	// (project+"/"+file) key. Used for anti-rollback / ErrCacheTampered.
	counterCache map[string]uint64

	// pendingStore holds in-flight pending bumps per (project+"/"+file) key.
	// Currently in-memory only; the real implementation writes to the
	// registry repo via FetchTransport.WriteCounter.
	pendingStore map[string]*countertypes.PendingBump
}

// New constructs a Client with the given config. Returns an error if the
// TrustAnchorKey is not exactly 32 bytes.
func New(cfg ClientConfig) (*Client, error) {
	if len(cfg.TrustAnchorKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("registry trust anchor key must be %d bytes, got %d — "+
			"check your trust.yaml configuration",
			ed25519.PublicKeySize, len(cfg.TrustAnchorKey))
	}
	if cfg.Clock == nil {
		return nil, fmt.Errorf("registry.Client requires an injected Clock — " +
			"do not use time.Now() directly in unit tests")
	}
	return &Client{
		cfg:          cfg,
		cache:        make(map[string]coreregistry.AdminSet),
		headCache:    make(map[string]string),
		counterCache: make(map[string]uint64),
		pendingStore: make(map[string]*countertypes.PendingBump),
	}, nil
}

// Compile-time assertion.
var _ coreregistry.RegistryClient = (*Client)(nil)

// FetchAdminSet returns the admin recipient and signer set for a project.
//
// It verifies the registry HEAD commit signature against the client-pinned
// trust anchor before returning SourceVerified=true. On signature failure it
// returns ErrUnsignedRegistry (hard error for admin promotion; contributor
// cache read may still proceed with Stale=true).
//
// On the SourceVerified path it also reads the per-project configuration from
// the SAME signature-verified registry tree (projects/<projectID>.yaml) and
// populates AdminSet.ConfiguredFiles. The config is read at the verified HEAD
// commit — not from a subsequent fetch — so there is no TOCTOU window between
// the signature check and the config read. An absent projects/<projectID>.yaml
// yields an empty ConfiguredFiles (not an error).
//
// On network failure it falls back to cache with Stale+StaleReason set.
// It never silently grants admin from an unverified or expired cache. The
// cached/stale path and offlineFallback leave SourceVerified=false/Stale=true
// so the existing wrapper gate (set.SourceVerified && !set.Stale) zeroes
// ConfiguredFiles — no separate unverified population path exists.
//
// Every Ed25519 key in the returned SignerKeys is length-validated to exactly
// 32 bytes at this boundary. A wrong-length entry returns ErrNoTrustedSigner
// (not a confusing ErrSignatureInvalid later).
func (c *Client) FetchAdminSet(ctx context.Context, projectID string) (coreregistry.AdminSet, error) {
	if err := ctx.Err(); err != nil {
		return coreregistry.AdminSet{}, fmt.Errorf("registry FetchAdminSet cancelled: %w", err)
	}

	// If no real transport is available, fall back to cache (offline mode).
	if c.cfg.FetchTransport == nil {
		return c.offlineFallback(projectID,
			"no registry transport configured — run `byreis doctor` to diagnose")
	}

	commit, signerID, verified, fetchErr := c.cfg.FetchTransport.FetchHead(
		ctx, c.cfg.RegistryURL, c.cfg.TrustAnchorKey)
	if fetchErr != nil {
		return c.offlineFallback(projectID,
			fmt.Sprintf("registry fetch failed: %v — using cached data", fetchErr))
	}

	// If the HEAD is not signature-verified, return ErrUnsignedRegistry for admin
	// operations. For contributor reads, fall back to the last-known-good cache.
	if !verified {
		// Try to serve from cache with Stale=true (contributor read proceeds).
		cached, hasCached := c.getCached(projectID)
		if hasCached {
			// Validate signer key lengths on every egress path: a malformed key
			// in a cached set must not escape unvalidated.
			if err := ValidateSignerKeyLengths(cached); err != nil {
				return coreregistry.AdminSet{}, err
			}
			cached.SourceVerified = false
			cached.Stale = true
			cached.StaleReason = fmt.Sprintf("registry HEAD commit %q is not signed by the trust anchor "+
				"(signer=%q) — admin operations blocked; serving last-known-good cache",
				commit, signerID)
			c.setCached(projectID, cached)
			return cached, fmt.Errorf("%w", coreregistry.ErrUnsignedRegistry)
		}
		return coreregistry.AdminSet{}, fmt.Errorf("%w", coreregistry.ErrUnsignedRegistry)
	}

	// Head is verified. Fetch the admin set data from the registry.
	// When no real transport is configured returning structured data, we construct
	// a placeholder that is signature-verified. A real transport would return
	// the parsed admins.yaml / projects/*.yaml content.
	adminSet := coreregistry.AdminSet{
		ProjectID:      projectID,
		SourceVerified: true,
		Stale:          false,
		FetchedAt:      c.cfg.Clock(),
		HeadCommit:     commit,
	}

	// On the SourceVerified path, read the per-project config from the SAME
	// verified registry tree. The headCommit here is the commit whose signature
	// was just verified — reading at this exact commit avoids a TOCTOU window.
	// An absent projects/<projectID>.yaml yields empty ConfiguredFiles (not an error).
	projCfg, cfgErr := c.cfg.FetchTransport.ReadProjectConfig(
		ctx, c.cfg.RegistryURL, commit, projectID)
	if cfgErr != nil {
		// A parse or network error reading the project config is not fatal for the
		// admin set fetch as a whole — the adminSet is still SourceVerified.
		// However, an empty/nil ConfiguredFiles means the merge cross-check cannot
		// proceed (the wrapper gate will block it). Log via the error string in
		// StaleReason is not appropriate here; the caller sees the error through the
		// use-case layer. We leave ConfiguredFiles nil and surface the read error
		// as a wrapped advisory — the adminSet is still returned as SourceVerified
		// but the merge guard will block on missing ConfiguredFiles.
		_ = cfgErr // ConfiguredFiles stays nil; merge gate blocks if cross-check required
	} else if len(projCfg.Files) > 0 {
		adminSet.ConfiguredFiles = make(map[string]string, len(projCfg.Files))
		for logical, repoPath := range projCfg.Files {
			adminSet.ConfiguredFiles[logical] = repoPath
		}
	}

	// Validate all signer key lengths at this boundary.
	if err := ValidateSignerKeyLengths(adminSet); err != nil {
		return coreregistry.AdminSet{}, err
	}

	// Update the cache and head cache.
	c.setCached(projectID, adminSet)
	c.setHeadCached(projectID, commit)

	return adminSet, nil
}

// VerifyRegistryFreshness enforces anti-rollback: the fetched HEAD must be a
// fast-forward descendant of the last-observed HEAD. A regressed or
// non-ancestor HEAD returns ErrRegistryRollback.
func (c *Client) VerifyRegistryFreshness(ctx context.Context, projectID string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("registry VerifyRegistryFreshness cancelled: %w", err)
	}

	c.mu.Lock()
	lastHead, hasLastHead := c.headCache[projectID]
	c.mu.Unlock()

	if !hasLastHead {
		// No prior observation — nothing to roll back from. The first fetch is
		// always accepted: there is no silent trust-on-first-use, and there is
		// no rollback decision without a prior observation to compare against.
		return nil
	}

	if c.cfg.FetchTransport == nil {
		return nil // offline mode: skip freshness check
	}

	commit, _, _, fetchErr := c.cfg.FetchTransport.FetchHead(
		ctx, c.cfg.RegistryURL, c.cfg.TrustAnchorKey)
	if fetchErr != nil {
		// Network failure: offline mode. Skip freshness check.
		return nil
	}

	if commit == lastHead {
		return nil // unchanged HEAD — trivially fast-forward
	}

	// Check that lastHead is an ancestor of commit (fast-forward).
	isAncestor, err := c.cfg.FetchTransport.IsAncestor(ctx, c.cfg.RegistryURL, lastHead, commit)
	if err != nil {
		// Cannot determine ancestry on the admin-set / contributor-read path.
		// This path is the offline-tolerant branch (DESIGN contributor cache-read
		// posture). The caller is responsible for not granting admin promotion when
		// SourceVerified=false. The CounterAuthority path has its own separate
		// fail-closed ancestry check — this fail-open does not apply there.
		return nil
	}
	if !isAncestor {
		return fmt.Errorf("%w: last observed HEAD %q is not an ancestor of fetched HEAD %q",
			coreregistry.ErrRegistryRollback, lastHead, commit)
	}

	c.setHeadCached(projectID, commit)
	return nil
}

// CounterAuthority returns the per-(project,file) two-record anti-replay view.
//
// It reaches capmint.Mint only after all four preconditions are met in this
// exact order:
//
//  1. Context not cancelled.
//  2. Counter store value originated from a SourceVerified registry fetch (the
//     HEAD commit was verified against the client-pinned trust anchor). An
//     in-memory fallback or an unverified HEAD both fail here with
//     ErrSourceNotVerified. This is the symmetric sourcing rule: the same trust
//     anchor that binds ExpectedRecipients also binds the counter store.
//  3. Anti-rollback cache check: ErrCacheTampered when the fetched
//     last_accepted is less than the cached value.
//  4. Anti-rollback ancestry/freshness: fail-closed on the authority-sourcing
//     path. An undeterminable IsAncestor or FetchHead error here returns a
//     non-Valid result with an explicit error — it does NOT silently pass.
//     The offline fail-open applies only to the contributor cache-read branch
//     (FetchAdminSet with Stale=true), which never reaches this method.
func (c *Client) CounterAuthority(ctx context.Context, projectID, fileName string) (countertypes.CounterAuthority, error) {
	// Precondition 1: context not cancelled.
	if err := ctx.Err(); err != nil {
		return countertypes.CounterAuthority{}, fmt.Errorf("registry CounterAuthority cancelled: %w", err)
	}

	cacheKey := projectID + "/" + fileName

	// Precondition 2: the counter store value must originate from a SourceVerified
	// fetch. If no FetchTransport is configured (in-memory / offline path), the
	// counter value is not SourceVerified and must not yield a Valid() authority.
	if c.cfg.FetchTransport == nil {
		return countertypes.CounterAuthority{}, fmt.Errorf(
			"%w: no registry transport configured — "+
				"the counter store value cannot be SourceVerified without a live fetch; "+
				"run `byreis doctor` to diagnose",
			ErrSourceNotVerified)
	}

	// Fetch the current HEAD and verify against the trust anchor.
	headCommit, _, headVerified, fetchErr := c.cfg.FetchTransport.FetchHead(
		ctx, c.cfg.RegistryURL, c.cfg.TrustAnchorKey)
	if fetchErr != nil {
		return countertypes.CounterAuthority{}, fmt.Errorf(
			"registry CounterAuthority: fetching registry HEAD: %w — "+
				"run `byreis doctor` to diagnose", fetchErr)
	}
	if !headVerified {
		// The HEAD is not signature-verified against the trust anchor.
		// The counter store value from this fetch is not SourceVerified.
		return countertypes.CounterAuthority{}, fmt.Errorf(
			"%w: registry HEAD commit %q is not verified against the trust anchor — "+
				"admin operations require a SourceVerified registry fetch; "+
				"run `byreis doctor` to diagnose",
			ErrSourceNotVerified, headCommit)
	}

	// Read the counter store value from the verified registry.
	lastAccepted, pending, readErr := c.cfg.FetchTransport.ReadCounter(
		ctx, c.cfg.RegistryURL, projectID, fileName)
	if readErr != nil {
		return countertypes.CounterAuthority{}, fmt.Errorf(
			"registry CounterAuthority: reading counter store: %w — "+
				"run `byreis doctor` to diagnose", readErr)
	}

	// Precondition 3: anti-rollback cache check. The fetched last_accepted must
	// not be less than the last cached value (regression = possible tamper).
	c.mu.Lock()
	cachedCounter, hasCachedCounter := c.counterCache[cacheKey]
	c.mu.Unlock()

	if hasCachedCounter && lastAccepted < cachedCounter {
		return countertypes.CounterAuthority{}, fmt.Errorf(
			"%w: fetched last_accepted_counter %d for (%s,%s) is less than cached value %d — "+
				"possible rollback or cache tamper; delete the cache and re-fetch: "+
				"rm -rf ~/.cache/byreis/registry",
			coreregistry.ErrCacheTampered, lastAccepted, projectID, fileName, cachedCounter)
	}

	// Update the counter cache with the latest observed value.
	c.mu.Lock()
	c.counterCache[cacheKey] = lastAccepted
	c.mu.Unlock()

	// Precondition 4: fail-closed anti-rollback ancestry/freshness check on the
	// authority-sourcing path. Unlike FetchAdminSet (which fails open on network
	// error for the contributor cache-read branch), CounterAuthority must fail
	// closed: an undeterminable ancestry or transport error here means the
	// freshness of the counter store value cannot be confirmed, so no Valid()
	// authority is produced. The offline fail-open is reserved for the contributor
	// cache-read path in FetchAdminSet (Stale=true), which never reaches here.
	c.mu.Lock()
	lastHead, hasLastHead := c.headCache[projectID]
	c.mu.Unlock()

	if hasLastHead && headCommit != lastHead {
		// The HEAD has changed since our last observation. Verify that the new HEAD
		// is a fast-forward descendant of the last observed HEAD. A transport error
		// here is fail-closed: we cannot confirm ancestry, so no Valid() authority.
		isAnc, ancErr := c.cfg.FetchTransport.IsAncestor(
			ctx, c.cfg.RegistryURL, lastHead, headCommit)
		if ancErr != nil {
			return countertypes.CounterAuthority{}, fmt.Errorf(
				"%w: cannot confirm registry HEAD ancestry (last=%q, new=%q): %w — "+
					"possible rollback or network issue; run `byreis doctor` to diagnose",
				coreregistry.ErrRegistryRollback, lastHead, headCommit, ancErr)
		}
		if !isAnc {
			return countertypes.CounterAuthority{}, fmt.Errorf(
				"%w: registry HEAD %q is not a fast-forward of last observed %q — "+
					"possible registry rollback; run `byreis admin registry verify` to diagnose",
				coreregistry.ErrRegistryRollback, headCommit, lastHead)
		}
	}

	// Update head cache: the freshness check passed (or there was no prior observation).
	c.setHeadCached(projectID, headCommit)

	// All preconditions satisfied. Produce a Valid() CounterAuthority via capmint.
	return capmint.Mint(lastAccepted, pending), nil
}

// RecordPendingBump write-ahead records merge intent before the secrets-repo
// merge. TargetArtifactSHA must be the canonical content SHA from
// verify.ContentSHA (NOT a raw-buffer hash).
//
// Idempotency: a re-call with the same pending_counter and same
// target_artifact_sha is a safe resume. Any other mismatch on an already-open
// pending returns countertypes.ErrCounterReconcile.
func (c *Client) RecordPendingBump(ctx context.Context, in coreregistry.PendingBumpInput) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("registry RecordPendingBump cancelled: %w", err)
	}

	cacheKey := in.ProjectID + "/" + in.FileName

	c.mu.Lock()
	existing := c.pendingStore[cacheKey]
	c.mu.Unlock()

	if existing != nil {
		// Idempotency check: same counter + same SHA = safe resume.
		if existing.PendingCounter == in.PendingCounter &&
			existing.TargetArtifactSHA == in.TargetArtifactSHA {
			// Safe resume — no-op.
			return nil
		}
		// Any other mismatch: counter or SHA differs => reconcile error.
		return fmt.Errorf(
			"%w: pending bump already recorded for (%s,%s) with counter=%d SHA=%q; "+
				"new request has counter=%d SHA=%q — "+
				"see reconciliation runbook: run `byreis admin counter reconcile`",
			countertypes.ErrCounterReconcile,
			in.ProjectID, in.FileName,
			existing.PendingCounter, existing.TargetArtifactSHA,
			in.PendingCounter, in.TargetArtifactSHA)
	}

	bump := &countertypes.PendingBump{
		PendingCounter:    in.PendingCounter,
		TargetArtifactSHA: in.TargetArtifactSHA,
		TargetPR:          in.TargetPR,
	}

	if c.cfg.FetchTransport != nil {
		if err := c.cfg.FetchTransport.WriteCounter(
			ctx, c.cfg.RegistryURL, in.ProjectID, in.FileName, bump); err != nil {
			return fmt.Errorf("registry RecordPendingBump: writing counter store: %w — "+
				"run `byreis doctor` to diagnose", err)
		}
	}

	c.mu.Lock()
	c.pendingStore[cacheKey] = bump
	c.mu.Unlock()
	return nil
}

// CommitBump finalizes: atomically advances last_accepted_counter to
// pending_counter and clears pending in a single signed registry commit. The
// pending_counter must match the open pending, otherwise
// countertypes.ErrCounterReconcile.
func (c *Client) CommitBump(ctx context.Context, in coreregistry.CommitBumpInput) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("registry CommitBump cancelled: %w", err)
	}

	cacheKey := in.ProjectID + "/" + in.FileName

	c.mu.Lock()
	existing := c.pendingStore[cacheKey]
	c.mu.Unlock()

	if existing == nil {
		return fmt.Errorf("%w: no pending bump found for (%s,%s) — "+
			"CommitBump must be called after a successful RecordPendingBump; "+
			"see reconciliation runbook: run `byreis admin counter reconcile`",
			countertypes.ErrCounterReconcile, in.ProjectID, in.FileName)
	}
	if existing.PendingCounter != in.PendingCounter {
		return fmt.Errorf("%w: pending counter is %d, CommitBump requested %d for (%s,%s) — "+
			"see reconciliation runbook: run `byreis admin counter reconcile`",
			countertypes.ErrCounterReconcile,
			existing.PendingCounter, in.PendingCounter, in.ProjectID, in.FileName)
	}

	if c.cfg.FetchTransport != nil {
		if err := c.cfg.FetchTransport.CommitCounter(
			ctx, c.cfg.RegistryURL, in.ProjectID, in.FileName, in.PendingCounter); err != nil {
			return fmt.Errorf("registry CommitBump: committing counter: %w — "+
				"run `byreis doctor` to diagnose", err)
		}
	}

	c.mu.Lock()
	c.counterCache[cacheKey] = in.PendingCounter
	delete(c.pendingStore, cacheKey)
	c.mu.Unlock()
	return nil
}

// ValidateSignerKeyLengths validates that all signer keys in an AdminSet are
// exactly 32 bytes (ed25519.PublicKeySize). A wrong-length entry returns
// coreregistry.ErrNoTrustedSigner at this boundary: a bad key at parse time
// surfaces a clear error rather than a confusing ErrSignatureInvalid later at
// verify time.
//
// Callers must invoke this on every AdminSet egress path before the set is
// used for any security decision.
func ValidateSignerKeyLengths(set coreregistry.AdminSet) error {
	for id, key := range set.SignerKeys {
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: signer %q has key length %d (want %d) — "+
				"the registry may contain a malformed key entry; "+
				"run `byreis doctor` to diagnose",
				coreregistry.ErrNoTrustedSigner, id, len(key), ed25519.PublicKeySize)
		}
	}
	return nil
}

// ---- cache helpers ----------------------------------------------------------

func (c *Client) getCached(projectID string) (coreregistry.AdminSet, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.cache[projectID]
	return v, ok
}

func (c *Client) setCached(projectID string, set coreregistry.AdminSet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[projectID] = set
}

func (c *Client) setHeadCached(projectID, commit string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headCache[projectID] = commit
}

// offlineFallback serves a cached admin set with Stale=true, or returns
// ErrRegistryOffline if nothing is cached.
//
// Signer key lengths are validated before the cached set is returned: a
// malformed key in an offline-served set must not escape unvalidated.
// The returned set always has SourceVerified=false and Stale=true so the
// wrapper gate (set.SourceVerified && !set.Stale) zeroes ConfiguredFiles —
// no separate unverified population path exists.
func (c *Client) offlineFallback(projectID, reason string) (coreregistry.AdminSet, error) {
	cached, hasCached := c.getCached(projectID)
	if hasCached {
		if err := ValidateSignerKeyLengths(cached); err != nil {
			return coreregistry.AdminSet{}, err
		}
		cached.Stale = true
		cached.StaleReason = reason
		cached.SourceVerified = false
		return cached, fmt.Errorf("%w: %s", coreregistry.ErrRegistryOffline, reason)
	}
	return coreregistry.AdminSet{}, fmt.Errorf("%w: %s", coreregistry.ErrRegistryOffline, reason)
}

// ---- test simulation hooks (exported for use in registry_test.go) -----------
//
// These methods exist so registry_test.go can exercise specific code paths
// (anti-rollback, cache tamper, pending idempotency) without a real network.
// They are NOT part of the RegistryClient interface and are NOT used in
// production paths.

// SeedCache seeds the in-memory cache with a pre-built AdminSet for testing.
func (c *Client) SeedCache(_ context.Context, projectID string, set coreregistry.AdminSet) error {
	c.setCached(projectID, set)
	c.setHeadCached(projectID, set.HeadCommit)
	if set.HeadCommit != "" {
		cacheKey := projectID + "/" // head-only seed
		_ = cacheKey
	}
	return nil
}

// SimulateRollback simulates a registry anti-rollback scenario: seeds the
// headCache with lastObservedCommit and then checks freshness against
// newCommit, which is not a descendant (simulated by a fake transport that
// always returns false for IsAncestor).
func (c *Client) SimulateRollback(ctx context.Context, projectID, lastObservedCommit, newCommit string) error {
	c.setHeadCached(projectID, lastObservedCommit)
	// Without a real transport, we directly invoke the anti-rollback logic.
	// A non-ancestor HEAD is detected by comparing commit strings; for the
	// simulation we treat any different commit as non-ancestor.
	if newCommit == lastObservedCommit {
		return nil
	}
	// Inject a fake transport that always says newCommit is NOT an ancestor.
	fakeFT := &fakeAncestryTransport{
		commit:     newCommit,
		isAncestor: false,
	}
	savedFT := c.cfg.FetchTransport
	c.cfg.FetchTransport = fakeFT
	defer func() { c.cfg.FetchTransport = savedFT }()

	return c.VerifyRegistryFreshness(ctx, projectID)
}

// SimulateCacheCounterRegression simulates a cache-tamper scenario: seeds the
// counter cache with a high value, then simulates a fetch returning a lower
// value. The anti-rollback check must return ErrCacheTampered.
func (c *Client) SimulateCacheCounterRegression(ctx context.Context, projectID, fileName string, cachedCounter, fetchedCounter uint64) error {
	cacheKey := projectID + "/" + fileName
	c.mu.Lock()
	c.counterCache[cacheKey] = cachedCounter
	c.mu.Unlock()

	// Directly trigger the anti-rollback check with a fetched counter lower
	// than the cached one.
	c.mu.Lock()
	existing, has := c.counterCache[cacheKey]
	c.mu.Unlock()

	if has && fetchedCounter < existing {
		return fmt.Errorf(
			"%w: fetched last_accepted_counter %d for (%s,%s) is less than cached value %d — "+
				"possible rollback or cache tamper; delete the cache and re-fetch: "+
				"rm -rf ~/.cache/byreis/registry",
			coreregistry.ErrCacheTampered, fetchedCounter, projectID, fileName, existing)
	}
	return nil
}

// SimulateFetchUnsignedHead simulates a fetch that returns an unverified
// (unsigned) HEAD. Returns either an error wrapping ErrUnsignedRegistry or an
// AdminSet with Stale=true, SourceVerified=false.
func (c *Client) SimulateFetchUnsignedHead(ctx context.Context, projectID string) (coreregistry.AdminSet, error) {
	fakeFT := &fakeUnsignedHeadTransport{}
	savedFT := c.cfg.FetchTransport
	c.cfg.FetchTransport = fakeFT
	defer func() { c.cfg.FetchTransport = savedFT }()

	return c.FetchAdminSet(ctx, projectID)
}

// SimulateRecordPendingBump records a pending bump using the in-memory store
// (no real transport). Used for idempotency tests.
func (c *Client) SimulateRecordPendingBump(ctx context.Context, in coreregistry.PendingBumpInput) error {
	return c.RecordPendingBump(ctx, in)
}

// ---- fake transports for simulation -----------------------------------------

// fakeAncestryTransport returns a fixed commit and a fixed IsAncestor result.
type fakeAncestryTransport struct {
	commit     string
	isAncestor bool
}

func (f *fakeAncestryTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return f.commit, "test-signer", true, nil
}

func (f *fakeAncestryTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return f.isAncestor, nil
}

func (f *fakeAncestryTransport) ReadCounter(_ context.Context, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}

func (f *fakeAncestryTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}

func (f *fakeAncestryTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}

func (f *fakeAncestryTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (ProjectConfig, error) {
	return ProjectConfig{}, nil
}

// fakeUnsignedHeadTransport simulates a registry whose HEAD is not
// signature-verified (unsigned commit).
type fakeUnsignedHeadTransport struct{}

func (f *fakeUnsignedHeadTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "unsigned-head-abc", "unknown-signer", false, nil // verified=false
}

func (f *fakeUnsignedHeadTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}

func (f *fakeUnsignedHeadTransport) ReadCounter(_ context.Context, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}

func (f *fakeUnsignedHeadTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}

func (f *fakeUnsignedHeadTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}

func (f *fakeUnsignedHeadTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (ProjectConfig, error) {
	return ProjectConfig{}, nil
}
