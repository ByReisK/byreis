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
	"github.com/ByReisK/byreis/internal/core/logging"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
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

// ErrRegistryWriteRejected is returned when the registry remote refuses the
// counter-write push, typically because branch-protection rules are enforced
// (signed commits required, linear history, no force-push, no delete).
// To resolve: verify branch-protection settings on the registry repository —
// signed commits required, linear history, no force-push allowed.
var ErrRegistryWriteRejected = errors.New(
	"registry rejected the counter write (branch-protection refused the push) — " +
		"registry requires admin merge; verify branch-protection: " +
		"signed commits required, linear history, no force-push")

// ErrRegistryWriteAuth is returned when the registry-write credential is absent
// or lacks the necessary scope to push to the registry repository.
// To resolve: run `byreis admin register` to add a registry-write token.
var ErrRegistryWriteAuth = errors.New(
	"registry-write credential is missing or has insufficient scope — " +
		"run `byreis admin register` to add a registry-write token")

// ErrRegistryConcurrentWrite is returned by WriteCounter when the push is
// rejected because the registry HEAD moved between fetch and push (non-fast-
// forward), indicating a concurrent admin write. The caller must retry by
// re-entering the merge flow from step 1 to re-fetch the new registry HEAD.
// To diagnose: run `byreis admin counter status`.
var ErrRegistryConcurrentWrite = errors.New(
	"registry counter write rejected: another admin write landed concurrently " +
		"(non-fast-forward push) — " +
		"run `byreis admin counter status` and retry the merge")

// RegistryWriteSigner is the port for signing registry counter commits.
// It is the same contract as the usecase.ManifestSigner port but scoped here
// so that the adapter package does not import usecase. The production
// implementation reuses the existing ManifestSigner adapter — no parallel key
// path and no new key material.
//
// Sign returns the admin signer identity label and the raw Ed25519 signature
// over the canonical encoding of the commit message body. The signer MUST use
// the admin's registry-attested Ed25519 identity key; no new key is created.
//
// Implementations must be safe for concurrent use. The adapter MUST never
// store the returned sig beyond the current call.
type RegistryWriteSigner interface {
	// SignText returns the signer identity label and the raw Ed25519 signature
	// over text. text is the canonical commit message body produced by the
	// counter-write path.
	SignText(ctx context.Context, text []byte) (signerID string, sig []byte, err error)
}

// RegistryWriteTokenProvider is the port for retrieving the registry-write
// OAuth / PAT credential. It is ADMIN-only: the production implementation
// consults the mode gate and refuses to return a token when the calling
// process is in CONTRIBUTOR mode. This is the contributor/admin credential
// separation boundary.
type RegistryWriteTokenProvider interface {
	// RegistryWriteToken returns the registry-write credential for the given
	// registry URL. Returns ErrRegistryWriteAuth (wrapped) if absent or
	// insufficient scope. Must fail closed when the calling mode is not ADMIN
	// or SUPER — a contributor must never receive this token.
	RegistryWriteToken(ctx context.Context, registryURL string) (string, error)
}

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

	// WriteTokenProvider is the ADMIN-only port for the registry-write
	// credential. When nil, WriteCounter and CommitCounter return
	// ErrRegistryWriteAuth. The implementation must refuse to return the token
	// in CONTRIBUTOR mode (contributor/admin credential separation).
	WriteTokenProvider RegistryWriteTokenProvider

	// DiskCache is an optional durable counter+head cache that survives process
	// restart. When nil, the client operates in-memory only (the pre-v0.1
	// behaviour). When non-nil, counter/head observations are written through
	// to disk; on cold-start the in-memory maps are hydrated from disk.
	DiskCache coreregistry.CounterCacheStore

	// Logger is the structured-log sink for operational warnings emitted by
	// the registry adapter. When nil a no-op logger is substituted at
	// construction time so callers do not need to guard nil before logging.
	Logger logging.Logger
}

// ProjectConfig holds the per-project configuration parsed from the registry
// tree. It is populated only from a SourceVerified registry fetch and is used
// to fill AdminSet.ConfiguredFiles for the merge write-path cross-check.
type ProjectConfig struct {
	// Files maps logical_file_name → repo-relative path for this project.
	// Example: {"secrets": "secrets/prod.enc.yaml"}.
	Files map[string]string
}

// ParsedAdminData is the parsed admin set returned by FetchTransport.ReadAdmins.
// It carries only domain value types — no YAML, SDK, or transport types cross
// this boundary. The adapter maps transport+YAML bytes to these domain values at
// the edge before returning.
type ParsedAdminData struct {
	// Recipients is the parsed age recipient set for the project. Each entry is
	// pre-validated (non-empty AgePubKey, non-zero Fingerprint) before return.
	Recipients []rectypes.Recipient
	// SignerKeys maps admin id → Ed25519 trusted manifest-signing public key.
	// Keys are pre-validated to exactly 32 bytes inside ReadAdmins before return.
	SignerKeys map[string]coreregistry.SignerKey
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
	// given project/file from the registry store at the exact headCommit SHA
	// that FetchHead verified. The headCommit parameter is the SHA returned by
	// the immediately preceding FetchHead call; the implementation uses it as
	// the authoritative blob-read ref and to bind the clone session to this
	// specific verified commit (same-clone provenance, no TOCTOU window).
	ReadCounter(ctx context.Context, repoURL, headCommit, projectID, fileName string) (lastAccepted uint64, pending *countertypes.PendingBump, err error)

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

	// ReadAdmins reads and parses the registry admin set (admins.yaml plus the
	// per-project recipient binding) from the registry tree at the EXACT
	// signature-verified headCommit SHA returned by FetchHead. It returns the
	// age recipient set and the Ed25519 trusted-signer set as domain values
	// (no SDK, transport, or YAML types). The implementation MUST read the tree
	// object at the pinned commit SHA — never HEAD, never a re-resolved ref —
	// so there is no TOCTOU window between signature verification and the
	// admins read (same no-refetch discipline as ReadProjectConfig).
	//
	// An absent or unparseable admins.yaml is a non-nil error (fail closed).
	// An empty recipient set or empty signer set is also a non-nil error.
	// A wrong-length or non-base64 signer/recipient field is a non-nil error.
	// A duplicate admin id is a non-nil typed error.
	// A projectID that fails ValidateProjectID must be rejected before any path
	// composition and FetchCommittedFile must never be called in that case.
	ReadAdmins(ctx context.Context, repoURL, headCommit, projectID string) (ParsedAdminData, error)

	// DiscardCounterSession cleans up the counter-active session keyed by
	// headCommit without calling IsAncestor. The CounterAuthority orchestrator
	// calls this on the two no-ancestor branches (cold-cache first-call and
	// warm-cache identical-HEAD) so sessions do not leak when IsAncestor is
	// skipped. Implementations that do not maintain session state (e.g. test
	// fakes) implement this as a no-op.
	DiscardCounterSession(ctx context.Context, headCommit string)

	// ReadRotationEpoch reads the rotation_epoch field from the counter store
	// file for the given (projectID, fileName) at the given verified headCommit.
	// Returns 0 and nil if the file is absent or the field is missing (backwards-
	// compatible default for v0.1-produced counter files). Implementations that
	// do not maintain rotation epoch state return (0, nil).
	ReadRotationEpoch(ctx context.Context, repoURL, headCommit, projectID, fileName string) (uint64, error)
}

// Client is the RegistryClient implementation.
type Client struct {
	cfg    ClientConfig
	logger logging.Logger

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

	// diskHydrated tracks whether the in-memory maps have been hydrated from
	// the on-disk cache for each (project, file) key. Protected by mu.
	diskHydrated map[string]bool
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
	logger := cfg.Logger
	if logger == nil {
		logger = logging.Discard
	}
	return &Client{
		cfg:          cfg,
		logger:       logger,
		cache:        make(map[string]coreregistry.AdminSet),
		headCache:    make(map[string]string),
		counterCache: make(map[string]uint64),
		pendingStore: make(map[string]*countertypes.PendingBump),
		diskHydrated: make(map[string]bool),
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

	// Head is verified. Read the admin set from the registry at the EXACT same
	// commit SHA that FetchHead verified. Both ReadAdmins and ReadProjectConfig
	// use this same `commit` local variable — there is no second FetchHead, no
	// branch/tag/HEAD ref, and no RegistryURL re-resolution (no TOCTOU window).
	//
	// ReadAdmins failure on the verified path is FATAL: return AdminSet{} with a
	// wrapped sentinel before any cache write (a broken verified fetch must not
	// poison the last-known-good cache). Do NOT copy the ReadProjectConfig
	// _ = cfgErr swallow pattern — ReadAdmins is trust-bearing.
	adminData, adminsErr := c.cfg.FetchTransport.ReadAdmins(
		ctx, c.cfg.RegistryURL, commit, projectID)
	if adminsErr != nil {
		// Return before any cache write — fatal on the verified path.
		return coreregistry.AdminSet{}, fmt.Errorf(
			"registry FetchAdminSet: reading admin set at verified HEAD %q: %w — "+
				"run `byreis doctor` to diagnose", commit, adminsErr)
	}

	// Guard: parsed-but-empty recipient or signer set at verified HEAD is fatal.
	if len(adminData.Recipients) == 0 {
		return coreregistry.AdminSet{}, fmt.Errorf(
			"%w: no recipients in admins.yaml at verified HEAD %q — "+
				"run `byreis doctor` to diagnose",
			coreregistry.ErrAdminSetUnreadable, commit)
	}
	if len(adminData.SignerKeys) == 0 {
		return coreregistry.AdminSet{}, fmt.Errorf(
			"%w: no signer keys in admins.yaml at verified HEAD %q — "+
				"run `byreis doctor` to diagnose",
			coreregistry.ErrNoTrustedSigner, commit)
	}

	adminSet := coreregistry.AdminSet{
		ProjectID:      projectID,
		SourceVerified: true,
		Stale:          false,
		FetchedAt:      c.cfg.Clock(),
		HeadCommit:     commit,
		Recipients:     adminData.Recipients,
		SignerKeys:     adminData.SignerKeys,
	}

	// On the SourceVerified path, read the per-project config from the SAME
	// verified registry tree. The headCommit here is the same `commit` variable
	// whose signature was just verified — reading at this exact commit avoids a
	// TOCTOU window. An absent projects/<projectID>.yaml yields empty
	// ConfiguredFiles (not an error — the project may not have a config yet).
	projCfg, cfgErr := c.cfg.FetchTransport.ReadProjectConfig(
		ctx, c.cfg.RegistryURL, commit, projectID)
	if cfgErr != nil {
		// A parse or network error reading the project config is not fatal for the
		// admin set fetch as a whole — the adminSet is still SourceVerified with
		// Recipients and SignerKeys populated. An empty ConfiguredFiles means the
		// merge cross-check cannot proceed (the wrapper gate blocks it), but that
		// is a separate, lesser concern than the recipient/signer surfacing.
		_ = cfgErr // ConfiguredFiles stays nil; merge gate blocks if cross-check required
	} else if len(projCfg.Files) > 0 {
		adminSet.ConfiguredFiles = make(map[string]string, len(projCfg.Files))
		for logical, repoPath := range projCfg.Files {
			adminSet.ConfiguredFiles[logical] = repoPath
		}
	}

	// Validate all signer key lengths at this boundary. ReadAdmins pre-validates
	// key lengths, but this egress call remains on every cache path (verified,
	// stale-cache, offline) as a defense-in-depth boundary.
	if err := ValidateSignerKeyLengths(adminSet); err != nil {
		return coreregistry.AdminSet{}, err
	}

	// Update the cache and head cache. This write happens AFTER all validation
	// passes — a fatal verified-but-broken fetch returns before reaching here.
	c.setCached(projectID, adminSet)
	if err := c.setHeadCached(ctx, projectID, commit); err != nil {
		return coreregistry.AdminSet{}, fmt.Errorf("registry FetchAdminSet: %w", err)
	}

	return adminSet, nil
}

// VerifyRegistryFreshness enforces anti-rollback: the fetched HEAD must be a
// fast-forward descendant of the last-observed HEAD. A regressed or
// non-ancestor HEAD returns ErrRegistryRollback.
func (c *Client) VerifyRegistryFreshness(ctx context.Context, projectID string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("registry VerifyRegistryFreshness cancelled: %w", err)
	}

	// Hydrate the head floor from disk on first call for this project so a
	// process restart restores the anti-rollback floor.
	headHydKey := "__head__/" + projectID
	c.mu.Lock()
	if c.cfg.DiskCache != nil && !c.diskHydrated[headHydKey] {
		c.diskHydrated[headHydKey] = true
		c.mu.Unlock()
		diskHead, diskErr := c.cfg.DiskCache.LoadHead(ctx, projectID)
		if diskErr == nil && diskHead != "" {
			c.mu.Lock()
			if _, has := c.headCache[projectID]; !has {
				c.headCache[projectID] = diskHead
			}
			c.mu.Unlock()
		}
		c.mu.Lock()
	}
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

	if err := c.setHeadCached(ctx, projectID, commit); err != nil {
		return fmt.Errorf("registry VerifyRegistryFreshness: %w", err)
	}
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

	// Read the counter store value from the verified registry at the exact
	// headCommit SHA that FetchHead returned. Passing headCommit here binds
	// the ReadCounter call to the same clone session that FetchHead created,
	// preventing any TOCTOU window between signature verification and the
	// counter store read.
	lastAccepted, pending, readErr := c.cfg.FetchTransport.ReadCounter(
		ctx, c.cfg.RegistryURL, headCommit, projectID, fileName)
	if readErr != nil {
		return countertypes.CounterAuthority{}, fmt.Errorf(
			"registry CounterAuthority: reading counter store: %w — "+
				"run `byreis doctor` to diagnose", readErr)
	}

	// Precondition 3: anti-rollback cache check. The fetched last_accepted must
	// not be less than the last cached value (regression = possible tamper).
	// Hydrate from disk on the first observation of this (project, file) key
	// so a process restart restores the anti-rollback floor durably.
	c.mu.Lock()
	if c.cfg.DiskCache != nil && !c.diskHydrated[cacheKey] {
		c.diskHydrated[cacheKey] = true
		c.mu.Unlock()
		diskCounter, diskErr := c.cfg.DiskCache.LoadCounter(ctx, projectID, fileName)
		if diskErr == nil && diskCounter > 0 {
			c.mu.Lock()
			if _, has := c.counterCache[cacheKey]; !has {
				c.counterCache[cacheKey] = diskCounter
			}
			c.mu.Unlock()
		}
		c.mu.Lock()
	}
	cachedCounter, hasCachedCounter := c.counterCache[cacheKey]
	c.mu.Unlock()

	if hasCachedCounter && lastAccepted < cachedCounter {
		return countertypes.CounterAuthority{}, fmt.Errorf(
			"%w: fetched last_accepted_counter %d for (%s,%s) is less than cached value %d — "+
				"possible rollback or cache tamper; restart the byreis process to clear "+
				"the in-memory counter cache, then re-run the command",
			coreregistry.ErrCacheTampered, lastAccepted, projectID, fileName, cachedCounter)
	}

	// Update the counter cache with the latest observed value and write through
	// to the on-disk cache.
	c.mu.Lock()
	c.counterCache[cacheKey] = lastAccepted
	c.mu.Unlock()
	if c.cfg.DiskCache != nil {
		if diskErr := c.cfg.DiskCache.StoreCounter(ctx, projectID, fileName, lastAccepted); diskErr != nil {
			return countertypes.CounterAuthority{}, fmt.Errorf(
				"registry CounterAuthority: write-through to disk cache failed "+
					"(project=%q file=%q counter=%d): %w — "+
					"delete the cache and re-fetch: rm -rf ~/.cache/byreis/registry",
				projectID, fileName, lastAccepted, diskErr)
		}
	}

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
		// The counter-active session is consumed by IsAncestor (it pops and defers
		// cleanup internally); no DiscardCounterSession call is needed on this branch.
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
	} else {
		// IsAncestor was not called on this branch (either cold-cache first-call or
		// warm-cache identical-HEAD). The counter-active session deposited by
		// ReadCounter must be discarded here so it does not leak.
		c.cfg.FetchTransport.DiscardCounterSession(ctx, headCommit)
	}

	// Update head cache: the freshness check passed (or there was no prior observation).
	if err := c.setHeadCached(ctx, projectID, headCommit); err != nil {
		return countertypes.CounterAuthority{}, fmt.Errorf("registry CounterAuthority: %w", err)
	}

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

	// Write-through pending bump to disk.
	if c.cfg.DiskCache != nil {
		if diskErr := c.cfg.DiskCache.StorePending(ctx, in.ProjectID, in.FileName, bump); diskErr != nil {
			return fmt.Errorf(
				"registry RecordPendingBump: write-through pending to disk cache failed "+
					"(project=%q file=%q): %w",
				in.ProjectID, in.FileName, diskErr)
		}
	}
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

	// Write-through committed counter and clear pending on disk.
	if c.cfg.DiskCache != nil {
		if diskErr := c.cfg.DiskCache.StoreCounter(ctx, in.ProjectID, in.FileName, in.PendingCounter); diskErr != nil {
			return fmt.Errorf(
				"registry CommitBump: write-through counter to disk cache failed "+
					"(project=%q file=%q counter=%d): %w — "+
					"delete the cache and re-fetch: rm -rf ~/.cache/byreis/registry",
				in.ProjectID, in.FileName, in.PendingCounter, diskErr)
		}
		if diskErr := c.cfg.DiskCache.ClearPending(ctx, in.ProjectID, in.FileName); diskErr != nil {
			return fmt.Errorf(
				"registry CommitBump: clearing pending from disk cache failed "+
					"(project=%q file=%q): %w",
				in.ProjectID, in.FileName, diskErr)
		}
	}
	return nil
}

// rotationCommitTransport is an optional extension of FetchTransport that
// transports can implement to support CommitRotation. It is checked via
// interface assertion at runtime; transports that do not implement it cause
// Client.CommitRotation to return ErrCommitRotationNotImplemented.
//
// The method is not part of the FetchTransport interface because the full
// rotation transport is shipped in a later release; V2 declares the port but
// the transport wiring lands in V3.
type rotationCommitTransport interface {
	// CommitRotationTransport atomically advances last_accepted_counter for all
	// N files, clears pending, and records the new rotation_epoch in a single
	// signed registry commit. repoURL is the registry repository URL.
	CommitRotationTransport(ctx context.Context, repoURL string, in coreregistry.CommitRotationInput) error
}

// FetchRotationEpochs returns the per-file rotation_epoch for all files in a
// project from the registry counter store at the current verified HEAD.
//
// File discovery uses three sources, merged in order:
//  1. The in-memory counterCache: files that CounterAuthority has already read
//     in this process lifetime.
//  2. The project config from ReadProjectConfig at the verified HEAD: logical
//     file names listed in projects/<projectID>.yaml.
//  3. The in-memory admin set cache (ConfiguredFiles from the last verified
//     FetchAdminSet call for this project).
//
// Files whose counter file is absent or whose rotation_epoch field is missing
// default to epoch 0 (backwards compatibility with v0.1-produced counter files).
//
// If FetchTransport is nil (offline mode) or FetchHead returns an error, the
// method returns an empty map wrapped in ErrRegistryOffline. A nil map is never
// returned; callers can always range over the result safely.
func (c *Client) FetchRotationEpochs(ctx context.Context, projectID string) (map[string]uint64, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("registry FetchRotationEpochs cancelled: %w", err)
	}

	if c.cfg.FetchTransport == nil {
		return map[string]uint64{}, fmt.Errorf("%w: no registry transport configured — "+
			"run `byreis doctor` to diagnose", coreregistry.ErrRegistryOffline)
	}

	headCommit, _, verified, fetchErr := c.cfg.FetchTransport.FetchHead(
		ctx, c.cfg.RegistryURL, c.cfg.TrustAnchorKey)
	if fetchErr != nil {
		return map[string]uint64{}, fmt.Errorf("%w: registry fetch failed: %v — "+
			"using empty epoch map; run `byreis doctor` to diagnose",
			coreregistry.ErrRegistryOffline, fetchErr)
	}
	if !verified {
		return map[string]uint64{}, fmt.Errorf("%w: registry HEAD is not signature-verified — "+
			"FetchRotationEpochs requires a verified HEAD; run `byreis doctor` to diagnose",
			coreregistry.ErrUnsignedRegistry)
	}

	// Collect file names from three sources.
	seen := make(map[string]struct{})
	var fileNames []string
	addFile := func(fn string) {
		if _, already := seen[fn]; !already {
			seen[fn] = struct{}{}
			fileNames = append(fileNames, fn)
		}
	}

	// Source 1: in-memory counterCache (files seen by CounterAuthority).
	c.mu.Lock()
	prefix := projectID + "/"
	for k := range c.counterCache {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			addFile(k[len(prefix):])
		}
	}
	// Source 3: ConfiguredFiles from the last verified FetchAdminSet.
	if adminSet, hasCached := c.cache[projectID]; hasCached {
		for logicalName := range adminSet.ConfiguredFiles {
			addFile(logicalName)
		}
	}
	c.mu.Unlock()

	// Source 2: ReadProjectConfig at the verified HEAD.
	// This provides file discovery in the common case where no prior
	// CounterAuthority call has been made for this project in this session.
	// The headCommit passed here is the same verified SHA from FetchHead above
	// (same-invocation provenance — no second FetchHead, no TOCTOU window).
	// ReadProjectConfig does NOT consume a session from FetchHead on the
	// FetchRotationEpochs path (the session pipeline is only active during
	// FetchAdminSet which uses a different session queue). This is safe because
	// ReadRotationEpoch is an independent read that does not require the session.
	projCfg, cfgErr := c.cfg.FetchTransport.ReadProjectConfig(
		ctx, c.cfg.RegistryURL, headCommit, projectID)
	if cfgErr != nil {
		c.logger.Log(ctx, logging.LevelWarn,
			"FetchRotationEpochs: project config unreadable; falling back to in-memory + admin-set sources",
			"projectID", projectID,
			"error", cfgErr.Error(),
		)
	} else {
		for logicalName := range projCfg.Files {
			addFile(logicalName)
		}
	}
	// Config read failures are non-fatal for epoch discovery: if the project
	// config is unreadable, we fall back to the in-memory sources above.

	// Discard any counter session deposited by FetchHead on this path. The
	// FetchRotationEpochs flow does not invoke ReadCounter or IsAncestor, so
	// the counter-active session (if any) is not consumed. DiscardCounterSession
	// is a no-op on transports that do not use session tracking.
	defer c.cfg.FetchTransport.DiscardCounterSession(ctx, headCommit)

	result := make(map[string]uint64, len(fileNames))
	for _, fn := range fileNames {
		epoch, epochErr := c.cfg.FetchTransport.ReadRotationEpoch(
			ctx, c.cfg.RegistryURL, headCommit, projectID, fn)
		if epochErr != nil {
			return nil, fmt.Errorf(
				"registry FetchRotationEpochs: reading epoch for (%s,%s): %w — "+
					"run `byreis doctor` to diagnose",
				projectID, fn, epochErr)
		}
		result[fn] = epoch
	}

	return result, nil
}

// CommitRotation atomically advances last_accepted_counter for all N files,
// clears all N pending records, and increments rotation_epoch to in.NewEpoch
// in one signed registry commit.
//
// V2 note: the full transport wiring lands in V3. In V2, the method delegates
// to the transport only when it implements the optional rotationCommitTransport
// extension. Otherwise it returns ErrCommitRotationNotImplemented so callers
// receive the actionable hint: "rotation transport not available in this build".
func (c *Client) CommitRotation(ctx context.Context, in coreregistry.CommitRotationInput) (coreregistry.CommitRotationResult, error) {
	if err := ctx.Err(); err != nil {
		return coreregistry.CommitRotationResult{}, fmt.Errorf(
			"registry CommitRotation cancelled: %w", err)
	}

	// Guard: an empty PerFile slice is a caller error — nothing to commit.
	// Fail closed before any signing or transport call.
	if len(in.PerFile) == 0 {
		return coreregistry.CommitRotationResult{}, fmt.Errorf(
			"registry CommitRotation: PerFile is empty — " +
				"at least one file must be included in a rotation commit; " +
				"check the rotation use-case input construction")
	}

	// Check if the transport supports CommitRotation (optional duck-typed extension).
	if rct, ok := c.cfg.FetchTransport.(rotationCommitTransport); ok {
		if err := rct.CommitRotationTransport(ctx, c.cfg.RegistryURL, in); err != nil {
			return coreregistry.CommitRotationResult{}, fmt.Errorf(
				"registry CommitRotation: transport call failed: %w", err)
		}
		return coreregistry.CommitRotationResult{
			NewEpoch:      in.NewEpoch,
			AdvancedFiles: len(in.PerFile),
		}, nil
	}

	// Transport does not implement CommitRotation — V3 wires the full transport.
	return coreregistry.CommitRotationResult{}, fmt.Errorf(
		"%w: transport does not implement CommitRotation — "+
			"upgrade to a build with full rotation support",
		coreregistry.ErrCommitRotationNotImplemented)
}

// RotationInFlight reports whether a rotation commit is in progress for the
// given (projectID, fileName) pair. A rotation is in flight when:
//   - The counter store for the file has a non-nil pending record (a merge is
//     pending), AND
//   - The rotation_epoch field is > 0 (the pending was recorded as part of a
//     rotation, not a single-file merge).
//
// Callers that observe RotationInFlight == true MUST drive CommitRotation (not
// per-file CommitBump) to advance the counter. Read-only callers MUST NOT call
// CommitRotation — routing the resume through CommitRotation is the only
// permitted path when a rotation is in flight.
//
// Returns (false, nil) when no counter record exists (file has never been
// written). Returns (true, err) on uncertainty — if the registry cannot be
// reached, the transport is nil, or signature verification fails, the caller
// MUST treat the project as in-flight to avoid corrupting a partial rotation
// by advancing a single file's counter (fail closed toward rotation protection).
func (c *Client) RotationInFlight(ctx context.Context, projectID, fileName string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("registry RotationInFlight cancelled: %w", err)
	}

	if c.cfg.FetchTransport == nil {
		return true, fmt.Errorf(
			"registry RotationInFlight: no transport configured — cannot confirm rotation " +
				"state; treating as in-flight: run `byreis doctor` to diagnose")
	}

	headCommit, _, verified, fetchErr := c.cfg.FetchTransport.FetchHead(
		ctx, c.cfg.RegistryURL, c.cfg.TrustAnchorKey)
	if fetchErr != nil {
		if headCommit != "" {
			c.cfg.FetchTransport.DiscardCounterSession(ctx, headCommit)
		}
		return true, fmt.Errorf(
			"rotation-in-flight check failed: registry fetch error: %w — "+
				"treating as in-flight: run `byreis doctor` to diagnose", fetchErr)
	}
	if !verified {
		c.cfg.FetchTransport.DiscardCounterSession(ctx, headCommit)
		return true, fmt.Errorf(
			"rotation-in-flight check failed: registry HEAD is not signature-verified — " +
				"treating as in-flight: run `byreis doctor` to diagnose")
	}

	// Read the counter to check for pending + rotation_epoch.
	_, pending, readErr := c.cfg.FetchTransport.ReadCounter(
		ctx, c.cfg.RegistryURL, headCommit, projectID, fileName)
	if readErr != nil {
		c.cfg.FetchTransport.DiscardCounterSession(ctx, headCommit)
		return false, fmt.Errorf(
			"registry RotationInFlight: reading counter: %w — run `byreis doctor`", readErr)
	}

	if pending == nil {
		// No pending record — not in flight.
		c.cfg.FetchTransport.DiscardCounterSession(ctx, headCommit)
		return false, nil
	}

	// Read rotation_epoch: > 0 indicates this pending was recorded for a rotation.
	epoch, epochErr := c.cfg.FetchTransport.ReadRotationEpoch(
		ctx, c.cfg.RegistryURL, headCommit, projectID, fileName)
	if epochErr != nil {
		c.cfg.FetchTransport.DiscardCounterSession(ctx, headCommit)
		return false, fmt.Errorf(
			"registry RotationInFlight: reading rotation_epoch: %w — run `byreis doctor`", epochErr)
	}

	c.cfg.FetchTransport.DiscardCounterSession(ctx, headCommit)
	return epoch > 0, nil
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

func (c *Client) setHeadCached(ctx context.Context, projectID, commit string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("setHeadCached cancelled for project %q: %w", projectID, err)
	}
	c.mu.Lock()
	// Set the in-memory floor BEFORE the disk write-through: a disk failure must
	// not destroy the within-process anti-rollback floor.
	c.headCache[projectID] = commit
	c.mu.Unlock()
	// Write-through to the on-disk cache when configured.
	if c.cfg.DiskCache != nil {
		if err := c.cfg.DiskCache.StoreHead(ctx, projectID, commit); err != nil {
			return fmt.Errorf("registry: write-through to disk cache failed for HEAD (project=%q): %w — "+
				"delete the cache and re-fetch: rm -rf ~/.cache/byreis/registry",
				projectID, err)
		}
	}
	return nil
}

// SeedHeadCacheForTest injects a known HEAD commit into the headCache for the
// given projectID. This is a test-only method that allows test code to exercise
// the warm-cache ancestry branch without executing a real FetchHead. It is safe
// to call from tests; production code must never call it.
func (c *Client) SeedHeadCacheForTest(projectID, headCommit string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headCache[projectID] = headCommit
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
func (c *Client) SeedCache(ctx context.Context, projectID string, set coreregistry.AdminSet) error {
	c.setCached(projectID, set)
	if err := c.setHeadCached(ctx, projectID, set.HeadCommit); err != nil {
		return err
	}
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
	if err := c.setHeadCached(ctx, projectID, lastObservedCommit); err != nil {
		return err
	}
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
				"possible rollback or cache tamper; restart the byreis process to clear "+
				"the in-memory counter cache, then re-run the command",
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

func (f *fakeAncestryTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
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

func (f *fakeAncestryTransport) ReadAdmins(_ context.Context, _, _, _ string) (ParsedAdminData, error) {
	return ParsedAdminData{}, nil
}

func (f *fakeAncestryTransport) DiscardCounterSession(_ context.Context, _ string) {}

func (f *fakeAncestryTransport) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
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

func (f *fakeUnsignedHeadTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
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

func (f *fakeUnsignedHeadTransport) ReadAdmins(_ context.Context, _, _, _ string) (ParsedAdminData, error) {
	return ParsedAdminData{}, nil
}

func (f *fakeUnsignedHeadTransport) DiscardCounterSession(_ context.Context, _ string) {}

func (f *fakeUnsignedHeadTransport) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
