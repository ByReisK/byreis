package registry

// VerifyAuditLog implements rotate.AuditVerifier for *registry.Client.
//
// It performs a full-history walk over audit/<projectID>.jsonl, binding every
// non-synthetic JSONL line to the signed commit that introduced it. The walk
// runs under a bounded deadline. The checkpoint is a performance amortisation
// only — no trust flows from it.
//
// Fail-closed contract:
//   - unsigned/anchor-mismatched HEAD → ErrUnsignedRegistry BEFORE any per-line
//     work. No partial walk on an unsigned HEAD.
//   - registry unreachable → ErrRegistryOffline. Never a partial-verified-as-clean
//     result.
//   - decode-ok content / ordering / presence / splice mismatch →
//     ErrAuditLogTampered naming the offending line.
//   - ctx cancellation / deadline → typed fail-closed error, no goroutine leak.
//
// Credential discipline: reads the registry with a read-only token sourced from
// cfg.ReadTokenProvider only. Acquires NO write token, NO signer. Imports
// neither crypto/identity nor crypto/decrypt (an AST-level import-discipline
// test in this package asserts the verifier file holds neither import).
//
// Trust root: per-commit Ed25519 signature re-verification pins to the SINGLE
// pinned cfg.TrustAnchorKey — NOT the mutable AdminSet.SignerKeys map. The
// byreis-signer footer is an attested label, not a trust key.
//
// Legacy posture: a line is BindingUnverifiedLegacy only when (1) its
// introducing commit carries no audit_entry_sha field AND (2) the introducing
// commit precedes the earliest binding-era boundary commit in this channel by
// git-history position (not by wall-clock timestamp, which an attacker can set
// freely). A line whose introducing commit carries audit_entry_sha is verified
// normally. A no-sha line at or after the binding-era boundary, or one not
// signed by the trust anchor, is BindingTampered, not legacy.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry/auditverify"
	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// fullWalkDeadline is the bounded ceiling for a cold full-history walk. Set to
// 90 seconds so a realistic registry with ~2k commits completes well inside the
// 120s race budget, leaving headroom for network jitter. Exceeding it is a
// typed fail-closed error when the deadline is exceeded.
const fullWalkDeadline = 90 * time.Second

// incrementalWalkDeadline bounds an incremental (checkpoint fast-forward) walk.
// The incremental walk covers only new commits since the checkpoint, so the
// bound is shorter.
const incrementalWalkDeadline = 60 * time.Second

// auditVerifyReadTimeout is the bounded ceiling for a git log / cat-file read
// within the walk loop.
const auditVerifyReadTimeout = 15 * time.Second

// CheckpointStore is the optional on-disk checkpoint cache for the audit
// verifier. When nil, the verifier always performs a cold full walk.
type CheckpointStore interface {
	Load(ctx context.Context, projectID string) (*auditverify.Checkpoint, error)
	Store(ctx context.Context, projectID string, cp auditverify.Checkpoint) error
}

// AuditVerifierConfig holds injected dependencies for VerifyAuditLog that are
// separate from ClientConfig. These are wired at the composition root.
type AuditVerifierConfig struct {
	// CheckpointStore is the optional on-disk checkpoint cache. Nil = cold walk
	// every time (functionally correct, just slower on large registries).
	CheckpointStore CheckpointStore
}

// WithAuditVerifierConfig attaches the optional verifier configuration (checkpoint
// store) to the Client. Must be called before VerifyAuditLog; it is NOT
// goroutine-safe (call once at construction time in the composition root).
func (c *Client) WithAuditVerifierConfig(vcfg AuditVerifierConfig) {
	c.verifierCfg = vcfg
}

// VerifyAuditLog implements rotate.AuditVerifier.
//
// It walks the full git history of audit/<projectID>.jsonl, binding each line
// to its introducing signed commit. The checkpoint is honoured only when it
// passes the fail-safe ancestry check. On any checkpoint anomaly
// the walk is forced cold.
func (c *Client) VerifyAuditLog(ctx context.Context, projectID string) (rotate.AuditVerifyResult, error) {
	if err := ctx.Err(); err != nil {
		return rotate.AuditVerifyResult{}, fmt.Errorf("VerifyAuditLog: context cancelled: %w", err)
	}
	if c.cfg.FetchTransport == nil {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog: no registry transport configured — "+
				"run `byreis doctor` to diagnose",
			coreregistry.ErrRegistryOffline)
	}

	if err := fetchtransport.ValidateProjectID(projectID); err != nil {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"VerifyAuditLog: invalid projectID %q: %w", projectID, err)
	}

	// Step 1: verify HEAD against the pinned trust anchor.
	// This MUST happen before any per-line work. An unsigned HEAD returns
	// ErrUnsignedRegistry with zero per-line output — no partial walk.
	headCommit, _, headVerified, fetchErr := c.cfg.FetchTransport.FetchHead(
		ctx, c.cfg.RegistryURL, c.cfg.TrustAnchorKey)
	if fetchErr != nil {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog: registry fetch failed: %v — "+
				"run `byreis doctor` to diagnose",
			coreregistry.ErrRegistryOffline, fetchErr)
	}
	defer c.cfg.FetchTransport.DiscardCounterSession(ctx, headCommit)

	if !headVerified {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog: registry HEAD %q is not verified against the "+
				"pinned trust anchor — run `byreis doctor` to diagnose",
			coreregistry.ErrUnsignedRegistry, headCommit)
	}

	// Step 2: determine whether we can use the checkpoint for an incremental walk.
	// The checkpoint is ONLY honoured when IsAncestor(checkpoint, current) == true
	// (the checkpoint SHA is a strict-or-equal ancestor of current HEAD).
	// Any error, false, absent SHA, project-ID mismatch, or line-count anomaly
	// forces a full cold re-walk (fail-safe — a forged checkpoint can only cause MORE work, never skip coverage).
	var walkFrom string // empty = cold walk from dawn of time
	fullWalk := true
	var ckpt *auditverify.Checkpoint

	if c.verifierCfg.CheckpointStore != nil {
		if loaded, loadErr := c.verifierCfg.CheckpointStore.Load(ctx, projectID); loadErr == nil && loaded != nil {
			ckpt = loaded
		}
	}

	// When ckpt.VerifiedHeadSHA == headCommit (unchanged HEAD), the incremental
	// walk covers zero new commits. We still fall through to the clone path: the
	// line-count parity check against ckpt.VerifiedLineCount happens after the
	// clone, inside verifyFromCheckpointSameHead. No special handling is needed
	// here — the checkpoint and ancestry checks below handle both the same-HEAD
	// and the incremental cases correctly.
	//
	// Ancestry check is deferred until after we have the clone.

	// Step 3: create an isolated workspace and clone at FULL depth (unshallow).
	// The bounded deadline wraps BOTH the clone/unshallow AND the walk so neither can run unbounded.
	deadline := fullWalkDeadline
	if ckpt != nil && fetchtransport.IsValidSHA(ckpt.VerifiedHeadSHA) && ckpt.ProjectID == projectID {
		deadline = incrementalWalkDeadline
	}
	walkCtx, walkCancel := fetchtransport.WithBoundedDeadline(ctx, deadline)
	defer walkCancel()

	tmpDir, mkErr := os.MkdirTemp("", "byreis-auditverify-*")
	if mkErr != nil {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog: cannot create temp workspace: %v — "+
				"check filesystem permissions: run `byreis doctor`",
			coreregistry.ErrRegistryOffline, mkErr)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec // 0700: owner-only scratch workspace
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"VerifyAuditLog: cannot chmod temp workspace: %w", chErr)
	}

	cloneDir := filepath.Join(tmpDir, "repo")
	hardenedEnv := buildHardenedEnv(tmpDir)

	// Clone at full depth (no --depth=1) to enable git log history walk.
	// Clone runs under the bounded walkCtx.
	pt, ok := c.cfg.FetchTransport.(*productionFetchTransport)
	if !ok {
		// Non-production transport (test double): return ErrRegistryOffline so
		// the caller gets a typed fail-closed error and knows the verifier is
		// unavailable without the real transport.
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog: full-history walk requires the production transport — "+
				"use VerifyAuditLog only with the real registry transport",
			coreregistry.ErrRegistryOffline)
	}

	_, cloneStderr, cloneExit, cloneErr := pt.verifier.RunSubprocess(
		walkCtx, tmpDir, hardenedEnv,
		"git", "clone", "--no-local", "--", c.cfg.RegistryURL, cloneDir,
	)
	if cloneErr != nil {
		if errors.Is(cloneErr, context.DeadlineExceeded) || errors.Is(cloneErr, context.Canceled) {
			return rotate.AuditVerifyResult{}, fmt.Errorf(
				"%w: VerifyAuditLog: clone cancelled (deadline exceeded) — "+
					"run `byreis doctor` to diagnose",
				coreregistry.ErrRegistryOffline)
		}
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog: git clone exec error: %v — run `byreis doctor`",
			coreregistry.ErrRegistryOffline, cloneErr)
	}
	if cloneExit != 0 {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog: git clone exited %d: %s — run `byreis doctor`",
			coreregistry.ErrRegistryOffline, cloneExit,
			fetchtransport.SanitizeOutput(cloneStderr))
	}

	// Check context after clone before any further work.
	if err := walkCtx.Err(); err != nil {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog: context cancelled after clone: %w",
			coreregistry.ErrRegistryOffline, err)
	}

	// Step 4: checkpoint ancestry check (fail-safe).
	// The checkpoint SHA MUST be a strict-or-equal ancestor of headCommit.
	// Argument order matters: IsAncestor(ancestor, tip) — the checkpoint must
	// be the ancestor and headCommit must be the tip.
	if ckpt != nil && fetchtransport.IsValidSHA(ckpt.VerifiedHeadSHA) && ckpt.ProjectID == projectID {
		isAnc, ancErr := runIsAncestorInClone(walkCtx, pt, tmpDir, cloneDir, hardenedEnv, ckpt.VerifiedHeadSHA, headCommit)
		if ancErr == nil && isAnc {
			if ckpt.VerifiedHeadSHA != headCommit {
				// Incremental: walk only commits since the checkpoint.
				walkFrom = ckpt.VerifiedHeadSHA
				fullWalk = false
			} else {
				// HEAD unchanged: verify line count parity then return from checkpoint.
				return verifyFromCheckpointSameHead(
					walkCtx, pt, tmpDir, cloneDir, hardenedEnv,
					headCommit, projectID, ckpt, c.cfg.TrustAnchorKey,
				)
			}
		}
		// Ancestry error, false, or any other anomaly → cold re-walk. Never skip.
	}

	// Step 5: run the walk. Build the allowed-signers file for per-commit
	// signature re-verification against the single pinned trust anchor.
	allowedSignersPath := filepath.Join(tmpDir, "allowed_signers")
	if wsErr := writeAnchorAllowedSigners(allowedSignersPath, c.cfg.TrustAnchorKey); wsErr != nil {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"VerifyAuditLog: cannot write allowed-signers file: %w", wsErr)
	}

	auditFilePath := "audit/" + projectID + ".jsonl"

	// Read the current blob at HEAD to get the full line list.
	blobCtx, blobCancel := fetchtransport.WithBoundedDeadline(walkCtx, auditVerifyReadTimeout)
	rawBlob, blobErr := pt.verifier.ReadBlobAtSHA(blobCtx, cloneDir, headCommit, auditFilePath)
	blobCancel()
	if blobErr != nil {
		if fetchtransport.IsBlobNotFound(blobErr) {
			// No audit file yet: clean empty result (all-legacy or no entries).
			return rotate.AuditVerifyResult{Entries: []rotate.AuditEntryView{}, FullWalk: fullWalk}, nil
		}
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog: reading audit blob: %v — run `byreis doctor`",
			coreregistry.ErrRegistryOffline, blobErr)
	}

	// Parse all JSONL lines.  The verifier needs both the display projection
	// (allEntries) and the raw line bytes (allRawLines) because the hash stored
	// in each commit body was computed over the raw committed bytes, not over a
	// re-serialised view.  AuditEntryView deliberately drops audit.Event.FileName
	// and other fields, so re-marshalling from the view produces a different hash.
	allEntries, allRawLines, parseErr := parseAuditJSONLWithRawLines(rawBlob, projectID)
	if parseErr != nil {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"VerifyAuditLog: parsing audit JSONL: %w", parseErr)
	}

	// Step 6: walk the git log for the audit file path and collect per-commit
	// metadata. Each commit body is verified against the pinned anchor.
	commitInfos, walkErr := walkAuditHistory(
		walkCtx, pt, tmpDir, cloneDir, hardenedEnv,
		allowedSignersPath, headCommit, walkFrom, auditFilePath,
	)
	if walkErr != nil {
		return rotate.AuditVerifyResult{}, walkErr
	}

	// Check context after walk.
	if err := walkCtx.Err(); err != nil {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog: context cancelled during walk: %w",
			coreregistry.ErrRegistryOffline, err)
	}

	// Step 7: bind each line to its introducing commit and classify.
	//
	// Incremental walk (walkFrom != ""): the git log covers only commits since
	// the checkpoint, so commitInfos describes only the NEW appended lines.
	// bindLines must receive only the NEW slice of allEntries/allRawLines so
	// that len(nonSyntheticIndices) == len(commitInfos).  The prior lines (from
	// the checkpoint walk) are already verified; they are re-tagged
	// BindingVerified in the final result without re-hashing (Approach A
	// amortisation).
	//
	// Fail-closed check: if the current non-synthetic count is less than
	// ckpt.VerifiedLineCount, lines were deleted/truncated since the checkpoint
	// → force a cold re-walk (the incremental result would be misleading).
	var result rotate.AuditVerifyResult
	var bindErr error

	if !fullWalk && ckpt != nil && ckpt.VerifiedLineCount > 0 {
		// Locate the split point: skip the first ckpt.VerifiedLineCount
		// non-synthetic entries (they were verified at checkpoint time).
		splitIdx := findNonSyntheticSplitIndex(allEntries, ckpt.VerifiedLineCount)
		if splitIdx < 0 {
			// Fewer non-synthetic lines than the checkpoint recorded: tamper or
			// deletion.  Force a cold re-walk by delegating to performColdReWalk.
			return performColdReWalk(
				walkCtx, pt, tmpDir, cloneDir, hardenedEnv,
				headCommit, projectID, c.cfg.TrustAnchorKey,
			)
		}

		// Bind only the new slice (allEntries[splitIdx:] and allRawLines[splitIdx:]).
		// The lineIndex values in commitInfos are reset to 0-based within the new
		// slice; bindLines receives the slice as if it were the full file.
		newEntries := allEntries[splitIdx:]
		newRawLines := allRawLines[splitIdx:]

		newResult, newBindErr := bindLines(newEntries, newRawLines, commitInfos, projectID, auditFilePath)

		// Re-assemble the full result: prior entries tagged BindingVerified +
		// newly bound entries.
		priorEntries := make([]rotate.AuditEntryView, splitIdx)
		copy(priorEntries, allEntries[:splitIdx])
		for i := range priorEntries {
			if !isSyntheticRow(priorEntries[i]) {
				priorEntries[i].BindingStatus = rotate.BindingVerified
			}
		}
		combined := make([]rotate.AuditEntryView, 0, len(allEntries))
		combined = append(combined, priorEntries...)
		combined = append(combined, newResult.Entries...)
		result = rotate.AuditVerifyResult{Entries: combined}
		bindErr = newBindErr
	} else {
		result, bindErr = bindLines(allEntries, allRawLines, commitInfos, projectID, auditFilePath)
	}

	// Step 8: store checkpoint on a clean full walk (no tamper, no error).
	if bindErr == nil && (fullWalk || ckpt != nil) {
		nonSyntheticCount := countNonSynthetic(result.Entries)
		newCkpt := auditverify.Checkpoint{
			ProjectID:         projectID,
			VerifiedHeadSHA:   headCommit,
			VerifiedLineCount: nonSyntheticCount,
			VerifiedAt:        time.Now().UTC(),
		}
		if c.verifierCfg.CheckpointStore != nil {
			// Write failure is non-fatal: log and continue.
			if storeErr := c.verifierCfg.CheckpointStore.Store(ctx, projectID, newCkpt); storeErr != nil {
				c.logger.Log(ctx, 1 /* warn */, "VerifyAuditLog: checkpoint store write failed",
					"project", projectID, "error", storeErr.Error())
			}
		}
	}

	result.FullWalk = fullWalk
	return result, bindErr
}

// verifyFromCheckpointSameHead handles the case where HEAD has not changed
// since the last successful walk. It re-reads the blob, counts non-synthetic
// lines, and if the count matches the checkpoint it returns the cached
// projection. A count mismatch forces a full cold re-walk.
func verifyFromCheckpointSameHead(
	ctx context.Context,
	pt *productionFetchTransport,
	tmpDir, cloneDir string,
	hardenedEnv []string,
	headCommit, projectID string,
	ckpt *auditverify.Checkpoint,
	anchorKey ed25519.PublicKey,
) (rotate.AuditVerifyResult, error) {
	auditFilePath := "audit/" + projectID + ".jsonl"
	blobCtx, blobCancel := fetchtransport.WithBoundedDeadline(ctx, auditVerifyReadTimeout)
	rawBlob, blobErr := pt.verifier.ReadBlobAtSHA(blobCtx, cloneDir, headCommit, auditFilePath)
	blobCancel()
	if blobErr != nil {
		if fetchtransport.IsBlobNotFound(blobErr) {
			return rotate.AuditVerifyResult{Entries: []rotate.AuditEntryView{}, FullWalk: false}, nil
		}
		// Cannot read blob: fall through to cold re-walk.
		return performColdReWalk(ctx, pt, tmpDir, cloneDir, hardenedEnv, headCommit, projectID, anchorKey)
	}

	allEntries, parseErr := parseAuditJSONL(rawBlob, projectID)
	if parseErr != nil {
		return performColdReWalk(ctx, pt, tmpDir, cloneDir, hardenedEnv, headCommit, projectID, anchorKey)
	}

	currentCount := countNonSynthetic(allEntries)
	// VerifiedLineCount is diagnostic only — it must NEVER bound re-checks.
	// The count is used ONLY as a tamper-signal: if the count changed while HEAD
	// did not, lines were deleted or added without a commit, which is tamper.
	if currentCount != ckpt.VerifiedLineCount {
		// Line count changed without HEAD moving: something tampered with the
		// working-tree blob. Force cold re-walk.
		return performColdReWalk(ctx, pt, tmpDir, cloneDir, hardenedEnv, headCommit, projectID, anchorKey)
	}

	// All checks passed: build the BindingVerified/legacy projection from the
	// previous walk's categories. Since we do not re-walk, entries that were
	// BindingVerified remain BindingVerified, and legacy remain legacy. We
	// re-tag all non-synthetic entries as BindingVerified to be conservative
	// (the last walk was clean; HEAD has not moved; line count matches).
	for i := range allEntries {
		if isSyntheticRow(allEntries[i]) {
			continue
		}
		if allEntries[i].BindingStatus == rotate.BindingMissing {
			// Tag newly seen non-synthetic entries as verified (they were present
			// in the last clean walk at this same HEAD).
			allEntries[i].BindingStatus = rotate.BindingVerified
		}
	}

	return rotate.AuditVerifyResult{Entries: allEntries, FullWalk: false}, nil
}

// performColdReWalk is a helper that delegates to the full-walk path after a
// checkpoint fast-forward fails. It re-uses the already-cloned workspace.
// anchorKey is the client-pinned Ed25519 trust anchor, threaded from the
// VerifyAuditLog method so no key material is sourced from the transport.
func performColdReWalk(
	ctx context.Context,
	pt *productionFetchTransport,
	tmpDir, cloneDir string,
	hardenedEnv []string,
	headCommit, projectID string,
	anchorKey ed25519.PublicKey,
) (rotate.AuditVerifyResult, error) {
	allowedSignersPath := filepath.Join(tmpDir, "allowed_signers")
	if wsErr := writeAnchorAllowedSigners(allowedSignersPath, anchorKey); wsErr != nil {
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"VerifyAuditLog(cold-rewalk): cannot write allowed-signers: %w", wsErr)
	}
	auditFilePath := "audit/" + projectID + ".jsonl"
	blobCtx, blobCancel := fetchtransport.WithBoundedDeadline(ctx, auditVerifyReadTimeout)
	rawBlob, blobErr := pt.verifier.ReadBlobAtSHA(blobCtx, cloneDir, headCommit, auditFilePath)
	blobCancel()
	if blobErr != nil {
		if fetchtransport.IsBlobNotFound(blobErr) {
			return rotate.AuditVerifyResult{Entries: []rotate.AuditEntryView{}, FullWalk: true}, nil
		}
		return rotate.AuditVerifyResult{}, fmt.Errorf(
			"%w: VerifyAuditLog(cold-rewalk): reading audit blob: %v",
			coreregistry.ErrRegistryOffline, blobErr)
	}
	allEntries, allRawLines, parseErr := parseAuditJSONLWithRawLines(rawBlob, projectID)
	if parseErr != nil {
		return rotate.AuditVerifyResult{}, parseErr
	}
	commitInfos, walkErr := walkAuditHistory(
		ctx, pt, tmpDir, cloneDir, hardenedEnv, allowedSignersPath, headCommit, "", auditFilePath)
	if walkErr != nil {
		return rotate.AuditVerifyResult{}, walkErr
	}
	result, bindErr := bindLines(allEntries, allRawLines, commitInfos, projectID, auditFilePath)
	result.FullWalk = true
	return result, bindErr
}

// auditCommitInfo records per-commit metadata extracted from the git log walk.
type auditCommitInfo struct {
	// SHA is the 40-char commit SHA.
	SHA string
	// AuditEntrySHA is the hex sha256 of the audit line this commit introduced,
	// parsed from the signed commit body's "audit_entry_sha: " line. Empty when
	// the commit predates the binding era (no such field in the body).
	AuditEntrySHA string
	// SignedByAnchor is true when git verify-commit confirmed the commit was
	// signed by exactly the pinned trust anchor (exit 0).
	SignedByAnchor bool
	// StagedFiles is the set of file paths staged in this commit. Used for the
	// cross-project-splice check.
	StagedFiles map[string]struct{}
	// LineIndex is the 0-based index (from the start of the file) of the line
	// this commit introduced, as determined by the walk order.
	LineIndex int
}

// walkAuditHistory runs git log over the audit file path and collects per-commit
// metadata for the binding phase. It returns commits in chronological order
// (oldest first), matching the line order in the JSONL file.
//
// walkFrom is the exclusive lower bound SHA for an incremental walk; empty means
// walk from the beginning of time (full cold walk). Each commit body is verified
// against the pinned trust anchor via git verify-commit.
//
// On any context cancellation the walk returns ErrRegistryOffline.
func walkAuditHistory(
	ctx context.Context,
	pt *productionFetchTransport,
	tmpDir, cloneDir string,
	hardenedEnv []string,
	allowedSignersPath, headCommit, walkFrom, auditFilePath string,
) ([]auditCommitInfo, error) {
	// Build the git log command. --follow ensures renames are tracked.
	// --reverse gives chronological (oldest-first) order to match JSONL line order.
	// --pretty=format:%H separates the SHAs cleanly.
	logArgs := []string{
		"log", "--reverse", "--pretty=format:%H",
		"--follow", "--diff-filter=A",
	}
	if walkFrom != "" {
		// Incremental: commits reachable from headCommit but not from walkFrom.
		logArgs = append(logArgs, walkFrom+".."+headCommit)
	} else {
		logArgs = append(logArgs, headCommit)
	}
	logArgs = append(logArgs, "--", auditFilePath)

	logCtx, logCancel := fetchtransport.WithBoundedDeadline(ctx, auditVerifyReadTimeout)
	logOut, logStderr, logExit, logErr := pt.verifier.RunSubprocess(
		logCtx, cloneDir, hardenedEnv, "git", logArgs...,
	)
	logCancel()
	if logErr != nil {
		if errors.Is(logErr, context.DeadlineExceeded) || errors.Is(logErr, context.Canceled) {
			return nil, fmt.Errorf(
				"%w: VerifyAuditLog: git log cancelled: %w",
				coreregistry.ErrRegistryOffline, logErr)
		}
		return nil, fmt.Errorf(
			"%w: VerifyAuditLog: git log exec error: %v — run `byreis doctor`",
			coreregistry.ErrRegistryOffline, logErr)
	}
	if logExit != 0 {
		return nil, fmt.Errorf(
			"%w: VerifyAuditLog: git log exited %d: %s — run `byreis doctor`",
			coreregistry.ErrRegistryOffline, logExit,
			fetchtransport.SanitizeOutput(logStderr))
	}

	// git log --diff-filter=A shows only the commit that ADDED the file. But for
	// an append-only JSONL, every new append is a modification (M). We need to
	// walk all commits that touched the file (added or modified).
	// Re-run without --diff-filter=A to get all touching commits.
	logArgs2 := []string{
		"log", "--reverse", "--pretty=format:%H",
		"--follow",
	}
	if walkFrom != "" {
		logArgs2 = append(logArgs2, walkFrom+".."+headCommit)
	} else {
		logArgs2 = append(logArgs2, headCommit)
	}
	logArgs2 = append(logArgs2, "--", auditFilePath)

	logCtx2, logCancel2 := fetchtransport.WithBoundedDeadline(ctx, auditVerifyReadTimeout)
	logOut2, logStderr2, logExit2, logErr2 := pt.verifier.RunSubprocess(
		logCtx2, cloneDir, hardenedEnv, "git", logArgs2...,
	)
	logCancel2()
	if logErr2 != nil {
		return nil, fmt.Errorf(
			"%w: VerifyAuditLog: git log (all) exec error: %v — run `byreis doctor`",
			coreregistry.ErrRegistryOffline, logErr2)
	}
	if logExit2 != 0 {
		return nil, fmt.Errorf(
			"%w: VerifyAuditLog: git log (all) exited %d: %s — run `byreis doctor`",
			coreregistry.ErrRegistryOffline, logExit2,
			fetchtransport.SanitizeOutput(logStderr2))
	}

	_ = logOut // first run (add-only) not used; all-commits run is authoritative

	// Parse SHA list. One SHA per line.
	shas := parseCommitSHAs(logOut2)

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: VerifyAuditLog: context cancelled: %w",
			coreregistry.ErrRegistryOffline, err)
	}

	// For each SHA, extract commit body and verify signature.
	infos := make([]auditCommitInfo, 0, len(shas))
	for i, sha := range shas {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: VerifyAuditLog: context cancelled during walk: %w",
				coreregistry.ErrRegistryOffline, err)
		}

		info, infoErr := extractCommitInfo(ctx, pt, tmpDir, cloneDir, hardenedEnv, allowedSignersPath, sha, i)
		if infoErr != nil {
			return nil, infoErr
		}
		infos = append(infos, info)
	}

	return infos, nil
}

// extractCommitInfo fetches the commit body, verifies its signature against the
// pinned anchor, extracts audit_entry_sha and staged files.
func extractCommitInfo(
	ctx context.Context,
	pt *productionFetchTransport,
	tmpDir, cloneDir string,
	hardenedEnv []string,
	allowedSignersPath, sha string,
	lineIndex int,
) (auditCommitInfo, error) {
	info := auditCommitInfo{SHA: sha, LineIndex: lineIndex}

	// Read commit body (raw commit message body, excluding the first blank line).
	bodyCtx, bodyCancel := fetchtransport.WithBoundedDeadline(ctx, auditVerifyReadTimeout)
	bodyOut, _, bodyExit, bodyErr := pt.verifier.RunSubprocess(
		bodyCtx, cloneDir, hardenedEnv,
		"git", "show", "-s", "--format=%B", sha,
	)
	bodyCancel()
	if bodyErr != nil || bodyExit != 0 {
		return info, fmt.Errorf(
			"%w: VerifyAuditLog: git show body for %q: exit %d err %v — run `byreis doctor`",
			coreregistry.ErrRegistryOffline, sha, bodyExit, bodyErr)
	}

	// Extract audit_entry_sha from the body (the "audit_entry_sha: <hex>" line).
	info.AuditEntrySHA = parseAuditEntrySHA(string(bodyOut))

	// Verify commit signature against the pinned anchor via git verify-commit.
	// We build a dedicated verify env that includes the allowed-signers file.
	verifyEnv := buildVerifyEnv(tmpDir, allowedSignersPath)

	verifyCtx, verifyCancel := fetchtransport.WithBoundedDeadline(ctx, auditVerifyReadTimeout)
	_, _, verifyExit, verifyErr := pt.verifier.RunSubprocess(
		verifyCtx, cloneDir, verifyEnv,
		"git", "verify-commit", "--raw", sha,
	)
	verifyCancel()
	// verifyErr is an exec-level error (binary not found, etc.). A non-zero exit
	// code just means the commit is not signed by the anchor — not a hard error.
	info.SignedByAnchor = (verifyErr == nil && verifyExit == 0)

	// Get the set of files changed by this commit (for cross-project-splice check).
	filesCtx, filesCancel := fetchtransport.WithBoundedDeadline(ctx, auditVerifyReadTimeout)
	filesOut, _, filesExit, filesErr := pt.verifier.RunSubprocess(
		filesCtx, cloneDir, hardenedEnv,
		"git", "diff-tree", "--no-commit-id", "-r", "--name-only", sha,
	)
	filesCancel()
	if filesErr == nil && filesExit == 0 {
		info.StagedFiles = parseFilesList(string(filesOut))
	}

	return info, nil
}

// bindLines binds each JSONL entry to its introducing commit and assigns the
// appropriate BindingStatus. It implements the legacy posture,
// the splice check, the reorder check, and the
// content-hash, anchor-signature, and presence/count checks.
//
// rawLines is a parallel slice to allEntries: rawLines[i] holds the original
// committed bytes (line + "\n") that produced allEntries[i], or nil for
// synthetic rows (malformed-line, truncation-advisory). The hash comparison
// uses rawLines[lineIdx] directly so it is byte-identical to what the signing
// path hashed when it produced audit_entry_sha.  Re-marshalling from
// AuditEntryView is incorrect because the view is a lossy projection and
// drops fields such as FileName, KeyName, and PRRef.
//
// The returned AuditVerifyResult.Entries preserves the original entry order.
// On a tamper outcome the function returns the PARTIAL result WITH the
// ErrAuditLogTampered error so the caller can render per-line status and still
// exit non-zero.
func bindLines(
	allEntries []rotate.AuditEntryView,
	rawLines [][]byte,
	commits []auditCommitInfo,
	projectID, auditFilePath string,
) (rotate.AuditVerifyResult, error) {
	result := rotate.AuditVerifyResult{Entries: make([]rotate.AuditEntryView, len(allEntries))}
	copy(result.Entries, allEntries)

	// Identify the binding-era boundary: the earliest commit (by history position)
	// that carries an audit_entry_sha field. This is the anchor for the legacy posture
	// (condition 2 of the legacy posture).
	bindingEraBoundaryIdx := -1 // index into commits slice
	for i, ci := range commits {
		if ci.AuditEntrySHA != "" {
			bindingEraBoundaryIdx = i
			break
		}
	}

	// Count non-synthetic entries (real JSONL data lines).
	// Each commit that touches the audit file is expected to introduce exactly
	// one new JSONL line (the append model). We pair commits[i] with lines in
	// chronological order.
	//
	// Synthetic rows (truncation-advisory, malformed-line) are not hash-checked
	// They carry BindingMissing by construction.

	// Build the ordered list of non-synthetic line indices from allEntries.
	nonSyntheticIndices := make([]int, 0, len(allEntries))
	for i, e := range allEntries {
		if !isSyntheticRow(e) {
			nonSyntheticIndices = append(nonSyntheticIndices, i)
		}
	}

	// Detect forged insert / delete: the number of non-synthetic lines must equal
	// the number of append commits covering this file.
	if len(nonSyntheticIndices) != len(commits) {
		// Count mismatch: either lines were deleted/truncated or forged-
		// inserted or the walk did not cover the full history.
		// Mark all non-synthetic lines as BindingTampered.
		for _, idx := range nonSyntheticIndices {
			result.Entries[idx].BindingStatus = rotate.BindingTampered
		}
		return result, fmt.Errorf(
			"%w: JSONL line count (%d) does not match introducing-commit count (%d) "+
				"for project %q — possible deletion/truncation or forged insert",
			coreregistry.ErrAuditLogTampered,
			len(nonSyntheticIndices), len(commits), projectID)
	}

	// Bind each non-synthetic line to its introducing commit in order.
	// Reorder check: the introducing commit index must be
	// strictly increasing (no reorder within the history).
	var tamperErr error
	for seq, lineIdx := range nonSyntheticIndices {
		ci := commits[seq]
		entry := allEntries[lineIdx]

		// Cross-project-splice check: the commit must stage
		// ONLY this project's audit file (plus its counter file(s)). A commit
		// that also touches another project's audit file is a splice.
		if len(ci.StagedFiles) > 0 {
			if spliceErr := checkSplice(ci.StagedFiles, projectID, auditFilePath); spliceErr != nil {
				result.Entries[lineIdx].BindingStatus = rotate.BindingTampered
				if tamperErr == nil {
					tamperErr = fmt.Errorf("%w: cross-project splice at line %d (commit %q): %v",
						coreregistry.ErrAuditLogTampered, lineIdx+1, ci.SHA, spliceErr)
				}
				continue
			}
		}

		// Legacy posture (see the method-header comment).
		if ci.AuditEntrySHA == "" {
			// This commit carries no audit_entry_sha — potentially legacy.
			if bindingEraBoundaryIdx >= 0 && seq >= bindingEraBoundaryIdx {
				// The commit CLAIMS to be legacy (no audit_entry_sha) but it appears
				// at or after the binding-era boundary — tamper.
				result.Entries[lineIdx].BindingStatus = rotate.BindingTampered
				if tamperErr == nil {
					tamperErr = fmt.Errorf(
						"%w: line %d (commit %q) claims legacy but is at or after "+
							"the binding-era boundary (commit index %d) — possible tamper",
						coreregistry.ErrAuditLogTampered, lineIdx+1, ci.SHA, bindingEraBoundaryIdx)
				}
				continue
			}
			// Either an all-legacy file (bindingEraBoundaryIdx < 0) or a line whose
			// introducing commit precedes the binding-era boundary by git-history
			// position. Ordering is established structurally by the linear,
			// append-only git-log walk and the line-count == introducing-commit-count
			// equality checked above; there is no separate counter-value check here.
			if !ci.SignedByAnchor {
				// Not signed by anchor: cannot establish authenticity even for legacy.
				// A non-anchor-signed historical commit is BindingTampered.
				result.Entries[lineIdx].BindingStatus = rotate.BindingTampered
				if tamperErr == nil {
					tamperErr = fmt.Errorf(
						"%w: line %d (commit %q) is not signed by the trust anchor "+
							"— non-anchor-signed historical commit is not legacy",
						coreregistry.ErrAuditLogTampered, lineIdx+1, ci.SHA)
				}
				continue
			}
			result.Entries[lineIdx].BindingStatus = rotate.BindingUnverifiedLegacy
			continue
		}

		// Binding-era line: ci.AuditEntrySHA is present. Compute sha256(rawLine)
		// using the original committed bytes (content-edit check).
		//
		// rawLines[lineIdx] is the line as written to the JSONL blob (including
		// the trailing "\n"), which is exactly what the signing path hashed when
		// it computed audit_entry_sha.  AuditEntryView is a lossy projection
		// (it drops FileName, KeyName, PRRef, and other audit.Event fields), so
		// re-marshalling from the view would produce a different hash.
		_ = entry // suppress unused warning
		rawLine := rawLines[lineIdx]
		if rawLine == nil {
			// Raw bytes absent for a non-synthetic entry: internal invariant
			// violated.  Fail closed — cannot verify hash without the raw bytes.
			result.Entries[lineIdx].BindingStatus = rotate.BindingTampered
			if tamperErr == nil {
				tamperErr = fmt.Errorf(
					"%w: line %d (commit %q) has no raw JSONL bytes available for hash verification — "+
						"internal invariant violated",
					coreregistry.ErrAuditLogTampered, lineIdx+1, ci.SHA)
			}
			continue
		}
		actualSHA := sha256HexOfLine(rawLine)

		if !ci.SignedByAnchor {
			// Not signed by anchor: anchor-mismatch → BindingTampered.
			result.Entries[lineIdx].BindingStatus = rotate.BindingTampered
			if tamperErr == nil {
				tamperErr = fmt.Errorf(
					"%w: line %d (commit %q) is not signed by the trust anchor",
					coreregistry.ErrAuditLogTampered, lineIdx+1, ci.SHA)
			}
			continue
		}

		if actualSHA != ci.AuditEntrySHA {
			// Content mismatch: the committed line was edited after signing.
			result.Entries[lineIdx].BindingStatus = rotate.BindingTampered
			if tamperErr == nil {
				tamperErr = fmt.Errorf(
					"%w: line %d sha256 mismatch (commit %q recorded %q, computed %q)",
					coreregistry.ErrAuditLogTampered, lineIdx+1, ci.SHA,
					ci.AuditEntrySHA, actualSHA)
			}
			continue
		}

		result.Entries[lineIdx].BindingStatus = rotate.BindingVerified
	}

	return result, tamperErr
}

// checkSplice enforces that the set of files staged in a commit is a subset of
// the exact allowed set: the audit file for this project and counter files for
// this project (counters/<projectID>/...). Any staged path outside that set —
// whether another project's audit file, another project's counter, or any
// unrelated registry file (admins.yaml, policy.yaml, secrets/*, etc.) — is
// treated as a splice and returns a non-nil error. The caller must treat a
// non-nil return as BindingTampered.
func checkSplice(staged map[string]struct{}, projectID, auditFilePath string) error {
	counterPrefix := "counters/" + projectID + "/"
	for f := range staged {
		if f == auditFilePath {
			continue // own audit file: allowed
		}
		if strings.HasPrefix(f, counterPrefix) {
			continue // own project's counter files: allowed
		}
		// Any other path — including other projects' audit files, other projects'
		// counters, and any non-audit registry file — is an unexpected staged
		// path and indicates a splice attempt.
		return fmt.Errorf(
			"staged file %q is outside the exact allowed set "+
				"({audit/%s.jsonl} ∪ {counters/%s/**}) for this commit — "+
				"possible cross-project splice or unrelated registry write",
			f, projectID, projectID)
	}
	return nil
}

// sha256HexOfLine returns the lowercase hex sha256 of the given line bytes.
func sha256HexOfLine(line []byte) string {
	if len(line) == 0 {
		return ""
	}
	sum := sha256.Sum256(line)
	return fmt.Sprintf("%x", sum[:])
}

// parseAuditEntrySHA extracts the value of the "audit_entry_sha: " line from
// a commit message body. Returns "" if the field is absent (pre-binding era).
func parseAuditEntrySHA(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "audit_entry_sha:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "audit_entry_sha:"))
			// Basic hex validation: must be 64 chars lowercase hex (sha256).
			if len(val) == 64 {
				allHex := true
				for _, c := range val {
					if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
						allHex = false
						break
					}
				}
				if allHex {
					return val
				}
			}
			return "" // malformed value: treat as absent
		}
	}
	return ""
}

// parseCommitSHAs parses a newline-separated list of commit SHAs from git log
// --pretty=format:%H output. Invalid SHAs are silently skipped.
func parseCommitSHAs(out []byte) []string {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var shas []string
	for scanner.Scan() {
		sha := strings.TrimSpace(scanner.Text())
		if fetchtransport.IsValidSHA(sha) {
			shas = append(shas, sha)
		}
	}
	return shas
}

// parseFilesList parses a newline-separated list of file paths.
func parseFilesList(out string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, line := range strings.Split(out, "\n") {
		f := strings.TrimSpace(line)
		if f != "" {
			m[f] = struct{}{}
		}
	}
	return m
}

// isSyntheticRow reports whether an AuditEntryView is a synthetic display row
// (truncation-advisory or malformed-line) that must never be hash-checked
// (they have no introducing-commit binding to check against).
//
// Synthetic rows are identified ONLY by their reserved Kind values. The Unknown
// flag is intentionally excluded: an entry with Unknown=true but Kind not in
// the reserved set has valid JSON bytes on disk (the parser only sets
// Unknown=true for unrecognised event kinds, not for malformed JSON). That
// entry participates in the git history and its raw bytes must be verified
// against audit_entry_sha. Treating Unknown rows as synthetic would allow a
// content edit that changes an event kind to an unrecognised value to silently
// evade hash verification.
func isSyntheticRow(e rotate.AuditEntryView) bool {
	return e.Kind == "truncated" || e.Kind == "malformed-line"
}

// findNonSyntheticSplitIndex returns the slice index of the first entry AFTER
// the first n non-synthetic entries.  It is used by the incremental walk path
// to locate the split between already-checkpointed entries and newly added
// entries.
//
// Returns -1 when the slice contains fewer than n non-synthetic entries, which
// signals that lines were deleted since the checkpoint (fail-closed).
func findNonSyntheticSplitIndex(entries []rotate.AuditEntryView, n int) int {
	count := 0
	for i, e := range entries {
		if !isSyntheticRow(e) {
			count++
			if count == n {
				return i + 1 // first index after the n-th non-synthetic entry
			}
		}
	}
	// Fewer than n non-synthetic entries: caller must force cold re-walk.
	return -1
}

// countNonSynthetic returns the number of non-synthetic entries in the slice.
func countNonSynthetic(entries []rotate.AuditEntryView) int {
	n := 0
	for _, e := range entries {
		if !isSyntheticRow(e) {
			n++
		}
	}
	return n
}

// buildHardenedEnv returns the minimal, isolated environment for audit-verifier
// git subprocess calls. Mirrors the environment discipline in the production
// transport fetch path.
func buildHardenedEnv(tmpDir string) []string {
	base := fetchtransport.CleanGitEnv()
	return append(base,
		"GIT_CONFIG_NOSYSTEM=1",
		"HOME="+tmpDir,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=file:https:ssh",
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0=/dev/null",
		"GIT_CONFIG_KEY_1=core.fsmonitor",
		"GIT_CONFIG_VALUE_1=",
	)
}

// buildVerifyEnv returns the environment for git verify-commit subprocess calls.
// It extends the hardened base with SSH signing config pointing to the
// allowed-signers file (same discipline as fetchtransport.VerifyHeadRetainClone).
func buildVerifyEnv(tmpDir, allowedSignersPath string) []string {
	base := fetchtransport.CleanGitEnv()
	return append(base,
		"GIT_CONFIG_NOSYSTEM=1",
		"HOME="+tmpDir,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=file:https:ssh",
		"GIT_CONFIG_COUNT=5",
		"GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0=/dev/null",
		"GIT_CONFIG_KEY_1=core.fsmonitor",
		"GIT_CONFIG_VALUE_1=",
		"GIT_CONFIG_KEY_2=gpg.format",
		"GIT_CONFIG_VALUE_2=ssh",
		"GIT_CONFIG_KEY_3=gpg.ssh.allowedSignersFile",
		"GIT_CONFIG_VALUE_3="+allowedSignersPath,
		"GIT_CONFIG_KEY_4=gpg.minTrustLevel",
		"GIT_CONFIG_VALUE_4=undefined",
	)
}

// writeAnchorAllowedSigners writes the trust-anchor public key as the sole entry
// in an SSH allowed-signers file. Delegates to the fetchtransport package's
// WriteAllowedSignersForAnchor so the encoding is byte-identical to the one used
// in VerifyHeadRetainClone: exit 0 from git verify-commit therefore implies the
// commit was signed by exactly the pinned anchor key.
func writeAnchorAllowedSigners(path string, anchorKey ed25519.PublicKey) error {
	return fetchtransport.WriteAllowedSignersForAnchor(path, anchorKey)
}

// runIsAncestorInClone runs git merge-base --is-ancestor in the verifier clone.
// Returns (true, nil) when ancestor is a strict-or-equal ancestor of tip.
// Any error returns (false, err) — the caller treats this as a force-cold-walk signal.
func runIsAncestorInClone(
	ctx context.Context,
	pt *productionFetchTransport,
	tmpDir, cloneDir string,
	hardenedEnv []string,
	ancestor, tip string,
) (bool, error) {
	mbCtx, mbCancel := fetchtransport.WithBoundedDeadline(ctx, 30*time.Second)
	defer mbCancel()
	_, _, exitCode, runErr := pt.verifier.RunSubprocess(
		mbCtx, cloneDir, hardenedEnv,
		"git", "merge-base", "--is-ancestor", ancestor, tip,
	)
	if runErr != nil {
		return false, runErr
	}
	switch exitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf("git merge-base --is-ancestor exited %d", exitCode)
	}
}
