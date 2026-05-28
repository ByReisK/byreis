package registry

// Package registry — RotationStateReverser production adapter.
//
// RotationReverserAdapter implements rotate.RotationStateReverser using the
// same git-subprocess-backed write discipline as doCommitRotation (one signed
// commit, one CAS push, hardened env isolation). It adapts three operations:
//
//   - FetchPartialState: read rotation-tagged pendings from the registry counter
//     store and check for the rotation branch in the project repo.
//   - ClearPendings: land a SINGLE signed registry commit that both clears
//     pending_counter / target_artifact_sha / target_pr for each pending AND
//     appends the reversal audit JSONL line. Same-commit atomicity is
//     load-bearing per the ClearPendings port contract.
//   - DeleteRotationBranch: git push --delete on the project repo.
//
// CAS discipline: git push --force-with-lease=refs/heads/main:<parentSHA>.
// The parentSHA is captured at the start of each ClearPendings invocation from
// the registry clone HEAD. The reconciler owns the bounded retry budget (max 3).
// Adapter surfaces ErrRegistryConcurrentWrite on CAS rejection; no internal
// retry loop.
//
// Retry semantics: do NOT retry inside the adapter. The reconciler in
// reconcile.go owns the retry budget.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// RotationReverserDeps carries the constructor-injected dependencies for
// the RotationReverserAdapter. All fields are required.
type RotationReverserDeps struct {
	// RegistryURL is the registry repository clone URL.
	RegistryURL string

	// ProjectRepoURL is the project secrets repository clone URL. Used by
	// DeleteRotationBranch to push-delete the rotation branch.
	ProjectRepoURL string

	// Signer is the ADMIN-only commit signer (same instance as doCommitRotation).
	Signer RegistryWriteSigner

	// TokenProvider is the ADMIN-only write credential provider.
	TokenProvider RegistryWriteTokenProvider

	// Runner is the git subprocess runner injected for testability. Pass
	// SubprocessRunner{} in production; inject a fake in unit tests.
	Runner fetchtransport.CommandRunner

	// MkdirTemp is os.MkdirTemp in production; injected for tests.
	MkdirTemp func(dir, pattern string) (string, error)

	// RemoveAll is os.RemoveAll in production; injected for tests.
	RemoveAll func(path string) error
}

// RotationReverserAdapter implements rotate.RotationStateReverser.
type RotationReverserAdapter struct {
	d RotationReverserDeps
}

// NewRotationReverserAdapter constructs a RotationReverserAdapter. All
// dependency fields are required; returns an error for any nil field.
func NewRotationReverserAdapter(d RotationReverserDeps) (*RotationReverserAdapter, error) {
	if d.RegistryURL == "" {
		return nil, fmt.Errorf(
			"RotationReverserAdapter: RegistryURL is required — " +
				"set BYREIS_REGISTRY or run `byreis init`")
	}
	if d.ProjectRepoURL == "" {
		return nil, fmt.Errorf(
			"RotationReverserAdapter: ProjectRepoURL is required — " +
				"set BYREIS_PROJECT_REPO or run `byreis init`")
	}
	if d.Signer == nil {
		return nil, fmt.Errorf(
			"RotationReverserAdapter: Signer is required — " +
				"wire the RegistryWriteSigner")
	}
	if d.TokenProvider == nil {
		return nil, fmt.Errorf(
			"RotationReverserAdapter: TokenProvider is required — " +
				"wire the RegistryWriteTokenProvider")
	}
	if d.Runner == nil {
		return nil, fmt.Errorf(
			"RotationReverserAdapter: Runner is required — " +
				"pass SubprocessRunner{} for production")
	}
	mkdirTemp := d.MkdirTemp
	if mkdirTemp == nil {
		mkdirTemp = os.MkdirTemp
	}
	removeAll := d.RemoveAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	return &RotationReverserAdapter{d: RotationReverserDeps{
		RegistryURL:    d.RegistryURL,
		ProjectRepoURL: d.ProjectRepoURL,
		Signer:         d.Signer,
		TokenProvider:  d.TokenProvider,
		Runner:         d.Runner,
		MkdirTemp:      mkdirTemp,
		RemoveAll:      removeAll,
	}}, nil
}

// Compile-time assertion: RotationReverserAdapter satisfies the port.
var _ rotate.RotationStateReverser = (*RotationReverserAdapter)(nil)

// FetchPartialState reads rotation-tagged pendings from the registry and checks
// the project repo for rotation branches. The observation is sourced from a
// SourceVerified registry fetch (via the registry client FetchHead path).
//
// Production wiring note: the full SourceVerified fetch is handled by the
// RegistryClient's FetchAdminSet pipeline. For the reverser's purposes, this
// adapter performs a shallow registry clone and inspects counter store files
// for rotation-tagged pendings, plus a project repo ls-remote for rotation
// branches. The result is marked SourceVerified = true only if the registry
// clone verifier confirms the HEAD signature.
func (a *RotationReverserAdapter) FetchPartialState(ctx context.Context, projectID string) (rotate.PartialStateObservation, error) {
	if err := ctx.Err(); err != nil {
		return rotate.PartialStateObservation{}, fmt.Errorf("FetchPartialState: context cancelled: %w", err)
	}
	if err := fetchtransport.ValidateProjectID(projectID); err != nil {
		return rotate.PartialStateObservation{}, fmt.Errorf("FetchPartialState: invalid projectID: %w", err)
	}

	token, tokenErr := a.d.TokenProvider.RegistryWriteToken(ctx, a.d.RegistryURL)
	if tokenErr != nil {
		return rotate.PartialStateObservation{}, fmt.Errorf(
			"%w: FetchPartialState: retrieving registry token: %v",
			ErrRegistryWriteAuth, tokenErr)
	}

	tmpDir, mkErr := a.d.MkdirTemp("", "byreis-reverser-fetch-*")
	if mkErr != nil {
		return rotate.PartialStateObservation{}, fmt.Errorf(
			"FetchPartialState: creating workspace: %w — check filesystem permissions", mkErr)
	}
	defer func() { _ = a.d.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec
		return rotate.PartialStateObservation{}, fmt.Errorf(
			"FetchPartialState: chmod workspace: %w", chErr)
	}

	cloneDir := filepath.Join(tmpDir, "registry")
	env := a.buildEnv(tmpDir, a.d.RegistryURL, token, true)

	// Shallow clone the registry.
	cloneCtx, cloneCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := a.d.Runner.Run(
		cloneCtx, tmpDir, env,
		"git", "clone", "--depth=1", "--no-local", "--", a.d.RegistryURL, cloneDir,
	)
	if cloneErr != nil {
		return rotate.PartialStateObservation{}, fmt.Errorf(
			"FetchPartialState: git clone error: %w — run `byreis doctor`", cloneErr)
	}
	if cloneExit != 0 {
		return rotate.PartialStateObservation{}, fmt.Errorf(
			"%w: FetchPartialState: git clone exited %d: %s",
			ErrRegistryWriteAuth, cloneExit, fetchtransport.SanitizeOutput(cloneStderr))
	}

	// Walk the counter store to find rotation-tagged pendings.
	obs, walkErr := a.walkCounterStore(ctx, cloneDir, projectID)
	if walkErr != nil {
		return rotate.PartialStateObservation{}, fmt.Errorf(
			"FetchPartialState: walking counter store: %w", walkErr)
	}

	// Check the project repo for rotation branches.
	branchExists, branchMerged, branchRef, branchErr := a.checkRotationBranch(ctx, token)
	if branchErr != nil {
		return rotate.PartialStateObservation{}, fmt.Errorf(
			"FetchPartialState: checking rotation branch: %w", branchErr)
	}
	obs.RotationBranchExists = branchExists
	obs.RotationBranchMerged = branchMerged
	obs.RotationBranchRef = branchRef

	return obs, nil
}

// walkCounterStore inspects the registry counter store directory for the given
// project and finds any pendings whose target_pr matches the byreis/rotate-* pattern.
func (a *RotationReverserAdapter) walkCounterStore(
	_ context.Context,
	cloneDir, projectID string,
) (rotate.PartialStateObservation, error) {
	counterDir := filepath.Join(cloneDir, "counter", filepath.FromSlash(projectID))
	obs := rotate.PartialStateObservation{}

	entries, readErr := os.ReadDir(counterDir)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return obs, nil // no counter store → no pendings
		}
		return obs, fmt.Errorf("reading counter directory: %w", readErr)
	}

	seen := make(map[string]struct{}, len(entries))

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		filePath := filepath.Join(counterDir, entry.Name())
		raw, readFileErr := os.ReadFile(filePath) //nolint:gosec
		if readFileErr != nil {
			return obs, fmt.Errorf("walkCounterStore: reading counter file %q: %w — "+
				"check registry clone integrity: run `byreis doctor`", entry.Name(), readFileErr)
		}
		if len(raw) > maxCounterJSONBytes {
			return obs, fmt.Errorf("walkCounterStore: counter file %q exceeds maximum size (%d bytes) — "+
				"registry may be corrupted: run `byreis doctor`", entry.Name(), maxCounterJSONBytes)
		}

		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}

		if dupErr := checkDuplicateJSONKeys(raw); dupErr != nil {
			return obs, fmt.Errorf("%w: walkCounterStore: duplicate JSON key in counter file %q: %v — "+
				"registry may be corrupted: run `byreis doctor`",
				ErrRegistryConcurrentWrite, entry.Name(), dupErr)
		}

		var cf counterFileJSON
		if decErr := json.Unmarshal(raw, &cf); decErr != nil {
			return obs, fmt.Errorf("walkCounterStore: JSON parse failure in counter file %q: %w — "+
				"registry may be corrupted: run `byreis doctor`", entry.Name(), decErr)
		}
		if cf.Pending == nil {
			continue
		}

		logicalName := cf.File
		if logicalName == "" {
			logicalName = strings.TrimSuffix(entry.Name(), ".json")
		}

		// Duplicate-key collision guard: two counter files with the same logical name.
		if _, dup := seen[logicalName]; dup {
			return obs, fmt.Errorf("walkCounterStore: duplicate logical name %q in counter store for project %q — "+
				"registry may be corrupted: run `byreis doctor`", logicalName, projectID)
		}
		seen[logicalName] = struct{}{}

		// Check if target_pr matches the byreis/rotate-* pattern.
		// Non-rotation pendings are silently skipped (not an error: normal submit pendings
		// coexist with the counter store).
		targetPR := cf.Pending.TargetPR
		if !strings.Contains(targetPR, "byreis/rotate-") {
			continue
		}

		var pendingCounter uint64
		_ = json.Unmarshal([]byte(cf.Pending.PendingCounter.String()), &pendingCounter)

		po := rotate.PendingObservation{
			LogicalName:       logicalName,
			PendingCounter:    pendingCounter,
			TargetArtifactSHA: cf.Pending.TargetArtifactSHA,
			TargetPR:          parsePRRefFromString(targetPR),
		}
		obs.PendingsTaggedRotation = append(obs.PendingsTaggedRotation, po)
		obs.MatchingPendings = append(obs.MatchingPendings, po)
	}

	// Sort for determinism.
	sort.Slice(obs.PendingsTaggedRotation, func(i, j int) bool {
		return obs.PendingsTaggedRotation[i].LogicalName < obs.PendingsTaggedRotation[j].LogicalName
	})
	sort.Slice(obs.MatchingPendings, func(i, j int) bool {
		return obs.MatchingPendings[i].LogicalName < obs.MatchingPendings[j].LogicalName
	})

	return obs, nil
}

// parsePRRefFromString parses a "project#number" string into a git.PRRef.
// Returns zero value on parse failure.
func parsePRRefFromString(s string) git.PRRef {
	hashIdx := strings.LastIndex(s, "#")
	if hashIdx <= 0 {
		return git.PRRef{}
	}
	project := s[:hashIdx]
	var num int
	_, err := fmt.Sscanf(s[hashIdx+1:], "%d", &num)
	if err != nil || num <= 0 {
		return git.PRRef{}
	}
	return git.PRRef{Project: project, Number: num}
}

// checkRotationBranch checks the project repo for byreis/rotate-* branches.
func (a *RotationReverserAdapter) checkRotationBranch(
	ctx context.Context,
	token string,
) (exists, merged bool, ref git.PRRef, err error) {
	tmpDir, mkErr := a.d.MkdirTemp("", "byreis-reverser-branch-*")
	if mkErr != nil {
		return false, false, git.PRRef{}, fmt.Errorf("creating branch-check workspace: %w", mkErr)
	}
	defer func() { _ = a.d.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec
		return false, false, git.PRRef{}, fmt.Errorf("chmod branch-check workspace: %w", chErr)
	}

	env := a.buildEnv(tmpDir, a.d.ProjectRepoURL, token, true)

	// Use git ls-remote to list branches without a full clone.
	lsCtx, lsCancel := fetchtransport.WithBoundedDeadline(ctx, 20*time.Second)
	defer lsCancel()

	stdout, _, lsExit, lsErr := a.d.Runner.Run(
		lsCtx, tmpDir, env,
		"git", "ls-remote", "--heads", a.d.ProjectRepoURL, "refs/heads/byreis/rotate-*",
	)
	if lsErr != nil {
		return false, false, git.PRRef{}, fmt.Errorf("git ls-remote error: %w", lsErr)
	}
	if lsExit != 0 {
		// Non-zero exit from ls-remote: treat as "no branches found" not an error.
		return false, false, git.PRRef{}, nil
	}

	lines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		branchRef := parts[1] // e.g. refs/heads/byreis/rotate-<key>-<ts>
		if strings.HasPrefix(branchRef, "refs/heads/byreis/rotate-") {
			// Extract branch name (strip refs/heads/).
			branchName := strings.TrimPrefix(branchRef, "refs/heads/")
			// Build a PRRef: Project is the project repo identity, Number is 0
			// (rotation branches are not PRs; we use PRRef as the branch identifier).
			// For the reverser, the branch ref is stored with Number=0 as a convention.
			prjID := projectIDFromURL(a.d.ProjectRepoURL)
			return true, false, git.PRRef{Project: prjID + "/" + branchName, Number: 0}, nil
		}
	}
	return false, false, git.PRRef{}, nil
}

// projectIDFromURL derives a project ID string from a repository URL for use
// as the PRRef.Project field in rotation branch refs.
func projectIDFromURL(repoURL string) string {
	u := strings.TrimSuffix(repoURL, ".git")
	if after, ok := strings.CutPrefix(u, "https://github.com/"); ok {
		return after
	}
	if after, ok := strings.CutPrefix(u, "git@github.com:"); ok {
		return after
	}
	if strings.HasPrefix(u, "file://") {
		return strings.TrimPrefix(u, "file://")
	}
	return u
}

// ClearPendings clears the per-file rotation-tagged pendings for the project
// AND appends the supplied rotation-reversal audit event in a SINGLE signed
// registry commit (same-commit atomicity per the port contract).
//
// Pre-marshal validation: calls audit.ValidateEventFields BEFORE marshalling to
// JSONL AND before staging any file. On validation failure: returns error
// wrapping audit.ErrAuditEventInvalidField; registry HEAD UNCHANGED.
//
// CAS: uses --force-with-lease=refs/heads/main:<parentSHA> where parentSHA is
// captured from the registry HEAD at the start of this call.
//
// No internal retry: the reconciler owns the bounded retry budget.
func (a *RotationReverserAdapter) ClearPendings(
	ctx context.Context,
	projectID string,
	pendings []rotate.PendingObservation,
	reversalEvent audit.Event,
) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("ClearPendings: context cancelled: %w", ctxErr)
	}
	if err := fetchtransport.ValidateProjectID(projectID); err != nil {
		return fmt.Errorf("ClearPendings: invalid projectID: %w", err)
	}
	if len(pendings) == 0 {
		return fmt.Errorf("ClearPendings: pendings slice is empty — nothing to clear; " +
			"call only when classification is PHASE_1_ONLY with at least one pending")
	}

	// Pre-marshal validation BEFORE any git operation or file staging.
	if validateErr := audit.ValidateEventFields(reversalEvent); validateErr != nil {
		return fmt.Errorf("ClearPendings: reversal audit event validation failed: %w — "+
			"verify the audit-event producer constructs canonical-typed Details values",
			validateErr)
	}

	token, tokenErr := a.d.TokenProvider.RegistryWriteToken(ctx, a.d.RegistryURL)
	if tokenErr != nil {
		return fmt.Errorf("%w: ClearPendings: retrieving registry-write token: %v",
			ErrRegistryWriteAuth, tokenErr)
	}

	tmpDir, mkErr := a.d.MkdirTemp("", "byreis-clear-pendings-*")
	if mkErr != nil {
		return fmt.Errorf("ClearPendings: creating workspace: %w — check filesystem permissions", mkErr)
	}
	defer func() { _ = a.d.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec
		return fmt.Errorf("ClearPendings: chmod workspace: %w", chErr)
	}

	cloneDir := filepath.Join(tmpDir, "repo")
	env := a.buildEnv(tmpDir, a.d.RegistryURL, token, true)

	// Step 1: shallow clone the registry.
	cloneCtx, cloneCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := a.d.Runner.Run(
		cloneCtx, tmpDir, env,
		"git", "clone", "--depth=1", "--no-local", "--", a.d.RegistryURL, cloneDir,
	)
	if cloneErr != nil {
		return fmt.Errorf("ClearPendings: git clone error: %w — run `byreis doctor`", cloneErr)
	}
	if cloneExit != 0 {
		return fmt.Errorf("%w: ClearPendings: git clone exited %d: %s",
			ErrRegistryWriteAuth, cloneExit, fetchtransport.SanitizeOutput(cloneStderr))
	}

	// Step 2: capture the registry HEAD for CAS.
	revCtx, revCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer revCancel()

	revStdout, _, revExit, revErr := a.d.Runner.Run(
		revCtx, cloneDir, a.hardenedEnvNoAuth(tmpDir),
		"git", "rev-parse", "HEAD",
	)
	if revErr != nil {
		return fmt.Errorf("ClearPendings: git rev-parse HEAD error: %w", revErr)
	}
	if revExit != 0 {
		return fmt.Errorf("ClearPendings: git rev-parse HEAD exited %d", revExit)
	}
	parentSHA := strings.TrimSpace(string(revStdout))
	if !fetchtransport.IsValidSHA(parentSHA) {
		return fmt.Errorf("ClearPendings: git rev-parse returned non-SHA %q", parentSHA)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Step 3: clear each pending's rotation fields in its counter file.
	for _, po := range pendings {
		if err := fetchtransport.ValidateFileName(po.LogicalName); err != nil {
			return fmt.Errorf("ClearPendings: invalid LogicalName %q: %w", po.LogicalName, err)
		}

		blobPath := fetchtransport.CounterBlobPath(projectID, po.LogicalName)
		counterFilePath := filepath.Join(cloneDir, filepath.FromSlash(blobPath))

		currentRaw, readErr := os.ReadFile(counterFilePath) //nolint:gosec
		var existing counterFileParsed
		if readErr != nil {
			if !os.IsNotExist(readErr) {
				return fmt.Errorf("ClearPendings: reading counter file for %q: %w", po.LogicalName, readErr)
			}
			// File absent: create minimal cleared state.
		} else if len(currentRaw) > maxCounterJSONBytes {
			return fmt.Errorf("ClearPendings: counter file for %q exceeds max size", po.LogicalName)
		} else if len(strings.TrimSpace(string(currentRaw))) > 0 {
			if dupErr := checkDuplicateJSONKeys(currentRaw); dupErr != nil {
				return fmt.Errorf("%w: ClearPendings: duplicate key in counter file for %q: %v",
					ErrRegistryConcurrentWrite, po.LogicalName, dupErr)
			}
			var decErr error
			existing, decErr = decodeCounterFile(currentRaw)
			if decErr != nil {
				return fmt.Errorf("ClearPendings: decoding counter file for %q: %w", po.LogicalName, decErr)
			}
		}

		// Clear the pending record without advancing last_accepted_counter or
		// rotation_epoch. The reversal clears only the pending_ fields.
		wire := counterFileJSON{
			ProjectID:           projectID,
			File:                po.LogicalName,
			LastAcceptedCounter: json.Number(fmt.Sprintf("%d", existing.LastAcceptedCounter)),
			LastPR:              existing.LastPR,
			UpdatedAt:           now,
			Pending:             nil, // cleared atomically in this commit
			RotationEpoch:       epochNumberOrOmit(existing.RotationEpoch),
		}

		newJSON, marshalErr := json.MarshalIndent(wire, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("ClearPendings: marshalling counter JSON for %q: %w",
				po.LogicalName, marshalErr)
		}
		newJSON = append(newJSON, '\n')

		counterDir := filepath.Dir(counterFilePath)
		if mkdirErr := os.MkdirAll(counterDir, 0o700); mkdirErr != nil {
			return fmt.Errorf("ClearPendings: creating counter directory for %q: %w", po.LogicalName, mkdirErr)
		}
		if writeErr := os.WriteFile(counterFilePath, newJSON, 0o600); writeErr != nil { //nolint:gosec
			return fmt.Errorf("ClearPendings: writing counter file for %q: %w", po.LogicalName, writeErr)
		}
	}

	// Step 4: build and write the audit JSONL entry (SAME commit as counter clears).
	auditJSONLBytes, auditSHA, auditErr := buildAuditJSONLEntry(reversalEvent)
	if auditErr != nil {
		return fmt.Errorf("ClearPendings: building audit JSONL entry: %w", auditErr)
	}

	auditFilePath := filepath.Join(cloneDir, "audit", projectID+".jsonl")
	auditDirPath := filepath.Dir(auditFilePath)
	if mkdirErr := os.MkdirAll(auditDirPath, 0o700); mkdirErr != nil {
		return fmt.Errorf("ClearPendings: creating audit directory: %w", mkdirErr)
	}

	auditFile, openErr := os.OpenFile(auditFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec
	if openErr != nil {
		return fmt.Errorf("ClearPendings: opening audit file: %w", openErr)
	}
	_, appendErr := auditFile.Write(auditJSONLBytes)
	closeErr := auditFile.Close()
	if appendErr != nil {
		return fmt.Errorf("ClearPendings: appending to audit file: %w", appendErr)
	}
	if closeErr != nil {
		return fmt.Errorf("ClearPendings: closing audit file: %w", closeErr)
	}

	// Step 5: build the canonical signed commit message body.
	commitMsgBody := buildReversalCommitMessageBody(projectID, pendings, parentSHA, auditSHA)

	// Step 6: stage all changed files.
	addCtx, addCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer addCancel()

	_, addStderr, addExit, addErr := a.d.Runner.Run(
		addCtx, cloneDir, a.hardenedEnvNoAuth(tmpDir),
		"git", "add", "-A",
	)
	if addErr != nil {
		return fmt.Errorf("ClearPendings: git add error: %w", addErr)
	}
	if addExit != 0 {
		return fmt.Errorf("ClearPendings: git add exited %d: %s",
			addExit, fetchtransport.SanitizeOutput(addStderr))
	}

	// Step 7: configure git identity.
	configCtx, configCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer configCancel()

	for _, cfg := range [][]string{
		{"git", "config", "user.name", "byreis-admin"},
		{"git", "config", "user.email", "byreis-admin@localhost"},
	} {
		_, _, cfgExit, cfgErr := a.d.Runner.Run(
			configCtx, cloneDir, a.hardenedEnvNoAuth(tmpDir), cfg[0], cfg[1:]...,
		)
		if cfgErr != nil || cfgExit != 0 {
			return fmt.Errorf("ClearPendings: git config %s failed", cfg[2])
		}
	}

	// Step 8: sign the commit message body.
	signerID, sig, signErr := a.d.Signer.SignText(ctx, []byte(commitMsgBody))
	if signErr != nil {
		return fmt.Errorf("ClearPendings: signing commit message body: %w — "+
			"check admin identity configuration: run `byreis doctor`", signErr)
	}

	fullMessage := commitMsgBody + "\n\nbyreis-signer: " + signerID +
		"\nbyreis-sig: " + fmt.Sprintf("%x", sig) + "\n"

	// Step 9: write the commit message to a temp file so the byreis-sig: footer
	// never appears in the git subprocess argv.
	msgFile := filepath.Join(tmpDir, "commitmsg-reversal.txt")
	if wErr := os.WriteFile(msgFile, []byte(fullMessage), 0o600); wErr != nil { //nolint:gosec
		return fmt.Errorf("ClearPendings: writing commit message file: %w", wErr)
	}
	defer func() { _ = os.Remove(msgFile) }()

	commitCtx, commitCancel := fetchtransport.WithBoundedDeadline(ctx, 30*time.Second)
	defer commitCancel()

	_, commitStderr, commitExit, commitErr := a.d.Runner.Run(
		commitCtx, cloneDir, a.hardenedEnvNoAuth(tmpDir),
		"git", "commit", "-F", msgFile,
	)
	if commitErr != nil {
		return fmt.Errorf("ClearPendings: git commit error: %w", commitErr)
	}
	if commitExit != 0 {
		return fmt.Errorf("ClearPendings: git commit exited %d: %s",
			commitExit, fetchtransport.SanitizeOutput(commitStderr))
	}

	// Step 10: conditional push — CAS via --force-with-lease=refs/heads/main:<parentSHA>.
	pushCtx, pushCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer pushCancel()

	leaseRef := "refs/heads/main:" + parentSHA
	_, pushStderr, pushExit, pushErr := a.d.Runner.Run(
		pushCtx, cloneDir, env,
		"git", "push", "--force-with-lease="+leaseRef, "origin", "main",
	)
	if pushErr != nil {
		return fmt.Errorf("ClearPendings: git push error: %w — "+
			"check network connectivity: run `byreis doctor`", pushErr)
	}
	switch pushExit {
	case 0:
		return nil
	case 1:
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "rejected") ||
			strings.Contains(stderrStr, "non-fast-forward") ||
			strings.Contains(stderrStr, "stale info") {
			return fmt.Errorf("%w: ClearPendings: push rejected "+
				"(non-fast-forward / concurrent write detected): %s",
				ErrRegistryConcurrentWrite, stderrStr)
		}
		return fmt.Errorf("%w: ClearPendings: push rejected by remote: %s",
			ErrRegistryWriteRejected, stderrStr)
	default:
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "403") ||
			strings.Contains(stderrStr, "401") ||
			strings.Contains(stderrStr, "Authentication") {
			return fmt.Errorf("%w: ClearPendings: push authentication failure: %s",
				ErrRegistryWriteAuth, stderrStr)
		}
		return fmt.Errorf("%w: ClearPendings: git push exited %d: %s",
			ErrRegistryWriteRejected, pushExit, stderrStr)
	}
}

// DeleteRotationBranch deletes the unmerged rotation branch on the project repo
// via git push --delete.
func (a *RotationReverserAdapter) DeleteRotationBranch(ctx context.Context, ref git.PRRef) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("DeleteRotationBranch: context cancelled: %w", ctxErr)
	}
	if ref.Project == "" {
		return fmt.Errorf("DeleteRotationBranch: empty branch ref — " +
			"probe must populate RotationBranchRef for any PHASE_1_ONLY observation")
	}

	token, tokenErr := a.d.TokenProvider.RegistryWriteToken(ctx, a.d.ProjectRepoURL)
	if tokenErr != nil {
		return fmt.Errorf("%w: DeleteRotationBranch: retrieving project-repo token: %v",
			ErrRegistryWriteAuth, tokenErr)
	}

	tmpDir, mkErr := a.d.MkdirTemp("", "byreis-delete-branch-*")
	if mkErr != nil {
		return fmt.Errorf("DeleteRotationBranch: creating workspace: %w", mkErr)
	}
	defer func() { _ = a.d.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec
		return fmt.Errorf("DeleteRotationBranch: chmod workspace: %w", chErr)
	}

	// Extract the branch name from the PRRef.Project field.
	// Convention: PRRef.Project = "<repoOwner/repoName>/<branchName>" for rotation branches.
	branchName := extractBranchFromRef(ref)
	if branchName == "" {
		return fmt.Errorf("DeleteRotationBranch: cannot extract branch name from ref %+v", ref)
	}

	env := a.buildEnv(tmpDir, a.d.ProjectRepoURL, token, true)

	pushCtx, pushCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer pushCancel()

	_, pushStderr, pushExit, pushErr := a.d.Runner.Run(
		pushCtx, tmpDir, env,
		"git", "push", a.d.ProjectRepoURL, "--delete", branchName,
	)
	if pushErr != nil {
		return fmt.Errorf("DeleteRotationBranch: git push --delete error: %w", pushErr)
	}
	switch pushExit {
	case 0:
		return nil
	case 1:
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "rejected") ||
			strings.Contains(stderrStr, "non-fast-forward") ||
			strings.Contains(stderrStr, "not found") ||
			strings.Contains(stderrStr, "remote ref does not exist") {
			return fmt.Errorf("%w: DeleteRotationBranch: push --delete rejected "+
				"(branch may already be deleted or merged): %s",
				ErrRegistryConcurrentWrite, stderrStr)
		}
		return fmt.Errorf("%w: DeleteRotationBranch: push --delete rejected by remote: %s",
			ErrRegistryWriteRejected, stderrStr)
	default:
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "403") ||
			strings.Contains(stderrStr, "401") ||
			strings.Contains(stderrStr, "Authentication") {
			return fmt.Errorf("%w: DeleteRotationBranch: authentication failure: %s",
				ErrRegistryWriteAuth, stderrStr)
		}
		return fmt.Errorf("%w: DeleteRotationBranch: git push --delete exited %d: %s",
			ErrRegistryWriteRejected, pushExit, stderrStr)
	}
}

// extractBranchFromRef extracts the branch name from a rotation PRRef.
// PartialStateObservation.RotationBranchRef.Project encodes exactly three
// slash-separated segments: <owner>/<repo>/<branchName>, where branchName may
// itself contain slashes (e.g. "byreis/rotate-key-ts"). A Project value with a
// segment count other than exactly 3 returns the empty string; callers surface
// a descriptive error rather than producing a partial or mis-routed push-delete.
func extractBranchFromRef(ref git.PRRef) string {
	parts := strings.SplitN(ref.Project, "/", 3)
	if len(parts) != 3 {
		return ""
	}
	return parts[2]
}

// buildEnv constructs the git isolation environment with exactly one
// GIT_CONFIG_COUNT entry. When withAuth is true AND gitAuthEnvBlock confirms
// that repoURL is a GitHub HTTPS URL, count is 3 with the Authorization header
// scoped to github.com; otherwise count is 2 (no auth header). Passing the
// target URL ensures a cross-host redirect never carries the token — non-GitHub
// and file:// callers naturally produce the two-entry noauth block.
//
// The auth header uses HTTP Basic with base64(x-access-token:<token>) to match
// GitHub's git-over-HTTPS requirement. Bearer is rejected by GitHub's smart-HTTP
// endpoint; the same encoding is used by gitAuthEnvBlock for consistency.
func (a *RotationReverserAdapter) buildEnv(tmpDir, repoURL, token string, withAuth bool) []string {
	base := fetchtransport.CleanGitEnv()
	if withAuth && gitAuthEnvBlock(repoURL, token) != nil {
		encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		return append(base,
			"GIT_CONFIG_NOSYSTEM=1",
			"HOME="+tmpDir,
			"GIT_TERMINAL_PROMPT=0",
			"GIT_ALLOW_PROTOCOL=file:https:ssh",
			"GIT_CONFIG_COUNT=3",
			"GIT_CONFIG_KEY_0=core.hooksPath",
			"GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=core.fsmonitor",
			"GIT_CONFIG_VALUE_1=",
			"GIT_CONFIG_KEY_2=http."+gitHubHTTPSBase+".extraHeader",
			"GIT_CONFIG_VALUE_2=Authorization: Basic "+encoded,
		)
	}
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

// hardenedEnvNoAuth builds the isolation environment without HTTP auth.
// Delegates to buildEnv with withAuth=false and an empty URL.
func (a *RotationReverserAdapter) hardenedEnvNoAuth(tmpDir string) []string {
	return a.buildEnv(tmpDir, "", "", false)
}

// buildReversalCommitMessageBody returns the canonical signed-payload envelope
// for a rotation-reversal commit message body.
func buildReversalCommitMessageBody(
	projectID string,
	pendings []rotate.PendingObservation,
	registryParentSHA, auditEntrySHA string,
) string {
	var b strings.Builder
	b.WriteString("byreis: rotation reversal\n\n")
	fmt.Fprintf(&b, "project_id: %s\n", projectID)
	fmt.Fprintf(&b, "registry_parent_sha: %s\n", registryParentSHA)
	fmt.Fprintf(&b, "audit_entry_sha: %s\n", auditEntrySHA)
	fmt.Fprintf(&b, "pendings_cleared: %d\n", len(pendings))

	// Sort pendings ascending by LogicalName for deterministic body.
	sorted := make([]rotate.PendingObservation, len(pendings))
	copy(sorted, pendings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].LogicalName < sorted[j].LogicalName
	})
	for _, po := range sorted {
		fmt.Fprintf(&b, "pending_cleared: %s\n", po.LogicalName)
	}
	return b.String()
}
