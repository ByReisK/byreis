package registry

// Phase2Executor implementation lives on rotationPhaseAdapter (defined in
// rotation_phase1.go). This file adds the Execute(ctx, Phase1Result) method.
//
// Phase-2 is the TERMINAL leg:
//   - CAS fast-forward push to project main with
//     --force-with-lease=refs/heads/main:<Phase1Result.ProjectParentSHA>.
//     NO bare --force. NO rebase. CAS rejection → ErrRegistryConcurrentWrite.
//   - Calls RegistryClient.CommitRotation with audit event built from the
//     plan stored by Phase-1 (via the planMu-guarded lastPlan field).
//   - Returns Phase2Result with MergedSHA and CommitRotationSHA.
//
// Error handling: errors NEVER trigger auto-rollback. A mid-flight
// failure is classified as PHASE_2_MIDFLIGHT by the reconciler and surfaces
// ErrRotationReconcile to the operator.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// Execute runs Phase-2: fast-forward merge via CAS push, then CommitRotation.
//
// The plan stored by Phase-1 is retrieved from the shared state. A Phase-2
// call without a preceding Phase-1 on the same adapter pair returns an error.
func (a *rotationPhase2Adapter) Execute(ctx context.Context, p1 rotate.Phase1Result) (rotate.Phase2Result, error) {
	if err := ctx.Err(); err != nil {
		return rotate.Phase2Result{}, fmt.Errorf("Phase2.Execute: context cancelled: %w", err)
	}

	// Retrieve the plan that Phase-1 stored.
	a.shared.planMu.Lock()
	plan := a.shared.lastPlan
	a.shared.planMu.Unlock()
	if plan == nil {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: no plan available — Phase1.Execute must be called " +
				"on the same adapter instance before Phase2.Execute")
	}

	if !fetchtransport.IsValidSHA(p1.ProjectParentSHA) {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: ProjectParentSHA %q is not a valid SHA — "+
				"Phase-1 must capture the project-repo HEAD before branch creation",
			p1.ProjectParentSHA)
	}
	if !fetchtransport.IsValidSHA(p1.RegistryParentSHA) {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: RegistryParentSHA %q is not a valid SHA — "+
				"Phase-1 must capture the registry HEAD after all pending bumps",
			p1.RegistryParentSHA)
	}
	if len(p1.PerFileResults) == 0 {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: no per-file results in Phase1Result — " +
				"Phase-1 must process at least one file")
	}
	if p1.BranchRef.Project == "" {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: empty BranchRef.Project in Phase1Result — " +
				"Phase-1 must populate BranchRef")
	}

	// Extract branch name from BranchRef.Project = "<owner>/<repo>/<branchName>".
	branchName := extractBranchFromRef(p1.BranchRef)
	if branchName == "" {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: cannot extract branch name from BranchRef %+v — "+
				"expected exactly three slash-separated segments",
			p1.BranchRef)
	}

	// Load the project-repo write credential.
	token, tokenErr := a.d.TokenProvider.RegistryWriteToken(ctx, a.d.ProjectRepoURL)
	if tokenErr != nil {
		return rotate.Phase2Result{}, fmt.Errorf(
			"%w: Phase2.Execute: retrieving project-repo token: %v",
			ErrRegistryWriteAuth, tokenErr)
	}

	// Create an isolated 0700 workspace for the CAS push.
	tmpDir, mkErr := a.d.MkdirTemp("", "byreis-rotation-phase2-*")
	if mkErr != nil {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: creating workspace: %w — check filesystem permissions", mkErr)
	}
	defer func() { _ = a.d.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: chmod workspace: %w", chErr)
	}

	cloneDir := tmpDir // we use a shallow clone of the project repo

	// buildEnv constructs the git isolation environment with exactly one
	// GIT_CONFIG_COUNT entry. When withAuth is true and a token is available,
	// the count is 3 and the Authorization header is appended; otherwise 2.
	buildEnv := func(withAuth bool) []string {
		base := fetchtransport.CleanGitEnv()
		if withAuth && token != "" {
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
				"GIT_CONFIG_KEY_2=http.extraHeader",
				"GIT_CONFIG_VALUE_2=Authorization: Bearer "+token,
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

	projCloneDir := tmpDir + "/project"

	// Step 7a: shallow clone the project repo at the rotation branch.
	cloneCtx, cloneCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := a.d.Runner.Run(
		cloneCtx, cloneDir, buildEnv(true),
		"git", "clone", "--depth=1", "--branch", branchName, "--no-local", "--",
		a.d.ProjectRepoURL, projCloneDir,
	)
	if cloneErr != nil {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: git clone error: %w — run `byreis doctor`", cloneErr)
	}
	if cloneExit != 0 {
		return rotate.Phase2Result{}, fmt.Errorf(
			"%w: Phase2.Execute: git clone exited %d: %s",
			ErrRegistryWriteAuth, cloneExit, fetchtransport.SanitizeOutput(cloneStderr))
	}

	// Step 7b: capture branch HEAD SHA (this becomes MergedSHA after the push
	// fast-forwards main to this commit).
	revCtx, revCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer revCancel()

	revStdout, _, revExit, revErr := a.d.Runner.Run(
		revCtx, projCloneDir, buildEnv(false),
		"git", "rev-parse", "HEAD",
	)
	if revErr != nil {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: git rev-parse HEAD error: %w", revErr)
	}
	if revExit != 0 {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: git rev-parse HEAD exited %d", revExit)
	}
	branchHeadSHA := strings.TrimSpace(string(revStdout))
	if !fetchtransport.IsValidSHA(branchHeadSHA) {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: git rev-parse returned non-SHA %q", branchHeadSHA)
	}

	// Step 7c: CAS fast-forward push — NO bare --force, NO rebase.
	// --force-with-lease=refs/heads/main:<ProjectParentSHA> atomically advances
	// main IFF it is still at ProjectParentSHA. A stale lease → CAS rejection.
	pushCtx, pushCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer pushCancel()

	leaseRef := "refs/heads/main:" + p1.ProjectParentSHA
	_, pushStderr, pushExit, pushErr := a.d.Runner.Run(
		pushCtx, projCloneDir, buildEnv(true),
		"git", "push", "--force-with-lease="+leaseRef, "origin",
		branchName+":main",
	)
	if pushErr != nil {
		return rotate.Phase2Result{}, fmt.Errorf(
			"Phase2.Execute: git push error: %w — run `byreis doctor`", pushErr)
	}
	switch pushExit {
	case 0:
		// CAS push succeeded: branchHeadSHA is now main HEAD.
	case 1:
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "rejected") ||
			strings.Contains(stderrStr, "non-fast-forward") ||
			strings.Contains(stderrStr, "stale info") {
			return rotate.Phase2Result{}, fmt.Errorf(
				"%w: Phase2.Execute: CAS push rejected "+
					"(project main moved since Phase-1: concurrent write): %s — "+
					"run `byreis admin rotation reconcile`",
				ErrRegistryConcurrentWrite, stderrStr)
		}
		return rotate.Phase2Result{}, fmt.Errorf(
			"%w: Phase2.Execute: push rejected by remote: %s",
			ErrRegistryWriteRejected, stderrStr)
	default:
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "403") || strings.Contains(stderrStr, "401") ||
			strings.Contains(stderrStr, "Authentication") {
			return rotate.Phase2Result{}, fmt.Errorf(
				"%w: Phase2.Execute: push authentication failure: %s",
				ErrRegistryWriteAuth, stderrStr)
		}
		return rotate.Phase2Result{}, fmt.Errorf(
			"%w: Phase2.Execute: git push exited %d: %s",
			ErrRegistryWriteRejected, pushExit, stderrStr)
	}

	// Step 8: CommitRotation — atomic N-file counter advance + pending clear +
	// epoch update + audit append in one signed registry commit.
	//
	// Build PerFileCommit list from Phase1Result.PerFileResults.
	perFile := make([]coreregistry.PerFileCommit, len(p1.PerFileResults))
	for i, pfr := range p1.PerFileResults {
		perFile[i] = coreregistry.PerFileCommit{
			LogicalName:    pfr.LogicalName,
			PendingCounter: pfr.PendingCounter,
			TargetSHA:      pfr.ContentSHA,
			TargetPR:       fmt.Sprintf("%s#%d", p1.BranchRef.Project, p1.BranchRef.Number),
		}
	}

	// Build the rotation audit event using the plan stored by Phase-1.
	// p1.FromRequestPR is non-nil only on `--from-request` lifts; nil keeps
	// the existing rotation audit-event shape for plain --add/--remove runs.
	auditEvent := rotate.BuildRotationAuditEvent(*plan, a.d.ProjectID, time.Now().UTC(), p1.FromRequestPR)

	commitRotInput := coreregistry.CommitRotationInput{
		ProjectID:         a.d.ProjectID,
		PerFile:           perFile,
		NewEpoch:          p1.PlannedEpoch,
		RegistryParentSHA: p1.RegistryParentSHA,
		AuditEntry:        auditEvent,
	}

	commitResult, commitRotErr := a.d.RegistryClient.CommitRotation(ctx, commitRotInput)
	if commitRotErr != nil {
		// Phase-2 is TERMINAL: no auto-rollback. Surface ErrRotationReconcile
		// so the operator can use `byreis admin rotation reconcile`.
		return rotate.Phase2Result{}, fmt.Errorf(
			"%w: Phase2.Execute: CommitRotation failed: %v — "+
				"the rotation branch is merged but the registry commit did not land; "+
				"run `byreis admin rotation reconcile`",
			rotate.ErrRotationReconcile, commitRotErr)
	}

	return rotate.Phase2Result{
		MergedSHA:         branchHeadSHA,
		CommitRotationSHA: commitResult.CommitSHA,
		NewEpoch:          commitResult.NewEpoch,
		IntegrityChecks:   nil, // post-merge integrity check is a v0.3 extension
	}, nil
}
