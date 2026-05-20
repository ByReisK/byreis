// Package github implements the internal/core/git.GitProvider interface using
// the GitHub REST API (github.com/google/go-github/v72). SDK types are mapped
// to domain types at this boundary; no GitHub SDK type leaks into
// internal/core/git or any other core package.
//
// ArtifactSHA semantics:
//   - The contributor-side move-detection SHA (returned by OpenSubmissionPR /
//     GetSubmission and checked by MergeSubmission) is sha256(raw artifact
//     bytes as pushed/fetched), with zero normalisation. This is the
//     repo-side pin for the on-PR move-detection TOCTOU guard.
//   - The of-record SHA recorded in MergeResult.LiveFileSHA is
//     verify.ContentSHA(parsedSignedArtifact) — the canonical-domain preimage
//     (sha256(manifest.Encode(m) || 0x1f || rawSig)). The registry adapter
//     MUST use this value for PendingBump.TargetArtifactSHA. The two SHAs
//     serve distinct purposes and MUST NOT be conflated.
//
// The recorder==verifier test (TestMergeSubmission_LiveFileSHA_EqualsContentSHA)
// proves that LiveFileSHA == verify.ContentSHA(parsed), one function, one
// preimage.
//
// This package honors context cancellation/deadlines on every API call.
// Auth errors produce an actionable hint. No token or secret appears in errors
// or structured logs.
package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	ghsdk "github.com/google/go-github/v72/github"
	"go.yaml.in/yaml/v3"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	coregit "github.com/ByReisK/byreis/internal/core/git"
)

// Package-level sentinel errors.
var (
	// ErrBranchConflict is returned by OpenSubmissionPR when the submission
	// branch already exists. The caller may clean up or resume via a
	// uniquely-named branch.
	ErrBranchConflict = errors.New(
		"submission branch already exists on GitHub — " +
			"use a unique branch name or clean up the existing one with `byreis submit --force`")
)

// retry parameters for transient errors.
const (
	maxRetries    = 3
	retryBaseWait = 200 * time.Millisecond
)

// Provider is the GitHub-backed GitProvider implementation. All fields are
// injected via New or NewWithClient; there are no globals.
type Provider struct {
	// client is the GitHub API client. Constructed and auth-wrapped at
	// injection time; never mutated after construction.
	client *ghsdk.Client

	// owner and repo are the parsed components of the project string (e.g.
	// "myorg/my-secrets" → owner="myorg", repo="my-secrets").
	owner string
	repo  string

	// baseBranch is the base branch to create PRs against (default "main").
	baseBranch string

	// submissionDir is the directory within the repo where unsigned submission
	// artifacts are committed (e.g. "submissions").
	submissionDir string
}

// New constructs a Provider with a real GitHub client authenticated by token.
// project must be "owner/repo". baseBranch is the PR target (e.g. "main").
// submissionDir is the directory for unsigned submission artifacts.
//
// An empty token is a configuration error: the caller must provide a token
// sourced from the OS keychain / BYREIS_KEY env (via internal/auth).
func New(token, project, baseBranch, submissionDir string) (*Provider, error) {
	if token == "" {
		return nil, fmt.Errorf("GitHub token is empty — run `byreis auth login` to authenticate")
	}
	client := ghsdk.NewClient(nil).WithAuthToken(token)
	return newProvider(client, project, baseBranch, submissionDir)
}

// NewWithClient constructs a Provider with an already-configured GitHub client.
// This is the injection point for tests (httptest fake servers).
// Returns (*Provider, error); a malformed project string returns
// coregit.ErrInvalidProject (never a panic).
func NewWithClient(client *ghsdk.Client, project, baseBranch, submissionDir string) (*Provider, error) {
	return newProvider(client, project, baseBranch, submissionDir)
}

func newProvider(client *ghsdk.Client, project, baseBranch, submissionDir string) (*Provider, error) {
	parts := strings.SplitN(project, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("%w: got %q — expected owner/repo (e.g. myorg/my-secrets)",
			coregit.ErrInvalidProject, project)
	}
	// The repo part must not contain a slash (triple-slash and deeper paths
	// are invalid project identifiers).
	if strings.Contains(parts[1], "/") {
		return nil, fmt.Errorf("%w: got %q — repo part must not contain '/'; "+
			"expected owner/repo (e.g. myorg/my-secrets)",
			coregit.ErrInvalidProject, project)
	}
	return &Provider{
		client:        client,
		owner:         parts[0],
		repo:          parts[1],
		baseBranch:    baseBranch,
		submissionDir: submissionDir,
	}, nil
}

// Compile-time assertion that Provider implements GitProvider.
var _ coregit.GitProvider = (*Provider)(nil)

// OpenSubmissionPR creates a branch + commit of the unsigned artifact and
// opens a PR. It returns the PR and the contributor-side ArtifactSHA
// (sha256 over the raw artifact bytes pushed, zero normalisation). This is
// the move-detection pin used by the on-PR artifact-SHA TOCTOU guard; it is distinct from verify.ContentSHA.
//
// The PR body is structured: it contains the caller-supplied justification text
// PLUS a single fenced byreis-submission JSON block encoding the SubmissionMeta
// (SecretsPath, Key, Action, Project, ArtifactSHA echo).
//
// The branch is assumed to be unique (named by the caller via the byreis
// convention). If the branch already exists, ErrBranchConflict is returned.
func (p *Provider) OpenSubmissionPR(ctx context.Context, in coregit.OpenPRInput) (coregit.PullRequest, error) {
	if err := ctx.Err(); err != nil {
		return coregit.PullRequest{}, fmt.Errorf("github OpenSubmissionPR cancelled: %w", err)
	}

	// 1. Resolve the base branch HEAD commit SHA.
	baseSHA, err := p.resolveRef(ctx, "refs/heads/"+p.baseBranch)
	if err != nil {
		return coregit.PullRequest{}, fmt.Errorf("resolving base branch %q: %w", p.baseBranch, err)
	}

	// 2. Create the submission branch off the base.
	err = p.createBranch(ctx, in.Branch, baseSHA)
	if err != nil {
		if errors.Is(err, ErrBranchConflict) {
			return coregit.PullRequest{}, ErrBranchConflict
		}
		return coregit.PullRequest{}, fmt.Errorf("creating submission branch %q: %w", in.Branch, err)
	}

	// 3. Commit the unsigned artifact to the submission directory on the branch.
	filePath := p.submissionFilePath(in.Branch)
	commitMsg := fmt.Sprintf("byreis: add submission artifact (%s %s)", actionLabel(in.Action), in.Key)
	err = p.commitFile(ctx, in.Branch, filePath, in.ArtifactBytes, commitMsg)
	if err != nil {
		return coregit.PullRequest{}, fmt.Errorf("committing submission artifact: %w", err)
	}

	// 4. Compute the contributor-side ArtifactSHA over the raw pushed bytes,
	// zero normalisation. This is the move-detection pin used by the on-PR
	// artifact-SHA TOCTOU guard; it is NOT the counter-authority target_artifact_sha.
	artifactSHA := rawBytesSHA(in.ArtifactBytes)

	// 5. Build the PR body: free-text justification + machine-parseable block.
	meta := coregit.SubmissionMeta{
		SchemaVersion: 1,
		Project:       in.Project,
		SecretsPath:   in.SecretsPath,
		BaseFilePath:  in.BaseFilePath,
		Key:           in.Key,
		Action:        actionLabel(in.Action),
		ArtifactSHA:   string(artifactSHA), // informational echo only
	}
	prBody := buildPRBody(in.Justification, meta)

	// 6. Open the PR.
	ghPR, err := p.createPR(ctx, in.Branch, in.TitleTemplate, prBody)
	if err != nil {
		return coregit.PullRequest{}, fmt.Errorf("opening submission PR: %w", err)
	}

	return coregit.PullRequest{
		Ref:         coregit.PRRef{Project: in.Project, Number: ghPR.GetNumber()},
		URL:         ghPR.GetHTMLURL(),
		Branch:      ghPR.GetHead().GetRef(),
		ArtifactSHA: artifactSHA,
	}, nil
}

// GetSubmission fetches the artifact bytes and PR metadata for admin review.
// ArtifactSHA is sha256(raw fetched bytes), zero normalisation — the
// move-detection pin that the admin passes to merge via --expect.
//
// It parses the SubmissionMeta from the PR body. If the block is absent or
// malformed, it returns ErrSubmissionMetaInvalid.
func (p *Provider) GetSubmission(ctx context.Context, ref coregit.PRRef) (coregit.Submission, error) {
	if err := ctx.Err(); err != nil {
		return coregit.Submission{}, fmt.Errorf("github GetSubmission cancelled: %w", err)
	}

	// Fetch PR metadata.
	pr, _, err := p.client.PullRequests.Get(ctx, p.owner, p.repo, ref.Number)
	if err != nil {
		return coregit.Submission{}, p.wrapAPIErr("GetSubmission/GetPR", err)
	}

	author := ""
	if pr.User != nil {
		author = pr.User.GetLogin()
	}

	// Parse the SubmissionMeta from the PR body. Absent or malformed block is
	// ErrSubmissionMetaInvalid — never a silent default-path fallback.
	meta, metaErr := coregit.ParseSubmissionMeta(pr.GetBody())
	if metaErr != nil {
		return coregit.Submission{}, fmt.Errorf("GetSubmission PR #%d: %w", ref.Number, metaErr)
	}

	// Derive the submission file path from the branch name.
	branchName := pr.GetHead().GetRef()
	filePath := p.submissionFilePath(branchName)

	// Fetch the artifact bytes from the PR branch.
	rawBytes, err := p.fetchFileContents(ctx, filePath, branchName)
	if err != nil {
		return coregit.Submission{}, fmt.Errorf("GetSubmission: fetching artifact from %q on branch %q: %w",
			filePath, branchName, err)
	}

	// Compute ArtifactSHA over the exact raw fetched bytes, zero normalisation.
	artifactSHA := rawBytesSHA(rawBytes)

	// Fetch the current live secrets file using the path from the parsed meta.
	// The base file path is informational; an error (e.g. first add) is non-fatal.
	var baseBytes []byte
	if meta.BaseFilePath != "" {
		baseBytes, _ = p.fetchFileContents(ctx, meta.BaseFilePath, p.baseBranch)
	}

	return coregit.Submission{
		Ref:           ref,
		Author:        author,
		Justification: extractJustification(pr.GetBody()),
		ArtifactBytes: rawBytes,
		ArtifactSHA:   artifactSHA,
		BaseFileBytes: baseBytes,
		Meta:          meta,
	}, nil
}

// MergeSubmission merges the reviewed submission. It first verifies the
// on-PR artifact SHA still equals ExpectSHA (move-detection TOCTOU guard — fails closed
// with ErrArtifactMoved). On success it commits SignedBytes to the protected
// secrets path (from MergeInput.SecretsPath) and merges the PR.
//
// MergeResult.LiveFileSHA is verify.ContentSHA(parsedSignedArtifact): the
// of-record canonical-domain SHA that the registry adapter MUST use for
// PendingBump.TargetArtifactSHA. The recorder==verifier contract is proven by
// TestMergeSubmission_LiveFileSHA_EqualsContentSHA.
//
// SecretsPath MUST be supplied in MergeInput (from the parsed + validated
// SubmissionMeta). The hardcoded defaultSecretsPath fallback has been removed.
func (p *Provider) MergeSubmission(ctx context.Context, in coregit.MergeInput) (coregit.MergeResult, error) {
	if err := ctx.Err(); err != nil {
		return coregit.MergeResult{}, fmt.Errorf("github MergeSubmission cancelled: %w", err)
	}

	// SecretsPath must be provided; no silent default-path fallback.
	if in.SecretsPath == "" {
		return coregit.MergeResult{}, fmt.Errorf(
			"%w: SecretsPath is empty in MergeInput — "+
				"the caller must supply the containment-validated path from SubmissionMeta",
			coregit.ErrSubmissionMetaInvalid)
	}

	// 1. Fetch PR metadata to resolve the head branch name.
	pr, _, err := p.client.PullRequests.Get(ctx, p.owner, p.repo, in.Ref.Number)
	if err != nil {
		return coregit.MergeResult{}, p.wrapAPIErr("MergeSubmission/GetPR", err)
	}
	branchName := pr.GetHead().GetRef()
	filePath := p.submissionFilePath(branchName)

	// 2. Fetch the current on-PR artifact to verify the move-detection content pin.
	currentBytes, err := p.fetchFileContents(ctx, filePath, branchName)
	if err != nil {
		return coregit.MergeResult{}, fmt.Errorf("MergeSubmission: fetching current artifact: %w", err)
	}
	currentSHA := rawBytesSHA(currentBytes)
	if currentSHA != in.ExpectSHA {
		// Move-detection invariant violated: artifact SHA changed since review. The admin must re-run review.
		return coregit.MergeResult{}, fmt.Errorf(
			"%w: current SHA %q ≠ expected %q",
			coregit.ErrArtifactMoved, currentSHA, in.ExpectSHA)
	}

	// 3. Parse the signed artifact bytes to compute LiveFileSHA via the
	// canonical verify.ContentSHA function (recorder==verifier).
	parsedSigned, err := unmarshalSigned(in.SignedBytes)
	if err != nil {
		return coregit.MergeResult{}, fmt.Errorf(
			"MergeSubmission: parsing signed artifact bytes: %w — "+
				"the SignedBytes must be a valid signed artifact produced by `byreis merge`", err)
	}
	liveFileSHA := verify.ContentSHA(parsedSigned)
	if liveFileSHA == "" {
		return coregit.MergeResult{}, fmt.Errorf(
			"MergeSubmission: verify.ContentSHA returned empty for the provided SignedBytes — " +
				"the artifact may be malformed or the signature field missing")
	}

	// 4. Use the containment-validated SecretsPath from MergeInput.
	// No fallback. No defaultSecretsPath. The path is caller-supplied and already
	// validated by ParseSubmissionMeta (lexical) and the use-case (identity cross-check).
	secretsPath := in.SecretsPath

	// 5. Commit the signed file-of-record to the secrets path on the base branch.
	mergeCommit, err := p.commitSignedFile(ctx, secretsPath, in.SignedBytes, in.CommitMessage)
	if err != nil {
		return coregit.MergeResult{}, fmt.Errorf("MergeSubmission: committing signed file: %w", err)
	}

	// 6. Merge (close) the PR.
	mergeResult, _, err := p.client.PullRequests.Merge(ctx, p.owner, p.repo, in.Ref.Number,
		"merged by byreis", &ghsdk.PullRequestOptions{
			MergeMethod: "squash",
		})
	if err != nil {
		return coregit.MergeResult{}, fmt.Errorf("MergeSubmission: merging PR #%d: %w", in.Ref.Number, p.wrapAPIErr("Merge", err))
	}

	finalCommit := mergeResult.GetSHA()
	if finalCommit == "" {
		finalCommit = mergeCommit
	}

	return coregit.MergeResult{
		MergedCommit: finalCommit,
		// LiveFileSHA is verify.ContentSHA(parsedSigned) — the of-record
		// canonical-domain SHA. The registry adapter uses this directly for
		// PendingBump.TargetArtifactSHA. It is NOT the raw git blob SHA.
		LiveFileSHA: liveFileSHA,
	}, nil
}

// RollbackSignedFile reverts the single signed-file commit identified by
// in.CommitSHA on the base branch. It is fail-closed: it refuses to rewrite
// history unless the live base-branch tip equals in.CommitSHA exactly (no
// foreign commit built on top) and in.PendingIdentity is structurally present.
//
// The only true no-op path is when in.CommitSHA was never written to the branch
// at all (the commit object does not exist). In that case the method returns nil
// without any mutation.
//
// The revert is a standard forward commit (parent's tree, child of in.CommitSHA)
// followed by a non-force ref update. No force-push, no history rewrite beyond
// the single identified commit.
//
// The decision to roll back is the caller's, driven by the registry
// pending/CommitBump state. This adapter does NOT consult PR-merged state.
func (p *Provider) RollbackSignedFile(ctx context.Context, in coregit.RollbackInput) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("github RollbackSignedFile cancelled: %w", err)
	}
	if err := in.Validate(); err != nil {
		return err
	}

	// Step 1: resolve the live base-branch tip. Bounded retry on transient errors.
	tipSHA, err := p.resolveRef(ctx, "refs/heads/"+p.baseBranch)
	if err != nil {
		return fmt.Errorf("RollbackSignedFile: resolving base branch %q: %w", p.baseBranch, err)
	}

	// Step 2: compare live tip to the identified commit.
	if tipSHA != in.CommitSHA {
		// The tip has advanced beyond our commit. Determine whether the commit
		// exists at all: if it does not, it was never written — no-op nil.
		// If it does exist, a foreign commit landed on top — ErrRollbackAmbiguous.
		exists, checkErr := p.commitExists(ctx, in.CommitSHA)
		if checkErr != nil {
			return fmt.Errorf("%w: could not verify commit %q — "+
				"check the base branch state and reconcile manually; underlying error: %v",
				coregit.ErrRollbackAmbiguous, in.CommitSHA, checkErr)
		}
		if !exists {
			// Commit was never written. True no-op.
			return nil
		}
		// Commit exists but is not the live tip — a foreign commit is on top.
		return fmt.Errorf("%w: live base tip %q != identified commit %q — "+
			"a foreign commit has been built on top; reconcile the base branch manually",
			coregit.ErrRollbackAmbiguous, tipSHA, in.CommitSHA)
	}

	// Step 3: fetch the orphaned commit to get its parent.
	orphan, err := p.getCommit(ctx, in.CommitSHA)
	if err != nil {
		return fmt.Errorf("%w: fetching orphaned commit %q: %v; "+
			"reconcile the base branch manually",
			coregit.ErrRollbackAmbiguous, in.CommitSHA, err)
	}
	if len(orphan.Parents) != 1 {
		return fmt.Errorf("%w: orphaned commit %q has %d parents (want exactly 1); "+
			"reconcile the base branch manually",
			coregit.ErrRollbackAmbiguous, in.CommitSHA, len(orphan.Parents))
	}
	parentSHA := orphan.Parents[0].GetSHA()
	if parentSHA == "" {
		return fmt.Errorf("%w: orphaned commit %q parent SHA is empty; "+
			"reconcile the base branch manually",
			coregit.ErrRollbackAmbiguous, in.CommitSHA)
	}

	// Step 4: fetch the parent commit to get its tree (the "pre-write" state).
	parentCommit, err := p.getCommit(ctx, parentSHA)
	if err != nil {
		return fmt.Errorf("%w: fetching parent commit %q: %v; "+
			"reconcile the base branch manually",
			coregit.ErrRollbackAmbiguous, parentSHA, err)
	}
	if parentCommit.Tree == nil || parentCommit.Tree.GetSHA() == "" {
		return fmt.Errorf("%w: parent commit %q has no tree SHA; "+
			"reconcile the base branch manually",
			coregit.ErrRollbackAmbiguous, parentSHA)
	}
	parentTreeSHA := parentCommit.Tree.GetSHA()

	// Step 5: create the revert commit — parent is in.CommitSHA, tree is the
	// parent commit's tree. This restores the base branch to the state before
	// the orphaned signed-file commit without touching any other commit.
	revertMsg := fmt.Sprintf("Revert signed-file commit %s", in.CommitSHA)
	revertSHA, err := p.createRevertCommit(ctx, in.CommitSHA, parentTreeSHA, revertMsg)
	if err != nil {
		return fmt.Errorf("RollbackSignedFile: creating revert commit: %w", err)
	}

	// Step 6: advance the base branch to the revert commit (non-force update).
	// This is a normal fast-forward: revertCommit's parent == in.CommitSHA == tip.
	if err := p.updateRef(ctx, "refs/heads/"+p.baseBranch, revertSHA, false); err != nil {
		return fmt.Errorf("RollbackSignedFile: advancing base branch to revert commit: %w", err)
	}
	return nil
}

// commitExists checks whether a commit with the given SHA exists in the
// repository via the Git Commits API. Returns (true, nil) if found,
// (false, nil) if not found (404), and (false, err) on other errors.
func (p *Provider) commitExists(ctx context.Context, sha string) (bool, error) {
	var exists bool
	err := p.withRetry(ctx, func() error {
		_, resp, apiErr := p.client.Git.GetCommit(ctx, p.owner, p.repo, sha)
		if apiErr != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				exists = false
				return errNoRetry{apiErr}
			}
			if resp != nil && isTransient(resp.StatusCode) {
				return apiErr // will retry
			}
			return errNoRetry{apiErr}
		}
		exists = true
		return nil
	})
	if err != nil {
		unwrapped := unwrapNoRetry(err)
		// A 404 from the Git API means commit does not exist — not an error.
		var ghErr *ghsdk.ErrorResponse
		if errors.As(unwrapped, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, p.wrapAPIErr("commitExists", unwrapped)
	}
	return exists, nil
}

// getCommit fetches the full Commit object for a given SHA.
func (p *Provider) getCommit(ctx context.Context, sha string) (*ghsdk.Commit, error) {
	var result *ghsdk.Commit
	err := p.withRetry(ctx, func() error {
		var resp *ghsdk.Response
		var apiErr error
		result, resp, apiErr = p.client.Git.GetCommit(ctx, p.owner, p.repo, sha)
		if apiErr != nil {
			if resp != nil && isTransient(resp.StatusCode) {
				return apiErr // will retry
			}
			return errNoRetry{apiErr}
		}
		return nil
	})
	if err != nil {
		return nil, p.wrapAPIErr("GetCommit", unwrapNoRetry(err))
	}
	return result, nil
}

// createRevertCommit creates a new commit on the base branch that has
// parentSHA as its sole parent and treeSHA as its tree. This restores the
// branch to the state of parentSHA's tree, effectively reverting parentSHA+1.
func (p *Provider) createRevertCommit(ctx context.Context, parentSHA, treeSHA, message string) (string, error) {
	var createdSHA string
	err := p.withRetry(ctx, func() error {
		newCommit := &ghsdk.Commit{
			Message: &message,
			Tree:    &ghsdk.Tree{SHA: &treeSHA},
			Parents: []*ghsdk.Commit{{SHA: &parentSHA}},
		}
		result, resp, apiErr := p.client.Git.CreateCommit(ctx, p.owner, p.repo, newCommit, nil)
		if apiErr != nil {
			if resp != nil && isTransient(resp.StatusCode) {
				return apiErr // will retry
			}
			return errNoRetry{apiErr}
		}
		createdSHA = result.GetSHA()
		return nil
	})
	if err != nil {
		return "", p.wrapAPIErr("CreateCommit(revert)", unwrapNoRetry(err))
	}
	return createdSHA, nil
}

// updateRef updates a git reference to point at newSHA. force controls whether
// a non-fast-forward update is permitted; rollback always passes force=false.
func (p *Provider) updateRef(ctx context.Context, ref, newSHA string, force bool) error {
	err := p.withRetry(ctx, func() error {
		ghRef := &ghsdk.Reference{
			Ref:    &ref,
			Object: &ghsdk.GitObject{SHA: &newSHA},
		}
		_, resp, apiErr := p.client.Git.UpdateRef(ctx, p.owner, p.repo, ghRef, force)
		if apiErr != nil {
			if resp != nil && isTransient(resp.StatusCode) {
				return apiErr // will retry
			}
			return errNoRetry{apiErr}
		}
		return nil
	})
	if err != nil {
		return p.wrapAPIErr("UpdateRef", unwrapNoRetry(err))
	}
	return nil
}

// CommentPR posts a body comment on the issue thread of the given PR.
func (p *Provider) CommentPR(ctx context.Context, ref coregit.PRRef, body string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("github CommentPR cancelled: %w", err)
	}
	_, _, err := p.client.Issues.CreateComment(ctx, p.owner, p.repo, ref.Number,
		&ghsdk.IssueComment{Body: &body})
	if err != nil {
		return p.wrapAPIErr("CommentPR", err)
	}
	return nil
}

// ---- internal helpers -------------------------------------------------------

// resolveRef returns the commit SHA for a git reference (e.g. "refs/heads/main").
// It retries on transient server errors with bounded exponential backoff.
func (p *Provider) resolveRef(ctx context.Context, ref string) (string, error) {
	var ghRef *ghsdk.Reference
	err := p.withRetry(ctx, func() error {
		var resp *ghsdk.Response
		var apiErr error
		ghRef, resp, apiErr = p.client.Git.GetRef(ctx, p.owner, p.repo, ref)
		if apiErr != nil {
			if resp != nil && isTransient(resp.StatusCode) {
				return apiErr // will retry
			}
			return errNoRetry{apiErr}
		}
		return nil
	})
	if err != nil {
		return "", p.wrapAPIErr("GetRef", unwrapNoRetry(err))
	}
	if ghRef.GetObject() == nil {
		return "", fmt.Errorf("GitHub ref %q has no object", ref)
	}
	return ghRef.GetObject().GetSHA(), nil
}

// createBranch creates a new git ref (branch) pointing at baseSHA.
// Returns ErrBranchConflict if the ref already exists (HTTP 422 with "already_exists").
func (p *Provider) createBranch(ctx context.Context, branch, baseSHA string) error {
	fullRef := "refs/heads/" + branch
	newRef := &ghsdk.Reference{
		Ref:    &fullRef,
		Object: &ghsdk.GitObject{SHA: &baseSHA},
	}
	_, resp, err := p.client.Git.CreateRef(ctx, p.owner, p.repo, newRef)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnprocessableEntity {
			return ErrBranchConflict
		}
		return p.wrapAPIErr("CreateRef", err)
	}
	return nil
}

// commitFile creates or updates a file at path on the given branch.
// Uses the Contents API (PUT) which handles both create and update.
func (p *Provider) commitFile(ctx context.Context, branch, path string, content []byte, message string) error {
	opts := &ghsdk.RepositoryContentFileOptions{
		Message: &message,
		Content: content,
		Branch:  &branch,
	}
	existingSHA, getErr := p.getFileGitSHA(ctx, path, branch)
	if getErr == nil && existingSHA != "" {
		opts.SHA = &existingSHA
	}

	_, _, err := p.client.Repositories.CreateFile(ctx, p.owner, p.repo, path, opts)
	if err != nil {
		return p.wrapAPIErr("CreateFile", err)
	}
	return nil
}

// commitSignedFile creates or updates the signed file-of-record on the base
// branch. Returns the commit SHA.
func (p *Provider) commitSignedFile(ctx context.Context, path string, content []byte, message string) (string, error) {
	opts := &ghsdk.RepositoryContentFileOptions{
		Message: &message,
		Content: content,
		Branch:  &p.baseBranch,
	}
	existingSHA, getErr := p.getFileGitSHA(ctx, path, p.baseBranch)
	if getErr == nil && existingSHA != "" {
		opts.SHA = &existingSHA
	}

	resp, _, err := p.client.Repositories.CreateFile(ctx, p.owner, p.repo, path, opts)
	if err != nil {
		return "", p.wrapAPIErr("CreateFile(signed)", err)
	}
	return resp.GetSHA(), nil
}

// createPR opens a pull request from head into baseBranch.
func (p *Provider) createPR(ctx context.Context, head, title, body string) (*ghsdk.PullRequest, error) {
	newPR := &ghsdk.NewPullRequest{
		Title: &title,
		Head:  &head,
		Base:  &p.baseBranch,
		Body:  &body,
	}
	pr, _, err := p.client.PullRequests.Create(ctx, p.owner, p.repo, newPR)
	if err != nil {
		return nil, p.wrapAPIErr("CreatePR", err)
	}
	return pr, nil
}

// FetchCommittedFile fetches the exact committed bytes of path at the given
// ref (branch or commit SHA) with no transformation. It satisfies the
// fileofrecord.FileFetcher port: a GitHub 404 response is wrapped as an
// error satisfying errors.Is(err, http404Err{}) so the fileofrecord adapter
// can recognise it as ErrFetchNotFound.
//
// This is the zero-normalization transport for the fileofrecord.Source adapter.
// The returned bytes are exactly the content stored in the git object; no CRLF
// rewriting or line-ending normalization is applied.
func (p *Provider) FetchCommittedFile(ctx context.Context, path, ref string) ([]byte, error) {
	raw, err := p.fetchFileContents(ctx, path, ref)
	if err != nil {
		var ghErr *ghsdk.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil &&
			ghErr.Response.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("file %q not found at ref %q: %w",
				path, ref, http404Err{})
		}
		return nil, err
	}
	return raw, nil
}

// http404Err is a typed not-found error returned by FetchCommittedFile. The
// fileofrecord adapter's isHTTP404 helper recognises it via the StatusCode()
// method, mapping it to ErrFetchNotFound for the caller.
type http404Err struct{}

func (http404Err) Error() string   { return "HTTP 404 not found" }
func (http404Err) StatusCode() int { return http.StatusNotFound }

// fetchFileContents fetches the raw bytes of a file at a given ref.
func (p *Provider) fetchFileContents(ctx context.Context, path, ref string) ([]byte, error) {
	fc, _, _, err := p.client.Repositories.GetContents(ctx, p.owner, p.repo, path,
		&ghsdk.RepositoryContentGetOptions{Ref: ref})
	if err != nil {
		return nil, p.wrapAPIErr("GetContents", err)
	}
	if fc == nil {
		return nil, fmt.Errorf("GitHub returned nil content for path %q at ref %q", path, ref)
	}
	raw, err := fc.GetContent()
	if err != nil {
		return nil, fmt.Errorf("decoding content for %q: %w", path, err)
	}
	return []byte(raw), nil
}

// getFileGitSHA returns the git blob SHA for a file at the given ref.
// Returns empty string if the file does not exist (404).
func (p *Provider) getFileGitSHA(ctx context.Context, path, ref string) (string, error) {
	fc, _, _, err := p.client.Repositories.GetContents(ctx, p.owner, p.repo, path,
		&ghsdk.RepositoryContentGetOptions{Ref: ref})
	if err != nil {
		var ghErr *ghsdk.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusNotFound {
			return "", nil
		}
		return "", err
	}
	if fc == nil {
		return "", nil
	}
	return fc.GetSHA(), nil
}

// submissionFilePath derives the artifact file path within the submission
// directory from the branch name. Branch naming convention:
// "byreis/add-<key>-<ts>" → "submissions/add-<key>-<ts>.yaml".
func (p *Provider) submissionFilePath(branch string) string {
	name := strings.TrimPrefix(branch, "byreis/")
	if name == branch {
		name = branch
	}
	return p.submissionDir + "/" + name + ".yaml"
}

// buildPRBody constructs the full PR body: free-text justification followed by
// the machine-parseable byreis-submission block. The block is the sole
// structured data source for SecretsPath/Key/Action on review+merge.
func buildPRBody(justification string, meta coregit.SubmissionMeta) string {
	var sb strings.Builder
	if justification != "" {
		sb.WriteString(justification)
		sb.WriteString("\n\n")
	}
	sb.WriteString(coregit.EncodeSubmissionMeta(meta))
	return sb.String()
}

// rawBytesSHA computes sha256(bytes) and returns the lowercase hex string.
// This is the contributor-side move-detection ArtifactSHA.
// Do NOT use this for the counter-authority target_artifact_sha — that MUST
// be verify.ContentSHA.
func rawBytesSHA(b []byte) coregit.ArtifactSHA {
	h := sha256.Sum256(b)
	return coregit.ArtifactSHA(hex.EncodeToString(h[:]))
}

// isTransient reports whether the HTTP status code is a transient server error
// that should be retried.
func isTransient(code int) bool {
	return code == http.StatusInternalServerError ||
		code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

// errNoRetry wraps an error to signal withRetry must not retry it.
type errNoRetry struct{ err error }

func (e errNoRetry) Error() string { return e.err.Error() }
func (e errNoRetry) Unwrap() error { return e.err }

func unwrapNoRetry(err error) error {
	var nr errNoRetry
	if errors.As(err, &nr) {
		return nr.err
	}
	return err
}

// withRetry calls fn up to 1+maxRetries times, backing off on transient errors.
// Non-transient errors (wrapped as errNoRetry) are returned immediately.
func (p *Provider) withRetry(ctx context.Context, fn func() error) error {
	var lastErr error
	wait := retryBaseWait
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("cancelled during retry: %w", err)
		}
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("cancelled during retry backoff: %w", ctx.Err())
			case <-time.After(wait):
			}
			wait *= 2
		}
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		var nr errNoRetry
		if errors.As(lastErr, &nr) {
			return nr.err
		}
		// Transient: retry.
	}
	return lastErr
}

// wrapAPIErr maps GitHub API errors to domain errors with actionable hints.
// It never includes the bearer token or any secret material.
func (p *Provider) wrapAPIErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var ghErr *ghsdk.ErrorResponse
	if errors.As(err, &ghErr) {
		switch ghErr.Response.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf(
				"GitHub auth expired or invalid for %s/%s — run `byreis auth login` to re-authenticate: %w",
				p.owner, p.repo, err)
		case http.StatusForbidden:
			return fmt.Errorf(
				"GitHub access denied for %s/%s (check branch protection / repo permissions) — "+
					"run `byreis auth login` if your token is expired: %w",
				p.owner, p.repo, err)
		case http.StatusNotFound:
			return fmt.Errorf(
				"GitHub resource not found in %s/%s (check project name and permissions): %w",
				p.owner, p.repo, err)
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("GitHub API call %q was cancelled or timed out: %w", op, err)
	}
	return fmt.Errorf("GitHub API error in %q for %s/%s: %w", op, p.owner, p.repo, err)
}

// actionLabel returns the human-readable label for a SubmitAction.
func actionLabel(a coregit.SubmitAction) string {
	if a == coregit.ActionReplace {
		return "replace"
	}
	return "add"
}

// extractJustification returns the human-readable portion of the PR body,
// stripping the machine-parseable byreis-submission block so callers get
// clean justification text.
func extractJustification(body string) string {
	// Remove the byreis-submission fenced block from the body.
	startMarker := "```byreis-submission"
	startIdx := strings.Index(body, startMarker)
	if startIdx == -1 {
		return strings.TrimSpace(body)
	}
	justification := strings.TrimSpace(body[:startIdx])
	// Also strip anything after the closing fence.
	endMarker := "```"
	afterStart := body[startIdx+len(startMarker):]
	nlIdx := strings.IndexByte(afterStart, '\n')
	if nlIdx != -1 {
		afterFenceLine := afterStart[nlIdx+1:]
		closeIdx := strings.Index(afterFenceLine, endMarker)
		if closeIdx != -1 {
			after := strings.TrimSpace(afterFenceLine[closeIdx+len(endMarker):])
			if after != "" && justification != "" {
				return justification + "\n\n" + after
			}
			if after != "" {
				return after
			}
		}
	}
	return justification
}

// unmarshalSigned deserialises a YAML artifact file into an artifact.Signed.
// The bytes are the exact content produced by the signing step and must not be
// normalised before calling; verify.ContentSHA is called on the result.
func unmarshalSigned(yamlBytes []byte) (artifact.Signed, error) {
	var s artifact.Signed
	if err := yaml.Unmarshal(yamlBytes, &s); err != nil {
		return artifact.Signed{}, fmt.Errorf("YAML unmarshal: %w", err)
	}
	return s, nil
}

// MarshalSigned serialises an artifact.Signed to YAML bytes. Exported so test
// helpers in the _test package can produce bytes for the adapter to parse.
func MarshalSigned(s artifact.Signed) ([]byte, error) {
	out, err := yaml.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("YAML marshal: %w", err)
	}
	return out, nil
}
