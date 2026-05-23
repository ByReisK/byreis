package github

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	ghsdk "github.com/google/go-github/v72/github"

	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// PRCloserAdapter implements usecase.PRCloser for a single GitHub repository.
// It performs EXACTLY two operations: post an issue comment and close a pull
// request. No file creation, no ref update, no content write, and no registry
// trust write are present in this type — a code reviewer can confirm by
// diffing the method set against the write-capable Provider.
//
// The adapter is repo-bound: the sourceRepo field is stamped at construction
// time and propagated into every RejectPRState returned by
// FetchPRStateForReject. This is the authoritative PR-type discriminator: the
// adapter that owns the connection sets the kind; no branch name can forge it.
type PRCloserAdapter struct {
	client     *ghsdk.Client
	owner      string
	repo       string
	sourceRepo usecase.RepoKind
}

// NewProjectRepoPRCloser constructs a PRCloserAdapter bound to a project
// secrets repository (submission PRs). projectRepo must be "owner/repo".
// Returns an error when the client is nil or the project string is malformed.
func NewProjectRepoPRCloser(client *ghsdk.Client, projectRepo string) (*PRCloserAdapter, error) {
	return newPRCloserAdapter(client, projectRepo, usecase.RepoKindProject)
}

// NewRegistryRepoPRCloser constructs a PRCloserAdapter bound to the admin
// registry repository (access-request PRs). registryRepo must be "owner/repo".
// Returns an error when the client is nil or the project string is malformed.
func NewRegistryRepoPRCloser(client *ghsdk.Client, registryRepo string) (*PRCloserAdapter, error) {
	return newPRCloserAdapter(client, registryRepo, usecase.RepoKindRegistry)
}

func newPRCloserAdapter(client *ghsdk.Client, repo string, kind usecase.RepoKind) (*PRCloserAdapter, error) {
	if client == nil {
		return nil, fmt.Errorf("PRCloserAdapter: github client must not be nil")
	}
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf(
			"%w: PRCloserAdapter: repository %q is not in owner/repo form",
			coregit.ErrInvalidProject, repo)
	}
	if strings.Contains(parts[1], "/") {
		return nil, fmt.Errorf(
			"%w: PRCloserAdapter: repository repo part %q must not contain '/'",
			coregit.ErrInvalidProject, repo)
	}
	return &PRCloserAdapter{
		client:     client,
		owner:      parts[0],
		repo:       parts[1],
		sourceRepo: kind,
	}, nil
}

// Compile-time assertion: PRCloserAdapter satisfies the consumer-defined port.
var _ usecase.PRCloser = (*PRCloserAdapter)(nil)

// FetchPRStateForReject fetches the typed state the reject use-case needs for
// fail-closed validation. All fields are sourced from typed GitHub SDK fields,
// never from the PR title or body. SourceRepo is stamped from this adapter's
// repo-bound kind — the authoritative type discriminator.
func (a *PRCloserAdapter) FetchPRStateForReject(
	ctx context.Context, ref coregit.PRRef,
) (usecase.RejectPRState, error) {
	if err := ctx.Err(); err != nil {
		return usecase.RejectPRState{},
			fmt.Errorf("FetchPRStateForReject cancelled: %w", err)
	}

	pr, _, err := a.client.PullRequests.Get(ctx, a.owner, a.repo, ref.Number)
	if err != nil {
		return usecase.RejectPRState{}, a.wrapErr("FetchPRStateForReject/GetPR", err)
	}

	// Map SDK types to domain types at the boundary — no SDK type leaks.
	var labels []string
	for _, l := range pr.Labels {
		if name := l.GetName(); name != "" {
			labels = append(labels, name)
		}
	}

	branchName := ""
	if pr.Head != nil {
		branchName = pr.Head.GetRef()
	}

	state := usecase.RejectPRState{
		Merged:     pr.GetMerged(),
		Closed:     pr.GetState() == "closed",
		BranchName: branchName,
		Labels:     labels,
		SourceRepo: a.sourceRepo, // authoritative; set by the adapter, not from PR fields
	}
	return state, nil
}

// CloseWithComment posts the (already-sanitized) reason as a public issue
// comment and then closes the pull request. Returns an error if either
// operation fails. Idempotent on an already-closed PR (no comment, no error).
//
// The use-case's Reject method enforces the merge-state check and idempotency
// logic before calling this method; this adapter does not duplicate those checks.
func (a *PRCloserAdapter) CloseWithComment(
	ctx context.Context, ref coregit.PRRef, sanitizedReason string,
) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("CloseWithComment cancelled: %w", err)
	}

	// Post the comment first. An error here leaves the PR open (no partial state).
	commentBody := sanitizedReason
	_, _, commentErr := a.client.Issues.CreateComment(
		ctx, a.owner, a.repo, ref.Number,
		&ghsdk.IssueComment{Body: &commentBody},
	)
	if commentErr != nil {
		return fmt.Errorf("posting reject comment on %s/%s#%d: %w",
			a.owner, a.repo, ref.Number,
			a.wrapErr("CreateComment", commentErr))
	}

	// Close the pull request.
	closed := "closed"
	_, _, closeErr := a.client.PullRequests.Edit(
		ctx, a.owner, a.repo, ref.Number,
		&ghsdk.PullRequest{State: &closed},
	)
	if closeErr != nil {
		return fmt.Errorf("closing PR %s/%s#%d: %w",
			a.owner, a.repo, ref.Number,
			a.wrapErr("PullRequests.Edit/close", closeErr))
	}
	return nil
}

// wrapErr maps GitHub API errors to domain errors with actionable hints.
func (a *PRCloserAdapter) wrapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var ghErr *ghsdk.ErrorResponse
	if isErrorResponse(err, &ghErr) {
		switch ghErr.Response.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf(
				"GitHub auth expired for %s/%s — run `byreis auth login` to re-authenticate: %w",
				a.owner, a.repo, err)
		case http.StatusForbidden:
			return fmt.Errorf(
				"GitHub access denied for %s/%s — check repo permissions and run `byreis auth login` if expired: %w",
				a.owner, a.repo, err)
		case http.StatusNotFound:
			return fmt.Errorf(
				"GitHub resource not found in %s/%s — check the PR number and project name: %w",
				a.owner, a.repo, err)
		}
	}
	return fmt.Errorf("GitHub API error in %q for %s/%s: %w", op, a.owner, a.repo, err)
}
