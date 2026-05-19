// Package git defines the GitProvider interface (consumer-defined) and domain
// types for the git hosting integration. NO GitHub SDK types appear here.
// The concrete implementation lives in internal/adapter/git/github.
package git

import (
	"context"
	"errors"
)

// ArtifactSHA is the sha256 over the exact, untransformed byte sequence of an
// artifact file as fetched from or pushed to git, with zero normalization. Two
// files that "mean the same YAML" but differ by one byte have different SHAs by
// design — that is what makes the review-to-merge content pin meaningful.
//
// Adapters must not re-marshal or normalize before computing this hash.
type ArtifactSHA string

// SubmitAction classifies a submission as Add or Replace.
// The action is determined by whether the key already exists in the live file.
type SubmitAction int

const (
	// ActionAdd is used when the key does not exist in the current live file.
	ActionAdd SubmitAction = iota
	// ActionReplace is used when the key already exists (explicit ack required).
	ActionReplace
)

// PRRef identifies a pull request within a project repository.
type PRRef struct {
	Project string // e.g. "myorg/my-app-secrets"
	Number  int
}

// PullRequest is the result of opening a submission PR.
type PullRequest struct {
	Ref         PRRef
	URL         string
	Branch      string
	ArtifactSHA ArtifactSHA // SHA of the exact pushed artifact bytes
}

// Submission is the result of fetching a submission PR for review.
type Submission struct {
	Ref           PRRef
	Author        string
	Justification string
	// ArtifactBytes is the EXACT untransformed bytes fetched from git.
	ArtifactBytes []byte
	// ArtifactSHA is sha256(ArtifactBytes) over the raw fetched bytes.
	// Adapters must hash the raw fetched buffer, never a re-marshalled form.
	ArtifactSHA ArtifactSHA
	// BaseFileBytes is the current live secrets file bytes (may be empty for first add).
	BaseFileBytes []byte
}

// OpenPRInput carries inputs for GitProvider.OpenSubmissionPR.
type OpenPRInput struct {
	Project       string
	Branch        string // byreis/<add|replace>-<key>-<ts>
	Action        SubmitAction
	Key           string
	ArtifactBytes []byte
	TitleTemplate string
	Justification string
}

// MergeInput carries inputs for GitProvider.MergeSubmission.
type MergeInput struct {
	Ref PRRef
	// ExpectSHA is the content pin: MergeSubmission fails closed with
	// ErrArtifactMoved if the on-PR artifact SHA no longer equals this value.
	ExpectSHA ArtifactSHA
	// SignedBytes is the signed file-of-record to commit to the protected
	// secrets path.
	SignedBytes   []byte
	CommitMessage string
}

// MergeResult is returned by MergeSubmission on success.
type MergeResult struct {
	MergedCommit string
	LiveFileSHA  string
}

// Sentinel errors.
var (
	// ErrArtifactMoved is returned by MergeSubmission when the on-PR artifact
	// SHA no longer equals ExpectSHA, i.e. the branch was re-pushed between
	// review and sign. Hard error; the admin must re-run review.
	ErrArtifactMoved = errors.New(
		"artifact has moved since review (branch was re-pushed) — " +
			"re-run `byreis review --pr N` to re-pin the new artifact before merging")
)

// GitProvider is the consumer-defined interface for git hosting operations.
// The concrete implementation lives in internal/adapter/git/github.
// GitLab is out of scope.
//
// All methods honor context cancellation/deadlines. All errors wrap with %w.
type GitProvider interface {
	// OpenSubmissionPR creates a branch + commit of the unsigned artifact and
	// opens a PR. It returns the PR and the full artifact content SHA actually
	// pushed (ArtifactSHA) — the content pin for review and merge.
	OpenSubmissionPR(ctx context.Context, in OpenPRInput) (PullRequest, error)

	// GetSubmission fetches the artifact bytes and PR metadata for review. It
	// returns the artifact content SHA (sha256 over the exact untransformed
	// fetched bytes, zero normalization) so review can pin exactly these bytes.
	GetSubmission(ctx context.Context, ref PRRef) (Submission, error)

	// MergeSubmission writes the signed file-of-record to the protected secrets
	// path and merges, only if the live artifact SHA still equals expectSHA.
	// Fails closed with ErrArtifactMoved otherwise.
	MergeSubmission(ctx context.Context, in MergeInput) (MergeResult, error)

	// CommentPR posts a comment on the PR (used for review summaries / audit).
	CommentPR(ctx context.Context, ref PRRef, body string) error
}
