// Package github implements the internal/core/git.GitProvider interface using
// the GitHub REST API. SDK types are mapped to domain types at this boundary;
// no GitHub SDK type leaks into core.
//
// This stub satisfies the GitProvider interface so the skeleton builds clean
// until the real implementation lands.
//
// ArtifactSHA: this adapter must compute ArtifactSHA over the raw fetched or
// pushed byte buffer with zero normalization. Re-marshalling the artifact
// before hashing breaks the content pin, so it is treated as a defect and is
// covered by a dedicated negative test.
package github

import (
	"context"

	coregit "github.com/ByReisK/byreis/internal/core/git"
)

// Provider is the GitHub-backed GitProvider implementation.
type Provider struct {
	// HTTP client, token, and org/repo config will be injected here.
	// Everything is constructor-injected; no globals.
}

// New constructs a Provider. Constructor parameters are added with the real
// implementation.
func New() *Provider {
	return &Provider{}
}

// Compile-time assertion that Provider implements GitProvider.
var _ coregit.GitProvider = (*Provider)(nil)

func (p *Provider) OpenSubmissionPR(_ context.Context, _ coregit.OpenPRInput) (coregit.PullRequest, error) {
	panic("not implemented") // stub: real implementation pending
}

func (p *Provider) GetSubmission(_ context.Context, _ coregit.PRRef) (coregit.Submission, error) {
	panic("not implemented") // stub: real implementation pending
}

func (p *Provider) MergeSubmission(_ context.Context, _ coregit.MergeInput) (coregit.MergeResult, error) {
	panic("not implemented") // stub: real implementation pending
}

func (p *Provider) CommentPR(_ context.Context, _ coregit.PRRef, _ string) error {
	panic("not implemented") // stub: real implementation pending
}
