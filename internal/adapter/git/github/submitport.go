package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	ghsdk "github.com/google/go-github/v72/github"

	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// ArtifactEncoder encodes a submit.OpenPRInput's Artifact to YAML bytes for
// the git commit. Defined as a function type so the shim does not need to
// import the artifactcodec adapter directly; the composition root supplies the
// concrete encoder at wiring time.
type ArtifactEncoder func(in submit.OpenPRInput) ([]byte, error)

// SubmitPortShim adapts the GitHub *Provider to the submit.GitPort interface.
//
// The submit use-case defines its own types (submit.OpenPRInput,
// submit.OpenedPR, submit.ErrBranchTaken) that differ from the coregit types,
// so this shim maps field-by-field at the boundary and translates the
// ErrBranchConflict sentinel so the use-case can detect the concurrent-branch
// race and refuse rather than silently dropping a secret.
//
// The shim lives in the github adapter package (already imports go-github) so
// no new dependency is introduced. It is wired only at the composition root
// (internal/app) and never imported by internal/core.
type SubmitPortShim struct {
	p       *Provider
	encoder ArtifactEncoder
}

// NewSubmitPortShim wraps a *Provider and an ArtifactEncoder as a submit.GitPort.
// The encoder converts submit.OpenPRInput.Artifact to YAML bytes for the git
// commit; the composition root supplies an EncodeUnsignedFromValues closure.
func NewSubmitPortShim(p *Provider, enc ArtifactEncoder) (*SubmitPortShim, error) {
	if p == nil {
		return nil, fmt.Errorf("github.NewSubmitPortShim: Provider is nil")
	}
	if enc == nil {
		return nil, fmt.Errorf("github.NewSubmitPortShim: ArtifactEncoder is nil")
	}
	return &SubmitPortShim{p: p, encoder: enc}, nil
}

// BranchExists reports whether the named branch already exists on the remote.
// Used for the concurrent-submission conflict guard in the submit use-case.
// A not-found result from the GitHub API is mapped to (false, nil).
func (s *SubmitPortShim) BranchExists(ctx context.Context, _ string, branch string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("BranchExists cancelled: %w", err)
	}

	var exists bool
	err := s.p.withRetry(ctx, func() error {
		_, resp, apiErr := s.p.client.Git.GetRef(ctx, s.p.owner, s.p.repo,
			"refs/heads/"+branch)
		if apiErr != nil {
			var ghErr *ghsdk.ErrorResponse
			if errors.As(apiErr, &ghErr) && ghErr.Response != nil &&
				ghErr.Response.StatusCode == http.StatusNotFound {
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
		// Map a not-found error to (false, nil): branch does not exist.
		var ghErr *ghsdk.ErrorResponse
		if errors.As(unwrapNoRetry(err), &ghErr) && ghErr.Response != nil &&
			ghErr.Response.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, s.p.wrapAPIErr("BranchExists", unwrapNoRetry(err))
	}
	return exists, nil
}

// OpenSubmissionPR encodes the artifact, maps submit.OpenPRInput to
// coregit.OpenPRInput, calls the provider, and maps the result back.
//
// Critical mapping: ErrBranchConflict → submit.ErrBranchTaken so a
// concurrent-branch race never silently drops a secret. The submit use-case
// refuses with ErrBranchConflict when it sees ErrBranchTaken.
func (s *SubmitPortShim) OpenSubmissionPR(ctx context.Context, in submit.OpenPRInput) (submit.OpenedPR, error) {
	if err := ctx.Err(); err != nil {
		return submit.OpenedPR{}, fmt.Errorf("OpenSubmissionPR cancelled: %w", err)
	}

	// Encode the artifact to YAML bytes. The submit use-case passes the
	// artifact.Unsigned value; the git commit requires the serialised bytes.
	artifactBytes, err := s.encoder(in)
	if err != nil {
		return submit.OpenedPR{}, fmt.Errorf("encoding submission artifact: %w", err)
	}

	// Map submit.OpenPRKey → coregit.KeyAction for the bulk-submission keys array.
	coreKeys := make([]coregit.KeyAction, 0, len(in.Keys))
	for _, k := range in.Keys {
		coreKeys = append(coreKeys, coregit.KeyAction{
			Key:    k.Key,
			Action: actionLabel(coregit.SubmitAction(k.Action)),
		})
	}

	coreIn := coregit.OpenPRInput{
		Project:       in.ProjectID,
		Branch:        in.Branch,
		Action:        coregit.SubmitAction(in.Action),
		Key:           in.Key,
		ArtifactBytes: artifactBytes,
		TitleTemplate: buildSubmitTitle(in),
		Justification: in.Justification,
		SecretsPath:   in.SecretsPath,
		BaseFilePath:  in.BaseFilePath,
		Keys:          coreKeys,
	}

	pr, err := s.p.OpenSubmissionPR(ctx, coreIn)
	if err != nil {
		if errors.Is(err, ErrBranchConflict) {
			// Map the adapter's concurrent-branch sentinel to the submit port's
			// sentinel so the use-case treats this as a REFUSE.
			return submit.OpenedPR{}, submit.ErrBranchTaken
		}
		return submit.OpenedPR{}, fmt.Errorf("opening submission PR: %w", err)
	}

	return submit.OpenedPR{
		Ref:         submit.PRRef{Project: pr.Ref.Project, Number: pr.Ref.Number},
		URL:         pr.URL,
		Branch:      pr.Branch,
		ArtifactSHA: string(pr.ArtifactSHA),
	}, nil
}

// buildSubmitTitle builds the PR title from submit.OpenPRInput.
func buildSubmitTitle(in submit.OpenPRInput) string {
	if len(in.Keys) > 0 {
		return fmt.Sprintf("byreis: bulk submission (%d keys)", len(in.Keys))
	}
	label := "add"
	if in.Action == submit.ActionReplace {
		label = "replace"
	}
	return fmt.Sprintf("byreis: %s %s", label, in.Key)
}

// Compile-time assertion that SubmitPortShim satisfies submit.GitPort.
var _ submit.GitPort = (*SubmitPortShim)(nil)
