// Package app provides the CLI wiring layer: it bridges the adapter
// implementations (internal/adapter/registry, internal/adapter/git/github) to
// the consumer-defined ports in the use-case packages
// (internal/core/usecase and internal/core/usecase/submit).
//
// This package MUST NOT be imported from internal/core/usecase or any of its
// sub-packages. The Clean Architecture dependency rule is preserved: core
// defines ports; adapters implement them; this wiring package lives outside
// core and wires them together for the CLI layer.
//
// The RecipientSourceWrapper and SubmitGitPort defined here implement the
// consumer-defined ports usecase.RecipientSource and submit.RecipientSource.
// They forward AdminSet.SourceVerified and Stale 1:1 (never synthesizing
// SourceVerified=true or Stale=false) and fill
// VerifiedRecipients.ConfiguredFiles ONLY from the SAME SourceVerified
// registry fetch as Set and TrustedSigners.
//
// Design contracts enforced here:
//
//	(i)   Defined OUTSIDE internal/core/usecase — this file is in internal/app.
//	(ii)  Forwards AdminSet.SourceVerified/Stale 1:1, never synthesized.
//	(iii) ConfiguredFiles filled only from the SourceVerified fetch.
//	(iv)  Maps ErrUnsignedRegistry/ErrRegistryOffline/ErrCacheTampered to a
//	      non-nil error or Recipients{SourceVerified:false}; never swallows.
//	(v)   Maps github.ErrBranchConflict → submit.ErrBranchTaken.
package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	githubadapter "github.com/ByReisK/byreis/internal/adapter/git/github"
	coregit "github.com/ByReisK/byreis/internal/core/git"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// RecipientSourceWrapper wraps the registry client interface and implements
// both usecase.RecipientSource (for Merge/Review) and submit.RecipientSource
// (for Submit). The two ports have the same semantic contract but different
// return types; this wrapper adapts both.
//
// The wrapper accepts the coreregistry.RegistryClient interface so the
// concrete adapter (or a fake) can be injected. This keeps the wrapper
// independently testable without a real network or git transport.
//
// The wrapper MUST NOT synthesize SourceVerified=true: it forwards the
// AdminSet value 1:1 from the registry adapter. ConfiguredFiles is filled
// ONLY from the same SourceVerified fetch as Set/TrustedSigners.
type RecipientSourceWrapper struct {
	registry coreregistry.RegistryClient
}

// NewRecipientSourceWrapper constructs a RecipientSourceWrapper around the
// given registry client. The argument must implement coreregistry.RegistryClient
// (satisfied by *registryadapter.Client in production).
func NewRecipientSourceWrapper(rc coreregistry.RegistryClient) *RecipientSourceWrapper {
	return &RecipientSourceWrapper{registry: rc}
}

// ExpectedRecipients implements usecase.RecipientSource for the Merge/Review
// use-cases. It maps AdminSet → VerifiedRecipients 1:1, forwarding
// SourceVerified and Stale without synthesis.
//
// ConfiguredFiles is filled only when SourceVerified=true and Stale=false.
// When the fetch returns ErrUnsignedRegistry, ErrRegistryOffline, or
// ErrCacheTampered, the error is propagated and no
// VerifiedRecipients{SourceVerified:true} is returned.
func (w *RecipientSourceWrapper) ExpectedRecipients(ctx context.Context, projectID string) (usecase.VerifiedRecipients, error) {
	set, err := w.registry.FetchAdminSet(ctx, projectID)
	if err != nil {
		// Map registry error sentinels: propagate as-is. Do NOT return a
		// VerifiedRecipients with SourceVerified=true on any error path.
		if errors.Is(err, coreregistry.ErrUnsignedRegistry) ||
			errors.Is(err, coreregistry.ErrRegistryOffline) ||
			errors.Is(err, coreregistry.ErrCacheTampered) {
			return usecase.VerifiedRecipients{SourceVerified: false, Stale: true}, fmt.Errorf(
				"registry fetch failed — admin operations require a verified registry: %w", err)
		}
		return usecase.VerifiedRecipients{}, fmt.Errorf(
			"fetching admin set failed: %w", err)
	}

	return adminSetToVerifiedRecipients(set), nil
}

// Recipients implements submit.RecipientSource for the Submit use-case. It
// maps AdminSet → submit.Recipients 1:1, forwarding SourceVerified and Stale
// without synthesis.
//
// When SourceVerified=false or Stale=true in the fetched AdminSet, the
// returned Recipients carries those values unchanged; Submit uses them to
// refuse without decrypting.
func (w *RecipientSourceWrapper) Recipients(ctx context.Context, projectID string) (submit.Recipients, error) {
	set, err := w.registry.FetchAdminSet(ctx, projectID)
	if err != nil {
		if errors.Is(err, coreregistry.ErrUnsignedRegistry) ||
			errors.Is(err, coreregistry.ErrRegistryOffline) ||
			errors.Is(err, coreregistry.ErrCacheTampered) {
			// Return a non-verified set (not swallowed into SourceVerified=true).
			return submit.Recipients{
					Set:            nil,
					SourceVerified: false,
					Stale:          true,
				}, fmt.Errorf(
					"registry fetch failed — submit requires a verified registry: %w", err)
		}
		return submit.Recipients{}, fmt.Errorf("fetching admin set for submit failed: %w", err)
	}

	// Forward 1:1 — never synthesize SourceVerified=true or Stale=false.
	return submit.Recipients{
		Set:            set.Recipients,
		SourceVerified: set.SourceVerified,
		Stale:          set.Stale,
	}, nil
}

// adminSetToVerifiedRecipients maps a registry AdminSet to a usecase
// VerifiedRecipients value. ConfiguredFiles is filled ONLY when
// SourceVerified=true and Stale=false; an unverified/stale set yields an
// empty/nil ConfiguredFiles so the merge cross-check cannot proceed on an
// unverified path.
func adminSetToVerifiedRecipients(set coreregistry.AdminSet) usecase.VerifiedRecipients {
	vr := usecase.VerifiedRecipients{
		Set:             set.Recipients,
		SourceVerified:  set.SourceVerified, // 1:1 forwarded, never synthesized
		Stale:           set.Stale,          // 1:1 forwarded, never synthesized
		ConfiguredFiles: nil,
	}

	// Fill TrustedSigners from the same fetch.
	if len(set.SignerKeys) > 0 {
		vr.TrustedSigners = make(map[string]ed25519.PublicKey, len(set.SignerKeys))
		for id, key := range set.SignerKeys {
			vr.TrustedSigners[id] = key
		}
	}

	// ConfiguredFiles MUST be filled ONLY from a SourceVerified fetch. A
	// stale or unverified fetch yields no usable ConfiguredFiles so a merge
	// cannot proceed with an attacker-controlled path map.
	if set.SourceVerified && !set.Stale && len(set.ConfiguredFiles) > 0 {
		vr.ConfiguredFiles = make(map[string]string, len(set.ConfiguredFiles))
		for logicalFile, repoPath := range set.ConfiguredFiles {
			vr.ConfiguredFiles[logicalFile] = repoPath
		}
	}

	return vr
}

// ArtifactEncoder encodes a submit.OpenPRInput artifact to on-disk YAML bytes.
// It is injected into SubmitGitPort at construction time and lives at the
// adapter boundary.
type ArtifactEncoder interface {
	// EncodeUnsigned serializes the artifact.Unsigned carried in the submit input
	// to the exact bytes that will be committed to git. The caller must not
	// normalize these bytes before hashing (they are the move-detection pin used by the on-PR artifact-SHA TOCTOU guard).
	EncodeUnsigned(in submit.OpenPRInput) ([]byte, error)
}

// SubmitGitPort implements submit.GitPort by wrapping the core git.GitProvider
// and mapping the submit-specific types to the domain types. It also maps
// github.ErrBranchConflict → submit.ErrBranchTaken.
type SubmitGitPort struct {
	provider coregit.GitProvider
	encoder  ArtifactEncoder
}

// NewSubmitGitPort constructs a SubmitGitPort. Both provider and encoder are
// required.
func NewSubmitGitPort(p coregit.GitProvider, enc ArtifactEncoder) (*SubmitGitPort, error) {
	if p == nil || enc == nil {
		return nil, fmt.Errorf(
			"app.NewSubmitGitPort: provider and encoder are required")
	}
	return &SubmitGitPort{provider: p, encoder: enc}, nil
}

// BranchExists is an advisory pre-check. The hard conflict guard is in
// OpenSubmissionPR (ErrBranchConflict → ErrBranchTaken). Returning false
// here is safe: a concurrent branch create is caught at OpenSubmissionPR
// time, not here.
func (s *SubmitGitPort) BranchExists(_ context.Context, _ string, _ string) (bool, error) {
	return false, nil
}

// OpenSubmissionPR serializes the artifact via the injected encoder and
// delegates to the wrapped GitProvider. It maps github.ErrBranchConflict
// (returned when the branch already exists on the remote) to
// submit.ErrBranchTaken so the submit use-case's concurrency guard triggers.
func (s *SubmitGitPort) OpenSubmissionPR(ctx context.Context, in submit.OpenPRInput) (submit.OpenedPR, error) {
	b, err := s.encoder.EncodeUnsigned(in)
	if err != nil {
		return submit.OpenedPR{}, fmt.Errorf("encoding submission artifact: %w", err)
	}

	pr, err := s.provider.OpenSubmissionPR(ctx, coregit.OpenPRInput{
		Project:       in.ProjectID,
		Branch:        in.Branch,
		Key:           in.Key,
		Action:        coregit.SubmitAction(in.Action),
		SecretsPath:   in.SecretsPath,
		BaseFilePath:  in.BaseFilePath,
		Justification: in.Justification,
		ArtifactBytes: b,
		TitleTemplate: fmt.Sprintf("[byreis] %s: %s", in.Action.String(), in.Key),
	})
	if err != nil {
		// Map ErrBranchConflict → submit.ErrBranchTaken so the submit use-case's concurrency guard triggers.
		if errors.Is(err, githubadapter.ErrBranchConflict) {
			return submit.OpenedPR{}, fmt.Errorf("%w: %v", submit.ErrBranchTaken, err)
		}
		return submit.OpenedPR{}, fmt.Errorf("opening submission PR: %w", err)
	}

	return submit.OpenedPR{
		Ref: submit.PRRef{
			Project: pr.Ref.Project,
			Number:  pr.Ref.Number,
		},
		URL:         pr.URL,
		Branch:      pr.Branch,
		ArtifactSHA: string(pr.ArtifactSHA),
	}, nil
}

// Compile-time assertions that both interfaces are satisfied.
var (
	_ usecase.RecipientSource = (*RecipientSourceWrapper)(nil)
	_ submit.RecipientSource  = (*RecipientSourceWrapper)(nil)
	_ submit.GitPort          = (*SubmitGitPort)(nil)
)
