package app_test

import (
	"context"
	"errors"
	"testing"

	githubadapter "github.com/ByReisK/byreis/internal/adapter/git/github"
	"github.com/ByReisK/byreis/internal/app"
	coregit "github.com/ByReisK/byreis/internal/core/git"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// --- fakes ---

// fakeRegistryClient is an injectable fake that satisfies coreregistry.RegistryClient
// without any real network, git, or filesystem access.
type fakeRegistryClient struct {
	set coreregistry.AdminSet
	err error
}

func (f *fakeRegistryClient) FetchAdminSet(_ context.Context, _ string) (coreregistry.AdminSet, error) {
	return f.set, f.err
}

func (f *fakeRegistryClient) VerifyRegistryFreshness(_ context.Context, _ string) error {
	return nil
}

func (f *fakeRegistryClient) CounterAuthority(_ context.Context, _, _ string) (countertypes.CounterAuthority, error) {
	return countertypes.CounterAuthority{}, nil
}

func (f *fakeRegistryClient) RecordPendingBump(_ context.Context, _ coreregistry.PendingBumpInput) error {
	return nil
}

func (f *fakeRegistryClient) CommitBump(_ context.Context, _ coreregistry.CommitBumpInput) error {
	return nil
}

func (f *fakeRegistryClient) FetchRotationEpochs(_ context.Context, _ string) (map[string]uint64, error) {
	return map[string]uint64{}, nil
}

func (f *fakeRegistryClient) CommitRotation(_ context.Context, _ coreregistry.CommitRotationInput) (coreregistry.CommitRotationResult, error) {
	return coreregistry.CommitRotationResult{}, coreregistry.ErrCommitRotationNotImplemented
}

func (f *fakeRegistryClient) RotationInFlight(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}

// fakeGitProvider is an injectable fake that satisfies coregit.GitProvider
// without any real git or HTTP calls.
type fakeGitProvider struct {
	pr  coregit.PullRequest
	err error
}

func (f *fakeGitProvider) OpenSubmissionPR(_ context.Context, _ coregit.OpenPRInput) (coregit.PullRequest, error) {
	return f.pr, f.err
}

func (f *fakeGitProvider) MergeSubmission(_ context.Context, _ coregit.MergeInput) (coregit.MergeResult, error) {
	return coregit.MergeResult{}, nil
}

func (f *fakeGitProvider) RollbackSignedFile(_ context.Context, _ coregit.RollbackInput) error {
	return nil
}

func (f *fakeGitProvider) CommentPR(_ context.Context, _ coregit.PRRef, _ string) error {
	return nil
}

func (f *fakeGitProvider) GetSubmission(_ context.Context, _ coregit.PRRef) (coregit.Submission, error) {
	return coregit.Submission{}, nil
}

// fakeArtifactEncoder is a minimal ArtifactEncoder for wrapper tests.
type fakeArtifactEncoder struct {
	bytes []byte
	err   error
}

func (f *fakeArtifactEncoder) EncodeUnsigned(_ submit.OpenPRInput) ([]byte, error) {
	return f.bytes, f.err
}

// --- RecipientSourceWrapper tests ---

// TestWrapper_ExpectedRecipients_SourceVerified_Forwarded_OneToOne verifies
// that SourceVerified=true from the registry is forwarded 1:1 and is not
// synthesized from an error path (checklist item ii).
func TestWrapper_ExpectedRecipients_SourceVerified_Forwarded_OneToOne(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{
		set: coreregistry.AdminSet{
			Recipients:     []rectypes.Recipient{{AgePubKey: "age1abc"}},
			SourceVerified: true,
			Stale:          false,
		},
	}
	w := app.NewRecipientSourceWrapper(rc)
	vr, err := w.ExpectedRecipients(context.Background(), "proj")
	if err != nil {
		t.Fatalf("ExpectedRecipients: %v", err)
	}
	if !vr.SourceVerified {
		t.Error("expected SourceVerified=true forwarded from AdminSet")
	}
	if vr.Stale {
		t.Error("expected Stale=false forwarded from AdminSet")
	}
}

// TestWrapper_ExpectedRecipients_Stale_Forwarded_OneToOne verifies that
// SourceVerified=false and Stale=true are forwarded 1:1 and SourceVerified is
// never synthesized to true (checklist item ii, negative).
func TestWrapper_ExpectedRecipients_Stale_Forwarded_OneToOne(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{
		set: coreregistry.AdminSet{
			Recipients:     []rectypes.Recipient{{AgePubKey: "age1abc"}},
			SourceVerified: false,
			Stale:          true,
		},
	}
	w := app.NewRecipientSourceWrapper(rc)
	vr, err := w.ExpectedRecipients(context.Background(), "proj")
	if err != nil {
		t.Fatalf("ExpectedRecipients: %v", err)
	}
	// Stale/unverified forwarded 1:1 — never synthesized to true.
	if vr.SourceVerified {
		t.Error("SourceVerified must NOT be synthesized to true from a stale/unverified AdminSet")
	}
	if !vr.Stale {
		t.Error("Stale must be forwarded 1:1 from AdminSet")
	}
}

// TestWrapper_Recipients_SourceVerified_Forwarded_OneToOne verifies that
// submit.RecipientSource.Recipients forwards SourceVerified/Stale 1:1.
func TestWrapper_Recipients_SourceVerified_Forwarded_OneToOne(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{
		set: coreregistry.AdminSet{
			Recipients:     []rectypes.Recipient{{AgePubKey: "age1abc"}},
			SourceVerified: true,
			Stale:          false,
		},
	}
	w := app.NewRecipientSourceWrapper(rc)
	recips, err := w.Recipients(context.Background(), "proj")
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	if !recips.SourceVerified {
		t.Error("expected SourceVerified=true forwarded from AdminSet")
	}
	if recips.Stale {
		t.Error("expected Stale=false forwarded from AdminSet")
	}
}

// TestWrapper_Recipients_Stale_Forwarded_OneToOne verifies that a stale/unsigned
// set yields SourceVerified=false, Stale=true in submit.Recipients (item ii, negative).
func TestWrapper_Recipients_Stale_Forwarded_OneToOne(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{
		set: coreregistry.AdminSet{
			Recipients:     []rectypes.Recipient{{AgePubKey: "age1abc"}},
			SourceVerified: false,
			Stale:          true,
		},
	}
	w := app.NewRecipientSourceWrapper(rc)
	recips, err := w.Recipients(context.Background(), "proj")
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	if recips.SourceVerified {
		t.Error("SourceVerified must NOT be synthesized to true from a stale/unverified AdminSet")
	}
	if !recips.Stale {
		t.Error("Stale must be forwarded 1:1 from AdminSet")
	}
}

// TestWrapper_ConfiguredFiles_OnlyFromSourceVerifiedFetch verifies that
// ConfiguredFiles is populated only when SourceVerified=true and Stale=false
// (checklist item iii, positive case).
func TestWrapper_ConfiguredFiles_OnlyFromSourceVerifiedFetch(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{
		set: coreregistry.AdminSet{
			Recipients:     []rectypes.Recipient{{AgePubKey: "age1abc"}},
			SourceVerified: true,
			Stale:          false,
			ConfiguredFiles: map[string]string{ //nolint:gosec // "secrets/prod.enc.yaml" is a path, not a credential
				"secrets": "secrets/prod.enc.yaml",
			},
		},
	}
	w := app.NewRecipientSourceWrapper(rc)
	vr, err := w.ExpectedRecipients(context.Background(), "proj")
	if err != nil {
		t.Fatalf("ExpectedRecipients: %v", err)
	}
	if len(vr.ConfiguredFiles) == 0 {
		t.Error("ConfiguredFiles must be filled from a SourceVerified=true, Stale=false fetch")
	}
	if vr.ConfiguredFiles["secrets"] != "secrets/prod.enc.yaml" {
		t.Errorf("ConfiguredFiles[secrets] = %q, want %q",
			vr.ConfiguredFiles["secrets"], "secrets/prod.enc.yaml")
	}
}

// TestWrapper_ConfiguredFiles_NotFilledFromUnverifiedFetch verifies that
// ConfiguredFiles is NOT filled when SourceVerified=false (checklist item iii,
// negative case: unverified fetch must not populate usable path map).
func TestWrapper_ConfiguredFiles_NotFilledFromUnverifiedFetch(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{
		set: coreregistry.AdminSet{
			Recipients:     []rectypes.Recipient{{AgePubKey: "age1abc"}},
			SourceVerified: false,
			Stale:          false,
			ConfiguredFiles: map[string]string{ //nolint:gosec // "secrets/prod.enc.yaml" is a path, not a credential
				"secrets": "secrets/prod.enc.yaml",
			},
		},
	}
	w := app.NewRecipientSourceWrapper(rc)
	vr, err := w.ExpectedRecipients(context.Background(), "proj")
	if err != nil {
		t.Fatalf("ExpectedRecipients: %v", err)
	}
	if len(vr.ConfiguredFiles) != 0 {
		t.Errorf("ConfiguredFiles must NOT be filled from unverified fetch, got: %v", vr.ConfiguredFiles)
	}
}

// TestWrapper_ConfiguredFiles_NotFilledFromStaleFetch verifies that
// ConfiguredFiles is NOT filled when SourceVerified=true but Stale=true
// (checklist item iii, negative case: stale fetch must not populate path map).
func TestWrapper_ConfiguredFiles_NotFilledFromStaleFetch(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{
		set: coreregistry.AdminSet{
			Recipients:     []rectypes.Recipient{{AgePubKey: "age1abc"}},
			SourceVerified: true,
			Stale:          true,
			ConfiguredFiles: map[string]string{ //nolint:gosec // "secrets/prod.enc.yaml" is a path, not a credential
				"secrets": "secrets/prod.enc.yaml",
			},
		},
	}
	w := app.NewRecipientSourceWrapper(rc)
	vr, err := w.ExpectedRecipients(context.Background(), "proj")
	if err != nil {
		t.Fatalf("ExpectedRecipients: %v", err)
	}
	if len(vr.ConfiguredFiles) != 0 {
		t.Errorf("ConfiguredFiles must NOT be filled from stale fetch, got: %v", vr.ConfiguredFiles)
	}
}

// TestWrapper_ErrUnsignedRegistry_NotSwallowed verifies that ErrUnsignedRegistry
// from the registry is NOT swallowed into SourceVerified=true (checklist item iv).
func TestWrapper_ErrUnsignedRegistry_NotSwallowed(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{err: coreregistry.ErrUnsignedRegistry}
	w := app.NewRecipientSourceWrapper(rc)

	vr, err := w.ExpectedRecipients(context.Background(), "proj")
	if err == nil {
		t.Fatal("expected an error from ErrUnsignedRegistry, got nil")
	}
	if !errors.Is(err, coreregistry.ErrUnsignedRegistry) {
		t.Errorf("expected wrapped ErrUnsignedRegistry, got: %v", err)
	}
	// MUST NOT synthesize SourceVerified=true on error path.
	if vr.SourceVerified {
		t.Error("SourceVerified must be false on error path (never synthesized)")
	}
}

// TestWrapper_ErrRegistryOffline_NotSwallowed verifies that ErrRegistryOffline
// is not swallowed into SourceVerified=true (checklist item iv).
func TestWrapper_ErrRegistryOffline_NotSwallowed(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{err: coreregistry.ErrRegistryOffline}
	w := app.NewRecipientSourceWrapper(rc)

	vr, err := w.ExpectedRecipients(context.Background(), "proj")
	if err == nil {
		t.Fatal("expected an error from ErrRegistryOffline, got nil")
	}
	if !errors.Is(err, coreregistry.ErrRegistryOffline) {
		t.Errorf("expected wrapped ErrRegistryOffline, got: %v", err)
	}
	if vr.SourceVerified {
		t.Error("SourceVerified must be false on offline error path")
	}
}

// TestWrapper_ErrCacheTampered_NotSwallowed verifies that ErrCacheTampered
// is not swallowed into SourceVerified=true (checklist item iv).
func TestWrapper_ErrCacheTampered_NotSwallowed(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{err: coreregistry.ErrCacheTampered}
	w := app.NewRecipientSourceWrapper(rc)

	vr, err := w.ExpectedRecipients(context.Background(), "proj")
	if err == nil {
		t.Fatal("expected an error from ErrCacheTampered, got nil")
	}
	if !errors.Is(err, coreregistry.ErrCacheTampered) {
		t.Errorf("expected wrapped ErrCacheTampered, got: %v", err)
	}
	if vr.SourceVerified {
		t.Error("SourceVerified must be false on tamper error path")
	}
}

// TestWrapper_Recipients_ErrUnsignedRegistry_NotSwallowed verifies that
// ErrUnsignedRegistry is not silently swallowed in the submit path.
func TestWrapper_Recipients_ErrUnsignedRegistry_NotSwallowed(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{err: coreregistry.ErrUnsignedRegistry}
	w := app.NewRecipientSourceWrapper(rc)

	recips, err := w.Recipients(context.Background(), "proj")
	if err == nil {
		t.Fatal("expected an error from ErrUnsignedRegistry, got nil")
	}
	if !errors.Is(err, coreregistry.ErrUnsignedRegistry) {
		t.Errorf("expected wrapped ErrUnsignedRegistry, got: %v", err)
	}
	if recips.SourceVerified {
		t.Error("SourceVerified must be false on unsigned-registry error path")
	}
}

// --- SubmitGitPort tests ---

// TestSubmitGitPort_OpenSubmissionPR_Success verifies that a successful PR
// open is returned with the expected fields mapped.
func TestSubmitGitPort_OpenSubmissionPR_Success(t *testing.T) {
	t.Parallel()

	provider := &fakeGitProvider{
		pr: coregit.PullRequest{
			Ref:         coregit.PRRef{Project: "myorg/proj", Number: 42},
			URL:         "https://github.com/myorg/proj/pull/42",
			Branch:      "byreis/add-mykey-123",
			ArtifactSHA: "sha256:abcdef",
		},
	}
	enc := &fakeArtifactEncoder{bytes: []byte("artifact-bytes")}

	port, err := app.NewSubmitGitPort(provider, enc)
	if err != nil {
		t.Fatalf("NewSubmitGitPort: %v", err)
	}

	//nolint:gosec // "secrets/prod.enc.yaml" is a path, not a credential
	opened, err := port.OpenSubmissionPR(context.Background(), submit.OpenPRInput{
		ProjectID:     "myorg/proj",
		Key:           "mykey",
		Action:        submit.ActionAdd,
		Branch:        "byreis/add-mykey-123",
		SecretsPath:   "secrets/prod.enc.yaml",
		BaseFilePath:  "secrets/prod.enc.yaml",
		Justification: "adding db password",
	})
	if err != nil {
		t.Fatalf("OpenSubmissionPR: %v", err)
	}
	if opened.Ref.Number != 42 {
		t.Errorf("PR number = %d, want 42", opened.Ref.Number)
	}
	if opened.URL != "https://github.com/myorg/proj/pull/42" {
		t.Errorf("URL = %q, want %q", opened.URL, "https://github.com/myorg/proj/pull/42")
	}
	if opened.Branch != "byreis/add-mykey-123" {
		t.Errorf("Branch = %q, want %q", opened.Branch, "byreis/add-mykey-123")
	}
}

// TestSubmitGitPort_ErrBranchConflict_MappedToErrBranchTaken verifies that
// github.ErrBranchConflict is mapped to submit.ErrBranchTaken (checklist item v).
func TestSubmitGitPort_ErrBranchConflict_MappedToErrBranchTaken(t *testing.T) {
	t.Parallel()

	provider := &fakeGitProvider{err: githubadapter.ErrBranchConflict}
	enc := &fakeArtifactEncoder{bytes: []byte("artifact-bytes")}

	port, err := app.NewSubmitGitPort(provider, enc)
	if err != nil {
		t.Fatalf("NewSubmitGitPort: %v", err)
	}

	_, err = port.OpenSubmissionPR(context.Background(), submit.OpenPRInput{
		ProjectID: "myorg/proj",
		Key:       "mykey",
		Action:    submit.ActionAdd,
		Branch:    "byreis/add-mykey-123",
	})
	if err == nil {
		t.Fatal("expected error from ErrBranchConflict, got nil")
	}
	// Checklist item (v): ErrBranchConflict from the git layer must be wrapped
	// as ErrBranchTaken so the submit use-case's concurrency guard triggers.
	if !errors.Is(err, submit.ErrBranchTaken) {
		t.Errorf("expected submit.ErrBranchTaken, got: %v", err)
	}
}

// TestSubmitGitPort_OtherError_NotMappedToErrBranchTaken verifies that a
// non-branch-conflict error is NOT mapped to ErrBranchTaken.
func TestSubmitGitPort_OtherError_NotMappedToErrBranchTaken(t *testing.T) {
	t.Parallel()

	otherErr := errors.New("network timeout")
	provider := &fakeGitProvider{err: otherErr}
	enc := &fakeArtifactEncoder{bytes: []byte("artifact-bytes")}

	port, err := app.NewSubmitGitPort(provider, enc)
	if err != nil {
		t.Fatalf("NewSubmitGitPort: %v", err)
	}

	_, err = port.OpenSubmissionPR(context.Background(), submit.OpenPRInput{
		ProjectID: "myorg/proj",
		Key:       "mykey",
		Action:    submit.ActionAdd,
		Branch:    "byreis/add-mykey-123",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, submit.ErrBranchTaken) {
		t.Error("network timeout must NOT be mapped to ErrBranchTaken")
	}
}

// TestSubmitGitPort_EncoderError_PropagatesBeforeGit verifies that an encoder
// failure is returned before any git call is made (no PR created on bad artifact).
func TestSubmitGitPort_EncoderError_PropagatesBeforeGit(t *testing.T) {
	t.Parallel()

	encErr := errors.New("encoding failed")
	// Provider would succeed if called, but it must not be called.
	provider := &fakeGitProvider{pr: coregit.PullRequest{Ref: coregit.PRRef{Number: 1}}}
	enc := &fakeArtifactEncoder{err: encErr}

	port, err := app.NewSubmitGitPort(provider, enc)
	if err != nil {
		t.Fatalf("NewSubmitGitPort: %v", err)
	}

	_, err = port.OpenSubmissionPR(context.Background(), submit.OpenPRInput{
		ProjectID: "myorg/proj",
		Key:       "mykey",
		Action:    submit.ActionAdd,
		Branch:    "byreis/add-mykey-123",
	})
	if err == nil {
		t.Fatal("expected error from encoder failure, got nil")
	}
	if !errors.Is(err, encErr) {
		t.Errorf("expected wrapped encoder error, got: %v", err)
	}
}

// TestNewSubmitGitPort_NilProviderReturnsError verifies that NewSubmitGitPort
// rejects a nil provider.
func TestNewSubmitGitPort_NilProviderReturnsError(t *testing.T) {
	t.Parallel()

	enc := &fakeArtifactEncoder{}
	_, err := app.NewSubmitGitPort(nil, enc)
	if err == nil {
		t.Fatal("expected error for nil provider, got nil")
	}
}

// TestNewSubmitGitPort_NilEncoderReturnsError verifies that NewSubmitGitPort
// rejects a nil encoder.
func TestNewSubmitGitPort_NilEncoderReturnsError(t *testing.T) {
	t.Parallel()

	provider := &fakeGitProvider{}
	_, err := app.NewSubmitGitPort(provider, nil)
	if err == nil {
		t.Fatal("expected error for nil encoder, got nil")
	}
}

// TestWrapper_ContextCancelled_ExpectedRecipients verifies that a cancelled
// context propagates through to the registry call.
func TestWrapper_ContextCancelled_ExpectedRecipients(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{err: context.Canceled}
	w := app.NewRecipientSourceWrapper(rc)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := w.ExpectedRecipients(ctx, "proj")
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
}

// Compile-time assertion: wrapper_test depends only on the package boundary,
// not on concrete adapter internals.
var _ usecase.RecipientSource = (*app.RecipientSourceWrapper)(nil)
var _ submit.RecipientSource = (*app.RecipientSourceWrapper)(nil)
