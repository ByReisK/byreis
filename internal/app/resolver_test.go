package app

import (
	"context"
	"errors"
	"testing"

	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// fakeRegistryClient is a minimal fake coreregistry.RegistryClient used to
// test the resolver without any real network or registry access.
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

var _ coreregistry.RegistryClient = (*fakeRegistryClient)(nil)

// TestResolver_NilRegistryClient_ReturnsTypedError asserts that when the
// registryClient field is nil the resolver returns a typed ErrFileOfRecordNotFound
// error — not a synthesized fallback string. This is the invariant guarantee:
// the resolver is only ever constructed with a non-nil client in production, but
// the nil branch must be fail-closed.
func TestResolver_NilRegistryClient_ReturnsTypedError(t *testing.T) {
	r := &prodRegistryConfiguredPathResolver{
		projectID:      "myproject",
		registryClient: nil,
	}

	got, err := r.ConfiguredPath(context.Background(), "myproject", "foo")
	if err == nil {
		t.Fatalf("expected error when registryClient is nil, got path %q", got)
	}
	if got != "" {
		t.Errorf("expected empty path when registryClient is nil, got %q", got)
	}
	if !errors.Is(err, usecase.ErrFileOfRecordNotFound) {
		t.Errorf("expected ErrFileOfRecordNotFound, got: %v", err)
	}
}

// TestResolver_UnverifiedAdminSet_ReturnsErrFileOfRecordNotFound asserts that
// when the AdminSet is not SourceVerified the resolver returns
// ErrFileOfRecordNotFound — not the hard-coded convention path.
func TestResolver_UnverifiedAdminSet_ReturnsErrFileOfRecordNotFound(t *testing.T) {
	tests := []struct {
		name string
		set  coreregistry.AdminSet
	}{
		{
			name: "unverified",
			set: coreregistry.AdminSet{
				SourceVerified:  false,
				Stale:           false,
				ConfiguredFiles: map[string]string{"foo": "vault/foo.enc.yaml"},
			},
		},
		{
			name: "stale",
			set: coreregistry.AdminSet{
				SourceVerified:  true,
				Stale:           true,
				ConfiguredFiles: map[string]string{"foo": "vault/foo.enc.yaml"},
			},
		},
		{
			name: "verified-but-no-matching-entry",
			set: coreregistry.AdminSet{
				SourceVerified:  true,
				Stale:           false,
				ConfiguredFiles: map[string]string{"bar": "vault/bar.enc.yaml"},
			},
		},
		{
			name: "verified-but-nil-ConfiguredFiles",
			set: coreregistry.AdminSet{
				SourceVerified:  true,
				Stale:           false,
				ConfiguredFiles: nil,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := &prodRegistryConfiguredPathResolver{
				projectID:      "myproject",
				registryClient: &fakeRegistryClient{set: tc.set},
			}

			got, err := r.ConfiguredPath(context.Background(), "myproject", "foo")
			if err == nil {
				t.Fatalf("expected error for case %q, got path %q", tc.name, got)
			}
			if got != "" {
				t.Errorf("case %q: expected empty path, got %q", tc.name, got)
			}
			if !errors.Is(err, usecase.ErrFileOfRecordNotFound) {
				t.Errorf("case %q: expected ErrFileOfRecordNotFound, got: %v", tc.name, err)
			}
			// Verify the fallback convention string is never returned.
			const conventionPrefix = "secrets/"
			if len(got) > len(conventionPrefix) && got[:len(conventionPrefix)] == conventionPrefix {
				t.Errorf("case %q: hard-coded convention path leaked into result: %q", tc.name, got)
			}
		})
	}
}

// TestResolver_HappyPath_ReturnsRegistryAttestedPath asserts that with a wired
// registry client and a SourceVerified AdminSet the resolver returns the
// registry-attested path from ConfiguredFiles — not the hard-coded convention.
func TestResolver_HappyPath_ReturnsRegistryAttestedPath(t *testing.T) {
	r := &prodRegistryConfiguredPathResolver{
		projectID: "myproject",
		registryClient: &fakeRegistryClient{
			set: coreregistry.AdminSet{
				SourceVerified: true,
				Stale:          false,
				ConfiguredFiles: map[string]string{
					"foo": "vault/foo.enc.yaml",
				},
			},
		},
	}

	got, err := r.ConfiguredPath(context.Background(), "myproject", "foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const want = "vault/foo.enc.yaml"
	if got != want {
		t.Errorf("got path %q, want registry-attested %q", got, want)
	}
	const convention = "secrets/foo.enc.yaml"
	if got == convention {
		t.Errorf("returned the hard-coded convention path %q instead of the registry-attested path", convention)
	}
}
