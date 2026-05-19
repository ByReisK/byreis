package app_test

import (
	"context"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// fakeAdminSetVerifiedStale builds a registry.AdminSet with SourceVerified=true
// and Stale=true to test the stale-cache path.
func fakeAdminSet(sourceVerified, stale bool, configuredFiles map[string]string) coreregistry.AdminSet {
	return coreregistry.AdminSet{
		Recipients:      []rectypes.Recipient{{AgePubKey: "age1abc"}},
		SourceVerified:  sourceVerified,
		Stale:           stale,
		ConfiguredFiles: configuredFiles,
	}
}

// ISP wiring assertions: BuildReadPathDeps returns use-case interfaces, not
// *PortAdapter. These compile-time assertions detect any regression where a
// concrete adapter type leaks across the boundary.
var (
	_ func() (usecase.Getter, usecase.DecryptUseCase, usecase.EditUseCase, error) = func() (usecase.Getter, usecase.DecryptUseCase, usecase.EditUseCase, error) {
		g, d, e, err := app.BuildReadPathDeps(
			nil, nil, nil, nil, nil, nil, nil, nil,
			nil, nil, nil, nil,
		)
		return g, d, e, err
	}
)

// TestBuildReadPathDeps_NilPorts_ReturnError verifies that BuildReadPathDeps with
// all-nil required base ports produces a descriptive error and does not panic.
func TestBuildReadPathDeps_NilPorts_ReturnError(t *testing.T) {
	t.Parallel()

	g, d, e, err := app.BuildReadPathDeps(
		nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
	)
	if err == nil {
		t.Fatal("BuildReadPathDeps with all-nil ports must return an error, got nil")
	}
	if g != nil || d != nil || e != nil {
		t.Errorf("on error, BuildReadPathDeps should return nil use-cases: g=%v d=%v e=%v", g, d, e)
	}
}

// TestWrapper_AfterB4Wiring_Stale_NoConfiguredFiles verifies the
// SourceVerified/Stale 1:1 forwarding and ConfiguredFiles-only-from-verified
// invariants still hold after B4-3 wiring (regression guards for STATE.md
// checklist items ii and iii).
func TestWrapper_AfterB4Wiring_Stale_NoConfiguredFiles(t *testing.T) {
	t.Parallel()

	rc := &fakeRegistryClient{
		set: fakeAdminSet(true, true, map[string]string{ //nolint:gosec // path, not a credential
			"f": "secrets/prod.enc.yaml",
		}),
	}
	w := app.NewRecipientSourceWrapper(rc)
	vr, err := w.ExpectedRecipients(context.Background(), "proj")
	if err != nil {
		t.Fatalf("ExpectedRecipients: %v", err)
	}
	if !vr.SourceVerified {
		t.Error("SourceVerified must be forwarded 1:1 (true)")
	}
	if !vr.Stale {
		t.Error("Stale must be forwarded 1:1 (true)")
	}
	if len(vr.ConfiguredFiles) != 0 {
		t.Errorf("ConfiguredFiles must be nil when Stale=true, got: %v", vr.ConfiguredFiles)
	}
}
