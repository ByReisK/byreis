//go:build shipgate

package app_test

// TestS3_BridgeForwardsAuditEntry is the S3 regression guard for the
// prodRegistryCounterStoreBridge.CommitBump mapping.
//
// Problem: the bridge maps usecase.CommitBumpInput field-by-field to
// coreregistry.CommitBumpInput. If a field is added to both structs but
// omitted from the mapping, the transport receives a zero value and silently
// drops that data — exactly what happened with AuditEntry before this fix.
// Standard unit tests that call Client.CommitBump directly never exercise this
// bridge and cannot catch the regression.
//
// This test drives a CommitBump call through the production bridge
// (NewProdCounterStoreBridgeForTest) with a spy coreregistry.RegistryClient
// that captures the coreregistry.CommitBumpInput it receives. It then asserts
// that the AuditEntry field is non-zero on arrival — proving the bridge
// forwarded it. A future unmapped-field reappearance breaks this test and is
// caught by `make test-shipgate` in CI.
//
// Coverage: the existing counter_write_audit_test.go suite drives
// Client.CommitBump directly (bypassing the bridge), so the routing to the
// audit transport is already covered there. This test covers only the bridge
// mapping layer — the structural gap that hid the showstopper.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/core/audit"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// TestS3_BridgeForwardsAuditEntry proves that prodRegistryCounterStoreBridge.CommitBump
// forwards the populated AuditEntry to the underlying RegistryClient unchanged.
// A bridge that omits AuditEntry: in.AuditEntry from the field mapping fails
// this test, catching any future unmapped-field regression at CI time.
func TestS3_BridgeForwardsAuditEntry(t *testing.T) {
	t.Parallel()

	spy := &s3RegistryClientSpy{}
	store := app.NewProdCounterStoreBridgeForTest(spy)

	wantEntry := audit.Event{
		Kind:       audit.EventKindMerge,
		OccurredAt: time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
		Actor:      "admin-label",
		ProjectID:  "proj-s3-bridge",
		FileName:   "secrets",
		KeyName:    "STRIPE-KEY",
		PRRef:      "myorg/myapp#42",
		Outcome:    "ok",
		Details:    map[string]string{"counter": "7"},
	}

	err := store.CommitBump(context.Background(), usecase.CommitBumpInput{
		ProjectID:      "proj-s3-bridge",
		FileName:       "secrets",
		PendingCounter: 7,
		PRRef:          "myorg/myapp#42",
		AuditEntry:     wantEntry,
	})
	if err != nil {
		t.Fatalf("CommitBump: %v", err)
	}

	if spy.lastInput.AuditEntry.Kind == "" {
		t.Fatal("bridge dropped AuditEntry: Kind is empty on arrival at RegistryClient — " +
			"AuditEntry: in.AuditEntry must be present in the CommitBump field mapping")
	}
	if spy.lastInput.AuditEntry.Kind != wantEntry.Kind {
		t.Errorf("AuditEntry.Kind = %q, want %q",
			spy.lastInput.AuditEntry.Kind, wantEntry.Kind)
	}
	if spy.lastInput.AuditEntry.ProjectID != wantEntry.ProjectID {
		t.Errorf("AuditEntry.ProjectID = %q, want %q",
			spy.lastInput.AuditEntry.ProjectID, wantEntry.ProjectID)
	}
	if spy.lastInput.AuditEntry.KeyName != wantEntry.KeyName {
		t.Errorf("AuditEntry.KeyName = %q, want %q",
			spy.lastInput.AuditEntry.KeyName, wantEntry.KeyName)
	}
	if spy.lastInput.AuditEntry.PRRef != wantEntry.PRRef {
		t.Errorf("AuditEntry.PRRef = %q, want %q",
			spy.lastInput.AuditEntry.PRRef, wantEntry.PRRef)
	}
	// Scalar fields must also be forwarded correctly.
	if spy.lastInput.ProjectID != "proj-s3-bridge" {
		t.Errorf("ProjectID = %q, want %q", spy.lastInput.ProjectID, "proj-s3-bridge")
	}
	if spy.lastInput.FileName != "secrets" {
		t.Errorf("FileName = %q, want %q", spy.lastInput.FileName, "secrets")
	}
	if spy.lastInput.PendingCounter != 7 {
		t.Errorf("PendingCounter = %d, want 7", spy.lastInput.PendingCounter)
	}
	if spy.lastInput.PRRef != "myorg/myapp#42" {
		t.Errorf("PRRef = %q, want %q", spy.lastInput.PRRef, "myorg/myapp#42")
	}
}

// TestS3_BridgeZeroAuditEntry_Forwarded proves that a zero AuditEntry
// (non-merge legacy path) is also forwarded correctly and does not cause an
// error at the bridge layer. The guard in Client.CommitBump uses Kind == "" to
// skip the audit transport, so the zero value must pass through unchanged.
func TestS3_BridgeZeroAuditEntry_Forwarded(t *testing.T) {
	t.Parallel()

	spy := &s3RegistryClientSpy{}
	store := app.NewProdCounterStoreBridgeForTest(spy)

	err := store.CommitBump(context.Background(), usecase.CommitBumpInput{
		ProjectID:      "proj-s3-zero",
		FileName:       "secrets",
		PendingCounter: 3,
		PRRef:          "myorg/myapp#5",
		// AuditEntry is deliberately zero.
	})
	if err != nil {
		t.Fatalf("CommitBump (zero audit): %v", err)
	}

	if spy.lastInput.AuditEntry.Kind != "" {
		t.Errorf("AuditEntry.Kind = %q, want empty (zero audit forwarded as-is)",
			spy.lastInput.AuditEntry.Kind)
	}
}

// ---- fake transport --------------------------------------------------------

// s3RegistryClientSpy is a coreregistry.RegistryClient that records the last
// CommitBumpInput it received. All other methods return nil/zero so the bridge
// call completes without requiring a real registry.
type s3RegistryClientSpy struct {
	lastInput coreregistry.CommitBumpInput
}

func (s *s3RegistryClientSpy) FetchAdminSet(_ context.Context, _ string) (coreregistry.AdminSet, error) {
	return coreregistry.AdminSet{}, nil
}
func (s *s3RegistryClientSpy) VerifyRegistryFreshness(_ context.Context, _ string) error {
	return nil
}
func (s *s3RegistryClientSpy) CounterAuthority(_ context.Context, _, _ string) (countertypes.CounterAuthority, error) {
	return countertypes.CounterAuthority{}, nil
}
func (s *s3RegistryClientSpy) RecordPendingBump(_ context.Context, _ coreregistry.PendingBumpInput) error {
	return nil
}
func (s *s3RegistryClientSpy) CommitBump(_ context.Context, in coreregistry.CommitBumpInput) error {
	s.lastInput = in
	return nil
}
func (s *s3RegistryClientSpy) FetchRotationEpochs(_ context.Context, _ string) (map[string]uint64, error) {
	return nil, nil
}
func (s *s3RegistryClientSpy) CommitRotation(_ context.Context, _ coreregistry.CommitRotationInput) (coreregistry.CommitRotationResult, error) {
	return coreregistry.CommitRotationResult{}, errors.New("CommitRotation not implemented in spy")
}
func (s *s3RegistryClientSpy) RotationInFlight(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
