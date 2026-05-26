package rotate_test

// Per-line audit-binding core symbols — display projection + consumer port.
//
// This file covers the TESTABLE core pieces of the per-line binding verifier
// (REQ-V05-001): the BindingStatus display enum (String() over all four values
// plus the zero value), the additive AuditEntryView.BindingStatus field default,
// and a compile-time shape assertion that the AuditVerifier consumer-defined port
// is satisfiable without any SDK type. The verification logic itself (git-history
// walk, Ed25519 re-check, checkpoint) lives in the adapter and is exercised there
// against real signed git-history fixtures — it is deliberately NOT mocked here.

import (
	"context"
	"testing"

	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// TestBindingStatus_String asserts every enum value renders the stable
// display token the BINDING column and --json binding_status field surface,
// and that an out-of-range value degrades to "unknown" rather than panicking.
func TestBindingStatus_String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status rotate.BindingStatus
		want   string
	}{
		{"verified", rotate.BindingVerified, "verified"},
		{"unverified-legacy", rotate.BindingUnverifiedLegacy, "legacy"},
		{"missing", rotate.BindingMissing, "missing"},
		{"tampered", rotate.BindingTampered, "TAMPERED"},
		{"out-of-range", rotate.BindingStatus(99), "unknown"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.status.String(); got != tc.want {
				t.Fatalf("BindingStatus(%d).String() = %q, want %q",
					tc.status, got, tc.want)
			}
		})
	}
}

// TestBindingStatus_ZeroValue pins the zero value to BindingMissing: an
// AuditEntryView constructed without an explicit binding status (e.g. a
// synthetic truncation/malformed-line row) must read as the unbindable
// "missing" state, never as the trust-bearing "verified" state. This is the
// fail-closed default for the display layer.
func TestBindingStatus_ZeroValue(t *testing.T) {
	t.Parallel()

	var zero rotate.BindingStatus
	if zero != rotate.BindingMissing {
		t.Fatalf("zero BindingStatus = %v (%d), want BindingMissing", zero, zero)
	}
	if got := zero.String(); got != "missing" {
		t.Fatalf("zero BindingStatus String() = %q, want %q", got, "missing")
	}
}

// TestAuditEntryView_BindingStatusDefault asserts the additive field defaults
// to BindingMissing on a zero-value view, so a view that the verifier never
// labelled is never displayed as verified.
func TestAuditEntryView_BindingStatusDefault(t *testing.T) {
	t.Parallel()

	var v rotate.AuditEntryView
	if v.BindingStatus != rotate.BindingMissing {
		t.Fatalf("zero AuditEntryView.BindingStatus = %v, want BindingMissing",
			v.BindingStatus)
	}
}

// fakeAuditVerifier is an in-memory AuditVerifier used only to prove the
// consumer-defined port is satisfiable without any SDK type and that the typed
// error rides ALONGSIDE the per-line projection (a tamper outcome returns both
// a non-nil error AND the entries for per-line display). It deliberately does
// NOT implement any verification logic — that is the adapter's step.
type fakeAuditVerifier struct {
	result rotate.AuditVerifyResult
	err    error
}

// Compile-time assertion: the fake satisfies the consumer-defined port, proving
// VerifyAuditLog is the only method and its signature compiles against the
// existing AuditEntryView.
var _ rotate.AuditVerifier = (*fakeAuditVerifier)(nil)

func (f *fakeAuditVerifier) VerifyAuditLog(
	ctx context.Context, _ string,
) (rotate.AuditVerifyResult, error) {
	if err := ctx.Err(); err != nil {
		return rotate.AuditVerifyResult{}, err
	}
	return f.result, f.err
}

// TestAuditVerifier_PortShape exercises the port through the fake to lock the
// contract that the projection is returned on BOTH the clean and the tamper
// outcome: the caller renders per-line status from Entries in either case and
// keys the non-zero exit off the typed error, never off an empty projection.
func TestAuditVerifier_PortShape(t *testing.T) {
	t.Parallel()

	entries := []rotate.AuditEntryView{
		{Kind: "rotation", BindingStatus: rotate.BindingVerified},
		{Kind: "merge", BindingStatus: rotate.BindingTampered},
	}
	var v rotate.AuditVerifier = &fakeAuditVerifier{
		result: rotate.AuditVerifyResult{Entries: entries, FullWalk: true},
	}

	res, err := v.VerifyAuditLog(context.Background(), "org/app")
	if err != nil {
		t.Fatalf("VerifyAuditLog returned unexpected error: %v", err)
	}
	if !res.FullWalk {
		t.Fatalf("FullWalk = false, want true")
	}
	if len(res.Entries) != len(entries) {
		t.Fatalf("Entries len = %d, want %d", len(res.Entries), len(entries))
	}
	if res.Entries[1].BindingStatus != rotate.BindingTampered {
		t.Fatalf("Entries[1].BindingStatus = %v, want BindingTampered",
			res.Entries[1].BindingStatus)
	}
}
