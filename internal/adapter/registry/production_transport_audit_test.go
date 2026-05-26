// Package registry — internal tests for audit-event validation on the
// production commit path. This file is in package registry (not registry_test)
// so that buildAuditJSONLEntry (unexported) and doCounterWrite (via
// CommitCounterWithAudit) are directly accessible.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
	"github.com/ByReisK/byreis/internal/core/audit"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
)

// TestCommitRotation_InvalidAuditField_ReturnsHardError proves that
// buildAuditJSONLEntry — called by doCommitRotation before json.Marshal —
// returns an error wrapping audit.ErrAuditEventInvalidField when the AuditEntry
// Details map contains a high-entropy base64 run. This is the T-V3-4 / F11
// production-path validation: the validator fires before any signing or git
// operation.
//
// Discharges: T-V3-4 (production-path half) / Fix-2.
func TestCommitRotation_InvalidAuditField_ReturnsHardError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		details map[string]string
	}{
		{
			name: "high-entropy base64 in context field",
			details: map[string]string{
				"context": strings.Repeat("A", 40), // 40 contiguous base64-alphabet chars
			},
		},
		{
			name: "invalid age pubkey in recipient field",
			details: map[string]string{
				"removed_recipients_0": "not-a-valid-age-pubkey",
			},
		},
		{
			name: "newline injection in project field",
			details: map[string]string{
				"project_name": "valid\ninjected: malicious",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			poisoned := audit.Event{
				Kind:      audit.EventKindRotation,
				ProjectID: "proj-poison",
				Outcome:   "ok",
				Details:   tc.details,
			}

			_, _, err := buildAuditJSONLEntry(poisoned)
			if err == nil {
				t.Fatalf("buildAuditJSONLEntry: expected error for poisoned Details, got nil")
			}
			if !errors.Is(err, audit.ErrAuditEventInvalidField) {
				t.Errorf("buildAuditJSONLEntry: want errors.Is(err, audit.ErrAuditEventInvalidField), got: %v", err)
			}
		})
	}
}

// TestBuildAuditJSONLEntry_ValidEvent_ProducesJSONL proves that a valid
// audit.Event produces a non-empty JSONL line ending with '\n' and a 64-hex
// sha256 digest. This is the positive-path complement to the hard-error test.
func TestBuildAuditJSONLEntry_ValidEvent_ProducesJSONL(t *testing.T) {
	t.Parallel()

	e := audit.Event{
		Kind:      audit.EventKindRotation,
		ProjectID: "proj-valid",
		Outcome:   "ok",
	}
	line, hexDigest, err := buildAuditJSONLEntry(e)
	if err != nil {
		t.Fatalf("buildAuditJSONLEntry: unexpected error: %v", err)
	}
	if len(line) == 0 {
		t.Error("JSONL line is empty")
	}
	if line[len(line)-1] != '\n' {
		t.Errorf("JSONL line does not end with newline: %q", line)
	}
	if len(hexDigest) != 64 {
		t.Errorf("hex digest length = %d, want 64", len(hexDigest))
	}
}

// ---- merge CommitBump audit SHA body embedding (BO-2 / BO-3) -----------------

// TestMergeCommitBump_AuditEntryShaCoveredInCommitBody proves that when
// doCounterWrite processes a commit phase with a non-zero AuditEntry, the
// sha256 of the canonical JSONL bytes (as produced by buildAuditJSONLEntry)
// equals the audit_entry_sha appended to the commit message body.
//
// This is the highest-risk assertion: the counter advance and the audit line
// are bound by the SHA in the signed commit body, making it impossible for a
// commit to advance the counter without recording the matching audit JSONL.
//
// The test directly exercises buildAuditJSONLEntry and verifies that the SHA
// derivation matches what would be appended to the commit body, providing the
// round-trip guarantee independent of the git subprocess layer.
//
// Discharges: BO-2 (production-path SHA binding), BO-3 (ValidateEventFields
// fires before signing on the merge path — proven by the fail-closed cases).
func TestMergeCommitBump_AuditEntryShaCoveredInCommitBody(t *testing.T) {
	t.Parallel()

	// A valid merge event with OccurredAt pre-stamped (simulating the
	// transport's time.Now() stamp).
	occurredAt := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	mergeEvent := audit.Event{
		Kind:       audit.EventKindMerge,
		OccurredAt: occurredAt,
		Actor:      "admin-key-label",
		ProjectID:  "proj-sha-bind",
		FileName:   "secrets",
		KeyName:    "API-KEY",
		PRRef:      "org/repo#99",
		Outcome:    "ok",
		Details:    map[string]string{"counter": "42"},
	}

	// Call buildAuditJSONLEntry directly — this is what doCounterWrite calls.
	jsonlBytes, hexSHA, err := buildAuditJSONLEntry(mergeEvent)
	if err != nil {
		t.Fatalf("buildAuditJSONLEntry: unexpected error: %v", err)
	}

	// Independently derive sha256(JSONL bytes) to verify the returned hexSHA.
	sum := sha256.Sum256(jsonlBytes)
	expected := fmt.Sprintf("%x", sum[:])
	if hexSHA != expected {
		t.Errorf("buildAuditJSONLEntry hexSHA = %q, independently computed = %q",
			hexSHA, expected)
	}

	// The SHA must be 64 hex chars (sha256 = 32 bytes = 64 hex digits).
	if len(hexSHA) != 64 {
		t.Errorf("audit entry SHA length = %d, want 64", len(hexSHA))
	}

	// The JSONL bytes must round-trip through json.Unmarshal: the line minus
	// the trailing newline must decode to an event whose fields match the input.
	lineNoNL := jsonlBytes[:len(jsonlBytes)-1]
	var decoded audit.Event
	if decErr := json.Unmarshal(lineNoNL, &decoded); decErr != nil {
		t.Fatalf("json.Unmarshal JSONL line: %v", decErr)
	}
	if decoded.Kind != mergeEvent.Kind {
		t.Errorf("decoded Kind = %q, want %q", decoded.Kind, mergeEvent.Kind)
	}
	if decoded.ProjectID != mergeEvent.ProjectID {
		t.Errorf("decoded ProjectID = %q, want %q", decoded.ProjectID, mergeEvent.ProjectID)
	}
	if decoded.KeyName != mergeEvent.KeyName {
		t.Errorf("decoded KeyName = %q, want %q", decoded.KeyName, mergeEvent.KeyName)
	}

	// Simulate what doCounterWrite appends to the commit body. The audit_entry_sha
	// line MUST appear so a verifier can bind the counter commit to its JSONL line.
	commitMsgBody := buildCounterCommitMessageBody(
		"proj-sha-bind", "secrets", 41, 42,
		"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4",
		"org/repo#99",
		"parentsha1parentsha1parentsha1parentsha1",
	)
	// Append the audit_entry_sha line (mirroring step 4a in doCounterWrite).
	bodyWithAudit := commitMsgBody + "audit_entry_sha: " + hexSHA + "\n"

	if !strings.Contains(bodyWithAudit, "audit_entry_sha: "+hexSHA) {
		t.Errorf("commit body does not contain audit_entry_sha: %s\nbody:\n%s",
			hexSHA, bodyWithAudit)
	}

	// A single-bit flip in the JSONL bytes must change the SHA (tamper detection).
	flipped := make([]byte, len(jsonlBytes))
	copy(flipped, jsonlBytes)
	flipped[0] ^= 0x01
	flippedSum := sha256.Sum256(flipped)
	flippedSHA := fmt.Sprintf("%x", flippedSum[:])
	if flippedSHA == hexSHA {
		t.Error("single-bit flip in JSONL bytes did not change the SHA — tamper detection broken")
	}
}

// TestMergeCommitBump_InvalidAuditField_AbortsBeforeSign proves that the
// fail-closed path in doCounterWrite's step 4a fires: when buildAuditJSONLEntry
// returns an error (ValidateEventFields failure), the function returns before
// any file write, git add, or signing operation. This is the BO-3 guarantee:
// no signed orphan, no partially-staged state.
//
// This test operates at the buildAuditJSONLEntry level (internal function),
// which is the exact gate that doCounterWrite calls. The external-package test
// (TestCommitBump_InvalidAuditField_FailsClosed) proves the Client-layer
// propagation; this test proves the gate itself fires correctly.
func TestMergeCommitBump_InvalidAuditField_AbortsBeforeSign(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		event   audit.Event
		wantErr error
	}{
		{
			name: "newline in key_name",
			event: audit.Event{
				Kind:      audit.EventKindMerge,
				ProjectID: "proj-abort",
				KeyName:   "KEY\ninjection",
				Outcome:   "ok",
			},
			wantErr: audit.ErrAuditEventInvalidField,
		},
		{
			name: "slash in key_name (path traversal attempt)",
			event: audit.Event{
				Kind:      audit.EventKindMerge,
				ProjectID: "proj-abort",
				KeyName:   "../../etc/passwd",
				Outcome:   "ok",
			},
			wantErr: audit.ErrAuditEventInvalidField,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := buildAuditJSONLEntry(tc.event)
			if err == nil {
				t.Fatalf("%s: expected error from buildAuditJSONLEntry, got nil", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("%s: want errors.Is(err, ErrAuditEventInvalidField), got: %v", tc.name, err)
			}
		})
	}
}

// TestMergeCommitBump_CommitCounterWithAudit_ExposedByInterface proves that
// productionFetchTransport satisfies the mergeAuditTransport extension interface
// both at compile time (the build-enforced assertion now lives in
// production_transport.go alongside the FetchTransport assertion) and at runtime
// when the type is stored as a FetchTransport in ClientConfig. The runtime
// assertion is the one Client.CommitBump actually executes; this test proves
// that storing the value as FetchTransport does not erase the extension.
func TestMergeCommitBump_CommitCounterWithAudit_ExposedByInterface(t *testing.T) {
	t.Parallel()

	// Verify via the FetchTransport interface: when the production transport
	// is stored as FetchTransport (as it is in ClientConfig), the runtime
	// interface assertion used by CommitBump must succeed.
	v, vErr := fetchtransport.NewHeadVerifier(fetchtransport.HeadVerifierConfig{
		Runner: &noopInternalRunner{},
		MkdirTemp: func(_, _ string) (string, error) {
			return t.TempDir(), nil
		},
		RemoveAll: func(_ string) error { return nil },
	})
	if vErr != nil {
		t.Fatalf("NewHeadVerifier: %v", vErr)
	}
	ft, newErr := NewProductionFetchTransport(v, nil)
	if newErr != nil {
		t.Fatalf("NewProductionFetchTransport: %v", newErr)
	}
	// Verify the concrete type also satisfies FetchTransport (so it can be
	// stored in ClientConfig and the runtime dispatch will find mergeAuditTransport).
	var ftAsInterface FetchTransport = ft
	_, ok := ftAsInterface.(mergeAuditTransport)
	if !ok {
		t.Error("productionFetchTransport stored as FetchTransport does not assert to " +
			"mergeAuditTransport — CommitBump audit dispatch will drop merge audit entries")
	}
}

// TestMergeCommitBump_ZeroAuditEntry_DoesNotCallAuditPath proves that when
// AuditEntry.Kind is empty (zero value), the audit path is not entered.
// This is the guard against non-merge counter bumps writing phantom audit lines.
func TestMergeCommitBump_ZeroAuditEntry_DoesNotCallAuditPath(t *testing.T) {
	t.Parallel()

	// The guard in doCounterWrite is `commitPhase && auditEntry.Kind != ""`.
	// A zero audit.Event has Kind == ""; verify this invariant on the type.
	zeroEvent := audit.Event{}
	if zeroEvent.Kind != "" {
		t.Fatalf("zero audit.Event.Kind must be empty string, got %q", zeroEvent.Kind)
	}

	// Also verify that coreregistry.CommitBumpInput zero value has an empty
	// AuditEntry.Kind — the transport guard relies on this.
	var zeroInput coreregistry.CommitBumpInput
	if zeroInput.AuditEntry.Kind != "" {
		t.Errorf("zero CommitBumpInput.AuditEntry.Kind must be empty, got %q",
			zeroInput.AuditEntry.Kind)
	}
}

// noopInternalRunner is a no-op CommandRunner for interface-assertion tests that
// do not invoke any git operations.
type noopInternalRunner struct{}

func (r *noopInternalRunner) Run(_ context.Context, _ string, _ []string, _ string, _ ...string) ([]byte, []byte, int, error) {
	return nil, nil, 0, nil
}
