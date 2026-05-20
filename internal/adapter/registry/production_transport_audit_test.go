// Package registry — internal tests for audit-event validation on the
// production commit path. This file is in package registry (not registry_test)
// so that buildAuditJSONLEntry (unexported) is directly accessible.
package registry

import (
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/core/audit"
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
