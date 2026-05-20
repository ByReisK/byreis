package audit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/core/audit"
)

// TestValidateEventFields_AcceptsValidDetails proves that canonical-typed
// Details values pass validation without error.
func TestValidateEventFields_AcceptsValidDetails(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		details map[string]string
	}{
		{name: "nil details", details: nil},
		{name: "empty details", details: map[string]string{}},
		{
			name:    "valid project field",
			details: map[string]string{"project_name": "my-project"},
		},
		{
			name:    "valid file field",
			details: map[string]string{"file_name": "secrets/main.enc.yaml"},
		},
		{
			name: "valid age pubkey",
			// "age1" + 58 lower-case bech32 chars = 62 total.
			details: map[string]string{"removed_recipients_0": "age1" + strings.Repeat("q", 58)},
		},
		{
			name:    "valid general short field",
			details: map[string]string{"status": "ok"},
		},
		{
			name:    "rotation_epoch decimal string",
			details: map[string]string{"rotation_epoch": "42"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := audit.Event{
				Kind:      audit.EventKindRotation,
				ProjectID: "proj-valid",
				Details:   tc.details,
			}
			if err := audit.ValidateEventFields(e); err != nil {
				t.Errorf("ValidateEventFields: unexpected error: %v", err)
			}
		})
	}
}

// TestValidateEventFields_RejectsInvalidPubkeyField proves that a Details field
// whose key contains "recipient", "pubkey", or "age_key" and whose value is not
// a canonical age1<58> string returns ErrAuditEventInvalidField.
func TestValidateEventFields_RejectsInvalidPubkeyField(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		key  string
		val  string
	}{
		{"recipient not age1 prefix", "removed_recipients_0", "notanagepubkey"},
		{"pubkey too short", "admin_pubkey", "age1short"},
		{"age_key wrong format", "age_key", "ssh-ed25519 AAAA..."},
		{"recipient all caps wrong", "recipient", "AGE1" + strings.Repeat("Q", 58)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := audit.Event{
				Kind:    audit.EventKindRotation,
				Details: map[string]string{tc.key: tc.val},
			}
			err := audit.ValidateEventFields(e)
			if err == nil {
				t.Fatalf("expected ErrAuditEventInvalidField, got nil")
			}
			if !errors.Is(err, audit.ErrAuditEventInvalidField) {
				t.Errorf("want errors.Is(err, ErrAuditEventInvalidField), got: %v", err)
			}
		})
	}
}

// TestValidateEventFields_RejectsInvalidProjectFileField proves that a Details
// field whose key contains "project", "file", or "name" and whose value fails
// the alphanumeric+dot+slash+dash pattern returns ErrAuditEventInvalidField.
func TestValidateEventFields_RejectsInvalidProjectFileField(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		key  string
		val  string
	}{
		{"project with newline injection", "project_name", "valid\ninjected: bad"},
		{"file too long", "file_name", strings.Repeat("a", 257)},
		{"name with control char", "key_name", "secrets/\x00null"},
		{"project with spaces", "project_name", "has spaces"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := audit.Event{
				Kind:    audit.EventKindRotation,
				Details: map[string]string{tc.key: tc.val},
			}
			err := audit.ValidateEventFields(e)
			if err == nil {
				t.Fatalf("expected ErrAuditEventInvalidField, got nil")
			}
			if !errors.Is(err, audit.ErrAuditEventInvalidField) {
				t.Errorf("want errors.Is(err, ErrAuditEventInvalidField), got: %v", err)
			}
		})
	}
}

// TestValidateEventFields_RejectsHighEntropyBase64InGeneralField proves that
// a general Details field (key not matching pubkey/recipient/project/file/name)
// whose value contains 32+ contiguous base64-alphabet characters returns
// ErrAuditEventInvalidField (secret-leak heuristic).
func TestValidateEventFields_RejectsHighEntropyBase64InGeneralField(t *testing.T) {
	t.Parallel()

	e := audit.Event{
		Kind: audit.EventKindRotation,
		Details: map[string]string{
			"context": strings.Repeat("A", 40),
		},
	}
	err := audit.ValidateEventFields(e)
	if err == nil {
		t.Fatal("expected ErrAuditEventInvalidField for high-entropy field, got nil")
	}
	if !errors.Is(err, audit.ErrAuditEventInvalidField) {
		t.Errorf("want errors.Is(err, ErrAuditEventInvalidField), got: %v", err)
	}
}

// TestValidateEventFields_AcceptsGeneralFieldBelowThreshold proves that a
// general field value with fewer than 32 contiguous base64-alphabet chars
// does NOT trigger the heuristic.
func TestValidateEventFields_AcceptsGeneralFieldBelowThreshold(t *testing.T) {
	t.Parallel()

	e := audit.Event{
		Kind: audit.EventKindRotation,
		Details: map[string]string{
			"context": strings.Repeat("A", 31), // 31 < 32 threshold
		},
	}
	if err := audit.ValidateEventFields(e); err != nil {
		t.Errorf("expected no error for 31-char base64 run, got: %v", err)
	}
}

// TestValidateEventFields_ErrSentinelIsWrapped proves that ErrAuditEventInvalidField
// is the sentinel wrapped inside the returned error, so callers can use
// errors.Is for typed dispatch.
func TestValidateEventFields_ErrSentinelIsWrapped(t *testing.T) {
	t.Parallel()

	e := audit.Event{
		Kind:    audit.EventKindRotation,
		Details: map[string]string{"removed_pubkey": "invalid"},
	}
	err := audit.ValidateEventFields(e)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, audit.ErrAuditEventInvalidField) {
		t.Errorf("errors.Is must match the sentinel: %v", err)
	}
}
