package audit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/core/audit"
)

// TestValidateEventFields_NoSchemaRegression is a golden corpus that pins the
// full accept/reject contract of ValidateEventFields across both the existing
// Details rules and the new top-level KeyName rule. It exists to catch a future
// edit that accidentally loosens or breaks either branch: every previously-valid
// event must still pass and every known-bad event must still fail. New
// crafted-KeyName bad cases (control/slash/over-256/high-entropy-style) are
// included so the KeyName branch cannot silently regress.
func TestValidateEventFields_NoSchemaRegression(t *testing.T) {
	t.Parallel()

	type golden struct {
		name  string
		event audit.Event
		valid bool
	}

	corpus := []golden{
		// --- known-good: Details branch (must stay valid) ---
		{
			name:  "good/nil details",
			event: audit.Event{Kind: audit.EventKindMerge},
			valid: true,
		},
		{
			name: "good/project and file fields",
			event: audit.Event{Kind: audit.EventKindMerge, Details: map[string]string{
				"project_name": "my-project",
				"file_name":    "secrets/main.enc.yaml",
			}},
			valid: true,
		},
		{
			name: "good/age pubkey field",
			event: audit.Event{Kind: audit.EventKindRotation, Details: map[string]string{
				"removed_recipients_0": "age1" + strings.Repeat("q", 58),
			}},
			valid: true,
		},
		{
			name: "good/sha hex field",
			event: audit.Event{Kind: audit.EventKindMerge, Details: map[string]string{
				"audit_entry_sha": strings.Repeat("a1", 32),
			}},
			valid: true,
		},
		{
			name: "good/pr ref field",
			event: audit.Event{Kind: audit.EventKindRotation, Details: map[string]string{
				"from_request_pr_url": "org/registry#42",
			}},
			valid: true,
		},
		{
			name: "good/short general field",
			event: audit.Event{Kind: audit.EventKindMerge, Details: map[string]string{
				"re_encrypted": "true",
				"counter":      "7",
			}},
			valid: true,
		},
		// --- known-good: new KeyName branch (must stay valid) ---
		{
			name:  "good/keyname simple",
			event: audit.Event{Kind: audit.EventKindMerge, KeyName: "API_KEY"},
			valid: true,
		},
		{
			name:  "good/keyname dotted-dashed",
			event: audit.Event{Kind: audit.EventKindMerge, KeyName: "db.creds-v2"},
			valid: true,
		},
		{
			name: "good/full merge event keyname plus details",
			event: audit.Event{
				Kind:      audit.EventKindMerge,
				ProjectID: "proj",
				FileName:  "secrets/prod.enc.yaml",
				KeyName:   "DATABASE_URL",
				PRRef:     "org/secrets#7",
				Outcome:   "ok",
				Details:   map[string]string{"counter": "3", "re_encrypted": "false"},
			},
			valid: true,
		},

		// --- known-bad: Details branch (must stay rejected) ---
		{
			name: "bad/invalid pubkey",
			event: audit.Event{Kind: audit.EventKindRotation, Details: map[string]string{
				"removed_pubkey": "notanagekey",
			}},
			valid: false,
		},
		{
			name: "bad/project newline injection",
			event: audit.Event{Kind: audit.EventKindMerge, Details: map[string]string{
				"project_name": "valid\ninjected: bad",
			}},
			valid: false,
		},
		{
			name: "bad/high-entropy general field",
			event: audit.Event{Kind: audit.EventKindMerge, Details: map[string]string{
				"context": strings.Repeat("A", 40),
			}},
			valid: false,
		},
		{
			name: "bad/justification denylist",
			event: audit.Event{Kind: audit.EventKindRotation, Details: map[string]string{
				"from_request_yaml_justification": "innocent",
			}},
			valid: false,
		},
		{
			name: "bad/non-hex sha",
			event: audit.Event{Kind: audit.EventKindMerge, Details: map[string]string{
				"target_sha": "ZZZZ-not-hex",
			}},
			valid: false,
		},

		// --- known-bad: new crafted KeyName cases (must be rejected) ---
		{
			name:  "bad/keyname slash",
			event: audit.Event{Kind: audit.EventKindMerge, KeyName: "secrets/key"},
			valid: false,
		},
		{
			name:  "bad/keyname control char",
			event: audit.Event{Kind: audit.EventKindMerge, KeyName: "API\x00KEY"},
			valid: false,
		},
		{
			name:  "bad/keyname newline",
			event: audit.Event{Kind: audit.EventKindMerge, KeyName: "API\nKEY"},
			valid: false,
		},
		{
			name:  "bad/keyname over 256",
			event: audit.Event{Kind: audit.EventKindMerge, KeyName: strings.Repeat("k", 257)},
			valid: false,
		},
		{
			name:  "bad/keyname whitespace",
			event: audit.Event{Kind: audit.EventKindMerge, KeyName: "my key"},
			valid: false,
		},
	}

	for _, g := range corpus {
		g := g
		t.Run(g.name, func(t *testing.T) {
			t.Parallel()
			err := audit.ValidateEventFields(g.event)
			if g.valid {
				if err != nil {
					t.Fatalf("corpus %q expected VALID but got error: %v", g.name, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("corpus %q expected INVALID but got nil", g.name)
			}
			if !errors.Is(err, audit.ErrAuditEventInvalidField) {
				t.Errorf("corpus %q: want errors.Is(ErrAuditEventInvalidField), got: %v", g.name, err)
			}
		})
	}
}
