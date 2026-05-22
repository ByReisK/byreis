package rotate_test

// Admin-side audit-read projection — read-only display contract.
//
// This file exercises three things, all without real network, fs, clock, or
// SDK contact:
//
//  1. The AuditReader.FetchAuditLog consumer-defined port, driven by an
//     in-memory fake. The fake proves the port is satisfiable and that the
//     spine never needs an SDK type to consume it.
//  2. The ProjectAuditEvent pure projection helper, which maps a raw
//     audit.Event to the SAFE AuditEntryView allowlist. The projection is the
//     security-critical surface: it is the only place a removed-recipient
//     pubkey or a contributor-authored justification could leak into the read
//     path, so it is property-tested against an adversarial event.
//  3. The forward-compat tolerance: an unrecognised event kind maps to a
//     warning-row view (Unknown=true), never a crash or a silent drop.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// fakeAuditReader is an in-memory AuditReader used to drive the FetchAuditLog
// contract tests. It holds the entries to return and an optional error so the
// fail-closed propagation path is exercised without any registry contact.
type fakeAuditReader struct {
	entries []rotate.AuditEntryView
	err     error
}

// Compile-time assertion: the fake satisfies the consumer-defined port. This
// keeps the package compiling and proves FetchAuditLog is the only method.
var _ rotate.AuditReader = (*fakeAuditReader)(nil)

func (f *fakeAuditReader) FetchAuditLog(
	ctx context.Context, _ string,
) ([]rotate.AuditEntryView, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.entries, nil
}

// TestFetchAuditLog_ReturnsEntries asserts the port surfaces every verified
// entry the adapter mapped, in order.
func TestFetchAuditLog_ReturnsEntries(t *testing.T) {
	t.Parallel()

	want := []rotate.AuditEntryView{
		{Kind: "rotation", OccurredAt: "2026-05-22T10:00:00Z", Actor: "alice", Project: "org/app", Outcome: "ok"},
		{Kind: "merge", OccurredAt: "2026-05-22T11:00:00Z", Actor: "bob", Project: "org/app", Outcome: "ok"},
	}
	var reader rotate.AuditReader = &fakeAuditReader{entries: want}

	got, err := reader.FetchAuditLog(context.Background(), "org/app")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("FetchAuditLog: got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Kind != want[i].Kind || got[i].OccurredAt != want[i].OccurredAt ||
			got[i].Actor != want[i].Actor || got[i].Project != want[i].Project ||
			got[i].Outcome != want[i].Outcome || got[i].Unknown != want[i].Unknown {
			t.Fatalf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestFetchAuditLog_EmptyIsNotAnError asserts an audit log with no entries is a
// valid non-error outcome ("no audit entries yet"), not a failure.
func TestFetchAuditLog_EmptyIsNotAnError(t *testing.T) {
	t.Parallel()

	var reader rotate.AuditReader = &fakeAuditReader{entries: nil}

	got, err := reader.FetchAuditLog(context.Background(), "org/app")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error on empty log: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("FetchAuditLog: got %d entries, want 0", len(got))
	}
}

// TestFetchAuditLog_PropagatesError asserts a backend (verify / offline)
// failure surfaces as a non-nil error so the caller never mistakes a fetch
// failure for an empty log — fail closed, never a best-effort display.
func TestFetchAuditLog_PropagatesError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("registry HEAD not signature-verified")
	var reader rotate.AuditReader = &fakeAuditReader{err: sentinel}

	_, err := reader.FetchAuditLog(context.Background(), "org/app")
	if !errors.Is(err, sentinel) {
		t.Fatalf("FetchAuditLog: want error wrapping %v, got %v", sentinel, err)
	}
}

// TestFetchAuditLog_HonoursContextCancellation asserts the port honours a
// cancelled context (binding I/O-cancellation standard).
func TestFetchAuditLog_HonoursContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var reader rotate.AuditReader = &fakeAuditReader{
		entries: []rotate.AuditEntryView{{Kind: "rotation"}},
	}
	if _, err := reader.FetchAuditLog(ctx, "org/app"); !errors.Is(err, context.Canceled) {
		t.Fatalf("FetchAuditLog: want context.Canceled, got %v", err)
	}
}

// occurred is a fixed RFC3339 UTC stamp used across the projection tests so the
// expected OccurredAt formatting is deterministic (no real clock).
var occurred = time.Date(2026, 5, 22, 10, 0, 0, 0, time.UTC)

// TestProjectAuditEvent_AllowlistAndDeny is the table-driven SAFE/DENY
// partition contract. Each case constructs a raw audit.Event and asserts which
// Details keys survive into AuditEntryView.SafeDetails.
func TestProjectAuditEvent_AllowlistAndDeny(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		ev          audit.Event
		wantKind    string
		wantUnknown bool
		wantSafe    map[string]string
	}{
		{
			name: "rotation with from_request provenance quartet survives",
			ev: audit.Event{
				Kind:       audit.EventKindRotation,
				OccurredAt: occurred,
				Actor:      "alice",
				ProjectID:  "org/app",
				Outcome:    "ok",
				Details: map[string]string{
					"from_request_pr_url":                 "org/admins#42",
					"from_request_pr_head_sha":            "deadbeef",
					"from_request_yaml_handle":            "contrib",
					"from_request_validated_author_login": "contrib",
				},
			},
			wantKind: "rotation",
			wantSafe: map[string]string{
				"from_request_pr_url":                 "org/admins#42",
				"from_request_pr_head_sha":            "deadbeef",
				"from_request_yaml_handle":            "contrib",
				"from_request_validated_author_login": "contrib",
			},
		},
		{
			name: "removed_recipients indexed pubkeys collapse to count-only",
			ev: audit.Event{
				Kind:       audit.EventKindRotation,
				OccurredAt: occurred,
				Outcome:    "ok",
				Details: map[string]string{
					"removed_recipients_0": "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsxxxxxx",
					"removed_recipients_1": "age1wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwsyyyyyy",
				},
			},
			wantKind: "rotation",
			wantSafe: map[string]string{
				"removed_recipients_count": "2",
			},
		},
		{
			name: "reversal anchored whole-key family survives; reason survives",
			ev: audit.Event{
				Kind:       audit.EventKindRotation,
				OccurredAt: occurred,
				Outcome:    "reverted",
				Details: map[string]string{
					"reversal_reason":             "phase-1-only-classification",
					"reversal_target_pr":          "org/app#7",
					"reversal_pendings_cleared_0": "db.enc.yaml",
					"reversal_pendings_cleared_1": "api.enc.yaml",
				},
			},
			wantKind: "rotation",
			wantSafe: map[string]string{
				"reversal_reason":             "phase-1-only-classification",
				"reversal_target_pr":          "org/app#7",
				"reversal_pendings_cleared_0": "db.enc.yaml",
				"reversal_pendings_cleared_1": "api.enc.yaml",
			},
		},
		{
			name: "justification denylist family is dropped",
			ev: audit.Event{
				Kind:       audit.EventKindRotation,
				OccurredAt: occurred,
				Outcome:    "ok",
				Details: map[string]string{
					"from_request_yaml_justification": "please let me in",
					"reversal_reason":                 "phase-1-only-classification",
				},
			},
			wantKind: "rotation",
			wantSafe: map[string]string{
				"reversal_reason": "phase-1-only-classification",
			},
		},
		{
			name: "unrecognised key dropped by omission (fail-closed)",
			ev: audit.Event{
				Kind:       audit.EventKindRotation,
				OccurredAt: occurred,
				Outcome:    "ok",
				Details: map[string]string{
					"some_future_key": "value",
					"reversal_reason": "phase-1-only-classification",
				},
			},
			wantKind: "rotation",
			wantSafe: map[string]string{
				"reversal_reason": "phase-1-only-classification",
			},
		},
		{
			name: "prefix-not-anchored reversal key is dropped",
			ev: audit.Event{
				Kind:       audit.EventKindRotation,
				OccurredAt: occurred,
				Outcome:    "ok",
				Details: map[string]string{
					"reversal_pendings_cleared_evil": "../../etc/passwd",
				},
			},
			wantKind: "rotation",
			wantSafe: map[string]string{},
		},
		{
			name: "removed_recipients non-numeric suffix does not count",
			ev: audit.Event{
				Kind:       audit.EventKindRotation,
				OccurredAt: occurred,
				Outcome:    "ok",
				Details: map[string]string{
					"removed_recipients_evil": "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsxxxxxx",
				},
			},
			wantKind: "rotation",
			wantSafe: map[string]string{},
		},
		{
			name: "accepted merge kind projects",
			ev: audit.Event{
				Kind:       audit.EventKindMerge,
				OccurredAt: occurred,
				Outcome:    "ok",
			},
			wantKind: "merge",
			wantSafe: map[string]string{},
		},
		{
			name: "accepted commit_bump kind projects",
			ev: audit.Event{
				Kind:       audit.EventKindCommitBump,
				OccurredAt: occurred,
				Outcome:    "ok",
			},
			wantKind: "counter.commit_bump",
			wantSafe: map[string]string{},
		},
		{
			name: "unrecognised kind maps to warning row (Unknown=true)",
			ev: audit.Event{
				Kind:       audit.EventKind("future.class"),
				OccurredAt: occurred,
				Outcome:    "ok",
			},
			wantKind:    "future.class",
			wantUnknown: true,
			wantSafe:    map[string]string{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := rotate.ProjectAuditEvent(tc.ev)

			if got.Kind != tc.wantKind {
				t.Fatalf("Kind: got %q, want %q", got.Kind, tc.wantKind)
			}
			if got.Unknown != tc.wantUnknown {
				t.Fatalf("Unknown: got %v, want %v", got.Unknown, tc.wantUnknown)
			}
			if got.OccurredAt != occurred.Format(time.RFC3339) {
				t.Fatalf("OccurredAt: got %q, want %q", got.OccurredAt, occurred.Format(time.RFC3339))
			}
			if len(got.SafeDetails) != len(tc.wantSafe) {
				t.Fatalf("SafeDetails: got %v, want %v", got.SafeDetails, tc.wantSafe)
			}
			for k, v := range tc.wantSafe {
				if got.SafeDetails[k] != v {
					t.Fatalf("SafeDetails[%q]: got %q, want %q", k, got.SafeDetails[k], v)
				}
			}
		})
	}
}

// TestProjectAuditEvent_NeverLeaksRecipientOrJustification is the adversarial
// property test: given an event carrying a raw removed-recipient pubkey AND a
// contributor justification, the projection must yield removed_recipients_count
// AND must contain no age1-prefixed value anywhere, no per-index
// removed_recipients_<N> key, and no from_request_yaml_just* key.
func TestProjectAuditEvent_NeverLeaksRecipientOrJustification(t *testing.T) {
	t.Parallel()

	const rawPubkey = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsxxxxxx"
	ev := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: occurred,
		Actor:      "alice",
		ProjectID:  "org/app",
		Outcome:    "reverted",
		Details: map[string]string{
			"removed_recipients_0":            rawPubkey,
			"removed_recipients_1":            rawPubkey,
			"removed_recipients_2":            rawPubkey,
			"from_request_yaml_justification": "let me in " + rawPubkey,
			"reversal_reason":                 "phase-1-only-classification",
		},
	}

	got := rotate.ProjectAuditEvent(ev)

	if got.SafeDetails["removed_recipients_count"] != "3" {
		t.Fatalf("removed_recipients_count: got %q, want %q",
			got.SafeDetails["removed_recipients_count"], "3")
	}
	for k, v := range got.SafeDetails {
		if strings.HasPrefix(strings.ToLower(k), "removed_recipients_") && k != "removed_recipients_count" {
			t.Fatalf("per-index removed_recipients key leaked: %q", k)
		}
		if strings.HasPrefix(strings.ToLower(k), "from_request_yaml_just") {
			t.Fatalf("justification key leaked: %q", k)
		}
		if strings.Contains(v, "age1") {
			t.Fatalf("SafeDetails[%q] leaks an age1-prefixed value: %q", k, v)
		}
	}
	// Also assert the projected non-Details fields carry no pubkey bytes.
	for _, field := range []string{got.Kind, got.OccurredAt, got.Actor, got.Project, got.Outcome} {
		if strings.Contains(field, "age1") {
			t.Fatalf("projected field leaks an age1-prefixed value: %q", field)
		}
	}
}
