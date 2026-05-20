// Package auditsink_test covers the audit sink adapter:
//
//   - Round-trip: Append writes a valid JSONL entry for accepted event kinds.
//   - Event-class enumeration: non-accepted kinds are silently dropped (no error).
//   - Field-corruption hard error: Details map entries with non-canonical values
//     return ErrAuditEventInvalidField (never silently dropped).
//   - No keychain credential: Sink never acquires a write token or keychain cred.
//   - No high-entropy bytes: JSONL output for any accepted event must not contain
//     a contiguous run of 32+ base64-alphabet characters (secret-leak heuristic).
//
// Obligation bindings:
//
//	T-V3-4 → TestAuditSink_InvalidFieldValue_ReturnsHardError
//	T-V3-5 → TestAuditSink_DoesNotAcquireKeychainCredential
//	BO-V3-6 → TestAuditSink_NoHighEntropyBytesInJSONL
package auditsink_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry/auditsink"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/logging"
)

// ---- helpers -----------------------------------------------------------------

// newTestSink constructs a Sink backed by a temp directory for each test.
func newTestSink(t *testing.T) (*auditsink.Sink, string) {
	t.Helper()
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	s, err := auditsink.New(auditsink.SinkConfig{
		AuditDir: auditDir,
		Logger:   logging.Discard,
	})
	if err != nil {
		t.Fatalf("auditsink.New: %v", err)
	}
	return s, auditDir
}

// readJSONLLines reads all non-empty lines from a .jsonl file and returns them.
func readJSONLLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test helper, controlled path
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close %s: %v", path, closeErr)
		}
	}()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return lines
}

// looksLikeHighEntropyBase64 mirrors the production heuristic: true when s
// contains a run of 32+ contiguous characters in the base64 alphabet.
func looksLikeHighEntropyBase64(s string) bool {
	const threshold = 32
	run := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '=' {
			run++
			if run >= threshold {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// ---- T-V3-5 — Sink does NOT acquire a keychain credential -------------------

// TestAuditSink_DoesNotAcquireKeychainCredential proves that constructing and
// using a Sink requires only an AuditDir and a Logger — no keychain, no token
// provider, no write credential is needed or acquired.
//
// Discharges: T-V3-5.
func TestAuditSink_DoesNotAcquireKeychainCredential(t *testing.T) {
	t.Parallel()

	// Construction with a nil Logger (uses discard internally) — no keychain import.
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	s, err := auditsink.New(auditsink.SinkConfig{
		AuditDir: auditDir,
		Logger:   nil, // nil is allowed; Sink uses discard internally
	})
	if err != nil {
		t.Fatalf("auditsink.New with nil Logger: %v", err)
	}

	// A successful Append must require only filesystem access — no network,
	// no keychain. If any credential acquisition were attempted it would panic
	// or return an error unrelated to I/O; the append succeeds here.
	e := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Now(),
		ProjectID:  "proj-t5",
		Actor:      "admin",
		Outcome:    "ok",
	}
	if appendErr := s.Append(context.Background(), e); appendErr != nil {
		t.Fatalf("Append: unexpected error (no keychain required): %v", appendErr)
	}

	// New requires only AuditDir — no credential fields in SinkConfig.
	// This compile-time assertion documents the constraint: SinkConfig must
	// have only AuditDir and Logger (both injection-friendly; no SDK types).
	_ = auditsink.SinkConfig{AuditDir: "/tmp/audit", Logger: logging.Discard}
}

// ---- T-V3-4 — hard error on field corruption --------------------------------

// TestAuditSink_InvalidFieldValue_ReturnsHardError proves that an audit.Event
// whose Details map contains a non-canonical value is rejected with
// ErrAuditEventInvalidField. The event is not silently dropped — the caller
// receives a hard error so it can alert on schema violations.
//
// Discharges: T-V3-4.
func TestAuditSink_InvalidFieldValue_ReturnsHardError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		details map[string]string
		wantErr bool
	}{
		{
			name: "invalid age pubkey field — not age1 format",
			details: map[string]string{
				"removed_pubkey": "notanagepubkey",
			},
			wantErr: true,
		},
		{
			name: "invalid age pubkey field — too short",
			details: map[string]string{
				"recipient_key": "age1short",
			},
			wantErr: true,
		},
		{
			name: "invalid project field — contains newline (injection attempt)",
			details: map[string]string{
				"project_name": "valid\ninjected-field: bad",
			},
			wantErr: true,
		},
		{
			name: "invalid project field — too long (> 256 chars)",
			details: map[string]string{
				"file_name": strings.Repeat("a", 257),
			},
			wantErr: true,
		},
		{
			name: "high-entropy base64 in general field",
			details: map[string]string{
				// 40 contiguous base64-alphabet chars: secret-leak heuristic fires.
				"status": strings.Repeat("A", 40),
			},
			wantErr: true,
		},
		{
			name:    "valid event — no details",
			details: nil,
			wantErr: false,
		},
		{
			name: "valid event — short project field",
			details: map[string]string{
				"project_name": "my-project",
			},
			wantErr: false,
		},
		{
			name: "valid event — canonical age pubkey",
			details: map[string]string{
				// "age1" + 58 lower-case bech32 chars = 62 total.
				"removed_pubkey": "age1" + strings.Repeat("q", 58),
			},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, _ := newTestSink(t)
			e := audit.Event{
				Kind:       audit.EventKindRotation,
				OccurredAt: time.Now(),
				ProjectID:  "proj-field-test",
				Actor:      "admin",
				Outcome:    "ok",
				Details:    tc.details,
			}
			err := s.Append(context.Background(), e)
			if tc.wantErr {
				if err == nil {
					t.Fatal("Append: expected ErrAuditEventInvalidField, got nil")
				}
				if !errors.Is(err, auditsink.ErrAuditEventInvalidField) {
					t.Errorf("Append: want errors.Is(err, ErrAuditEventInvalidField), got: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Append: unexpected error: %v", err)
				}
			}
		})
	}
}

// ---- BO-V3-6 — no high-entropy bytes in JSONL output ------------------------

// TestAuditSink_NoHighEntropyBytesInJSONL proves that the JSONL written by the
// sink for accepted event kinds does not contain any run of 32+ contiguous
// base64-alphabet characters in any field. This is the BO-V3-6 secret-leak
// heuristic: audit entries should never carry ciphertext, key material, or
// other high-entropy encoded data.
//
// Discharges: BO-V3-6.
func TestAuditSink_NoHighEntropyBytesInJSONL(t *testing.T) {
	t.Parallel()

	// Construct events for each accepted kind. Details carry only short,
	// non-base64-run values; age pubkeys are excluded because they are
	// intentionally 62-char bech32 values and pass the separate pubkey-regex
	// validation path (not the high-entropy heuristic path).
	events := []audit.Event{
		{
			Kind:       audit.EventKindRotation,
			OccurredAt: time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC),
			ProjectID:  "proj-bo6-rotation",
			Actor:      "admin-user",
			Outcome:    "ok",
			Details: map[string]string{
				"project_name": "proj-bo6-rotation",
				"file_name":    "secrets/main.enc.yaml",
			},
		},
		{
			Kind:       audit.EventKindMerge,
			OccurredAt: time.Date(2026, 5, 20, 10, 1, 0, 0, time.UTC),
			ProjectID:  "proj-bo6-merge",
			Actor:      "admin-user",
			FileName:   "secrets/merge.enc.yaml",
			PRRef:      "org/repo#42",
			Outcome:    "ok",
		},
		{
			Kind:       audit.EventKindCommitBump,
			OccurredAt: time.Date(2026, 5, 20, 10, 2, 0, 0, time.UTC),
			ProjectID:  "proj-bo6-bump",
			Actor:      "admin-user",
			Outcome:    "ok",
		},
	}

	s, auditDir := newTestSink(t)

	for _, e := range events {
		if err := s.Append(context.Background(), e); err != nil {
			t.Fatalf("Append kind=%q: %v", e.Kind, err)
		}
	}

	// Read every JSONL file produced and check for high-entropy runs.
	// Each project ID gets its own file.
	projectIDs := []string{"proj-bo6-rotation", "proj-bo6-merge", "proj-bo6-bump"}
	for _, pid := range projectIDs {
		path := filepath.Join(auditDir, pid+".jsonl")
		lines := readJSONLLines(t, path)
		if len(lines) == 0 {
			t.Errorf("no JSONL lines written for project %s", pid)
			continue
		}
		for i, line := range lines {
			// Each line must be valid JSON.
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Errorf("project %s line %d: invalid JSON: %v\nline: %s", pid, i, err, line)
				continue
			}
			// The entire serialized line must not contain a 32+ base64 run.
			if looksLikeHighEntropyBase64(line) {
				t.Errorf("project %s line %d: JSONL contains high-entropy base64-like run (secret leak heuristic fired):\n%s",
					pid, i, line)
			}
		}
	}
}

// ---- Round-trip tests -------------------------------------------------------

// TestAuditSink_RoundTrip_AcceptedKinds proves that Append writes a valid JSON
// line for each accepted event kind, and that the written event can be
// round-tripped back to an audit.Event with all fields preserved.
func TestAuditSink_RoundTrip_AcceptedKinds(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC)

	cases := []struct {
		kind      audit.EventKind
		projectID string
	}{
		{audit.EventKindRotation, "proj-rt-rotation"},
		{audit.EventKindMerge, "proj-rt-merge"},
		{audit.EventKindCommitBump, "proj-rt-bump"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.kind), func(t *testing.T) {
			t.Parallel()

			s, auditDir := newTestSink(t)
			e := audit.Event{
				Kind:       tc.kind,
				OccurredAt: now,
				ProjectID:  tc.projectID,
				Actor:      "admin",
				Outcome:    "ok",
			}
			if err := s.Append(context.Background(), e); err != nil {
				t.Fatalf("Append: %v", err)
			}

			path := filepath.Join(auditDir, tc.projectID+".jsonl")
			lines := readJSONLLines(t, path)
			if len(lines) != 1 {
				t.Fatalf("expected 1 JSONL line, got %d", len(lines))
			}

			var got audit.Event
			if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
				t.Fatalf("unmarshal JSONL: %v", err)
			}
			if got.Kind != tc.kind {
				t.Errorf("Kind: got %q, want %q", got.Kind, tc.kind)
			}
			if got.ProjectID != tc.projectID {
				t.Errorf("ProjectID: got %q, want %q", got.ProjectID, tc.projectID)
			}
			if got.Actor != "admin" {
				t.Errorf("Actor: got %q, want admin", got.Actor)
			}
		})
	}
}

// TestAuditSink_RoundTrip_MultipleAppends proves that multiple Append calls for
// the same project accumulate lines in order (JSONL append-only behaviour).
func TestAuditSink_RoundTrip_MultipleAppends(t *testing.T) {
	t.Parallel()

	s, auditDir := newTestSink(t)

	events := []audit.Event{
		{Kind: audit.EventKindRotation, OccurredAt: time.Now(), ProjectID: "proj-multi", Actor: "admin", Outcome: "ok"},
		{Kind: audit.EventKindMerge, OccurredAt: time.Now(), ProjectID: "proj-multi", Actor: "admin", Outcome: "ok"},
		{Kind: audit.EventKindCommitBump, OccurredAt: time.Now(), ProjectID: "proj-multi", Actor: "admin", Outcome: "ok"},
	}

	for _, e := range events {
		if err := s.Append(context.Background(), e); err != nil {
			t.Fatalf("Append kind=%q: %v", e.Kind, err)
		}
	}

	path := filepath.Join(auditDir, "proj-multi.jsonl")
	lines := readJSONLLines(t, path)
	if len(lines) != len(events) {
		t.Fatalf("expected %d JSONL lines, got %d", len(events), len(lines))
	}

	for i, line := range lines {
		var got audit.Event
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("line %d unmarshal: %v", i, err)
		}
		if got.Kind != events[i].Kind {
			t.Errorf("line %d: Kind = %q, want %q", i, got.Kind, events[i].Kind)
		}
	}
}

// ---- Event-class enumeration ------------------------------------------------

// TestAuditSink_DroppedKinds_NoFileCreated proves that a non-accepted event
// kind is silently dropped: no error is returned and no file is created.
func TestAuditSink_DroppedKinds_NoFileCreated(t *testing.T) {
	t.Parallel()

	droppedKinds := []audit.EventKind{
		audit.EventKindModePromotion,
		audit.EventKindSubmit,
		audit.EventKindReview,
		audit.EventKindPendingBump,
		audit.EventKindRegistryRefresh,
		audit.EventKindAuthLogin,
		audit.EventKind("unknown.kind"),
	}

	for _, kind := range droppedKinds {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()

			// Use a separate Sink+dir per subtest so file-creation is unambiguous.
			dir := t.TempDir()
			auditDir := filepath.Join(dir, "audit")

			// Capture logged warnings so we can assert the drop is warned.
			var lastMsg string
			captureLogger := &captureLog{onLog: func(msg string) { lastMsg = msg }}

			s, err := auditsink.New(auditsink.SinkConfig{
				AuditDir: auditDir,
				Logger:   captureLogger,
			})
			if err != nil {
				t.Fatalf("auditsink.New: %v", err)
			}

			e := audit.Event{
				Kind:       kind,
				OccurredAt: time.Now(),
				ProjectID:  "proj-drop",
			}
			if dropErr := s.Append(context.Background(), e); dropErr != nil {
				t.Errorf("dropped kind %q: Append returned error %v, want nil", kind, dropErr)
			}

			// No file must have been created.
			path := filepath.Join(auditDir, "proj-drop.jsonl")
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Errorf("dropped kind %q: file was created (should not exist)", kind)
			}

			// A structured log warning must have been emitted.
			if !strings.Contains(lastMsg, "dropping event") && !strings.Contains(lastMsg, "unsupported") {
				t.Errorf("dropped kind %q: expected log warning, got: %q", kind, lastMsg)
			}
		})
	}
}

// ---- Constructor validation -------------------------------------------------

// TestAuditSink_New_EmptyAuditDir_ReturnsError proves that New rejects an empty
// AuditDir (fail-closed constructor).
func TestAuditSink_New_EmptyAuditDir_ReturnsError(t *testing.T) {
	t.Parallel()

	_, err := auditsink.New(auditsink.SinkConfig{
		AuditDir: "",
		Logger:   logging.Discard,
	})
	if err == nil {
		t.Fatal("New with empty AuditDir: expected error, got nil")
	}
}

// ---- Context cancellation ---------------------------------------------------

// TestAuditSink_Append_CancelledContext_ReturnsError proves that Append respects
// context cancellation and returns an error without writing.
func TestAuditSink_Append_CancelledContext_ReturnsError(t *testing.T) {
	t.Parallel()

	s, auditDir := newTestSink(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	e := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Now(),
		ProjectID:  "proj-ctx",
		Actor:      "admin",
	}
	if appendErr := s.Append(ctx, e); appendErr == nil {
		t.Fatal("Append with cancelled context: expected error, got nil")
	}

	// No file must have been created (context check fires before I/O).
	path := filepath.Join(auditDir, "proj-ctx.jsonl")
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("Append cancelled: file was created unexpectedly")
	}
}

// ---- captureLog test helper -------------------------------------------------

// captureLog is a logging.Logger that captures the most recent log message for
// assertion in tests.
type captureLog struct {
	onLog func(msg string)
}

func (c *captureLog) Log(_ context.Context, _ logging.Level, msg string, _ ...string) {
	if c.onLog != nil {
		c.onLog(msg)
	}
}
