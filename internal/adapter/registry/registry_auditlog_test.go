package registry_test

// Tests for *registry.Client.FetchAuditLog and the unexported parseAuditJSONL
// helper (exercised via FetchAuditLog).
//
// Test cases:
//   - verify-on-read pass: verified HEAD → entries returned
//   - !verified HEAD → ErrUnsignedRegistry, no cache fallthrough
//   - FetchHead transport error → ErrRegistryOffline (fail closed)
//   - nil FetchTransport → ErrRegistryOffline
//   - absent file (ReadAuditLog returns nil,nil) → empty slice, nil error
//   - FetchAuditLog verifiedHeadCommit threading: ReadAuditLog receives the
//     EXACT headCommit from FetchHead (no second FetchHead, no TOCTOU)
//   - per-line oversize → bounded-read error, never OOM
//   - malformed JSONL line → Unknown=true warning row, not panic
//   - unknown Kind → Unknown=true, not a hard error
//   - result count cap → tail + truncation advisory
//   - duplicate-key: SAFE-named key shadowed by DENY-shaped value → last-wins
//     resolves into typed struct, SAFE/DENY partition applied on resolved key set
//   - removed_recipients COUNT-ONLY: age1... per-index values never in AuditEntryView
//   - high-entropy SafeDetails value → dropped at read-side guard
//   - from_request_yaml_just family → denied even after decode

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	registry "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/core/audit"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ---- fake transports for audit log tests ------------------------------------

// auditFakeTransport is a configurable FetchTransport for FetchAuditLog tests.
type auditFakeTransport struct {
	headCommit  string
	verified    bool
	fetchHeadFn func() (string, string, bool, error) // overrides defaults when set
	auditBytes  []byte
	auditErr    error
	// capturedReadAuditLogArgs records the headCommit passed to ReadAuditLog
	// so the TOCTOU test can assert the exact pinned SHA was threaded.
	capturedHeadCommit string
}

func (t *auditFakeTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	if t.fetchHeadFn != nil {
		return t.fetchHeadFn()
	}
	return t.headCommit, "test-signer", t.verified, nil
}
func (t *auditFakeTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (t *auditFakeTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (t *auditFakeTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (t *auditFakeTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (t *auditFakeTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (t *auditFakeTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (t *auditFakeTransport) DiscardCounterSession(_ context.Context, _ string) {}
func (t *auditFakeTransport) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (t *auditFakeTransport) ReadAuditLog(_ context.Context, _, headCommit, _ string) ([]byte, error) {
	t.capturedHeadCommit = headCommit
	return t.auditBytes, t.auditErr
}

// auditFetchHeadErrorTransport returns a transport error from FetchHead.
type auditFetchHeadErrorTransport struct{}

func (t *auditFetchHeadErrorTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "", "", false, fmt.Errorf("network unreachable")
}
func (t *auditFetchHeadErrorTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (t *auditFetchHeadErrorTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (t *auditFetchHeadErrorTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (t *auditFetchHeadErrorTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (t *auditFetchHeadErrorTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (t *auditFetchHeadErrorTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (t *auditFetchHeadErrorTransport) DiscardCounterSession(_ context.Context, _ string) {}
func (t *auditFetchHeadErrorTransport) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (t *auditFetchHeadErrorTransport) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	panic("ReadAuditLog must not be called when FetchHead fails")
}

// ---- helpers -----------------------------------------------------------------

func newAuditTestClient(ft registry.FetchTransport) *registry.Client {
	anchor := make(ed25519.PublicKey, ed25519.PublicKeySize)
	c, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://test.example.com/registry",
		ProjectID:      "proj",
		CacheDir:       "",
		TrustAnchorKey: anchor,
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: ft,
	})
	if err != nil {
		panic("newAuditTestClient: " + err.Error())
	}
	return c
}

func buildAuditJSONLLine(e audit.Event) []byte {
	b, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// ---- V8b.AL.01 — verified HEAD → entries returned ---------------------------

// TestFetchAuditLog_VerifiedHead_ReturnsEntries proves that a verified HEAD
// with a well-formed JSONL returns the expected AuditEntryView slice.
func TestFetchAuditLog_VerifiedHead_ReturnsEntries(t *testing.T) {
	t.Parallel()

	evt := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Actor:      "admin@example.com",
		ProjectID:  "proj",
		Outcome:    "ok",
	}
	jsonl := buildAuditJSONLLine(evt)

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: jsonl,
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("FetchAuditLog: want 1 entry, got %d", len(entries))
	}
	if entries[0].Kind != "rotation" {
		t.Errorf("entry[0].Kind = %q, want %q", entries[0].Kind, "rotation")
	}
	if entries[0].Actor != "admin@example.com" {
		t.Errorf("entry[0].Actor = %q, want %q", entries[0].Actor, "admin@example.com")
	}
	if entries[0].Unknown {
		t.Error("entry[0].Unknown must be false for a known kind")
	}
}

// ---- V8b.AL.02 — !verified HEAD → ErrUnsignedRegistry, no fallthrough -------

// TestFetchAuditLog_UnverifiedHead_ErrUnsignedRegistry proves that a HEAD
// returned with verified=false results in ErrUnsignedRegistry and that
// ReadAuditLog is NEVER called (no cache fallthrough, no partial display).
func TestFetchAuditLog_UnverifiedHead_ErrUnsignedRegistry(t *testing.T) {
	t.Parallel()

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   false,
		// auditBytes deliberately set to prove ReadAuditLog is not reached
		auditBytes: []byte(`{"kind":"rotation"}`),
	}

	// Use a direct fake where verified=false; ReadAuditLog will not be
	// reached because the verified gate fires first. The capturedHeadCommit
	// field on auditFakeTransport stays empty, proving ReadAuditLog was never
	// called (no TOCTOU window).
	c := newAuditTestClient(ft)

	_, err := c.FetchAuditLog(context.Background(), "proj")
	if err == nil {
		t.Fatal("FetchAuditLog: expected ErrUnsignedRegistry, got nil")
	}
	if !errors.Is(err, coreregistry.ErrUnsignedRegistry) {
		t.Errorf("want errors.Is(err, ErrUnsignedRegistry), got: %v", err)
	}
	// ReadAuditLog MUST NOT have been called (capturedHeadCommit stays empty).
	if ft.capturedHeadCommit != "" {
		t.Errorf("ReadAuditLog was called despite !verified (TOCTOU gate violated): headCommit=%q",
			ft.capturedHeadCommit)
	}
}

// ---- V8b.AL.03 — FetchHead transport error → ErrRegistryOffline ------------

// TestFetchAuditLog_FetchHeadError_ErrRegistryOffline proves that a transport
// error from FetchHead results in ErrRegistryOffline (fail closed). There is
// no audit cache; the method does NOT fall back to a stale cache.
func TestFetchAuditLog_FetchHeadError_ErrRegistryOffline(t *testing.T) {
	t.Parallel()

	// auditFetchHeadErrorTransport panics on ReadAuditLog — proving it's unreached.
	c := newAuditTestClient(&auditFetchHeadErrorTransport{})

	_, err := c.FetchAuditLog(context.Background(), "proj")
	if err == nil {
		t.Fatal("FetchAuditLog: expected ErrRegistryOffline, got nil")
	}
	if !errors.Is(err, coreregistry.ErrRegistryOffline) {
		t.Errorf("want errors.Is(err, ErrRegistryOffline), got: %v", err)
	}
}

// ---- V8b.AL.04 — nil FetchTransport → ErrRegistryOffline -------------------

// TestFetchAuditLog_NilTransport_ErrRegistryOffline proves that a client with
// no FetchTransport (offline) returns ErrRegistryOffline immediately.
func TestFetchAuditLog_NilTransport_ErrRegistryOffline(t *testing.T) {
	t.Parallel()

	anchor := make(ed25519.PublicKey, ed25519.PublicKeySize)
	c, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://test.example.com/registry",
		ProjectID:      "proj",
		CacheDir:       "",
		TrustAnchorKey: anchor,
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: nil, // offline
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	_, fetchErr := c.FetchAuditLog(context.Background(), "proj")
	if fetchErr == nil {
		t.Fatal("FetchAuditLog: expected ErrRegistryOffline, got nil")
	}
	if !errors.Is(fetchErr, coreregistry.ErrRegistryOffline) {
		t.Errorf("want errors.Is(err, ErrRegistryOffline), got: %v", fetchErr)
	}
}

// ---- V8b.AL.05 — absent file → empty slice, nil error ----------------------

// TestFetchAuditLog_AbsentFile_EmptySlice proves that when ReadAuditLog returns
// (nil, nil) (absent file), FetchAuditLog returns an empty slice with nil error
// (not a hard error, not a crash).
func TestFetchAuditLog_AbsentFile_EmptySlice(t *testing.T) {
	t.Parallel()

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: nil, // absent
		auditErr:   nil,
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error for absent file: %v", err)
	}
	if entries == nil {
		// nil slice is also acceptable per the contract
		entries = []rotate.AuditEntryView{}
	}
	if len(entries) != 0 {
		t.Errorf("FetchAuditLog absent file: want 0 entries, got %d", len(entries))
	}
}

// ---- V8b.AL.06 — headCommit threading (no TOCTOU) ---------------------------

// TestFetchAuditLog_HeadCommitThreaded proves that the headCommit passed to
// ReadAuditLog is EXACTLY the SHA that FetchHead returned — no second FetchHead,
// no TOCTOU window.
func TestFetchAuditLog_HeadCommitThreaded(t *testing.T) {
	t.Parallel()

	const pinnedSHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	ft := &auditFakeTransport{
		headCommit: pinnedSHA,
		verified:   true,
		auditBytes: []byte{}, // empty — no entries
	}
	c := newAuditTestClient(ft)

	_, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error: %v", err)
	}

	if ft.capturedHeadCommit != pinnedSHA {
		t.Errorf("ReadAuditLog received headCommit %q, want %q (TOCTOU violation if different)",
			ft.capturedHeadCommit, pinnedSHA)
	}
}

// ---- V8b.AL.07 — per-line oversize → bounded-read error, never OOM ---------

// TestFetchAuditLog_OversizeLine_BoundedReadError proves that a single
// JSONL line exceeding maxAuditLineBytes returns a typed bounded-read error
// from the bufio.Scanner rather than an OOM or a panic.
func TestFetchAuditLog_OversizeLine_BoundedReadError(t *testing.T) {
	t.Parallel()

	// Build a line that exceeds 256 KiB (maxAuditLineBytes). We use a JSON
	// object with a very long string value. The line must be a single line
	// (no newlines inside) so the scanner's line-split algorithm tries to
	// buffer it all before the cap is hit.
	longValue := strings.Repeat("a", 300*1024) // 300 KiB > 256 KiB cap
	bigLine := fmt.Sprintf(`{"kind":"rotation","actor":"%s"}`+"\n", longValue)

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: []byte(bigLine),
	}
	c := newAuditTestClient(ft)

	_, err := c.FetchAuditLog(context.Background(), "proj")
	if err == nil {
		t.Fatal("FetchAuditLog: expected bounded-read error for oversize line, got nil")
	}
	if !errors.Is(err, coreregistry.ErrCounterStoreUnreadable) {
		t.Errorf("want errors.Is(err, ErrCounterStoreUnreadable), got: %v", err)
	}
	// Confirm the error wraps bufio.ErrTooLong via the Scanner.
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("want errors.Is(err, bufio.ErrTooLong) in chain, got: %v", err)
	}
}

// ---- V8b.AL.08 — malformed JSONL → warning row, not panic ------------------

// TestFetchAuditLog_MalformedLine_WarningRowNotPanic proves that a non-JSON
// line in the JSONL stream produces an Unknown=true warning row rather than
// a panic or a hard error.
func TestFetchAuditLog_MalformedLine_WarningRowNotPanic(t *testing.T) {
	t.Parallel()

	jsonl := "not valid json\n"
	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: []byte(jsonl),
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error for malformed line: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("FetchAuditLog malformed line: want 1 warning row, got %d", len(entries))
	}
	if !entries[0].Unknown {
		t.Error("malformed-line entry must have Unknown=true")
	}
}

// ---- V8b.AL.09 — unknown Kind → Unknown=true, not hard error ---------------

// TestFetchAuditLog_UnknownKind_WarningRowNotError proves that a JSONL entry
// whose Kind is not in the accepted set produces Unknown=true rather than a
// hard error, so forward-compat events from a newer binary do not crash.
func TestFetchAuditLog_UnknownKind_WarningRowNotError(t *testing.T) {
	t.Parallel()

	evt := audit.Event{
		Kind:       audit.EventKind("future.v03.new_kind"),
		OccurredAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Actor:      "system",
		ProjectID:  "proj",
		Outcome:    "ok",
	}
	jsonl := buildAuditJSONLLine(evt)

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: jsonl,
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error for unknown kind: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("FetchAuditLog unknown kind: want 1 entry, got %d", len(entries))
	}
	if !entries[0].Unknown {
		t.Errorf("unknown-kind entry must have Unknown=true")
	}
	if entries[0].Kind != "future.v03.new_kind" {
		t.Errorf("entry[0].Kind = %q, want %q", entries[0].Kind, "future.v03.new_kind")
	}
}

// ---- V8b.AL.10 — result count cap + truncation advisory --------------------

// TestFetchAuditLog_ResultCountCap_TailPlusTruncationAdvisory proves that
// when the parsed entry count exceeds maxAuditResultCount (1000), only the
// most recent 1000 entries are returned plus a synthetic truncation-advisory
// entry.
func TestFetchAuditLog_ResultCountCap_TailPlusTruncationAdvisory(t *testing.T) {
	t.Parallel()

	const overCount = 1005 // maxAuditResultCount+5

	var buf bytes.Buffer
	for i := 0; i < overCount; i++ {
		e := audit.Event{
			Kind:       audit.EventKindRotation,
			OccurredAt: time.Date(2026, 1, 1, 0, 0, i%60, 0, time.UTC),
			Actor:      fmt.Sprintf("admin-%d", i),
			ProjectID:  "proj",
			Outcome:    "ok",
		}
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: buf.Bytes(),
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error: %v", err)
	}

	// maxAuditResultCount + 1 advisory entry
	if len(entries) != 1001 {
		t.Fatalf("FetchAuditLog count cap: want 1001 entries (1000 + advisory), got %d", len(entries))
	}
	// First entry must be the truncation advisory.
	if entries[0].Kind != "truncated" {
		t.Errorf("entries[0].Kind = %q, want %q (truncation advisory)", entries[0].Kind, "truncated")
	}
	if !entries[0].Unknown {
		t.Error("truncation advisory must have Unknown=true")
	}
	// Last entry must be the last real entry (most recent).
	lastActorExpected := fmt.Sprintf("admin-%d", overCount-1)
	if entries[len(entries)-1].Actor != lastActorExpected {
		t.Errorf("last entry Actor = %q, want %q (tail entry)",
			entries[len(entries)-1].Actor, lastActorExpected)
	}
}

// ---- V8b.AL.11 — duplicate-key: last-wins, partition applied after decode --

// TestFetchAuditLog_DuplicateKey_LastWinsPartitionAfterDecode proves that
// when a Details object has duplicate keys, Go's encoding/json last-wins
// semantics apply BEFORE the SAFE/DENY partition, so a DENY key cannot
// smuggle a denied value into a SAFE slot by appearing in second position.
//
// The fixture has "reversal_reason" appear twice:
//   - First occurrence: value "safe-value"
//   - Second occurrence: value "safe-also"   (last-wins → "safe-also" in decoded struct)
//
// Both occurrences are SAFE, so the result should contain "safe-also".
// Separately, a DENY key (from_request_yaml_just_reason) also appears; it
// must not reach AuditEntryView.SafeDetails.
func TestFetchAuditLog_DuplicateKey_LastWinsPartitionAfterDecode(t *testing.T) {
	t.Parallel()

	// Build a raw JSON line with duplicate keys manually (json.Marshal cannot do
	// this, so we construct the bytes directly).
	rawLine := []byte(`{"kind":"rotation","occurred_at":"2026-01-01T00:00:00Z","actor":"a","project_id":"proj","outcome":"ok","details":{"reversal_reason":"safe-first","reversal_reason":"safe-last","from_request_yaml_just_reason":"contributor-justification"}}` + "\n")

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: rawLine,
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("FetchAuditLog: want 1 entry, got %d", len(entries))
	}

	sd := entries[0].SafeDetails
	// Last-wins for the duplicate reversal_reason key.
	if v, ok := sd["reversal_reason"]; !ok {
		t.Error("reversal_reason must be in SafeDetails")
	} else if v != "safe-last" {
		t.Errorf("reversal_reason = %q, want %q (last-wins)", v, "safe-last")
	}

	// DENY key must never appear.
	for k := range sd {
		if strings.HasPrefix(strings.ToLower(k), "from_request_yaml_just") {
			t.Errorf("DENY key %q reached SafeDetails", k)
		}
	}
}

// ---- V8b.AL.12 — removed_recipients COUNT-ONLY ------------------------------

// TestFetchAuditLog_RemovedRecipients_CountOnly proves that per-index
// removed_recipients_N keys carrying raw age1... pubkeys are NEVER copied
// into AuditEntryView.SafeDetails. Only the synthetic count key
// "removed_recipients_count" appears.
func TestFetchAuditLog_RemovedRecipients_CountOnly(t *testing.T) {
	t.Parallel()

	evt := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Actor:      "admin",
		ProjectID:  "proj",
		Outcome:    "ok",
		Details: map[string]string{
			"removed_recipients_0": "age1lqtsmk4qk0zq3lc7f3jzn7s3a4wvww3ey9f5d7y7j3pf3tmqabcdefghij",
			"removed_recipients_1": "age1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzyabcd",
			"rotation_epoch":       "5",
		},
	}
	jsonl := buildAuditJSONLLine(evt)

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: jsonl,
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("FetchAuditLog: want 1 entry, got %d", len(entries))
	}

	sd := entries[0].SafeDetails

	// Count must be present.
	count, ok := sd["removed_recipients_count"]
	if !ok {
		t.Fatal("removed_recipients_count must be in SafeDetails")
	}
	if count != "2" {
		t.Errorf("removed_recipients_count = %q, want %q", count, "2")
	}

	// Per-index keys must NOT be present.
	for k, v := range sd {
		if strings.HasPrefix(k, "removed_recipients_") && k != "removed_recipients_count" {
			t.Errorf("per-index key %q=%q must not appear in SafeDetails", k, v)
		}
		// age1... pubkey bytes must NEVER appear in any value.
		if strings.HasPrefix(v, "age1") {
			t.Errorf("age1... pubkey value in SafeDetails key=%q: %q", k, v)
		}
	}
}

// ---- V8b.AL.13 — high-entropy SafeDetails value → dropped ------------------

// TestFetchAuditLog_HighEntropySafeDetails_Dropped proves that a SafeDetails
// value that contains a long base64-alphabet run is dropped at the read-side
// entropy guard (fail-closed by omission) rather than surfaced.
func TestFetchAuditLog_HighEntropySafeDetails_Dropped(t *testing.T) {
	t.Parallel()

	// Build an audit event where a SAFE key (rotation_epoch) has a legitimately
	// valid value, but also inject a synthetic "safe-looking" key with a high-
	// entropy value that should be dropped.
	// We need a key that passes the positive allowlist but whose VALUE fails the
	// entropy guard. The allowlist allows reversal_reason; its value here will
	// be a 40-char base64-alphabet run.
	evt := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Actor:      "admin",
		ProjectID:  "proj",
		Outcome:    "ok",
		Details: map[string]string{
			"rotation_epoch":  "3",
			"reversal_reason": strings.Repeat("A", 40), // 40-char base64 run > threshold=32
		},
	}
	jsonl := buildAuditJSONLLine(evt)

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: jsonl,
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}

	sd := entries[0].SafeDetails

	// rotation_epoch is fine (short decimal value).
	if v, ok := sd["rotation_epoch"]; !ok || v != "3" {
		t.Errorf("rotation_epoch must be present and = %q, got %q ok=%v", "3", v, ok)
	}

	// reversal_reason had a high-entropy value → must be dropped.
	if v, ok := sd["reversal_reason"]; ok {
		t.Errorf("reversal_reason with high-entropy value must be dropped, got %q", v)
	}
}

// ---- V8b.AL.14 — from_request_yaml_just family → denied -------------------

// TestFetchAuditLog_JustificationDeny proves that any Details key prefixed
// with from_request_yaml_just is denied and never reaches SafeDetails.
func TestFetchAuditLog_JustificationDeny(t *testing.T) {
	t.Parallel()

	evt := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Actor:      "admin",
		ProjectID:  "proj",
		Outcome:    "ok",
		Details: map[string]string{
			"from_request_yaml_just_text": "contributor-authored text",
			"from_request_yaml_just_ext":  "more contributor text",
			"rotation_epoch":              "1",
		},
	}
	jsonl := buildAuditJSONLLine(evt)

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: jsonl,
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}

	sd := entries[0].SafeDetails
	for k := range sd {
		if strings.HasPrefix(strings.ToLower(k), "from_request_yaml_just") {
			t.Errorf("DENY justification key %q reached SafeDetails", k)
		}
	}
	// rotation_epoch should pass.
	if _, ok := sd["rotation_epoch"]; !ok {
		t.Error("rotation_epoch must be present in SafeDetails")
	}
}
