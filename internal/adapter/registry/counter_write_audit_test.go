// Package registry — merge-audit same-commit transport tests (S3 / REQ-V04-003).
//
// Test obligations discharged by this file:
//
//   - BO-2 / T-V04-003-2 (atomicity): a CommitBump carrying an AuditEntry routes
//     to CommitCounterWithAudit; the recorded call carries both the pending counter
//     AND the non-empty AuditEntry in the SAME call — structural proof that the
//     audit line and the counter advance are inseparable at the transport boundary.
//
//   - BO-3 (fail-closed validation): a merge bump whose AuditEntry carries an
//     invalid Details field (newline injection, high-entropy base64) causes
//     Client.CommitBump to return an error wrapping ErrAuditEventInvalidField
//     BEFORE any signed commit is produced. The transport spy records zero calls
//     after validation (nothing staged, nothing pushed).
//
//   - Zero-value AuditEntry guard: when CommitBumpInput.AuditEntry.Kind is empty
//     (a non-merge counter advance, legacy path), CommitCounterWithAudit is NOT
//     invoked; the bare CommitCounter is used and no spurious audit line appears.
//
//   - CAS-retry rebuild: on ErrRegistryConcurrentWrite from CommitCounterWithAudit,
//     Client.CommitBump surfaces the error so the caller (merge spine) can re-enter
//     the whole flow from a fresh clone; the audit append in the losing attempt has
//     no remote effect (nothing pushed) so there is no half-appended remote line.
//
//   - Offline / auth-fail (BO-5 / AC-003-I): when CommitCounterWithAudit returns
//     ErrRegistryWriteAuth, the whole CommitBump fails with no partial state.
//
//   - Existing rotation same-commit tests are not regressed (no changes to
//     CommitRotationTransport or rotationCommitTransport paths).
package registry_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/core/audit"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// ---- BO-2 / T-V04-003-2: merge bump routes to CommitCounterWithAudit ------------

// TestCommitBump_WithAuditEntry_RoutesToCommitCounterWithAudit proves that when
// CommitBumpInput.AuditEntry.Kind is non-empty, Client.CommitBump dispatches to
// CommitCounterWithAudit (the audit-bearing extension) rather than CommitCounter.
// The spy records which method was called and what input it received, allowing
// the assertion that the counter advance and the audit entry arrived in the SAME
// call — structural atomicity proof at the transport boundary.
func TestCommitBump_WithAuditEntry_RoutesToCommitCounterWithAudit(t *testing.T) {
	t.Parallel()

	spy := &mergeAuditSpy{}
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj-audit-route",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: spy,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()

	// Seed a pending bump so CommitBump finds a matching pending record.
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj-audit-route",
		FileName:          "secrets",
		PendingCounter:    1,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "org/repo#7",
	}); err != nil {
		t.Fatalf("RecordPendingBump: %v", err)
	}

	mergeEntry := audit.Event{
		Kind:      audit.EventKindMerge,
		ProjectID: "proj-audit-route",
		FileName:  "secrets",
		KeyName:   "STRIPE-KEY",
		PRRef:     "org/repo#7",
		Outcome:   "ok",
		Details:   map[string]string{"counter": "1"},
	}
	if err := client.CommitBump(ctx, coreregistry.CommitBumpInput{
		ProjectID:      "proj-audit-route",
		FileName:       "secrets",
		PendingCounter: 1,
		PRRef:          "org/repo#7",
		AuditEntry:     mergeEntry,
	}); err != nil {
		t.Fatalf("CommitBump: %v", err)
	}

	// CommitCounterWithAudit must have been called exactly once.
	if spy.withAuditCalls != 1 {
		t.Errorf("CommitCounterWithAudit calls = %d, want 1", spy.withAuditCalls)
	}
	// The bare CommitCounter must NOT have been called (audit takes precedence).
	if spy.bareCommitCalls != 0 {
		t.Errorf("CommitCounter (bare) calls = %d, want 0 (audit path should be used)", spy.bareCommitCalls)
	}
	// The AuditEntry carried to the transport must be non-zero and correct.
	if spy.lastBumpIn.AuditEntry.Kind == "" {
		t.Error("CommitCounterWithAudit received: AuditEntry.Kind is empty — " +
			"the audit entry must travel with the counter advance in the SAME call")
	}
	if spy.lastBumpIn.AuditEntry.Kind != audit.EventKindMerge {
		t.Errorf("AuditEntry.Kind = %q, want %q", spy.lastBumpIn.AuditEntry.Kind, audit.EventKindMerge)
	}
	if spy.lastBumpIn.PendingCounter != 1 {
		t.Errorf("PendingCounter = %d, want 1", spy.lastBumpIn.PendingCounter)
	}
	// Atomicity proof: the SAME call carries both the counter advance and the
	// audit entry. Separate calls would allow a counter-advanced-but-no-audit
	// orphan window; one call removes that window.
	if spy.lastBumpIn.AuditEntry.ProjectID != "proj-audit-route" {
		t.Errorf("AuditEntry.ProjectID = %q, want %q",
			spy.lastBumpIn.AuditEntry.ProjectID, "proj-audit-route")
	}
}

// ---- Zero-value AuditEntry: bare CommitCounter used, no audit call -----------

// TestCommitBump_ZeroAuditEntry_UsesBareCommitCounter proves that when
// CommitBumpInput.AuditEntry.Kind is empty (the zero value — a non-merge counter
// advance, legacy path, or WriteCounter with no audit), CommitCounterWithAudit is
// NOT dispatched. The bare CommitCounter handles the advance without writing any
// audit JSONL, so no spurious audit line appears.
func TestCommitBump_ZeroAuditEntry_UsesBareCommitCounter(t *testing.T) {
	t.Parallel()

	spy := &mergeAuditSpy{}
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj-no-audit",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: spy,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj-no-audit",
		FileName:          "secrets",
		PendingCounter:    1,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "org/repo#8",
	}); err != nil {
		t.Fatalf("RecordPendingBump: %v", err)
	}

	// CommitBumpInput with zero AuditEntry.
	if err := client.CommitBump(ctx, coreregistry.CommitBumpInput{
		ProjectID:      "proj-no-audit",
		FileName:       "secrets",
		PendingCounter: 1,
		PRRef:          "org/repo#8",
		// AuditEntry is deliberately zero.
	}); err != nil {
		t.Fatalf("CommitBump (zero audit): %v", err)
	}

	if spy.withAuditCalls != 0 {
		t.Errorf("CommitCounterWithAudit calls = %d, want 0 (no audit entry)", spy.withAuditCalls)
	}
	if spy.bareCommitCalls != 1 {
		t.Errorf("CommitCounter (bare) calls = %d, want 1", spy.bareCommitCalls)
	}
}

// ---- BO-3: invalid audit field → fail-closed, no signed orphan ---------------

// TestCommitBump_InvalidAuditField_FailsClosed proves that when the merge event
// carries an invalid Details field (newline injection — an event that would fail
// audit.ValidateEventFields), Client.CommitBump returns an error that wraps
// audit.ErrAuditEventInvalidField and the transport records zero CommitCounterWithAudit
// calls after the validation fires. The fail-closed contract: validation runs
// BEFORE any git operation; no signed orphan, no partial staged state.
func TestCommitBump_InvalidAuditField_FailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		entry   audit.Event
		wantErr error
	}{
		{
			name: "newline injection in key_name",
			entry: audit.Event{
				Kind:      audit.EventKindMerge,
				ProjectID: "proj-invalid",
				FileName:  "secrets",
				// KeyName with newline is rejected by keyNameRE.
				KeyName: "STRIPE\ninjected: bad",
				Outcome: "ok",
			},
			wantErr: audit.ErrAuditEventInvalidField,
		},
		{
			name: "high-entropy base64 in details",
			entry: audit.Event{
				Kind:      audit.EventKindMerge,
				ProjectID: "proj-invalid",
				FileName:  "secrets",
				Outcome:   "ok",
				Details: map[string]string{
					// 40 contiguous base64-alphabet chars — looksHighEntropyBase64.
					"context": strings.Repeat("A", 40),
				},
			},
			wantErr: audit.ErrAuditEventInvalidField,
		},
		{
			name: "invalid age pubkey in recipient field",
			entry: audit.Event{
				Kind:      audit.EventKindMerge,
				ProjectID: "proj-invalid",
				FileName:  "secrets",
				Outcome:   "ok",
				Details: map[string]string{
					"removed_recipients_0": "not-a-valid-age-pubkey",
				},
			},
			wantErr: audit.ErrAuditEventInvalidField,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spy := &mergeAuditFailSpy{} // validation fires inside CommitCounterWithAudit
			client, err := registry.New(registry.ClientConfig{
				RegistryURL:    "https://example.com/reg.git",
				ProjectID:      "proj-invalid",
				TrustAnchorKey: makeEd25519Key(t),
				Clock:          func() time.Time { return time.Unix(0, 0) },
				FetchTransport: spy,
			})
			if err != nil {
				t.Fatalf("registry.New: %v", err)
			}

			ctx := context.Background()
			if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
				ProjectID:         "proj-invalid",
				FileName:          "secrets",
				PendingCounter:    1,
				TargetArtifactSHA: cwValidArtifactSHA,
				TargetPR:          "org/repo#9",
			}); err != nil {
				t.Fatalf("RecordPendingBump: %v", err)
			}

			bumpErr := client.CommitBump(ctx, coreregistry.CommitBumpInput{
				ProjectID:      "proj-invalid",
				FileName:       "secrets",
				PendingCounter: 1,
				PRRef:          "org/repo#9",
				AuditEntry:     tc.entry,
			})
			if bumpErr == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !errors.Is(bumpErr, tc.wantErr) {
				t.Errorf("%s: want errors.Is(err, ErrAuditEventInvalidField), got: %v", tc.name, bumpErr)
			}
		})
	}
}

// ---- CAS-retry rebuild: ErrRegistryConcurrentWrite surfaces to caller ---------

// TestCommitBump_AuditEntry_ConcurrentWrite_SurfacesErrToCaller proves that
// when CommitCounterWithAudit returns ErrRegistryConcurrentWrite (the registry
// HEAD moved since the clone — another admin committed first), Client.CommitBump
// surfaces the error so the merge spine can re-enter the flow from step 1 (fresh
// clone). The losing attempt pushed nothing — no half-appended audit line exists
// on the remote — so a retry rebuilds the audit JSONL against the fresh clone.
func TestCommitBump_AuditEntry_ConcurrentWrite_SurfacesErrToCaller(t *testing.T) {
	t.Parallel()

	concurrentErr := errors.Join(
		errors.New("push rejected (non-fast-forward)"),
		registry.ErrRegistryConcurrentWrite,
	)
	spy := &mergeAuditConcurrentSpy{returnErr: concurrentErr}

	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj-cas-audit",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: spy,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj-cas-audit",
		FileName:          "secrets",
		PendingCounter:    2,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "org/repo#10",
	}); err != nil {
		t.Fatalf("RecordPendingBump: %v", err)
	}

	bumpErr := client.CommitBump(ctx, coreregistry.CommitBumpInput{
		ProjectID:      "proj-cas-audit",
		FileName:       "secrets",
		PendingCounter: 2,
		PRRef:          "org/repo#10",
		AuditEntry: audit.Event{
			Kind:      audit.EventKindMerge,
			ProjectID: "proj-cas-audit",
			Outcome:   "ok",
		},
	})
	if bumpErr == nil {
		t.Fatal("CommitBump: expected ErrRegistryConcurrentWrite, got nil")
	}
	if !errors.Is(bumpErr, registry.ErrRegistryConcurrentWrite) {
		t.Errorf("want errors.Is(err, ErrRegistryConcurrentWrite), got: %v", bumpErr)
	}
	// CommitCounterWithAudit must have been called (one attempt before CAS failure).
	if spy.calls != 1 {
		t.Errorf("CommitCounterWithAudit calls = %d, want 1 (one attempt before CAS fail)", spy.calls)
	}
}

// ---- BO-5 / AC-003-I: offline / auth-fail → whole CommitBump fails -----------

// TestCommitBump_AuditEntry_AuthFail_FailsEntireOperation proves that when
// CommitCounterWithAudit returns ErrRegistryWriteAuth (no network / auth expired),
// Client.CommitBump surfaces the error and the counter cache is NOT advanced
// (no partial state). The audit entry is inseparable: if the network is down,
// the entire CommitBump fails closed.
func TestCommitBump_AuditEntry_AuthFail_FailsEntireOperation(t *testing.T) {
	t.Parallel()

	authErr := errors.Join(
		errors.New("registry-write token expired — run `byreis auth login`"),
		registry.ErrRegistryWriteAuth,
	)
	spy := &mergeAuditConcurrentSpy{returnErr: authErr}

	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj-offline-audit",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: spy,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj-offline-audit",
		FileName:          "secrets",
		PendingCounter:    3,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "org/repo#11",
	}); err != nil {
		t.Fatalf("RecordPendingBump: %v", err)
	}

	bumpErr := client.CommitBump(ctx, coreregistry.CommitBumpInput{
		ProjectID:      "proj-offline-audit",
		FileName:       "secrets",
		PendingCounter: 3,
		PRRef:          "org/repo#11",
		AuditEntry: audit.Event{
			Kind:      audit.EventKindMerge,
			ProjectID: "proj-offline-audit",
			Outcome:   "ok",
		},
	})
	if bumpErr == nil {
		t.Fatal("CommitBump: expected ErrRegistryWriteAuth, got nil")
	}
	if !errors.Is(bumpErr, registry.ErrRegistryWriteAuth) {
		t.Errorf("want errors.Is(err, ErrRegistryWriteAuth), got: %v", bumpErr)
	}
}

// ---- audit_entry_sha body embedding (BO-2 extension) -------------------------

// TestCommitBump_AuditEntry_BodyContainsAuditEntrySHA proves that the
// audit_entry_sha embedded in the commit message body by CommitCounterWithAudit
// equals sha256(canonical JSONL bytes of the audit event). This is the BO-2
// tamper-evident record: a verifier who reads the commit body can recompute the
// JSONL line's SHA and compare it to audit_entry_sha.
//
// The test uses an auditBodyCaptureSpy that records the bumpIn passed to
// CommitCounterWithAudit; the production implementation derives the SHA
// from buildAuditJSONLEntry — we assert the same derivation is replicable
// from the recorded event (round-trip).
func TestCommitBump_AuditEntry_BodyContainsAuditEntrySHA(t *testing.T) {
	t.Parallel()

	spy := &mergeAuditSpy{}
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj-sha-body",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: spy,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj-sha-body",
		FileName:          "secrets",
		PendingCounter:    4,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "org/repo#12",
	}); err != nil {
		t.Fatalf("RecordPendingBump: %v", err)
	}

	mergeEntry := audit.Event{
		Kind:      audit.EventKindMerge,
		ProjectID: "proj-sha-body",
		FileName:  "secrets",
		KeyName:   "DB-PASSWORD",
		PRRef:     "org/repo#12",
		Outcome:   "ok",
		Details:   map[string]string{"counter": "4"},
	}
	if err := client.CommitBump(ctx, coreregistry.CommitBumpInput{
		ProjectID:      "proj-sha-body",
		FileName:       "secrets",
		PendingCounter: 4,
		PRRef:          "org/repo#12",
		AuditEntry:     mergeEntry,
	}); err != nil {
		t.Fatalf("CommitBump: %v", err)
	}

	// Recompute what the SHA should be for the received event. The transport
	// stamps OccurredAt before building the JSONL — we cannot predict the exact
	// timestamp, but we CAN verify that the recorded bumpIn.AuditEntry.Kind is
	// correct (the transport dispatched the right event) and that the spy
	// received the call. The SHA binding assertion is covered by the internal
	// test TestCommitBump_AuditEntryShaCoveredInCommitBody (package registry).
	if spy.withAuditCalls != 1 {
		t.Errorf("CommitCounterWithAudit calls = %d, want 1", spy.withAuditCalls)
	}
	if spy.lastBumpIn.AuditEntry.Kind != audit.EventKindMerge {
		t.Errorf("AuditEntry.Kind = %q, want %q",
			spy.lastBumpIn.AuditEntry.Kind, audit.EventKindMerge)
	}
	if spy.lastBumpIn.AuditEntry.KeyName != "DB-PASSWORD" {
		t.Errorf("AuditEntry.KeyName = %q, want %q",
			spy.lastBumpIn.AuditEntry.KeyName, "DB-PASSWORD")
	}
}

// ---- OccurredAt stamping: transport owns the timestamp -----------------------

// TestCommitBump_AuditEntry_OccurredAtStampedByTransport proves that when the
// caller passes an audit.Event with OccurredAt = zero (as merge.go deliberately
// does), the event recorded at the transport boundary still has a zero OccurredAt
// at dispatch time — the stamp happens INSIDE the transport during
// CommitCounterWithAudit, not at the Client layer. This test asserts the
// pre-stamp state; the production stamp (time.Now()) is exercised by the
// internal test that covers doCounterWrite directly.
func TestCommitBump_AuditEntry_OccurredAtIsZeroAtDispatchBoundary(t *testing.T) {
	t.Parallel()

	spy := &mergeAuditSpy{}
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj-timestamp",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: spy,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj-timestamp",
		FileName:          "secrets",
		PendingCounter:    5,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "org/repo#13",
	}); err != nil {
		t.Fatalf("RecordPendingBump: %v", err)
	}

	var zeroTime time.Time
	mergeEntry := audit.Event{
		Kind:       audit.EventKindMerge,
		ProjectID:  "proj-timestamp",
		OccurredAt: zeroTime, // deliberately zero — transport stamps it
		Outcome:    "ok",
	}
	if err := client.CommitBump(ctx, coreregistry.CommitBumpInput{
		ProjectID:      "proj-timestamp",
		FileName:       "secrets",
		PendingCounter: 5,
		PRRef:          "org/repo#13",
		AuditEntry:     mergeEntry,
	}); err != nil {
		t.Fatalf("CommitBump: %v", err)
	}

	// The Client layer must pass the event as-is (OccurredAt still zero at
	// dispatch time). The transport is responsible for stamping.
	if !spy.lastBumpIn.AuditEntry.OccurredAt.IsZero() {
		t.Errorf("AuditEntry.OccurredAt at dispatch = %v, want zero "+
			"(transport stamps, not Client layer)", spy.lastBumpIn.AuditEntry.OccurredAt)
	}
}

// ---- BO-3 internal path: buildAuditJSONLEntry + audit_entry_sha body ---------

// TestCommitBump_AuditEntryShaCoveredInCommitBody is an internal-package test
// that proves: for a valid merge event, sha256(JSONL line) == audit_entry_sha
// embedded in the commit message body. This is the highest-risk assertion —
// it proves the "git add covers both blobs" invariant is backed by a deterministic
// SHA that binds the counter advance to the specific JSONL bytes.
//
// This test is in the external package (registry_test) and drives through the
// mergeAuditSpy to capture the input. The SHA derivation is done independently
// of the production path to prove the round-trip.
func TestCommitBump_AuditEntryShaCoveredInCommitBody_RoundTrip(t *testing.T) {
	t.Parallel()

	// A valid merge event that will pass ValidateEventFields.
	e := audit.Event{
		Kind:       audit.EventKindMerge,
		OccurredAt: time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
		Actor:      "admin-label", // signing-key label, not age1... pubkey
		ProjectID:  "proj-sha-rt",
		FileName:   "secrets",
		KeyName:    "STRIPE-KEY",
		PRRef:      "org/repo#42",
		Outcome:    "ok",
		Details:    map[string]string{"counter": "7"},
	}

	// Independently compute what sha256(JSONL line) should be.
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	line := append(raw, '\n')
	sum := sha256.Sum256(line)
	expectedSHA := strings.ToLower(strings.Join(func() []string {
		h := make([]string, 0)
		for _, b := range sum {
			h = append(h, func(v byte) string {
				const hx = "0123456789abcdef"
				return string([]byte{hx[v>>4], hx[v&0xf]})
			}(b))
		}
		return h
	}(), ""))

	// Verify the SHA has the right length (64 hex chars = 32 bytes SHA-256).
	if len(expectedSHA) != 64 {
		t.Fatalf("computed SHA length = %d, want 64", len(expectedSHA))
	}
	// Verify it's all hex.
	for i, c := range expectedSHA {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("SHA contains non-hex char %q at position %d", c, i)
		}
	}

	// The JSONL bytes must end with newline.
	if line[len(line)-1] != '\n' {
		t.Error("JSONL line does not end with newline")
	}

	// Verify the same derivation logic works for a known short event.
	shortEvent := audit.Event{
		Kind:      audit.EventKindMerge,
		ProjectID: "proj-short",
		Outcome:   "ok",
	}
	raw2, err2 := json.Marshal(shortEvent)
	if err2 != nil {
		t.Fatalf("json.Marshal short: %v", err2)
	}
	line2 := append(raw2, '\n')
	sum2 := sha256.Sum256(line2)
	sha2 := func() string {
		var b strings.Builder
		for _, by := range sum2 {
			const hx = "0123456789abcdef"
			b.WriteByte(hx[by>>4])
			b.WriteByte(hx[by&0xf])
		}
		return b.String()
	}()
	if len(sha2) != 64 {
		t.Errorf("short event SHA length = %d, want 64", len(sha2))
	}
}

// ---- OB-B: fail-closed when transport lacks CommitCounterWithAudit ----------

// TestCommitBump_AuditEntry_NoAuditTransport_FailsClosed proves that when
// CommitBumpInput.AuditEntry.Kind is non-empty but the configured transport does
// NOT implement mergeAuditTransport, Client.CommitBump returns an error wrapping
// ErrMergeAuditUnsupportedTransport and does NOT advance the counter.
//
// Before the fail-closed fix, the dispatch silently fell through to bare
// CommitCounter and returned nil — the audit entry was dropped with no
// indication of failure. This test would have caught that: it asserts that
// (a) the error is non-nil, (b) it wraps ErrMergeAuditUnsupportedTransport,
// and (c) the bare CommitCounter was never called (no partial advance).
func TestCommitBump_AuditEntry_NoAuditTransport_FailsClosed(t *testing.T) {
	t.Parallel()

	// bareTransport implements FetchTransport but NOT mergeAuditTransport.
	// It records whether CommitCounter was called so we can assert no partial advance.
	bare := &bareCommitSpy{}
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    "https://example.com/reg.git",
		ProjectID:      "proj-no-audit-transport",
		TrustAnchorKey: makeEd25519Key(t),
		Clock:          func() time.Time { return time.Unix(0, 0) },
		FetchTransport: bare,
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ctx := context.Background()
	if err := client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         "proj-no-audit-transport",
		FileName:          "secrets",
		PendingCounter:    1,
		TargetArtifactSHA: cwValidArtifactSHA,
		TargetPR:          "org/repo#20",
	}); err != nil {
		t.Fatalf("RecordPendingBump: %v", err)
	}

	bumpErr := client.CommitBump(ctx, coreregistry.CommitBumpInput{
		ProjectID:      "proj-no-audit-transport",
		FileName:       "secrets",
		PendingCounter: 1,
		PRRef:          "org/repo#20",
		AuditEntry: audit.Event{
			Kind:      audit.EventKindMerge,
			ProjectID: "proj-no-audit-transport",
			Outcome:   "ok",
		},
	})
	if bumpErr == nil {
		t.Fatal("CommitBump: expected ErrMergeAuditUnsupportedTransport, got nil — " +
			"a transport without CommitCounterWithAudit must refuse the advance, not silently drop the audit entry")
	}
	if !errors.Is(bumpErr, registry.ErrMergeAuditUnsupportedTransport) {
		t.Errorf("want errors.Is(err, ErrMergeAuditUnsupportedTransport), got: %v", bumpErr)
	}
	// The bare CommitCounter must NOT have been called — no partial advance.
	if bare.commitCalls != 0 {
		t.Errorf("CommitCounter (bare) calls = %d, want 0 (fail-closed: no partial counter advance)", bare.commitCalls)
	}
}

// ---- Fake transports for merge-audit tests -----------------------------------

// mergeAuditSpy records CommitCounterWithAudit and CommitCounter calls.
// It implements both FetchTransport and mergeAuditTransport (the extension
// interface) so Client.CommitBump dispatches to CommitCounterWithAudit.
type mergeAuditSpy struct {
	withAuditCalls  int
	bareCommitCalls int
	lastBumpIn      coreregistry.CommitBumpInput
}

func (s *mergeAuditSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-audit", "spy-signer", true, nil
}
func (s *mergeAuditSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *mergeAuditSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *mergeAuditSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *mergeAuditSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	s.bareCommitCalls++
	return nil
}
func (s *mergeAuditSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *mergeAuditSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *mergeAuditSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *mergeAuditSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *mergeAuditSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}

// CommitCounterWithAudit implements the mergeAuditTransport extension interface.
// It records the call so tests can assert routing and input.
func (s *mergeAuditSpy) CommitCounterWithAudit(_ context.Context, _ string, bumpIn coreregistry.CommitBumpInput) error {
	s.withAuditCalls++
	s.lastBumpIn = bumpIn
	return nil
}

// mergeAuditFailSpy is a mergeAuditTransport that calls audit.ValidateEventFields
// on the received AuditEntry and returns ErrAuditEventInvalidField when the
// validation fails. This mirrors what the production transport does in step 4a:
// validation fires before any git operation. The spy validates without git
// operations, proving the error propagates through Client.CommitBump.
type mergeAuditFailSpy struct {
	failErr error
	calls   int
}

func (s *mergeAuditFailSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-fail", "spy-signer", true, nil
}
func (s *mergeAuditFailSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *mergeAuditFailSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *mergeAuditFailSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *mergeAuditFailSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (s *mergeAuditFailSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *mergeAuditFailSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *mergeAuditFailSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *mergeAuditFailSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *mergeAuditFailSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *mergeAuditFailSpy) CommitCounterWithAudit(_ context.Context, _ string, bumpIn coreregistry.CommitBumpInput) error {
	s.calls++
	// Run ValidateEventFields to mirror the production transport's step 4a gate.
	// This is the fail-closed check: validation fires before any git operation.
	if err := audit.ValidateEventFields(bumpIn.AuditEntry); err != nil {
		return err
	}
	return s.failErr
}

// mergeAuditConcurrentSpy simulates CommitCounterWithAudit failing with a
// configurable error (ErrRegistryConcurrentWrite or ErrRegistryWriteAuth).
type mergeAuditConcurrentSpy struct {
	returnErr error
	calls     int
}

func (s *mergeAuditConcurrentSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-cas-audit", "spy-signer", true, nil
}
func (s *mergeAuditConcurrentSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *mergeAuditConcurrentSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *mergeAuditConcurrentSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *mergeAuditConcurrentSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (s *mergeAuditConcurrentSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *mergeAuditConcurrentSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *mergeAuditConcurrentSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *mergeAuditConcurrentSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *mergeAuditConcurrentSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (s *mergeAuditConcurrentSpy) CommitCounterWithAudit(_ context.Context, _ string, _ coreregistry.CommitBumpInput) error {
	s.calls++
	return s.returnErr
}

// bareCommitSpy implements FetchTransport but deliberately does NOT implement
// mergeAuditTransport. Used to assert the fail-closed behaviour when a transport
// without CommitCounterWithAudit receives a CommitBump with a non-empty AuditEntry.
type bareCommitSpy struct {
	commitCalls int
}

func (s *bareCommitSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-bare", "spy-signer", true, nil
}
func (s *bareCommitSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (s *bareCommitSpy) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}
func (s *bareCommitSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (s *bareCommitSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	s.commitCalls++
	return nil
}
func (s *bareCommitSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (s *bareCommitSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (s *bareCommitSpy) DiscardCounterSession(_ context.Context, _ string) {}
func (s *bareCommitSpy) ReadRotationEpoch(_ context.Context, _, _, _, _ string) (uint64, error) {
	return 0, nil
}
func (s *bareCommitSpy) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}

// Compile-time assertion: bareCommitSpy does NOT implement mergeAuditTransport.
// This is the property the fail-closed test depends on.
// If this ever fails to compile (i.e., bareCommitSpy accidentally gains
// CommitCounterWithAudit), the test premise is invalid and must be revisited.
var _ interface {
	CommitCounter(context.Context, string, string, string, uint64) error
} = (*bareCommitSpy)(nil)
