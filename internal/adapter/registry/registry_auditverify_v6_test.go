package registry_test

// V0.6 adapter-internal behavioral guards for the audit verifier.
//
// S3-rewire:
//   - Parser-fabricated rows ("malformed-line", "truncated") carry Synthetic=true,
//     Unknown=true, BindingMissing, confirming the parse site sets the typed field.
//   - A valid-JSON row with an unrecognised kind (Unknown=true) carries
//     Synthetic=false, confirming the orthogonality invariant (Unknown != Synthetic).
//   - A content edit to an Unknown=true row is still caught as BindingTampered /
//     ErrAuditLogTampered: the tamper-evasion path (treating Unknown as synthetic to
//     skip hash check) stays closed after the isSyntheticRow rewrite.
//
// S4 fail-closed:
//   - The determinable exact-set splice check (v0.5 allowlist) still fires correctly
//     when the staged-file set is available: the S4 change does not regress the
//     determinable case.
//   - The undeterminable-staged-set fail-closed path is asserted directly in
//     registry_auditverify_v6internal_test.go (package registry) which can call
//     bindLines with a fabricated StagedFilesUndeterminable=true commit.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ---- S3: Synthetic field set at parse time -----------------------------------

// TestS3_SyntheticField_MalformedLine verifies that a genuinely malformed JSONL
// line (non-parseable bytes) produces a row with Synthetic=true and Unknown=true.
// The parse site must set the typed Synthetic field, not leave it at the zero value
// for isSyntheticRow to infer from the Kind string.
func TestS3_SyntheticField_MalformedLine(t *testing.T) {
	t.Parallel()

	malformed := []byte("not valid json\n")
	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: malformed,
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 row, got %d", len(entries))
	}
	row := entries[0]
	if row.Kind != "malformed-line" {
		t.Errorf("row.Kind = %q, want %q", row.Kind, "malformed-line")
	}
	if !row.Unknown {
		t.Errorf("malformed-line row must have Unknown=true")
	}
	if !row.Synthetic {
		t.Errorf("malformed-line row must have Synthetic=true — parse site must set the typed field")
	}
	if row.BindingStatus != rotate.BindingMissing {
		t.Errorf("malformed-line row BindingStatus = %v, want BindingMissing", row.BindingStatus)
	}
}

// TestS3_SyntheticField_Truncated verifies that the truncation-advisory row
// emitted when the entry count exceeds the cap carries Synthetic=true and Unknown=true.
func TestS3_SyntheticField_Truncated(t *testing.T) {
	t.Parallel()

	const overCount = 1002 // exceeds maxAuditResultCount (1000)
	var buf []byte
	for i := 0; i < overCount; i++ {
		e := audit.Event{
			Kind:       audit.EventKindRotation,
			OccurredAt: time.Date(2026, 1, 1, 0, 0, i%60, 0, time.UTC),
			Actor:      fmt.Sprintf("admin-%d", i),
			ProjectID:  "proj",
			Outcome:    "ok",
		}
		raw, _ := json.Marshal(e)
		buf = append(buf, append(raw, '\n')...)
	}

	ft := &auditFakeTransport{
		headCommit: "aabbccddaabbccddaabbccddaabbccddaabbccdd",
		verified:   true,
		auditBytes: buf,
	}
	c := newAuditTestClient(ft)

	entries, err := c.FetchAuditLog(context.Background(), "proj")
	if err != nil {
		t.Fatalf("FetchAuditLog: unexpected error: %v", err)
	}
	// maxAuditResultCount entries + 1 advisory.
	if len(entries) != 1001 {
		t.Fatalf("want 1001 entries (1000 tail + advisory), got %d", len(entries))
	}
	advisory := entries[0]
	if advisory.Kind != "truncated" {
		t.Errorf("advisory.Kind = %q, want %q", advisory.Kind, "truncated")
	}
	if !advisory.Unknown {
		t.Errorf("truncated advisory must have Unknown=true")
	}
	if !advisory.Synthetic {
		t.Errorf("truncated advisory must have Synthetic=true — parse site must set the typed field")
	}
	if advisory.BindingStatus != rotate.BindingMissing {
		t.Errorf("truncated advisory BindingStatus = %v, want BindingMissing", advisory.BindingStatus)
	}
}

// TestS3_UnknownKind_NotSynthetic verifies that a valid-JSON row with an
// unrecognised Kind carries Unknown=true but Synthetic=false. This confirms the
// orthogonality invariant: Unknown is a forward-compat display hint for a line
// that decoded successfully; Synthetic is the parser-fabricated-row marker. The
// two are disjoint. An Unknown row must remain in the binding walk.
func TestS3_UnknownKind_NotSynthetic(t *testing.T) {
	t.Parallel()

	evt := audit.Event{
		Kind:       audit.EventKind("future.v99.unknown_kind"),
		OccurredAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		Actor:      "admin",
		ProjectID:  "proj",
		Outcome:    "ok",
	}
	raw, _ := json.Marshal(evt)
	jsonl := append(raw, '\n')

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
	row := entries[0]
	if !row.Unknown {
		t.Errorf("unknown-kind row must have Unknown=true")
	}
	if row.Synthetic {
		t.Errorf("unknown-kind row must have Synthetic=false — it decoded successfully and must stay in the binding walk")
	}
}

// ---- S3: Unknown row stays hash-verified (tamper-evasion closed) -------------

// TestS3_UnknownKindRow_ContentEditCaughtAsTamper builds a 2-event signed
// git history where the second event uses an unrecognised kind. A content edit
// to that row must still be caught as BindingTampered / ErrAuditLogTampered.
//
// This guards the tamper-evasion invariant after the isSyntheticRow rewrite:
// with the old Kind-string check, isSyntheticRow returned false for Unknown rows
// (correct); with the new Synthetic-field check it also returns false for Unknown
// rows (Synthetic=false), so the behaviour is preserved. This test confirms the
// preservation is behavioral, not just structural.
func TestS3_UnknownKindRow_ContentEditCaughtAsTamper(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}

	const projectID = "s3-unknown-tamper"

	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)
	ev0 := audit.Event{
		Kind:       audit.EventKindMerge,
		OccurredAt: base,
		Actor:      "admin",
		ProjectID:  projectID,
		Outcome:    "ok",
	}
	// ev1 uses a future-unknown kind: its row will have Unknown=true, Synthetic=false.
	ev1 := audit.Event{
		Kind:       audit.EventKind("future.v99.unknown_for_s3"),
		OccurredAt: base.Add(time.Minute),
		Actor:      "admin",
		ProjectID:  projectID,
		Outcome:    "ok",
	}

	history := newSignedAuditHistory(t, projectID, []audit.Event{ev0, ev1})
	repoDir := repoPathFromURL(history.RepoURL)

	// Read the 2-line blob and flip one byte in the second line (the unknown-kind
	// row). The signed commit body still carries the original sha — the content
	// edit must be detected via hash mismatch, not silently skipped because
	// Unknown=true was mistakenly treated as synthetic.
	blob := currentAuditBlob(t, repoDir, projectID)
	lines := splitJSONLLines(blob)
	if len(lines) != 2 {
		t.Fatalf("S3: expected 2 JSONL lines, got %d", len(lines))
	}
	// Flip one byte inside the second line (the unknown-kind row, index 5 is
	// safely inside the JSON object after the opening brace).
	line1 := make([]byte, len(lines[1]))
	copy(line1, lines[1])
	line1[5] ^= 0x01
	mutated := append(lines[0], line1...)

	writeAndAmendLastCommit(t, repoDir, projectID, mutated)

	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	assertTamperedResult(t, "S3/UnknownKind/ContentEdit", result, err)
}

// ---- S4: determinable splice check still fires (v0.5 behavior intact) --------

// TestS4_DeterminableSpliceBehaviorIntact verifies that the v0.5 exact-set
// splice-check (allowlist rule) still catches a real splice when the
// staged-file set IS determinable. This confirms the S4 change (adding the
// undeterminable fail-closed path BEFORE the existing splice check) does not
// regress the determinable case.
func TestS4_DeterminableSpliceBehaviorIntact(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}

	const (
		mainProject  = "s4-splice-main"
		otherProject = "s4-splice-other"
	)

	events := buildTestAuditEvents(mainProject)[:1]
	history := newSignedAuditHistory(t, mainProject, events)
	repoDir := repoPathFromURL(history.RepoURL)

	// Build the second event for the main project and a line for another project.
	secondEvent := buildTestAuditEvents(mainProject)[1]
	secondLine, secondEntrySHA := buildCommittableJSONLLine(t, secondEvent)

	otherAuditPath := filepath.Join(repoDir, "audit", otherProject+".jsonl")
	otherLine := fmt.Sprintf(
		`{"kind":"merge","occurred_at":"2026-05-27T10:00:00Z","actor":"splice","project_id":%q,"outcome":"ok"}`,
		otherProject,
	) + "\n"
	if err := os.WriteFile(otherAuditPath, []byte(otherLine), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("S4: write other audit file: %v", err)
	}

	mainAuditPath := filepath.Join(repoDir, "audit", mainProject+".jsonl")
	f, err := os.OpenFile(mainAuditPath, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("S4: open main audit file: %v", err)
	}
	if _, wErr := f.Write(secondLine); wErr != nil {
		_ = f.Close()
		t.Fatalf("S4: write main audit file: %v", wErr)
	}
	_ = f.Close()

	// Stage BOTH files in one commit: the legitimate audit append AND the other
	// project's file — a cross-project splice.
	gitInRepoFatal(t, repoDir, "add", "--",
		filepath.Join("audit", mainProject+".jsonl"),
		filepath.Join("audit", otherProject+".jsonl"),
	)
	msg := fmt.Sprintf("audit: s4 determinable splice test\n\naudit_entry_sha: %s\n", secondEntrySHA)
	msgFile := filepath.Join(t.TempDir(), "s4-msg.txt")
	if wErr := os.WriteFile(msgFile, []byte(msg), 0o600); wErr != nil { //nolint:gosec // test fixture
		t.Fatalf("S4: write commit msg: %v", wErr)
	}
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile, "-S")

	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, mainProject)
	assertTamperedResult(t, "S4/DeterminableSpliceBehaviorIntact", result, err)
}
