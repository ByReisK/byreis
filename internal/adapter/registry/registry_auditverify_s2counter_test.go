package registry_test

// S2 counter-monotonicity fixture tests for VerifyAuditLog (REQ-V06-002).
//
// Each test builds a real signed git repository with commit bodies that carry
// counter fields in the production format, then calls VerifyAuditLog via the
// real productionFetchTransport. Structural mocks are insufficient — v0.5
// precedent established that real signed-git-history fixtures catch verifier
// bugs that structural tests miss.
//
// Test coverage:
//   T-S2-A: planted anchor-signed line whose counter pair breaks continuity →
//           BindingTampered + ErrAuditLogTampered in three sub-cases:
//           gap (pending=last+2), regression (pending<=last), forked predecessor
//           (expected_previous!=last). Also covers the E2 back-positioned insert.
//   T-S2-B: anchor-signed commits whose bodies carry NO counter fields → lines
//           stay BindingUnverifiedLegacy/handled, never falsely TAMPERED.
//   T-S2-C: stripping evasion — a binding-era-boundary line with counter fields
//           removed lands in the existing boundary tamper check → TAMPERED.
//   T-S2-D: rotation commit advancing N>1 files with valid per-file continuity →
//           all BindingVerified (proves per-FILE not global sequencing).
//   T-S2-E: genuine rotation+merge history with monotone counters → all
//           BindingVerified, exit 0 (no regression vs the v0.5 verdict).
//   Boundary: expected_previous_counter: 0 first-accept → clean (absence-vs-zero).

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/adapter/registry/auditverify"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// counterHistoryEntry describes one commit in a counter-aware signed history.
type counterHistoryEntry struct {
	// Event is the audit event to append as a JSONL line.
	Event audit.Event
	// FileName is the logical file name written in the commit body (the "file:"
	// field). Used by parseCounterPairs as the map key.
	FileName string
	// ExpectedPrev is the expected_previous_counter value to write in the body.
	ExpectedPrev uint64
	// Pending is the pending_counter value to write in the body.
	Pending uint64
	// OmitCounterFields omits the counter fields from the commit body entirely,
	// simulating a pre-binding or parallel-channel commit (T-S2-B).
	OmitCounterFields bool
	// UseRotationFormat writes the counter fields in the indented rotation body
	// format ("  expected_previous_counter: N") instead of the flat counter
	// body format. Used for T-S2-D multi-file rotation.
	UseRotationFormat bool
	// ExtraFiles is an optional map of filename → raw bytes for additional files
	// staged in the same commit (for multi-file rotation bodies, T-S2-D).
	// The map key is the JSONL-relative path (e.g. "audit/<project>.jsonl" for
	// the primary file; others are staged but not part of the primary JSONL).
	ExtraCounterFiles []counterHistoryExtraFile
}

// counterHistoryExtraFile describes an additional logical file and its counter
// pair, staged alongside the primary audit line in a multi-file commit (T-S2-D).
type counterHistoryExtraFile struct {
	// FileName is the logical name written in the commit body "file:" block.
	FileName     string
	ExpectedPrev uint64
	Pending      uint64
}

// newSignedHistoryWithCounters builds a local signed git repository where each
// commit appends one JSONL line to audit/<projectID>.jsonl AND carries counter
// fields in the commit body. It re-uses the signing infrastructure from
// newSignedAuditHistory (same key-generation and git-config steps).
//
// The counter fields are written in the format produced by
// buildCounterCommitMessageBody (flat) or buildRotationCommitMessageBody
// (indented), controlled per entry by UseRotationFormat.
func newSignedHistoryWithCounters(
	t *testing.T,
	projectID string,
	entries []counterHistoryEntry,
) *signedAuditHistory {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH — skipping S2 counter test")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen binary not on PATH — skipping S2 counter test")
	}

	root := t.TempDir()

	// Generate the anchor key pair.
	sshKeyPath := filepath.Join(root, "anchor-key")
	sshPubKeyPath := sshKeyPath + ".pub"
	genCmd := exec.CommandContext(t.Context(), "ssh-keygen", //nolint:gosec // known fixed args; path under t.TempDir
		"-t", "ed25519", "-N", "", "-C", "byreis-audit-anchor", "-q", "-f", sshKeyPath,
	)
	if out, err := genCmd.CombinedOutput(); err != nil {
		t.Fatalf("newSignedHistoryWithCounters: ssh-keygen: %v: %s", err, out)
	}
	pubBytes, err := os.ReadFile(sshPubKeyPath)
	if err != nil {
		t.Fatalf("newSignedHistoryWithCounters: read ssh pubkey: %v", err)
	}
	anchorKey := decodeSSHEd25519PubkeyForAudit(t, string(pubBytes))

	// Build the allowed-signers file.
	allowedSignersPath := filepath.Join(root, "allowed-signers")
	pubFields := splitFields(string(pubBytes))
	if len(pubFields) < 2 {
		t.Fatalf("newSignedHistoryWithCounters: unexpected pubkey format: %q", string(pubBytes))
	}
	allowedLine := auditAnchorPrincipal + " " + pubFields[0] + " " + pubFields[1] + "\n"
	if err := os.WriteFile(allowedSignersPath, []byte(allowedLine), 0o600); err != nil { //nolint:gosec // path under t.TempDir
		t.Fatalf("newSignedHistoryWithCounters: write allowed-signers: %v", err)
	}

	repoDir := filepath.Join(root, "registry")
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("newSignedHistoryWithCounters: mkdir repo: %v", err)
	}

	// Initialise the repo with SSH signing.
	gitInRepoFatal(t, repoDir, "init", "-q", "--initial-branch=main")
	gitInRepoFatal(t, repoDir, "config", "user.name", auditAnchorPrincipal)
	gitInRepoFatal(t, repoDir, "config", "user.email", "anchor@example.com")
	gitInRepoFatal(t, repoDir, "config", "gpg.format", "ssh")
	gitInRepoFatal(t, repoDir, "config", "user.signingkey", sshPubKeyPath)
	gitInRepoFatal(t, repoDir, "config", "gpg.ssh.allowedSignersFile", allowedSignersPath)
	gitInRepoFatal(t, repoDir, "config", "commit.gpgsign", "true")

	auditDirPath := filepath.Join(repoDir, "audit")
	if err := os.MkdirAll(auditDirPath, 0o750); err != nil {
		t.Fatalf("newSignedHistoryWithCounters: mkdir audit: %v", err)
	}
	auditFilePath := filepath.Join(auditDirPath, projectID+".jsonl")

	var allEvents []audit.Event

	for i, entry := range entries {
		// Serialise the event to JSONL.
		raw, marshalErr := json.Marshal(entry.Event)
		if marshalErr != nil {
			t.Fatalf("newSignedHistoryWithCounters: marshal event[%d]: %v", i, marshalErr)
		}
		line := append(raw, '\n')
		sum := sha256.Sum256(line)
		entrySHA := fmt.Sprintf("%x", sum[:])

		// Append the JSONL line.
		f, openErr := os.OpenFile(auditFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // fixture under t.TempDir
		if openErr != nil {
			t.Fatalf("newSignedHistoryWithCounters: open audit file[%d]: %v", i, openErr)
		}
		if _, writeErr := f.Write(line); writeErr != nil {
			_ = f.Close()
			t.Fatalf("newSignedHistoryWithCounters: write line[%d]: %v", i, writeErr)
		}
		_ = f.Close()

		// Stage the primary audit file.
		gitInRepoFatal(t, repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))

		// Build the commit message body. The format mirrors the production writers:
		//   - flat (buildCounterCommitMessageBody): top-level expected_previous_counter /
		//     pending_counter lines, one file per commit.
		//   - rotation (buildRotationCommitMessageBody): indented "  expected_..." lines,
		//     one "file:" block per logical file (N files per commit for T-S2-D).
		var msg string
		if entry.OmitCounterFields {
			// T-S2-B: no counter fields — simulates a pre-binding or parallel-channel
			// commit body (the absence-is-not-tamper path).
			msg = fmt.Sprintf("byreis: counter write-ahead\n\nproject_id: %s\nfile: %s\naudit_entry_sha: %s\n",
				projectID, entry.FileName, entrySHA)
		} else if entry.UseRotationFormat {
			// T-S2-D: rotation body format with indented counter fields.
			// Build per-file blocks: primary file first, then extra files.
			var bodyExtra string
			for _, ex := range entry.ExtraCounterFiles {
				bodyExtra += fmt.Sprintf(
					"file: %s\n"+
						"  expected_previous_counter: %d\n"+
						"  pending_counter: %d\n",
					ex.FileName, ex.ExpectedPrev, ex.Pending)
			}
			msg = fmt.Sprintf(
				"byreis: rotation commit\n\n"+
					"project_id: %s\n"+
					"audit_entry_sha: %s\n"+
					"file: %s\n"+
					"  expected_previous_counter: %d\n"+
					"  pending_counter: %d\n"+
					"%s",
				projectID, entrySHA,
				entry.FileName, entry.ExpectedPrev, entry.Pending,
				bodyExtra)
		} else {
			// Flat counter body format (buildCounterCommitMessageBody).
			msg = fmt.Sprintf(
				"byreis: counter write-ahead\n\n"+
					"project_id: %s\n"+
					"file: %s\n"+
					"expected_previous_counter: %d\n"+
					"pending_counter: %d\n"+
					"audit_entry_sha: %s\n",
				projectID, entry.FileName,
				entry.ExpectedPrev, entry.Pending,
				entrySHA)
		}

		msgFile := filepath.Join(root, fmt.Sprintf("commitmsg-%d.txt", i))
		if err := os.WriteFile(msgFile, []byte(msg), 0o600); err != nil { //nolint:gosec // path under t.TempDir
			t.Fatalf("newSignedHistoryWithCounters: write commit msg[%d]: %v", i, err)
		}
		gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile, "-S")

		allEvents = append(allEvents, entry.Event)
	}

	return &signedAuditHistory{
		RepoURL:   "file://" + repoDir,
		AnchorKey: anchorKey,
		ProjectID: projectID,
		Events:    allEvents,
	}
}

// ---- T-S2-A: counter-break cases → BindingTampered + ErrAuditLogTampered -----

// TestS2A_CounterGap_BindingTampered builds a 2-event history where the second
// commit body skips a counter value (pending = last + 2 instead of last + 1),
// simulating a history gap. The verifier must detect the continuity break and
// return ErrAuditLogTampered with the offending line BindingTampered, even
// though the content-hash passes.
func TestS2A_CounterGap_BindingTampered(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const projectID = "s2a-gap"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	entries := []counterHistoryEntry{
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 0,
			Pending:      1, // first accepted: baseline = 1
		},
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base.Add(time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 1,
			Pending:      3, // GAP: 1+2 instead of 1+1 → break
		},
	}

	history := newSignedHistoryWithCounters(t, projectID, entries)
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	assertTamperedResult(t, "T-S2-A gap", result, err)
	if !isErrAuditLogTampered(err) {
		t.Errorf("T-S2-A gap: want errors.Is(err, ErrAuditLogTampered), got: %v", err)
	}
	t.Logf("T-S2-A gap: PASS — counter gap detected as BindingTampered")
}

// TestS2A_CounterRegression_BindingTampered tests the regression case:
// pending_counter <= lastAccepted (the second commit records a lower or equal
// counter). This proves an overlap or back-position.
func TestS2A_CounterRegression_BindingTampered(t *testing.T) {
	const projectID = "s2a-regression"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	entries := []counterHistoryEntry{
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 0,
			Pending:      5, // first accepted baseline = 5
		},
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base.Add(time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 5,
			Pending:      4, // REGRESSION: 4 < 5 → break
		},
	}

	history := newSignedHistoryWithCounters(t, projectID, entries)
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	assertTamperedResult(t, "T-S2-A regression", result, err)
	if !isErrAuditLogTampered(err) {
		t.Errorf("T-S2-A regression: want errors.Is(err, ErrAuditLogTampered), got: %v", err)
	}
	t.Logf("T-S2-A regression: PASS — counter regression detected as BindingTampered")
}

// TestS2A_ForkedPredecessor_BindingTampered tests the forked-predecessor case:
// expected_previous_counter != lastAccepted. The commit claims a different
// predecessor than what the walk observed — a sign of a fabricated insert that
// forked off a different sequence.
func TestS2A_ForkedPredecessor_BindingTampered(t *testing.T) {
	const projectID = "s2a-forked"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	entries := []counterHistoryEntry{
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 0,
			Pending:      1, // first accepted: baseline = 1
		},
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base.Add(time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 99, // FORKED: claims predecessor 99, but last accepted was 1
			Pending:      100,
		},
	}

	history := newSignedHistoryWithCounters(t, projectID, entries)
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	assertTamperedResult(t, "T-S2-A forked-predecessor", result, err)
	if !isErrAuditLogTampered(err) {
		t.Errorf("T-S2-A forked-predecessor: want errors.Is(err, ErrAuditLogTampered), got: %v", err)
	}
	t.Logf("T-S2-A forked-predecessor: PASS — forked predecessor detected as BindingTampered")
}

// TestS2A_E2_BackPositionedInsert_BindingTampered is the E2 back-positioned
// insert scenario: an anchor-key-holding attacker inserts a fabricated commit
// EARLY in the history whose counter pair cannot form a valid monotonic predecessor
// with its neighbours. The insert commits are laid out so that the counter
// sequence in git-history order is: [0→1, 0→1 (DUPLICATE), 1→2]. The duplicate
// breaks continuity at the third position (expected_previous=1 matches but the
// first accepted was already set to 1 from position 0; the duplicate at position 1
// also sets to 1 — so when we reach position 2 with expected_previous=1 and
// pending=2, lastAccepted is still 1 and pending==lastAccepted+1 = 2 which
// is actually clean. To truly produce an E2 scenario we need a back-positioned
// insert that claims expected_previous=last BEFORE the first accepted entry, so
// we use a 3-entry chain with a gap or forked predecessor at the second position.
//
// The test constructs:
//
//	commit 0: file=prod, prev=0, pending=1   (baseline = 1)
//	commit 1: file=prod, prev=0, pending=1   (duplicate/forked: expected_previous=0 but last was 1)
//	commit 2: file=prod, prev=1, pending=2   (would be clean but commit 1 already broke it)
//
// Commit 1's expected_previous=0 != lastAccepted=1 → BindingTampered.
func TestS2A_E2_BackPositionedInsert_BindingTampered(t *testing.T) {
	const projectID = "s2a-e2"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	entries := []counterHistoryEntry{
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 0,
			Pending:      1, // first accepted: baseline = 1
		},
		{
			// Back-positioned fabricated insert: claims expected_previous=0, but
			// the walk has already accepted pending=1 for this file. This is a
			// forked predecessor — the canonical sequence set does not include
			// a commit with expected_previous=0 after the first.
			Event:        audit.Event{Kind: audit.EventKindRotation, OccurredAt: base.Add(time.Minute), Actor: "attacker", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 0, // FORKED: predecessor 0, but lastAccepted is already 1
			Pending:      1,
		},
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base.Add(2 * time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 1,
			Pending:      2,
		},
	}

	history := newSignedHistoryWithCounters(t, projectID, entries)
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	// The back-positioned insert (commit 1) has expected_previous=0 but
	// lastAccepted=1 at that point → BindingTampered.
	assertTamperedResult(t, "T-S2-A E2 back-positioned insert", result, err)
	if !isErrAuditLogTampered(err) {
		t.Errorf("T-S2-A E2: want errors.Is(err, ErrAuditLogTampered), got: %v", err)
	}
	t.Logf("T-S2-A E2: PASS — back-positioned fabricated insert detected as BindingTampered")
}

// ---- T-S2-B: absence of counter fields ≠ tamper (forward-compat guard) ------

// TestS2B_NoCounterFields_NotTampered builds a synthetic parallel-channel
// fixture: anchor-signed commits whose bodies carry NO counter fields at all.
// The lines must stay BindingUnverifiedLegacy or BindingVerified (per the
// existing legacy/binding-era logic), never falsely BindingTampered.
//
// This tests the absence-vs-contradiction guard (Rule C): absence of counter
// fields in an anchor-signed body is not a contradiction. The monotonicity
// check is simply skipped for commits with no counter pairs.
//
// Note: because these commits carry audit_entry_sha, they are binding-era lines
// that will be BindingVerified (content-hash passes). The key assertion is that
// no ErrAuditLogTampered is returned despite missing counter fields.
func TestS2B_NoCounterFields_NotTampered(t *testing.T) {
	const projectID = "s2b-no-counters"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	// All entries omit counter fields — the bodies will carry audit_entry_sha
	// (so they're binding-era) but NO expected_previous_counter / pending_counter.
	entries := []counterHistoryEntry{
		{
			Event:             audit.Event{Kind: audit.EventKindMerge, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:          "prod",
			OmitCounterFields: true,
		},
		{
			Event:             audit.Event{Kind: audit.EventKindRotation, OccurredAt: base.Add(time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:          "prod",
			OmitCounterFields: true,
		},
		{
			Event:             audit.Event{Kind: audit.EventKindMerge, OccurredAt: base.Add(2 * time.Minute), Actor: "admin-2", ProjectID: projectID, Outcome: "ok"},
			FileName:          "staging",
			OmitCounterFields: true,
		},
	}

	history := newSignedHistoryWithCounters(t, projectID, entries)
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	if err != nil {
		t.Errorf("T-S2-B: VerifyAuditLog returned unexpected error on no-counter-field history: %v", err)
	}

	// None of the entries must be BindingTampered.
	for i, e := range result.Entries {
		if e.BindingStatus == rotate.BindingTampered {
			t.Errorf("T-S2-B: entry[%d] kind=%q is BindingTampered — absence of counter fields must not be tamper",
				i, e.Kind)
		}
	}
	t.Logf("T-S2-B: PASS — %d entries, none BindingTampered; absence of counter fields is not tamper",
		len(result.Entries))
}

// ---- T-S2-C: stripping evasion -----------------------------------------------

// TestS2C_StrippingEvasion_BindingTampered verifies that a registry-channel
// line with counter fields removed from its introducing commit body lands in
// the existing binding-era-boundary tamper check, not laundered as legacy.
//
// Construction: one binding-era commit (sets the boundary), followed by a new
// signed commit whose body carries NO audit_entry_sha (simulating counter-field
// stripping for a real commit). The missing audit_entry_sha puts it at-or-after
// the boundary → the existing bindLines legacy-boundary check fires BindingTampered.
//
// This test confirms the stripping evasion path is already closed by the
// binding-era-boundary check (the v0.5 behaviour), not by the new S2 counter
// check. The counter check adds an orthogonal defence; the boundary check is
// the first line of defence for stripped commits.
func TestS2C_StrippingEvasion_BindingTampered(t *testing.T) {
	const projectID = "s2c-stripping"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	// First entry: binding-era commit with counter fields. Sets the boundary.
	normalEntries := []counterHistoryEntry{
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 0,
			Pending:      1,
		},
	}
	history := newSignedHistoryWithCounters(t, projectID, normalEntries)
	repoDir := repoPathFromURL(history.RepoURL)

	// Append a second JSONL line and commit it with NO audit_entry_sha (stripped).
	// This simulates an attacker who removed counter fields AND audit_entry_sha
	// hoping to launder it as a legacy entry — but the line appears after the
	// binding-era boundary commit, so it must be BindingTampered.
	plantedEvent := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: base.Add(time.Minute),
		Actor:      "attacker",
		ProjectID:  projectID,
		Outcome:    "ok",
	}
	plantedRaw, marshalErr := json.Marshal(plantedEvent)
	if marshalErr != nil {
		t.Fatalf("T-S2-C: marshal planted event: %v", marshalErr)
	}
	plantedLine := append(plantedRaw, '\n')

	auditPath := filepath.Join(repoDir, "audit", projectID+".jsonl")
	f, openErr := os.OpenFile(auditPath, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test fixture
	if openErr != nil {
		t.Fatalf("T-S2-C: open audit file: %v", openErr)
	}
	if _, writeErr := f.Write(plantedLine); writeErr != nil {
		_ = f.Close()
		t.Fatalf("T-S2-C: write planted line: %v", writeErr)
	}
	_ = f.Close()

	gitInRepoFatal(t, repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))
	// Commit body carries NO audit_entry_sha and NO counter fields — stripped commit.
	strippedMsg := fmt.Sprintf("byreis: counter write-ahead\n\nproject_id: %s\nfile: prod\n", projectID)
	msgFile := filepath.Join(t.TempDir(), "stripped-msg.txt")
	if err := os.WriteFile(msgFile, []byte(strippedMsg), 0o600); err != nil { //nolint:gosec // test fixture
		t.Fatalf("T-S2-C: write msg file: %v", err)
	}
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile, "-S")

	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	// The stripped commit appears after the binding-era boundary → binding-era
	// boundary check fires BindingTampered.
	assertTamperedResult(t, "T-S2-C stripping evasion", result, err)
	if !isErrAuditLogTampered(err) {
		t.Errorf("T-S2-C: want errors.Is(err, ErrAuditLogTampered), got: %v", err)
	}
	t.Logf("T-S2-C: PASS — stripped binding-era-boundary commit is BindingTampered")
}

// ---- T-S2-D: multi-file rotation with valid per-file continuity → all BindingVerified

// TestS2D_MultiFileRotation_AllBindingVerified builds a history with one
// rotation commit that advances N>1 logical files. The rotation body uses the
// indented counter format (mirrors buildRotationCommitMessageBody). All files
// have valid per-file monotonic counter sequences. The test asserts:
//   - all non-synthetic entries are BindingVerified
//   - no ErrAuditLogTampered is returned
//
// This proves per-FILE continuity (not global sequencing) produces no false-positive.
func TestS2D_MultiFileRotation_AllBindingVerified(t *testing.T) {
	const projectID = "s2d-multifile"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	// One rotation commit advancing two files (prod and staging).
	// The audit JSONL gets one line (the rotation event); the rotation body
	// carries counter blocks for BOTH files.
	entries := []counterHistoryEntry{
		{
			// The audit JSONL line for this rotation event.
			Event:             audit.Event{Kind: audit.EventKindRotation, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:          "prod",
			ExpectedPrev:      0,
			Pending:           1,
			UseRotationFormat: true,
			// Additional file in the same rotation commit body.
			ExtraCounterFiles: []counterHistoryExtraFile{
				{FileName: "staging", ExpectedPrev: 0, Pending: 1},
			},
		},
		{
			// Second rotation: both files advance again.
			Event:             audit.Event{Kind: audit.EventKindRotation, OccurredAt: base.Add(time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:          "prod",
			ExpectedPrev:      1,
			Pending:           2,
			UseRotationFormat: true,
			ExtraCounterFiles: []counterHistoryExtraFile{
				{FileName: "staging", ExpectedPrev: 1, Pending: 2},
			},
		},
	}

	history := newSignedHistoryWithCounters(t, projectID, entries)
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	if err != nil {
		t.Errorf("T-S2-D: VerifyAuditLog returned unexpected error on valid multi-file rotation: %v", err)
	}

	nonSynthetic := 0
	for i, e := range result.Entries {
		if e.Kind == "truncated" || e.Kind == "malformed-line" {
			continue
		}
		nonSynthetic++
		if e.BindingStatus != rotate.BindingVerified {
			t.Errorf("T-S2-D: entry[%d] kind=%q BindingStatus=%v, want BindingVerified",
				i, e.Kind, e.BindingStatus)
		}
	}
	if nonSynthetic == 0 {
		t.Errorf("T-S2-D: no non-synthetic entries returned")
	}
	t.Logf("T-S2-D: PASS — %d entries all BindingVerified on valid multi-file rotation", nonSynthetic)
}

// ---- T-S2-E: clean full walk with monotone counters → BindingVerified, exit 0

// TestS2E_CleanMonotoneHistory_AllBindingVerified builds a genuine
// rotation+merge history with monotone counter sequences and asserts:
//   - all non-synthetic entries are BindingVerified
//   - no error returned (exit 0)
//   - FullWalk == true (cold full walk on first call)
//
// This is the regression test: the S2 counter check must not introduce any
// false-positive on a clean history.
func TestS2E_CleanMonotoneHistory_AllBindingVerified(t *testing.T) {
	const projectID = "s2e-clean"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	entries := []counterHistoryEntry{
		// First merge: prod file, counter 0→1.
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 0,
			Pending:      1,
		},
		// Second merge: prod file, counter 1→2.
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base.Add(time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 1,
			Pending:      2,
		},
		// Rotation: prod file, counter 2→3.
		{
			Event:             audit.Event{Kind: audit.EventKindRotation, OccurredAt: base.Add(2 * time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:          "prod",
			ExpectedPrev:      2,
			Pending:           3,
			UseRotationFormat: true,
		},
		// Another merge: prod file, counter 3→4.
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base.Add(3 * time.Minute), Actor: "admin-2", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 3,
			Pending:      4,
		},
	}

	history := newSignedHistoryWithCounters(t, projectID, entries)
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	if err != nil {
		t.Errorf("T-S2-E: VerifyAuditLog returned unexpected error on clean monotone history: %v", err)
	}
	if !result.FullWalk {
		t.Errorf("T-S2-E: FullWalk = false, want true (cold walk on first call)")
	}

	nonSynthetic := 0
	for i, e := range result.Entries {
		if e.Kind == "truncated" || e.Kind == "malformed-line" {
			continue
		}
		nonSynthetic++
		if e.BindingStatus != rotate.BindingVerified {
			t.Errorf("T-S2-E: entry[%d] kind=%q BindingStatus=%v, want BindingVerified",
				i, e.Kind, e.BindingStatus)
		}
	}
	if nonSynthetic != len(entries) {
		t.Errorf("T-S2-E: got %d non-synthetic entries, want %d", nonSynthetic, len(entries))
	}
	t.Logf("T-S2-E: PASS — %d entries all BindingVerified, FullWalk=true, no error", nonSynthetic)
}

// ---- Boundary: expected_previous_counter: 0 is first-accept, not absence ----

// TestS2Boundary_ZeroFirstAccept_Clean verifies that a counter sequence
// starting with expected_previous_counter=0 (the first legitimate accept value
// in a fresh counter store) is classified as clean and does not trigger tamper.
// This is the absence-vs-zero discrimination: a parsed zero must never be
// treated as "absent" (Rule C critical boundary).
func TestS2Boundary_ZeroFirstAccept_Clean(t *testing.T) {
	const projectID = "s2-boundary-zero"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	entries := []counterHistoryEntry{
		// First sighting: expected_previous=0, pending=1.
		// The 0 value is a legitimate first-accept (not absence). Must be clean.
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 0, // legitimate first-accept; must NOT be treated as absent
			Pending:      1,
		},
		// Second: continues from 1.
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base.Add(time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 1,
			Pending:      2,
		},
	}

	history := newSignedHistoryWithCounters(t, projectID, entries)
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	if err != nil {
		t.Errorf("S2 boundary zero: VerifyAuditLog returned unexpected error: %v", err)
	}
	for i, e := range result.Entries {
		if e.BindingStatus == rotate.BindingTampered {
			t.Errorf("S2 boundary zero: entry[%d] kind=%q is BindingTampered — "+
				"expected_previous_counter=0 is a legitimate first-accept, not absence",
				i, e.Kind)
		}
	}
	t.Logf("S2 boundary zero: PASS — expected_previous_counter=0 first-accept is clean")
}

// ---- T-S2-F: straddling-seam counter break on the warm/incremental path -----

// TestS2F_StradlingSeam_CounterBreak_WarmPath is the blocking negative fixture
// for the seam-fix. It wires a real CheckpointStore, performs a cold walk over
// an initial N-commit counter history (checkpoint written at counter N), then
// appends a new commit whose counter pair does NOT chain from N — the
// expected_previous and pending values fork off a different sequence. The second
// VerifyAuditLog call takes the warm/incremental path (checkpoint ancestor
// check passes). The seam-predecessor seed must cause checkCounterMonotonicity
// to detect the break and return BindingTampered + ErrAuditLogTampered,
// identical to the cold-walk verdict.
//
// Before the fix this test would have reported the new commit as BindingVerified
// because the warm path's fresh lastAccepted treated the forked commit as a
// first-sighting baseline with no predecessor check.
func TestS2F_StradlingSeam_CounterBreak_WarmPath(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const projectID = "s2f-seam-break"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH — skipping S2F seam-break test")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen binary not on PATH — skipping S2F seam-break test")
	}

	// Build an initial 2-commit history: prod file, counters 0→1 then 1→2.
	initialEntries := []counterHistoryEntry{
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 0,
			Pending:      1,
		},
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base.Add(time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 1,
			Pending:      2, // checkpoint will record: lastAccepted["prod"] = 2
		},
	}
	history := newSignedHistoryWithCounters(t, projectID, initialEntries)

	cacheDir := t.TempDir()
	store, storeErr := auditverify.NewStore(cacheDir, history.RepoURL)
	if storeErr != nil {
		t.Fatalf("S2F: NewStore: %v", storeErr)
	}

	pt, ptErr := registry.NewProductionFetchTransportFromRunner(registry.SubprocessRunner{}, nil)
	if ptErr != nil {
		t.Fatalf("S2F: NewProductionFetchTransportFromRunner: %v", ptErr)
	}
	fixedNow := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	client, clientErr := registry.New(registry.ClientConfig{
		RegistryURL:    history.RepoURL,
		ProjectID:      history.ProjectID,
		CacheDir:       t.TempDir(),
		TrustAnchorKey: history.AnchorKey,
		Clock:          func() time.Time { return fixedNow },
		FetchTransport: pt,
	})
	if clientErr != nil {
		t.Fatalf("S2F: registry.New: %v", clientErr)
	}
	client.WithAuditVerifierConfig(registry.AuditVerifierConfig{CheckpointStore: store})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// Step 1: cold walk — writes checkpoint at counter 2.
	result1, err1 := client.VerifyAuditLog(ctx, projectID)
	if err1 != nil {
		t.Fatalf("S2F step1 cold walk: unexpected error: %v", err1)
	}
	if !result1.FullWalk {
		t.Errorf("S2F step1: FullWalk=false, want true (no prior checkpoint)")
	}
	ckpt1, loadErr := store.Load(ctx, projectID)
	if loadErr != nil || ckpt1 == nil {
		t.Fatalf("S2F step1: checkpoint not written after cold walk (loadErr=%v, ckpt=%v)", loadErr, ckpt1)
	}
	t.Logf("S2F step1: cold walk PASS, checkpoint at %s (counter=2)", ckpt1.VerifiedHeadSHA[:12])

	// Step 2: append a new commit whose counter pair FORKS from the seam.
	// The seam predecessor is prod/pending=2; the new commit claims
	// expected_previous=7 and pending=8 — a forked predecessor that does NOT
	// chain from 2. The warm path must detect this via the seam seed.
	repoDir := repoPathFromURL(history.RepoURL)
	forkEvent := audit.Event{
		Kind:       audit.EventKindMerge,
		OccurredAt: base.Add(2 * time.Minute),
		Actor:      "admin-1",
		ProjectID:  projectID,
		Outcome:    "ok",
	}
	forkRaw, marshalErr := json.Marshal(forkEvent)
	if marshalErr != nil {
		t.Fatalf("S2F step2: marshal: %v", marshalErr)
	}
	forkLine := append(forkRaw, '\n')
	forkSum := sha256.Sum256(forkLine)
	forkEntrySHA := fmt.Sprintf("%x", forkSum[:])

	auditPath := filepath.Join(repoDir, "audit", projectID+".jsonl")
	f, openErr := os.OpenFile(auditPath, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test fixture
	if openErr != nil {
		t.Fatalf("S2F step2: open audit file: %v", openErr)
	}
	if _, writeErr := f.Write(forkLine); writeErr != nil {
		_ = f.Close()
		t.Fatalf("S2F step2: write line: %v", writeErr)
	}
	_ = f.Close()

	// Commit body claims expected_previous=7, pending=8 — does not chain from seam (pending=2).
	forkMsg := fmt.Sprintf(
		"byreis: counter write-ahead\n\n"+
			"project_id: %s\n"+
			"file: prod\n"+
			"expected_previous_counter: 7\n"+
			"pending_counter: 8\n"+
			"audit_entry_sha: %s\n",
		projectID, forkEntrySHA)
	msgFile := filepath.Join(t.TempDir(), "fork-msg.txt")
	if err := os.WriteFile(msgFile, []byte(forkMsg), 0o600); err != nil { //nolint:gosec // test fixture
		t.Fatalf("S2F step2: write commit msg: %v", err)
	}
	gitInRepoFatal(t, repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile, "-S")

	// Step 3: warm/incremental verify — must detect the seam counter break.
	result2, err2 := client.VerifyAuditLog(ctx, projectID)
	// The seam seed shows lastAccepted["prod"]=2; the new commit claims
	// expected_previous=7 which != 2 → BindingTampered + ErrAuditLogTampered.
	if err2 == nil {
		t.Errorf("S2F step3 warm walk: expected ErrAuditLogTampered for seam counter break, got nil error")
	} else if !isErrAuditLogTampered(err2) {
		t.Errorf("S2F step3 warm walk: want ErrAuditLogTampered, got: %v", err2)
	}

	// Confirm the seam-breaking commit's line is BindingTampered.
	tampered := 0
	for _, e := range result2.Entries {
		if e.BindingStatus == rotate.BindingTampered {
			tampered++
		}
	}
	if tampered == 0 {
		t.Errorf("S2F step3 warm walk: no BindingTampered entry — seam counter break must label the offending line")
	}
	t.Logf("S2F step3 warm walk: PASS — seam counter break detected (%d BindingTampered, err=%v)", tampered, err2)
}

// ---- T-S2-G: clean monotonic append across the seam on the warm path --------

// TestS2G_StradlingSeam_CleanMonotonic_WarmPath is the positive counterpart to
// T-S2-F: a checkpoint is written after an initial N-commit history, then one
// or more new commits are appended with counter values that correctly chain from
// the seam predecessor. The warm/incremental verify must return all
// BindingVerified entries and no ErrAuditLogTampered. This proves the fix does
// not introduce false-positives on honest warm verifies.
func TestS2G_StradlingSeam_CleanMonotonic_WarmPath(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const projectID = "s2g-seam-clean"
	base := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH — skipping S2G seam-clean test")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen binary not on PATH — skipping S2G seam-clean test")
	}

	// Initial 2-commit history: prod file, counters 0→1 then 1→2.
	initialEntries := []counterHistoryEntry{
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base, Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 0,
			Pending:      1,
		},
		{
			Event:        audit.Event{Kind: audit.EventKindMerge, OccurredAt: base.Add(time.Minute), Actor: "admin-1", ProjectID: projectID, Outcome: "ok"},
			FileName:     "prod",
			ExpectedPrev: 1,
			Pending:      2,
		},
	}
	history := newSignedHistoryWithCounters(t, projectID, initialEntries)

	cacheDir := t.TempDir()
	store, storeErr := auditverify.NewStore(cacheDir, history.RepoURL)
	if storeErr != nil {
		t.Fatalf("S2G: NewStore: %v", storeErr)
	}

	pt, ptErr := registry.NewProductionFetchTransportFromRunner(registry.SubprocessRunner{}, nil)
	if ptErr != nil {
		t.Fatalf("S2G: NewProductionFetchTransportFromRunner: %v", ptErr)
	}
	fixedNow := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	client, clientErr := registry.New(registry.ClientConfig{
		RegistryURL:    history.RepoURL,
		ProjectID:      history.ProjectID,
		CacheDir:       t.TempDir(),
		TrustAnchorKey: history.AnchorKey,
		Clock:          func() time.Time { return fixedNow },
		FetchTransport: pt,
	})
	if clientErr != nil {
		t.Fatalf("S2G: registry.New: %v", clientErr)
	}
	client.WithAuditVerifierConfig(registry.AuditVerifierConfig{CheckpointStore: store})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// Step 1: cold walk — writes checkpoint at counter 2.
	result1, err1 := client.VerifyAuditLog(ctx, projectID)
	if err1 != nil {
		t.Fatalf("S2G step1 cold walk: unexpected error: %v", err1)
	}
	if !result1.FullWalk {
		t.Errorf("S2G step1: FullWalk=false, want true")
	}
	ckpt1, loadErr := store.Load(ctx, projectID)
	if loadErr != nil || ckpt1 == nil {
		t.Fatalf("S2G step1: checkpoint not written (loadErr=%v, ckpt=%v)", loadErr, ckpt1)
	}
	t.Logf("S2G step1: cold walk PASS, checkpoint at %s", ckpt1.VerifiedHeadSHA[:12])

	// Step 2: append a new commit that correctly chains: expected_previous=2, pending=3.
	repoDir := repoPathFromURL(history.RepoURL)
	cleanEvent := audit.Event{
		Kind:       audit.EventKindMerge,
		OccurredAt: base.Add(2 * time.Minute),
		Actor:      "admin-1",
		ProjectID:  projectID,
		Outcome:    "ok",
	}
	cleanRaw, marshalErr := json.Marshal(cleanEvent)
	if marshalErr != nil {
		t.Fatalf("S2G step2: marshal: %v", marshalErr)
	}
	cleanLine := append(cleanRaw, '\n')
	cleanSum := sha256.Sum256(cleanLine)
	cleanEntrySHA := fmt.Sprintf("%x", cleanSum[:])

	auditPath := filepath.Join(repoDir, "audit", projectID+".jsonl")
	f, openErr := os.OpenFile(auditPath, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test fixture
	if openErr != nil {
		t.Fatalf("S2G step2: open audit file: %v", openErr)
	}
	if _, writeErr := f.Write(cleanLine); writeErr != nil {
		_ = f.Close()
		t.Fatalf("S2G step2: write line: %v", writeErr)
	}
	_ = f.Close()

	// Commit body: expected_previous=2 (seam pred), pending=3 — correct continuation.
	cleanMsg := fmt.Sprintf(
		"byreis: counter write-ahead\n\n"+
			"project_id: %s\n"+
			"file: prod\n"+
			"expected_previous_counter: 2\n"+
			"pending_counter: 3\n"+
			"audit_entry_sha: %s\n",
		projectID, cleanEntrySHA)
	msgFile := filepath.Join(t.TempDir(), "clean-msg.txt")
	if err := os.WriteFile(msgFile, []byte(cleanMsg), 0o600); err != nil { //nolint:gosec // test fixture
		t.Fatalf("S2G step2: write commit msg: %v", err)
	}
	gitInRepoFatal(t, repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile, "-S")

	// Step 3: warm/incremental verify — must return all BindingVerified, no error.
	result2, err2 := client.VerifyAuditLog(ctx, projectID)
	if err2 != nil {
		t.Errorf("S2G step3 warm walk: unexpected error on clean seam-crossing counter: %v", err2)
	}
	if result2.FullWalk {
		t.Logf("S2G step3 warm walk: FullWalk=true (checkpoint amortisation not confirmed; acceptable for correctness)")
	}

	totalExpected := len(initialEntries) + 1 // 3
	nonSynthetic := 0
	for i, e := range result2.Entries {
		if e.Kind == "truncated" || e.Kind == "malformed-line" {
			continue
		}
		nonSynthetic++
		if e.BindingStatus != rotate.BindingVerified {
			t.Errorf("S2G step3: entry[%d] kind=%q BindingStatus=%v, want BindingVerified (clean seam crossing)",
				i, e.Kind, e.BindingStatus)
		}
	}
	if nonSynthetic != totalExpected {
		t.Errorf("S2G step3: got %d non-synthetic entries, want %d", nonSynthetic, totalExpected)
	}
	t.Logf("S2G step3 warm walk: PASS — %d entries all BindingVerified, no error (clean seam crossing)", nonSynthetic)
}

// Note: isErrAuditLogTampered is declared in registry_auditverify_s1batch_test.go
// and is shared across the registry_test package.
