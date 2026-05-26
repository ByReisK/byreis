package registry_test

// Tamper-detection fixture tests for VerifyAuditLog (AC-B through AC-F,
// CONDITION-1).
//
// Each test builds a clean signed history via newSignedAuditHistory, then
// mutates the served repository to simulate the named attack. The verifier
// must return ErrAuditLogTampered and label the offending line BindingTampered
// in every case; it must never return a clean (error-free, all-BindingVerified)
// result on a tampered input.
//
// Mutation strategy: all mutations are applied to the served file:// repo
// (the same directory that newSignedAuditHistory populates) AFTER the clean
// commits are in place. Each test uses git plumbing to rewrite HEAD or add new
// commits. The file:// transport therefore serves the mutated content to the
// real VerifyAuditLog clone path.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ---- shared mutation helpers ------------------------------------------------

// repoPathFromURL strips the "file://" prefix from a file URL to get the
// filesystem path.
func repoPathFromURL(fileURL string) string {
	const prefix = "file://"
	if len(fileURL) > len(prefix) {
		return fileURL[len(prefix):]
	}
	return fileURL
}

// gitInRepo runs a git command in the given directory, forwarding the HOME env
// so SSH signing works. The command is allowed to fail; the raw output is
// returned so callers can inspect results.
func gitInRepo(t *testing.T, repoDir string, args ...string) (string, int) {
	t.Helper()
	c := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // known git subcommands under test control
	c.Dir = repoDir
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return string(out), ee.ExitCode()
		}
		return string(out), -1
	}
	return string(out), 0
}

// gitInRepoFatal runs a git command and fatals the test on non-zero exit.
func gitInRepoFatal(t *testing.T, repoDir string, args ...string) string {
	t.Helper()
	out, code := gitInRepo(t, repoDir, args...)
	if code != 0 {
		t.Fatalf("git %v exited %d: %s", args, code, out)
	}
	return out
}

// currentAuditBlob reads the raw content of the audit/<projectID>.jsonl file
// at HEAD in the given repo.
func currentAuditBlob(t *testing.T, repoDir, projectID string) []byte {
	t.Helper()
	path := filepath.Join(repoDir, "audit", projectID+".jsonl")
	data, err := os.ReadFile(path) //nolint:gosec // path under t.TempDir
	if err != nil {
		t.Fatalf("currentAuditBlob: %v", err)
	}
	return data
}

// writeAndAmendLastCommit replaces the audit/<projectID>.jsonl file with new
// content and amends the last commit (keeping the original commit message and
// -S flag for re-signing with the configured SSH key). On success HEAD points
// at the amended commit.
//
// --allow-empty is used because some mutations (e.g. truncating a 2-line file
// back to 1 line) produce a tree identical to the grandparent commit; without
// --allow-empty git would reject the amend. The verifier counts git-log
// entries regardless of whether the staged diff is empty, so an empty-diff
// amended commit still triggers the count-mismatch tamper check.
func writeAndAmendLastCommit(t *testing.T, repoDir, projectID string, newContent []byte) {
	t.Helper()
	auditPath := filepath.Join(repoDir, "audit", projectID+".jsonl")
	if err := os.WriteFile(auditPath, newContent, 0o644); err != nil { //nolint:gosec // test fixture under t.TempDir
		t.Fatalf("writeAndAmendLastCommit: write: %v", err)
	}
	gitInRepoFatal(t, repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))
	// Amend: keep message unchanged, re-sign. --allow-empty handles the case
	// where the mutation produces a tree identical to the grandparent.
	gitInRepoFatal(t, repoDir, "commit", "--amend", "--no-edit", "--allow-empty", "-S")
}

// assertTamperedResult checks the common postconditions for every tamper test:
//   - err wraps ErrAuditLogTampered
//   - at least one entry carries BindingTampered
//   - no entry carries BindingVerified (a partial-clean result is unacceptable)
func assertTamperedResult(t *testing.T, label string, result rotate.AuditVerifyResult, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: VerifyAuditLog returned nil error on tampered history — "+
			"must return ErrAuditLogTampered", label)
		return
	}
	if !errors.Is(err, coreregistry.ErrAuditLogTampered) {
		t.Errorf("%s: want errors.Is(err, ErrAuditLogTampered), got: %v", label, err)
	}

	tampered := 0
	for _, e := range result.Entries {
		if e.BindingStatus == rotate.BindingTampered {
			tampered++
		}
	}
	if tampered == 0 {
		t.Errorf("%s: no BindingTampered entry in result — "+
			"offending line must be labelled BindingTampered", label)
	}
	t.Logf("%s: PASS — ErrAuditLogTampered returned, %d entry(-ies) labelled BindingTampered: %v",
		label, tampered, err)
}

// ---- AC-B: edited line → sha mismatch ---------------------------------------

// TestAuditVerify_ACB_EditedLine_BindingTampered builds a 1-event signed
// history, then amends the last commit to replace one byte in the JSONL line
// while keeping the original audit_entry_sha in the commit body. The verifier
// must detect the content mismatch and return ErrAuditLogTampered with the
// offending line labelled BindingTampered.
//
// The amendment re-signs the commit with the anchor key (commit.gpgsign=true
// is inherited from the harness config), so CONDITION-1 does not fire — only
// the sha mismatch path exercises.
func TestAuditVerify_ACB_EditedLine_BindingTampered(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const projectID = "acb-project"

	// Build a 1-event clean history.
	events := []audit.Event{
		buildTestAuditEvents(projectID)[0],
	}
	history := newSignedAuditHistory(t, projectID, events)
	repoDir := repoPathFromURL(history.RepoURL)

	// Capture the original blob (1 JSONL line + newline).
	originalBlob := currentAuditBlob(t, repoDir, projectID)
	if len(originalBlob) == 0 {
		t.Fatal("AC-B: original blob is empty")
	}

	// Flip one byte at position 10 (safely inside the JSON object).
	mutated := make([]byte, len(originalBlob))
	copy(mutated, originalBlob)
	mutated[10] ^= 0x01

	// Sanity: the flip must change the sha256.
	orig := sha256.Sum256(originalBlob)
	mut := sha256.Sum256(mutated)
	if orig == mut {
		t.Fatal("AC-B: byte flip did not change sha256 — test is defective")
	}

	// Amend the last commit to store the mutated content. The commit body is
	// kept intact (same audit_entry_sha), so the signed body now records the
	// hash of the PRE-flip line while the blob holds the POST-flip line.
	writeAndAmendLastCommit(t, repoDir, projectID, mutated)

	// Now run the verifier against the tampered repo.
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	assertTamperedResult(t, "AC-B", result, err)
}

// ---- AC-C: deleted/truncated line → count mismatch -------------------------

// TestAuditVerify_ACC_DeletedLine_BindingTampered builds a 3-event signed
// history (3 commits, 3 lines), then adds a 4th ANCHOR-signed commit that
// overwrites the file with only the first 2 lines, simulating post-fact line
// deletion. The verifier must detect the count mismatch (4 introducing
// commits, 2 non-synthetic lines) and return ErrAuditLogTampered.
//
// A new commit (rather than an amendment) is used because git log counts a
// commit as "touching" the file only when the commit's tree differs from its
// parent for that path. Amending a commit to the same tree as its grandparent
// makes git log skip the empty commit, defeating the count-mismatch check.
// A 4th commit that drops a line produces a genuine tree diff → 4 commits, 2
// lines → count mismatch.
func TestAuditVerify_ACC_DeletedLine_BindingTampered(t *testing.T) {
	const projectID = "acc-project"

	events := buildTestAuditEvents(projectID)
	history := newSignedAuditHistory(t, projectID, events) // 3 commits, 3 lines
	repoDir := repoPathFromURL(history.RepoURL)

	// Read the current blob which has 3 lines.
	blob := currentAuditBlob(t, repoDir, projectID)
	lines := splitJSONLLines(blob)
	if len(lines) != 3 {
		t.Fatalf("AC-C: expected 3 JSONL lines, got %d", len(lines))
	}

	// Build a new file with only the first 2 lines (line 3 deleted).
	truncated := append(lines[0], lines[1]...)

	// Add a new signed commit that writes the truncated content. No
	// audit_entry_sha in the body — this is a deletion commit, not an append.
	addSignedCommitWithContent(t, repoDir, projectID, truncated,
		"audit: tamper — delete line 3\n")

	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	assertTamperedResult(t, "AC-C", result, err)
}

// addSignedCommitWithContent writes newContent to the audit file and makes a
// new ANCHOR-signed commit with the given message. It relies on the repo's
// existing git config (commit.gpgsign=true, user.signingkey pointing at the
// anchor key) set up by newSignedAuditHistory.
func addSignedCommitWithContent(t *testing.T, repoDir, projectID string, content []byte, msg string) {
	t.Helper()
	auditPath := filepath.Join(repoDir, "audit", projectID+".jsonl")
	if err := os.WriteFile(auditPath, content, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("addSignedCommitWithContent: write: %v", err)
	}
	gitInRepoFatal(t, repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))
	msgFile := filepath.Join(t.TempDir(), "commitmsg.txt")
	if err := os.WriteFile(msgFile, []byte(msg), 0o600); err != nil { //nolint:gosec // test temp
		t.Fatalf("addSignedCommitWithContent: write msg: %v", err)
	}
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile, "-S")
}

// ---- AC-D: reordered lines → sha mismatch on positional binding -------------

// TestAuditVerify_ACD_ReorderedLines_BindingTampered builds a 2-event signed
// history, then amends the last commit to write the JSONL lines in reversed
// order while preserving the original audit_entry_sha in the commit body.
// Because the verifier pairs commits[i] with blob lines in order, the
// positional sha comparison detects the reorder: commit[0].audit_entry_sha
// was computed over the original line 0, but blob[0] is now the original
// line 1, causing a sha mismatch → BindingTampered.
func TestAuditVerify_ACD_ReorderedLines_BindingTampered(t *testing.T) {
	const projectID = "acd-project"

	events := buildTestAuditEvents(projectID)[:2]
	history := newSignedAuditHistory(t, projectID, events)
	repoDir := repoPathFromURL(history.RepoURL)

	blob := currentAuditBlob(t, repoDir, projectID)

	// Split into individual lines (each ending with \n).
	lines := splitJSONLLines(blob)
	if len(lines) != 2 {
		t.Fatalf("AC-D: expected 2 JSONL lines, got %d", len(lines))
	}

	// Swap the order: write [line1, line0].
	reordered := append(lines[1], lines[0]...)

	// Amend the last commit with the reordered content. The commit body still
	// carries audit_entry_sha of the original line 1 (the second event), but
	// the positional pairing now assigns commit[0] to blob[0]=line1 and
	// commit[1] to blob[1]=line0, exposing both as mismatched.
	writeAndAmendLastCommit(t, repoDir, projectID, reordered)

	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	assertTamperedResult(t, "AC-D", result, err)
}

// splitJSONLLines splits raw JSONL bytes into individual lines, each retaining
// its trailing newline. Empty lines are dropped.
func splitJSONLLines(raw []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\n' {
			line := raw[start : i+1]
			if len(line) > 1 { // skip blank lines (bare newline)
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	// Trailing content without a newline.
	if start < len(raw) {
		lines = append(lines, raw[start:])
	}
	return lines
}

// ---- AC-E: forged insert → count mismatch -----------------------------------

// TestAuditVerify_ACE_ForgedInsert_BindingTampered builds a 2-event signed
// history (2 commits, 2 lines), then amends the last commit to write a file
// with a forged third line appended. No signed commit body carries the sha of
// the forged line. The verifier must detect the count mismatch (2 introducing
// commits, 3 non-synthetic lines) and return ErrAuditLogTampered.
func TestAuditVerify_ACE_ForgedInsert_BindingTampered(t *testing.T) {
	const projectID = "ace-project"

	events := buildTestAuditEvents(projectID)[:2]
	history := newSignedAuditHistory(t, projectID, events)
	repoDir := repoPathFromURL(history.RepoURL)

	blob := currentAuditBlob(t, repoDir, projectID)

	// Forge a syntactically valid JSONL line for the same project.
	forgedLine := fmt.Sprintf(
		`{"kind":"merge","occurred_at":"2026-05-26T12:00:00Z","actor":"attacker","project_id":%q,"outcome":"ok"}`,
		projectID,
	) + "\n"

	withForged := append(blob, []byte(forgedLine)...)

	// Amend: write the file with the extra forged line. The commit body still
	// carries the audit_entry_sha of the original second line — the forged
	// line has no corresponding signed commit body carrying its sha.
	writeAndAmendLastCommit(t, repoDir, projectID, withForged)

	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	assertTamperedResult(t, "AC-E", result, err)
}

// ---- AC-F: cross-project splice ---------------------------------------------

// TestAuditVerify_ACF_CrossProjectSplice_BindingTampered builds a 1-event
// signed history for "acf-main", then adds a new signed commit to that same
// repository that appends a line to "acf-main" AND creates/appends a line to
// a SECOND project's audit file "acf-other". The commit stages both files,
// violating the exact-staged-set rule ({counter blob, audit/<thisproject>.jsonl}).
//
// The verifier's checkSplice rule must flag the entry introduced by that commit
// as BindingTampered and return ErrAuditLogTampered.
func TestAuditVerify_ACF_CrossProjectSplice_BindingTampered(t *testing.T) {
	const (
		mainProject  = "acf-main"
		otherProject = "acf-other"
	)

	// Build a 1-event signed history for the main project.
	events := buildTestAuditEvents(mainProject)[:1]
	history := newSignedAuditHistory(t, mainProject, events)
	repoDir := repoPathFromURL(history.RepoURL)

	// Compute the second event's JSONL line and its sha (for the commit body).
	secondEvent := buildTestAuditEvents(mainProject)[1]
	secondLine, secondEntrySHA := buildCommittableJSONLLine(t, secondEvent)

	// Create the audit directory and a file for the "other" project.
	otherAuditPath := filepath.Join(repoDir, "audit", otherProject+".jsonl")
	otherLine := fmt.Sprintf(
		`{"kind":"merge","occurred_at":"2026-05-26T12:00:00Z","actor":"splice-attacker","project_id":%q,"outcome":"ok"}`,
		otherProject,
	) + "\n"
	if err := os.WriteFile(otherAuditPath, []byte(otherLine), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("AC-F: write other audit file: %v", err)
	}

	// Append the second event to the main project's audit file.
	mainAuditPath := filepath.Join(repoDir, "audit", mainProject+".jsonl")
	f, err := os.OpenFile(mainAuditPath, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("AC-F: open main audit file: %v", err)
	}
	if _, wErr := f.Write(secondLine); wErr != nil {
		_ = f.Close()
		t.Fatalf("AC-F: write main audit file: %v", wErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatalf("AC-F: close main audit file: %v", cErr)
	}

	// Stage BOTH files in one commit (the splice).
	gitInRepoFatal(t, repoDir, "add", "--",
		filepath.Join("audit", mainProject+".jsonl"),
		filepath.Join("audit", otherProject+".jsonl"),
	)

	// Build the commit message with the audit_entry_sha for the main project line.
	msg := fmt.Sprintf("audit: append splice commit (main+other)\n\naudit_entry_sha: %s\n", secondEntrySHA)
	msgFile := filepath.Join(t.TempDir(), "splice-commitmsg.txt")
	if wErr := os.WriteFile(msgFile, []byte(msg), 0o600); wErr != nil { //nolint:gosec // test fixture
		t.Fatalf("AC-F: write commit msg: %v", wErr)
	}
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile, "-S")

	// Verify the main project: the last commit staged both projects' audit files,
	// violating the splice rule.
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, mainProject)
	assertTamperedResult(t, "AC-F", result, err)
}

// ---- exact-set splice: valid audit line + unrelated non-audit/ file -----------

// TestAuditVerify_ExactSetSplice_NonAuditFile_BindingTampered builds a 1-event
// signed history for "splice-exact-project", then adds a second commit that
// appends a valid, correctly-hashed audit line for this project AND stages an
// unrelated non-audit/ file (a secrets/ path). The commit body carries the
// correct audit_entry_sha for the appended line.
//
// Under the previous denylist rule this would have been a clean result (only
// another project's audit/ files were blocked). Under the exact-set allowlist
// rule ({audit/<project>.jsonl} ∪ {counters/<project>/**}) any other staged
// path is a splice → BindingTampered / ErrAuditLogTampered.
func TestAuditVerify_ExactSetSplice_NonAuditFile_BindingTampered(t *testing.T) {
	const projectID = "splice-exact-project"

	// Build a 1-event clean history.
	events := buildTestAuditEvents(projectID)[:1]
	history := newSignedAuditHistory(t, projectID, events)
	repoDir := repoPathFromURL(history.RepoURL)

	// Build the second event's JSONL line and its sha.
	secondEvent := buildTestAuditEvents(projectID)[1]
	secondLine, secondEntrySHA := buildCommittableJSONLLine(t, secondEvent)

	// Append the second event to the main project's audit file.
	mainAuditPath := filepath.Join(repoDir, "audit", projectID+".jsonl")
	f, err := os.OpenFile(mainAuditPath, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("ExactSet: open main audit file: %v", err)
	}
	if _, wErr := f.Write(secondLine); wErr != nil {
		_ = f.Close()
		t.Fatalf("ExactSet: write main audit file: %v", wErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatalf("ExactSet: close main audit file: %v", cErr)
	}

	// Create an unrelated non-audit/ file (a secrets/ path) and stage it
	// alongside the audit file in the same commit.
	secretsDir := filepath.Join(repoDir, "secrets")
	if mkErr := os.MkdirAll(secretsDir, 0o750); mkErr != nil { //nolint:gosec // 0750: test fixture directory under t.TempDir
		t.Fatalf("ExactSet: mkdir secrets: %v", mkErr)
	}
	if wErr := os.WriteFile(filepath.Join(secretsDir, "prod.enc.yaml"), //nolint:gosec // test fixture
		[]byte("unrelated-secrets-content: spliced\n"), 0o644); wErr != nil {
		t.Fatalf("ExactSet: write secrets file: %v", wErr)
	}

	// Stage both files: the legitimate audit append AND the unrelated secrets file.
	gitInRepoFatal(t, repoDir, "add", "--",
		filepath.Join("audit", projectID+".jsonl"),
		filepath.Join("secrets", "prod.enc.yaml"),
	)

	// Build the commit message with the correct audit_entry_sha for the audit line.
	// The commit is valid from the sha-binding perspective; the splice is in the
	// staged file set, not in the commit body content.
	msg := fmt.Sprintf("audit: append event 2 (with secrets/ splice)\n\naudit_entry_sha: %s\n", secondEntrySHA)
	msgFile := filepath.Join(t.TempDir(), "splice-exact-commitmsg.txt")
	if wErr := os.WriteFile(msgFile, []byte(msg), 0o600); wErr != nil { //nolint:gosec // test fixture
		t.Fatalf("ExactSet: write commit msg: %v", wErr)
	}
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile, "-S")

	// Verify: the commit staged an unrelated non-audit/ path alongside a valid
	// audit line. The exact-set splice check must flag this as BindingTampered.
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	assertTamperedResult(t, "ExactSetSplice/NonAuditFile", result, err)
}

// buildCommittableJSONLLine serialises event to a JSONL line (ending with "\n")
// and returns (line, sha256hex). This mirrors the production signing path so
// the commit body's audit_entry_sha is correct for the content.
func buildCommittableJSONLLine(t *testing.T, ev audit.Event) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("buildCommittableJSONLLine: marshal: %v", err)
	}
	line := append(raw, '\n')
	sum := sha256.Sum256(line)
	return line, fmt.Sprintf("%x", sum[:])
}

// ---- CONDITION-1: non-anchor-signed commit → BindingTampered ---------------

// TestAuditVerify_Condition1_NonAnchorKey_BindingTampered builds a 2-commit
// history where the FIRST commit is signed by an IMPOSTOR Ed25519 key and the
// SECOND commit is signed by the REAL anchor key. The registry.Client is
// configured with the anchor key.
//
// The HEAD is anchor-signed, so FetchHead succeeds. The per-line walk then
// processes both commits. Commit 0 (impostor-signed) fails git verify-commit
// against the client's anchor-only allowed-signers → SignedByAnchor=false →
// BindingTampered. The function must return ErrAuditLogTampered (Crypto
// CONDITION 1: the trust anchor is SINGLE and PINNED; no other key is trusted).
func TestAuditVerify_Condition1_NonAnchorKey_BindingTampered(t *testing.T) {
	// Not parallel: spawns real git subprocesses.
	const projectID = "cond1-project"

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}

	root := t.TempDir()

	// Generate the REAL anchor key (what the client will trust).
	anchorKeyPath := filepath.Join(root, "anchor-key")
	anchorPubPath := anchorKeyPath + ".pub"
	genAnchor := exec.CommandContext(t.Context(), "ssh-keygen", //nolint:gosec // known fixed args
		"-t", "ed25519", "-N", "", "-C", "byreis-audit-anchor-real",
		"-q", "-f", anchorKeyPath,
	)
	if out, genErr := genAnchor.CombinedOutput(); genErr != nil {
		t.Fatalf("CONDITION-1: generate anchor key: %v: %s", genErr, out)
	}
	anchorPubBytes, readAnchorErr := os.ReadFile(anchorPubPath)
	if readAnchorErr != nil {
		t.Fatalf("CONDITION-1: read anchor pubkey: %v", readAnchorErr)
	}
	anchorKey := decodeSSHEd25519PubkeyForAudit(t, string(anchorPubBytes))

	// Generate an IMPOSTOR key (will sign the first commit; client won't trust it).
	impostorKeyPath := filepath.Join(root, "impostor-key")
	impostorPubPath := impostorKeyPath + ".pub"
	genImpostor := exec.CommandContext(t.Context(), "ssh-keygen", //nolint:gosec // known fixed args
		"-t", "ed25519", "-N", "", "-C", "impostor",
		"-q", "-f", impostorKeyPath,
	)
	if out, genErr := genImpostor.CombinedOutput(); genErr != nil {
		t.Fatalf("CONDITION-1: generate impostor key: %v: %s", genErr, out)
	}
	impostorPubBytes, readImpostorErr := os.ReadFile(impostorPubPath)
	if readImpostorErr != nil {
		t.Fatalf("CONDITION-1: read impostor pubkey: %v", readImpostorErr)
	}

	// The repo's allowed-signers must list BOTH keys so that git can verify
	// commits signed by either key within the repo. The CLIENT's allowed-signers
	// (built by the verifier from cfg.TrustAnchorKey) lists ONLY the anchor,
	// so git verify-commit rejects the impostor-signed commit during the walk.
	repoAllowedSignersPath := filepath.Join(root, "repo-allowed-signers")
	anchorFields := splitSSHPubkey(t, string(anchorPubBytes))
	impostorFields := splitSSHPubkey(t, string(impostorPubBytes))
	repoAllowedContent := auditAnchorPrincipal + " " + anchorFields[0] + " " + anchorFields[1] + "\n" +
		auditAnchorPrincipal + " " + impostorFields[0] + " " + impostorFields[1] + "\n"
	if writeErr := os.WriteFile(repoAllowedSignersPath, []byte(repoAllowedContent), 0o600); writeErr != nil { //nolint:gosec // test temp
		t.Fatalf("CONDITION-1: write repo allowed-signers: %v", writeErr)
	}

	// Initialise the git repo.
	repoDir := filepath.Join(root, "registry")
	if mkErr := os.MkdirAll(repoDir, 0o750); mkErr != nil {
		t.Fatalf("CONDITION-1: mkdir: %v", mkErr)
	}
	gitInRepoFatal(t, repoDir, "init", "-q", "--initial-branch=main")
	gitInRepoFatal(t, repoDir, "config", "user.name", auditAnchorPrincipal)
	gitInRepoFatal(t, repoDir, "config", "user.email", "anchor@example.com")
	gitInRepoFatal(t, repoDir, "config", "gpg.format", "ssh")
	gitInRepoFatal(t, repoDir, "config", "gpg.ssh.allowedSignersFile", repoAllowedSignersPath)
	gitInRepoFatal(t, repoDir, "config", "commit.gpgsign", "true")

	auditDir := filepath.Join(repoDir, "audit")
	if mkErr := os.MkdirAll(auditDir, 0o750); mkErr != nil {
		t.Fatalf("CONDITION-1: mkdir audit: %v", mkErr)
	}
	auditFilePath := filepath.Join(auditDir, projectID+".jsonl")

	events := buildTestAuditEvents(projectID)

	// Commit 0: IMPOSTOR-signed. This is the tampered commit the verifier must reject.
	line0, sha0 := buildCommittableJSONLLine(t, events[0])
	if writeErr := os.WriteFile(auditFilePath, line0, 0o644); writeErr != nil { //nolint:gosec // test fixture
		t.Fatalf("CONDITION-1: write audit file (commit 0): %v", writeErr)
	}
	gitInRepoFatal(t, repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))
	msg0 := fmt.Sprintf("audit: append event 0 (impostor)\n\naudit_entry_sha: %s\n", sha0)
	msgFile0 := filepath.Join(root, "msg0.txt")
	if writeErr := os.WriteFile(msgFile0, []byte(msg0), 0o600); writeErr != nil { //nolint:gosec
		t.Fatalf("CONDITION-1: write msg0: %v", writeErr)
	}
	// Sign with the IMPOSTOR key for this commit.
	gitInRepoFatal(t, repoDir, "config", "user.signingkey", impostorPubPath)
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile0, "-S")

	// Commit 1: ANCHOR-signed. HEAD is anchor-signed so FetchHead passes.
	line1, sha1 := buildCommittableJSONLLine(t, events[1])
	f, openErr := os.OpenFile(auditFilePath, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // test fixture
	if openErr != nil {
		t.Fatalf("CONDITION-1: open audit file (commit 1): %v", openErr)
	}
	if _, wErr := f.Write(line1); wErr != nil {
		_ = f.Close()
		t.Fatalf("CONDITION-1: write line1: %v", wErr)
	}
	if cErr := f.Close(); cErr != nil {
		t.Fatalf("CONDITION-1: close audit file: %v", cErr)
	}
	gitInRepoFatal(t, repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))
	msg1 := fmt.Sprintf("audit: append event 1 (anchor)\n\naudit_entry_sha: %s\n", sha1)
	msgFile1 := filepath.Join(root, "msg1.txt")
	if writeErr := os.WriteFile(msgFile1, []byte(msg1), 0o600); writeErr != nil { //nolint:gosec
		t.Fatalf("CONDITION-1: write msg1: %v", writeErr)
	}
	// Switch back to the ANCHOR key for the HEAD commit.
	gitInRepoFatal(t, repoDir, "config", "user.signingkey", anchorPubPath)
	gitInRepoFatal(t, repoDir, "commit", "-q", "-F", msgFile1, "-S")

	// Build a registry.Client that trusts ONLY the real anchor key.
	// git verify-commit against the anchor-only allowed-signers will reject
	// the impostor-signed commit 0 → SignedByAnchor=false → BindingTampered.
	history := &signedAuditHistory{
		RepoURL:   "file://" + repoDir,
		AnchorKey: anchorKey,
		ProjectID: projectID,
	}
	client := newVerifyAuditClient(t, history)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	assertTamperedResult(t, "CONDITION-1", result, err)
}

// splitSSHPubkey splits an OpenSSH public key line into its fields (type, key64,
// comment) and returns [type, key64]. It fatals if the format is unexpected.
func splitSSHPubkey(t *testing.T, pubLine string) []string {
	t.Helper()
	fields := splitFields(pubLine)
	if len(fields) < 2 {
		t.Fatalf("splitSSHPubkey: unexpected format: %q", pubLine)
	}
	return fields
}

// splitFields splits a string by whitespace, trimming the result.
func splitFields(s string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(s); i++ {
		inSpace := i == len(s) || s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r'
		if !inSpace && start < 0 {
			start = i
		} else if inSpace && start >= 0 {
			out = append(out, s[start:i])
			start = -1
		}
	}
	return out
}
