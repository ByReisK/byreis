package registry_test

// Signed-git-history fixture tests for VerifyAuditLog.
//
// This file provides a reusable helper, newSignedAuditHistory, that constructs
// a deterministic local git repository (under t.TempDir()) with one or more
// SSH-signed commits each appending exactly one JSONL line to
// audit/<project>.jsonl, with the commit body embedding the canonical
// audit_entry_sha field.  The resulting file:// repo can be consumed by a
// registry.Client wired with the real productionFetchTransport + SubprocessRunner
// so that VerifyAuditLog exercises its full signed-history walk path.
//
// AC-A clean: a well-formed signed history where every line passes hash
// verification results in AuditVerifyResult where every non-synthetic entry
// carries BindingVerified, FullWalk==true, and no error.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// auditAnchorPrincipal mirrors the fixed principalName constant in the
// fetchtransport package.  The allowed-signers file written by the fixture
// must use this exact string so git verify-commit parses it correctly and
// the verifier's principal-confirmation check passes.
const auditAnchorPrincipal = "byreis-anchor"

// signedAuditHistory is the result of newSignedAuditHistory.
type signedAuditHistory struct {
	// RepoURL is the file:// URL pointing at the local git repo.
	RepoURL string
	// AnchorKey is the raw Ed25519 public key that signed every commit.
	AnchorKey ed25519.PublicKey
	// ProjectID is the project identifier used as the JSONL file basename.
	ProjectID string
	// Events is the ordered list of audit events committed into the repo.
	Events []audit.Event
}

// newSignedAuditHistory builds a deterministic local git repository with
// one SSH-signed commit per event.  Each commit appends exactly one JSONL
// line to audit/<projectID>.jsonl and embeds "audit_entry_sha: <hex>" in
// the commit message body so the audit verifier can bind line-to-commit.
//
// Requirements:
//   - The git and ssh-keygen binaries must be on PATH; the helper skips the
//     calling test via t.Skip when either is absent.
//   - All filesystem work is scoped to t.TempDir(); no ~/.config or real
//     network access occurs.
//   - The injected clock controls audit.Event.OccurredAt so the JSONL is
//     deterministic across runs.
//
// Signature:
//
//	func newSignedAuditHistory(t *testing.T, projectID string, events []audit.Event) *signedAuditHistory
func newSignedAuditHistory(t *testing.T, projectID string, events []audit.Event) *signedAuditHistory {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not on PATH — skipping signed-history test")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen binary not on PATH — skipping signed-history test")
	}

	root := t.TempDir()

	// Step 1: generate a fresh Ed25519 SSH signing key.
	sshKeyPath := filepath.Join(root, "anchor-key")
	sshPubKeyPath := sshKeyPath + ".pub"
	genCmd := exec.CommandContext(t.Context(), "ssh-keygen", //nolint:gosec // known fixed args; path under t.TempDir
		"-t", "ed25519",
		"-N", "",
		"-C", "byreis-audit-anchor",
		"-q",
		"-f", sshKeyPath,
	)
	if out, err := genCmd.CombinedOutput(); err != nil {
		t.Fatalf("newSignedAuditHistory: ssh-keygen: %v: %s", err, out)
	}
	pubBytes, err := os.ReadFile(sshPubKeyPath)
	if err != nil {
		t.Fatalf("newSignedAuditHistory: reading ssh pubkey: %v", err)
	}
	anchorKey := decodeSSHEd25519PubkeyForAudit(t, string(pubBytes))

	// Step 2: build the allowed-signers file so in-repo git verify-commit works.
	allowedSignersPath := filepath.Join(root, "allowed-signers")
	pubFields := strings.Fields(strings.TrimSpace(string(pubBytes)))
	if len(pubFields) < 2 {
		t.Fatalf("newSignedAuditHistory: unexpected ssh pubkey format: %q", string(pubBytes))
	}
	allowedLine := auditAnchorPrincipal + " " + pubFields[0] + " " + pubFields[1] + "\n"
	if err := os.WriteFile(allowedSignersPath, []byte(allowedLine), 0o600); err != nil { //nolint:gosec // path under t.TempDir; content is non-secret pubkey
		t.Fatalf("newSignedAuditHistory: writing allowed-signers: %v", err)
	}

	// Step 3: initialise the git repo and configure SSH signing.
	repoDir := filepath.Join(root, "registry")
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("newSignedAuditHistory: mkdir repo: %v", err)
	}

	runGit := func(dir string, args ...string) {
		t.Helper()
		c := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // args are known git subcommands
		c.Dir = dir
		// Preserve HOME so ssh-keygen / ssh-agent are reachable; suppress
		// system-level git config pollution.
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("newSignedAuditHistory: git %v in %s: %v: %s", args, dir, err, out)
		}
	}

	// Initialise the bare-ish working repo (non-bare: we need the working tree
	// to write audit/ files).
	runGit(repoDir, "init", "-q", "--initial-branch=main")
	runGit(repoDir, "config", "user.name", auditAnchorPrincipal)
	runGit(repoDir, "config", "user.email", "anchor@example.com")
	runGit(repoDir, "config", "gpg.format", "ssh")
	runGit(repoDir, "config", "user.signingkey", sshPubKeyPath)
	runGit(repoDir, "config", "gpg.ssh.allowedSignersFile", allowedSignersPath)
	runGit(repoDir, "config", "commit.gpgsign", "true")

	// Step 4: create the audit directory.
	auditDir := filepath.Join(repoDir, "audit")
	if err := os.MkdirAll(auditDir, 0o750); err != nil {
		t.Fatalf("newSignedAuditHistory: mkdir audit: %v", err)
	}
	auditFilePath := filepath.Join(auditDir, projectID+".jsonl")

	// Step 5: commit one JSONL line per event.
	for i, ev := range events {
		// Serialise the event to canonical JSONL bytes (same logic as production
		// buildAuditJSONLEntry: json.Marshal(event) + "\n").
		raw, marshalErr := json.Marshal(ev)
		if marshalErr != nil {
			t.Fatalf("newSignedAuditHistory: marshal event[%d]: %v", i, marshalErr)
		}
		line := append(raw, '\n')

		// Compute the sha256 hex digest of the JSONL line.
		sum := sha256.Sum256(line)
		entrySHA := fmt.Sprintf("%x", sum[:])

		// Append the line to the audit file (create on first iteration).
		f, openErr := os.OpenFile(auditFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // fixture file under t.TempDir
		if openErr != nil {
			t.Fatalf("newSignedAuditHistory: open audit file: %v", openErr)
		}
		if _, writeErr := f.Write(line); writeErr != nil {
			_ = f.Close()
			t.Fatalf("newSignedAuditHistory: write line[%d]: %v", i, writeErr)
		}
		if closeErr := f.Close(); closeErr != nil {
			t.Fatalf("newSignedAuditHistory: close audit file: %v", closeErr)
		}

		// Stage the audit file.
		runGit(repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))

		// Build the commit message with the required audit_entry_sha footer.
		// The verifier's extractCommitInfo parses "audit_entry_sha: <hex>" from
		// the commit body, so it must appear exactly this way.
		msg := fmt.Sprintf("audit: append %s event %d\n\naudit_entry_sha: %s\n",
			string(ev.Kind), i+1, entrySHA)

		// Write the commit message to a temp file to avoid shell quoting issues.
		msgFile := filepath.Join(root, fmt.Sprintf("commitmsg-%d.txt", i))
		if err := os.WriteFile(msgFile, []byte(msg), 0o600); err != nil { //nolint:gosec // path under t.TempDir
			t.Fatalf("newSignedAuditHistory: writing commit msg: %v", err)
		}

		runGit(repoDir, "commit", "-q", "-F", msgFile, "-S")
	}

	return &signedAuditHistory{
		RepoURL:   "file://" + repoDir,
		AnchorKey: anchorKey,
		ProjectID: projectID,
		Events:    events,
	}
}

// newVerifyAuditClient builds a registry.Client backed by the real
// productionFetchTransport and SubprocessRunner, suitable for calling
// VerifyAuditLog against a local git repo.
func newVerifyAuditClient(t *testing.T, history *signedAuditHistory) *registry.Client {
	t.Helper()

	pt, err := registry.NewProductionFetchTransportFromRunner(registry.SubprocessRunner{}, nil)
	if err != nil {
		t.Fatalf("newVerifyAuditClient: NewProductionFetchTransportFromRunner: %v", err)
	}

	fixedNow := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	client, err := registry.New(registry.ClientConfig{
		RegistryURL:    history.RepoURL,
		ProjectID:      history.ProjectID,
		CacheDir:       t.TempDir(),
		TrustAnchorKey: history.AnchorKey,
		Clock:          func() time.Time { return fixedNow },
		FetchTransport: pt,
	})
	if err != nil {
		t.Fatalf("newVerifyAuditClient: registry.New: %v", err)
	}
	return client
}

// decodeSSHEd25519PubkeyForAudit extracts the raw 32-byte Ed25519 public key
// from an OpenSSH "ssh-ed25519 BASE64 [comment]" line.  It is a local copy of
// the identical helper in the shipgate test so the registry test package does
// not import an internal test package.
func decodeSSHEd25519PubkeyForAudit(t *testing.T, pubLine string) ed25519.PublicKey {
	t.Helper()
	fields := strings.Fields(strings.TrimSpace(pubLine))
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		t.Fatalf("decodeSSHEd25519PubkeyForAudit: unexpected format: %q", pubLine)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatalf("decodeSSHEd25519PubkeyForAudit: base64-decode: %v", err)
	}
	if len(blob) < 4 {
		t.Fatalf("decodeSSHEd25519PubkeyForAudit: blob too short")
	}
	typeLen := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	keyOffset := 4 + typeLen + 4
	if keyOffset > len(blob) {
		t.Fatalf("decodeSSHEd25519PubkeyForAudit: malformed blob: typeLen=%d", typeLen)
	}
	keyLen := int(blob[4+typeLen])<<24 | int(blob[5+typeLen])<<16 |
		int(blob[6+typeLen])<<8 | int(blob[7+typeLen])
	if keyOffset+keyLen > len(blob) || keyLen != ed25519.PublicKeySize {
		t.Fatalf("decodeSSHEd25519PubkeyForAudit: key length %d != %d", keyLen, ed25519.PublicKeySize)
	}
	key := make([]byte, ed25519.PublicKeySize)
	copy(key, blob[keyOffset:keyOffset+keyLen])
	return key
}

// buildTestAuditEvents returns a small ordered set of well-formed audit.Event
// values suitable for the signed-history harness.  OccurredAt is pinned to a
// deterministic value so the JSONL bytes are byte-stable across runs.
func buildTestAuditEvents(projectID string) []audit.Event {
	base := time.Date(2026, 5, 26, 10, 0, 0, 0, time.UTC)
	return []audit.Event{
		{
			Kind:       audit.EventKindMerge,
			OccurredAt: base,
			Actor:      "admin-1",
			ProjectID:  projectID,
			FileName:   "prod",
			Outcome:    "ok",
		},
		{
			Kind:       audit.EventKindRotation,
			OccurredAt: base.Add(time.Minute),
			Actor:      "admin-1",
			ProjectID:  projectID,
			FileName:   "prod",
			Outcome:    "ok",
		},
		{
			Kind:       audit.EventKindMerge,
			OccurredAt: base.Add(2 * time.Minute),
			Actor:      "admin-2",
			ProjectID:  projectID,
			FileName:   "staging",
			Outcome:    "ok",
		},
	}
}

// ---- AC-A: clean signed history → all BindingVerified, FullWalk true --------

// TestAuditVerify_ACA_CleanSignedHistory_AllBindingVerified verifies that
// VerifyAuditLog on a well-formed signed registry history returns every
// non-synthetic entry as BindingVerified, produces no error, and sets
// FullWalk: true (AC-A clean path).
//
// The test builds a real local git repo (under t.TempDir()) with three
// SSH-signed commits each appending one JSONL line to audit/<project>.jsonl,
// where each commit body carries the canonical "audit_entry_sha: <hex>" field.
// A registry.Client backed by the real productionFetchTransport and
// SubprocessRunner then calls VerifyAuditLog against the file:// URL.
func TestAuditVerify_ACA_CleanSignedHistory_AllBindingVerified(t *testing.T) {
	// Not parallel: spawns real git subprocesses; serialising avoids temp-dir
	// contention and keeps log output legible.

	const projectID = "testproject"
	events := buildTestAuditEvents(projectID)
	history := newSignedAuditHistory(t, projectID, events)

	client := newVerifyAuditClient(t, history)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	result, err := client.VerifyAuditLog(ctx, projectID)
	if err != nil {
		t.Fatalf("AC-A: VerifyAuditLog returned unexpected error: %v", err)
	}
	if !result.FullWalk {
		t.Errorf("AC-A: FullWalk = false, want true (cold full walk expected on first call)")
	}

	// Collect all non-synthetic entries and assert each is BindingVerified.
	nonSynthetic := 0
	for i, e := range result.Entries {
		if e.Unknown || e.Kind == "truncated" || e.Kind == "malformed-line" {
			// Synthetic row: BindingMissing is correct by construction.
			continue
		}
		nonSynthetic++
		if e.BindingStatus != rotate.BindingVerified {
			t.Errorf("AC-A: entry[%d] kind=%q BindingStatus=%v, want BindingVerified",
				i, e.Kind, e.BindingStatus)
		}
	}
	if nonSynthetic == 0 {
		t.Errorf("AC-A: no non-synthetic entries returned — history has %d events", len(events))
	}
	if nonSynthetic != len(events) {
		t.Errorf("AC-A: got %d non-synthetic entries, want %d", nonSynthetic, len(events))
	}

	t.Logf("AC-A: VerifyAuditLog returned %d entries (%d non-synthetic), all BindingVerified, FullWalk=%v",
		len(result.Entries), nonSynthetic, result.FullWalk)
}
