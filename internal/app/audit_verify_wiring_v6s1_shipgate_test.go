//go:build shipgate

package app_test

// v0.6 S1 positive-composition and security shipgate guards for the contributor
// `audit verify` verb.
//
// Covered:
//   - T-S1-C (B1-T3 + B1-T5 crypto obligation): in CONTRIBUTOR mode,
//     BuildProductionDeps wires deps.AuditVerifier non-nil AND backed by a
//     read-only client (WriteTokenProvider == nil). Non-nil alone is insufficient
//     — a future refactor that moves the type-assertion above the write-reassignment
//     block would pass the non-nil check but silently give the contributor a
//     write-enabled verifier.
//   - T-S1-E (threat AC-001-B): a contributor-mode `audit verify` run against a
//     TAMPERED real-signed-history fixture returns a non-zero exit (ExitTrustError)
//     AND emits the per-line projection. Exit-0-on-tamper is shipgate-class.
//   - T-S1-F (threat checkpoint fail-safe for the new audience): a poisoned or
//     forged checkpoint (wrong HEAD SHA / inflated line count) forces a cold
//     re-walk and yields the SAME verdict as a cold walk. Trust must not flow
//     from the contributor-writable cache file.
//   - Clean-history path: contributor `audit verify` on a well-formed signed
//     history → all BindingVerified, exit 0.
//
// Fixture strategy: builds a real local git repo (t.TempDir()) with SSH-signed
// commits, exactly as the v0.5 registry_auditverify signed-history tests do.
// The fixture code is self-contained in this package to avoid cross-package
// test coupling. Real git + ssh-keygen binaries required; tests hard-fail (not
// skip) when they are absent, per the ship-gate "cannot run = fail" rule.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/adapter/registry/auditverify"
	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/audit"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ─── T-S1-C: positive-composition read-only assertion ────────────────────────

// TestS1_AuditVerifierIsReadOnlyInContributorMode is the T-S1-C guard.
//
// It asserts that in CONTRIBUTOR mode (no admin key) BuildProductionDeps wires
// deps.AuditVerifier backed by a read-only *registryadapter.Client — one whose
// WriteTokenProvider is nil. A write-enabled verifier would allow a registry-
// write credential to flow through the contributor verify path.
//
// Non-nil alone is INSUFFICIENT per the design: the non-nil guard is already
// covered by TestS1_AuditVerifierWiredWhenRegistryConfigured; this test adds
// the read-only dimension explicitly so a refactor that moves the type-assertion
// above the write-reassignment block is caught before ship.
//
// Strategy: uses the D-1 fixture (real file:// registry with a SourceVerified
// anchor-signed HEAD) but sets BYREIS_KEY_FILE to a non-existent path so mode
// detection downgrades to CONTRIBUTOR. In CONTRIBUTOR mode the write-signer is
// never constructed and the regClient used for AuditVerifier is the read-only
// instance.
func TestS1_AuditVerifierIsReadOnlyInContributorMode(t *testing.T) {
	if d1GitMissing() {
		t.Fatalf("T-S1-C: required binary 'git' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}
	if d1SSHKeygenMissing() {
		t.Fatalf("T-S1-C: required binary 'ssh-keygen' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	fx := newD1Fixture(t)

	// Set up a contributor environment: no admin key file (downgrades to CONTRIBUTOR).
	t.Setenv("BYREIS_CONFIG", fx.configDir)
	t.Setenv("BYREIS_CACHE", fx.cacheDir)
	t.Setenv("BYREIS_REGISTRY", fx.registryURL)
	t.Setenv("BYREIS_PROJECT", d1ProjectID)
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile) // no key → CONTRIBUTOR mode
	t.Setenv("BYREIS_SIGN_KEY_FILE", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("T-S1-C: BuildProductionDeps returned error: %v", err)
	}
	if deps == nil {
		t.Fatal("T-S1-C: BuildProductionDeps returned nil deps")
	}
	if deps.AuditVerifier == nil {
		t.Fatalf("T-S1-C: deps.AuditVerifier is nil in CONTRIBUTOR mode — " +
			"the verifier must be wired regardless of mode")
	}

	readOnly, isProductionClient := app.AuditVerifierIsReadOnlyForTest(deps.AuditVerifier)
	if !isProductionClient {
		t.Fatalf("T-S1-C: deps.AuditVerifier is not a *registryadapter.Client — " +
			"production composition must wire the production registry client")
	}
	if !readOnly {
		t.Fatalf("T-S1-C READ-ONLY VIOLATION: deps.AuditVerifier in CONTRIBUTOR mode is " +
			"backed by a write-enabled client (WriteTokenProvider != nil) — " +
			"the contributor verify path must NEVER have a write credential; " +
			"check that the AuditVerifier type-assertion happens before the " +
			"write-reassignment block in BuildProductionDeps")
	}
}

// ─── T-S1-E: tamper → non-zero exit (AC-001-B) ───────────────────────────────

// TestS1_ContributorAuditVerify_TamperedHistory_NonZeroExit is T-S1-E.
//
// AC-001-B assertion: `audit verify` on a TAMPERED real-signed-history fixture
// (a line whose content hash does not match the introducing commit's
// audit_entry_sha) returns ExitTrustError (non-zero) AND emits per-line output.
//
// Exit-0-on-tamper is a shipgate-class defect for the contributor audience
// specifically: contributors run this as a CI tripwire (`|| exit 1`). A false
// clean result is a complete security failure.
//
// The fixture: a clean signed history with one well-formed entry is built;
// then the JSONL file in the repo is tampered by overwriting it directly and
// force-amending the commit, so the on-disk content diverges from the
// audit_entry_sha in the commit body. This simulates a content-hash mismatch.
func TestS1_ContributorAuditVerify_TamperedHistory_NonZeroExit(t *testing.T) {
	if d1GitMissing() {
		t.Fatalf("T-S1-E: required binary 'git' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}
	if d1SSHKeygenMissing() {
		t.Fatalf("T-S1-E: required binary 'ssh-keygen' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	const projectID = "tamper-e2e"
	events := []audit.Event{
		{
			Kind:       audit.EventKindMerge,
			OccurredAt: time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
			Actor:      "admin-1",
			ProjectID:  projectID,
			FileName:   "prod",
			Outcome:    "ok",
		},
	}

	// Build a clean signed history first.
	history := v6s1NewSignedAuditHistory(t, projectID, events)

	// Tamper: overwrite the JSONL file with a different line that does NOT
	// match the audit_entry_sha recorded in the signed commit body.
	tamperedLine := `{"kind":"merge","occurred_at":"2026-05-27T10:00:00Z","actor":"INJECTED","project_id":"tamper-e2e","file":"prod","outcome":"TAMPERED"}` + "\n"
	repoDir := strings.TrimPrefix(history.repoURL, "file://")
	auditFile := filepath.Join(repoDir, "audit", projectID+".jsonl")
	if err := os.WriteFile(auditFile, []byte(tamperedLine), 0o644); err != nil { //nolint:gosec // test fixture under t.TempDir
		t.Fatalf("T-S1-E: overwrite audit file: %v", err)
	}
	// Re-stage and force-amend to create a dirty but still SSH-signed commit
	// whose body still carries the OLD audit_entry_sha — the hash mismatch.
	v6s1GitRun(t, repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))
	v6s1GitRun(t, repoDir, "commit", "--amend", "--no-edit", "-S")

	// Build a registry client and drive audit verify through the CLI layer.
	cacheDir := t.TempDir()
	verifier := v6s1NewVerifyClient(t, history, cacheDir)

	verifyDeps := &cli.Deps{
		Policy:        nil, // nil policy = all modes allowed (belt-and-suspenders)
		CurrentMode:   0,   // ModeContributor
		AuditVerifier: verifier,
	}

	var outBuf, errBuf bytes.Buffer
	root := cli.NewRootCmdWithDeps(verifyDeps)
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"audit", "verify", "--project", projectID})
	runErr := root.Execute()

	if runErr == nil {
		t.Fatal("T-S1-E AC-001-B VIOLATION: `audit verify` on tampered history returned nil error " +
			"(exit 0) — exit-0-on-tamper is a shipgate-class defect for the contributor audience; " +
			"contributors use this as a CI tripwire and a false clean exit is a complete security failure")
	}
	exitCode := cli.ExitCodeOf(runErr)
	if exitCode != int(render.ExitTrustError) {
		t.Errorf("T-S1-E: exit code = %d, want %d (ExitTrustError); error: %v",
			exitCode, render.ExitTrustError, runErr)
	}
	if !errors.Is(runErr, coreregistry.ErrAuditLogTampered) {
		t.Errorf("T-S1-E: error must wrap ErrAuditLogTampered, got: %v", runErr)
	}
	// Per-line projection must be emitted even on tamper (entries ride alongside
	// the error — never a partial-verified-as-clean result).
	if outBuf.Len() == 0 {
		t.Errorf("T-S1-E: stdout is empty on tamper — per-line entries must be rendered " +
			"alongside the non-zero exit so operators can identify the offending line")
	}
}

// ─── T-S1-F: checkpoint fail-safe ────────────────────────────────────────────

// TestS1_ContributorAuditVerify_PoisonedCheckpoint_ForcesColWalk is T-S1-F.
//
// A contributor-poisoned or forged checkpoint (wrong HEAD SHA / inflated line
// count / non-ancestor SHA) must force a cold re-walk and yield the SAME
// verdict as a cold walk. Trust must not flow from the contributor-writable
// cache file.
//
// Two scenarios are covered:
//  1. Wrong HEAD SHA in checkpoint → cold re-walk → same clean verdict.
//  2. Inflated VerifiedLineCount → line count is a display hint only; the walk
//     re-verifies every line regardless and returns the correct count.
//
// Both scenarios assert the result is identical to a cold walk (no checkpoint).
func TestS1_ContributorAuditVerify_PoisonedCheckpoint_ForcesColWalk(t *testing.T) {
	if d1GitMissing() {
		t.Fatalf("T-S1-F: required binary 'git' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}
	if d1SSHKeygenMissing() {
		t.Fatalf("T-S1-F: required binary 'ssh-keygen' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	const projectID = "checkpoint-f"
	events := []audit.Event{
		{
			Kind:       audit.EventKindMerge,
			OccurredAt: time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
			Actor:      "admin-1",
			ProjectID:  projectID,
			FileName:   "prod",
			Outcome:    "ok",
		},
		{
			Kind:       audit.EventKindRotation,
			OccurredAt: time.Date(2026, 5, 27, 10, 1, 0, 0, time.UTC),
			Actor:      "admin-1",
			ProjectID:  projectID,
			FileName:   "prod",
			Outcome:    "ok",
		},
	}

	history := v6s1NewSignedAuditHistory(t, projectID, events)

	t.Run("wrong_head_sha_forces_cold_walk", func(t *testing.T) {
		cacheDir := t.TempDir()

		// Plant a poisoned checkpoint with a wrong HEAD SHA.
		poisonStore, storeErr := auditverify.NewStore(cacheDir, history.repoURL)
		if storeErr != nil {
			t.Fatalf("T-S1-F: NewStore: %v", storeErr)
		}
		poisonedCheckpoint := auditverify.Checkpoint{
			ProjectID:         projectID,
			VerifiedHeadSHA:   "deadbeef00000000000000000000000000000000", // wrong SHA
			VerifiedLineCount: 9999,                                        // inflated
			VerifiedAt:        time.Now(),
		}
		if err := poisonStore.Store(context.Background(), projectID, poisonedCheckpoint); err != nil {
			t.Fatalf("T-S1-F: storing poisoned checkpoint: %v", err)
		}

		// Cold walk (no checkpoint): expected baseline.
		coldCacheDir := t.TempDir()
		coldClient := v6s1NewVerifyClient(t, history, coldCacheDir)
		ctx := context.Background()
		coldResult, coldErr := coldClient.VerifyAuditLog(ctx, projectID)
		if coldErr != nil {
			t.Fatalf("T-S1-F: cold walk returned error: %v", coldErr)
		}

		// Poisoned checkpoint walk: must yield the same result.
		poisonedClient := v6s1NewVerifyClientWithCheckpoint(t, history, cacheDir, poisonStore)
		poisonResult, poisonErr := poisonedClient.VerifyAuditLog(ctx, projectID)
		if poisonErr != nil {
			t.Fatalf("T-S1-F: poisoned-checkpoint walk returned error: %v", poisonErr)
		}

		// Verdict must match: same number of non-synthetic entries and same binding statuses.
		if len(coldResult.Entries) != len(poisonResult.Entries) {
			t.Errorf("T-S1-F: cold walk returned %d entries, poisoned walk returned %d — "+
				"the checkpoint must not affect entry count",
				len(coldResult.Entries), len(poisonResult.Entries))
		}
		for i := range coldResult.Entries {
			if i >= len(poisonResult.Entries) {
				break
			}
			c, p := coldResult.Entries[i], poisonResult.Entries[i]
			if c.BindingStatus != p.BindingStatus {
				t.Errorf("T-S1-F: entry[%d]: cold BindingStatus=%v, poisoned BindingStatus=%v — "+
					"a poisoned checkpoint must not change the binding verdict",
					i, c.BindingStatus, p.BindingStatus)
			}
		}
	})

	t.Run("inflated_line_count_does_not_skip_verification", func(t *testing.T) {
		cacheDir := t.TempDir()

		// Get the real HEAD SHA for the repo.
		repoDir := strings.TrimPrefix(history.repoURL, "file://")
		headSHA := v6s1GitRevParse(t, repoDir, "HEAD")

		// Plant a checkpoint with the correct HEAD SHA but inflated line count.
		// A broken verifier might stop early if it "trusts" the inflated count
		// and thinks it has already verified more lines than exist.
		inflatedStore, storeErr := auditverify.NewStore(cacheDir, history.repoURL)
		if storeErr != nil {
			t.Fatalf("T-S1-F: NewStore: %v", storeErr)
		}
		inflatedCheckpoint := auditverify.Checkpoint{
			ProjectID:         projectID,
			VerifiedHeadSHA:   headSHA,
			VerifiedLineCount: 99999,
			VerifiedAt:        time.Now(),
		}
		if err := inflatedStore.Store(context.Background(), projectID, inflatedCheckpoint); err != nil {
			t.Fatalf("T-S1-F: storing inflated checkpoint: %v", err)
		}

		// The walk must complete and verify all real lines. A verifier that uses
		// VerifiedLineCount as a stop condition would either skip lines or error.
		// A correct verifier ignores the count and re-verifies the commit range.
		client := v6s1NewVerifyClientWithCheckpoint(t, history, cacheDir, inflatedStore)
		result, err := client.VerifyAuditLog(context.Background(), projectID)
		if err != nil {
			t.Fatalf("T-S1-F: inflated-checkpoint walk returned error: %v", err)
		}

		// Count non-synthetic verified entries.
		verified := 0
		for _, e := range result.Entries {
			if e.BindingStatus == rotate.BindingVerified {
				verified++
			}
		}
		if verified != len(events) {
			t.Errorf("T-S1-F: got %d BindingVerified entries, want %d — "+
				"inflated VerifiedLineCount must not cause lines to be skipped",
				verified, len(events))
		}
	})
}

// ─── Clean-history contributor path: exit 0, all BindingVerified ─────────────

// TestS1_ContributorAuditVerify_CleanHistory_ExitZeroAllVerified is the positive
// clean-history path for the contributor audience specifically. A well-formed
// signed history returns all BindingVerified and exit 0 for a CONTRIBUTOR caller.
func TestS1_ContributorAuditVerify_CleanHistory_ExitZeroAllVerified(t *testing.T) {
	if d1GitMissing() {
		t.Fatalf("required binary 'git' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}
	if d1SSHKeygenMissing() {
		t.Fatalf("required binary 'ssh-keygen' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	const projectID = "clean-contrib"
	events := []audit.Event{
		{
			Kind:       audit.EventKindMerge,
			OccurredAt: time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
			Actor:      "admin-1",
			ProjectID:  projectID,
			FileName:   "prod",
			Outcome:    "ok",
		},
	}
	history := v6s1NewSignedAuditHistory(t, projectID, events)
	verifier := v6s1NewVerifyClient(t, history, t.TempDir())

	var outBuf, errBuf bytes.Buffer
	root := cli.NewRootCmdWithDeps(&cli.Deps{
		AuditVerifier: verifier,
	})
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"audit", "verify", "--project", projectID})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	runErr := root.ExecuteContext(ctx)
	if runErr != nil {
		t.Fatalf("clean-history contributor audit verify returned error: %v\nstderr: %s",
			runErr, errBuf.String())
	}
	if cli.ExitCodeOf(runErr) != 0 {
		t.Fatalf("exit code = %d, want 0", cli.ExitCodeOf(runErr))
	}
	// All entries must be BindingVerified.
	if !strings.Contains(outBuf.String(), "verified") {
		t.Errorf("stdout %q must contain verified binding status", outBuf.String())
	}
}

// ─── signed-history fixture harness (self-contained) ─────────────────────────
//
// These helpers are a local copy of the registry_auditverify_signedhistory_test.go
// harness, adapted for use within the app_test package. They are intentionally
// prefixed v6s1_ to avoid name collisions with the D-1 fixture helpers.

type v6s1SignedHistory struct {
	repoURL   string
	anchorKey ed25519.PublicKey
	projectID string
}

// v6s1NewSignedAuditHistory builds a local git repo with one SSH-signed commit
// per event, each appending one JSONL line to audit/<projectID>.jsonl with the
// canonical audit_entry_sha footer.
func v6s1NewSignedAuditHistory(t *testing.T, projectID string, events []audit.Event) *v6s1SignedHistory {
	t.Helper()
	root := t.TempDir()

	// Generate fresh SSH signing key.
	sshKeyPath := filepath.Join(root, "anchor-key")
	sshPubKeyPath := sshKeyPath + ".pub"
	genCmd := exec.CommandContext(t.Context(), "ssh-keygen", //nolint:gosec // known args; path under t.TempDir
		"-t", "ed25519", "-N", "", "-C", "v6s1-anchor", "-q", "-f", sshKeyPath,
	)
	if out, err := genCmd.CombinedOutput(); err != nil {
		t.Fatalf("v6s1NewSignedAuditHistory: ssh-keygen: %v: %s", err, out)
	}
	pubBytes, err := os.ReadFile(sshPubKeyPath)
	if err != nil {
		t.Fatalf("v6s1NewSignedAuditHistory: reading pubkey: %v", err)
	}
	anchorKey := v6s1DecodeSSHEd25519Pubkey(t, string(pubBytes))

	// Build allowed-signers file.
	allowedSignersPath := filepath.Join(root, "allowed-signers")
	pubFields := strings.Fields(strings.TrimSpace(string(pubBytes)))
	if len(pubFields) < 2 {
		t.Fatalf("v6s1NewSignedAuditHistory: unexpected pubkey format: %q", string(pubBytes))
	}
	allowedLine := "byreis-anchor " + pubFields[0] + " " + pubFields[1] + "\n"
	if err := os.WriteFile(allowedSignersPath, []byte(allowedLine), 0o600); err != nil { //nolint:gosec // path under t.TempDir
		t.Fatalf("v6s1NewSignedAuditHistory: writing allowed-signers: %v", err)
	}

	// Initialise the git repo.
	repoDir := filepath.Join(root, "registry")
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("v6s1NewSignedAuditHistory: mkdir repo: %v", err)
	}

	v6s1GitRun(t, repoDir, "init", "-q", "--initial-branch=main")
	v6s1GitRun(t, repoDir, "config", "user.name", "byreis-anchor")
	v6s1GitRun(t, repoDir, "config", "user.email", "anchor@example.com")
	v6s1GitRun(t, repoDir, "config", "gpg.format", "ssh")
	v6s1GitRun(t, repoDir, "config", "user.signingkey", sshPubKeyPath)
	v6s1GitRun(t, repoDir, "config", "gpg.ssh.allowedSignersFile", allowedSignersPath)
	v6s1GitRun(t, repoDir, "config", "commit.gpgsign", "true")

	auditDir := filepath.Join(repoDir, "audit")
	if err := os.MkdirAll(auditDir, 0o750); err != nil {
		t.Fatalf("v6s1NewSignedAuditHistory: mkdir audit: %v", err)
	}
	auditFilePath := filepath.Join(auditDir, projectID+".jsonl")

	for i, ev := range events {
		raw, marshalErr := json.Marshal(ev)
		if marshalErr != nil {
			t.Fatalf("v6s1NewSignedAuditHistory: marshal event[%d]: %v", i, marshalErr)
		}
		line := append(raw, '\n')
		sum := sha256.Sum256(line)
		entrySHA := fmt.Sprintf("%x", sum[:])

		f, openErr := os.OpenFile(auditFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // test fixture under t.TempDir
		if openErr != nil {
			t.Fatalf("v6s1NewSignedAuditHistory: open audit file: %v", openErr)
		}
		if _, writeErr := f.Write(line); writeErr != nil {
			_ = f.Close()
			t.Fatalf("v6s1NewSignedAuditHistory: write line[%d]: %v", i, writeErr)
		}
		_ = f.Close()

		v6s1GitRun(t, repoDir, "add", "--", filepath.Join("audit", projectID+".jsonl"))

		msg := fmt.Sprintf("audit: append event %d\n\naudit_entry_sha: %s\n", i+1, entrySHA)
		msgFile := filepath.Join(root, fmt.Sprintf("msg-%d.txt", i))
		if err := os.WriteFile(msgFile, []byte(msg), 0o600); err != nil { //nolint:gosec // path under t.TempDir
			t.Fatalf("v6s1NewSignedAuditHistory: writing commit msg: %v", err)
		}
		v6s1GitRun(t, repoDir, "commit", "-q", "-F", msgFile, "-S")
	}

	return &v6s1SignedHistory{
		repoURL:   "file://" + repoDir,
		anchorKey: anchorKey,
		projectID: projectID,
	}
}

// v6s1NewVerifyClient builds a registry.Client backed by the real
// productionFetchTransport for VerifyAuditLog calls against a local git repo.
func v6s1NewVerifyClient(t *testing.T, h *v6s1SignedHistory, cacheDir string) *registryadapter.Client {
	t.Helper()
	pt, err := registryadapter.NewProductionFetchTransportFromRunner(registryadapter.SubprocessRunner{}, nil)
	if err != nil {
		t.Fatalf("v6s1NewVerifyClient: NewProductionFetchTransportFromRunner: %v", err)
	}
	fixedNow := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	client, err := registryadapter.New(registryadapter.ClientConfig{
		RegistryURL:    h.repoURL,
		ProjectID:      h.projectID,
		CacheDir:       cacheDir,
		TrustAnchorKey: h.anchorKey,
		Clock:          func() time.Time { return fixedNow },
		FetchTransport: pt,
	})
	if err != nil {
		t.Fatalf("v6s1NewVerifyClient: registry.New: %v", err)
	}
	return client
}

// v6s1NewVerifyClientWithCheckpoint builds a registry.Client with a pre-wired
// checkpoint store. Used by the T-S1-F checkpoint fail-safe tests.
func v6s1NewVerifyClientWithCheckpoint(t *testing.T, h *v6s1SignedHistory, cacheDir string, store *auditverify.Store) *registryadapter.Client {
	t.Helper()
	client := v6s1NewVerifyClient(t, h, cacheDir)
	client.WithAuditVerifierConfig(registryadapter.AuditVerifierConfig{
		CheckpointStore: store,
	})
	return client
}

// v6s1GitRun runs a git command in the given directory. Hard-fails on error.
func v6s1GitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	c := exec.CommandContext(t.Context(), "git", args...) //nolint:gosec // known git args; dir is t.TempDir
	c.Dir = dir
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("v6s1GitRun: git %v in %s: %v: %s", args, dir, err, out)
	}
}

// v6s1GitRevParse returns the full SHA for the given ref (e.g. "HEAD").
func v6s1GitRevParse(t *testing.T, repoDir, ref string) string {
	t.Helper()
	c := exec.CommandContext(t.Context(), "git", "rev-parse", ref) //nolint:gosec // known args
	c.Dir = repoDir
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.Output()
	if err != nil {
		t.Fatalf("v6s1GitRevParse: git rev-parse %s in %s: %v", ref, repoDir, err)
	}
	return strings.TrimSpace(string(out))
}

// v6s1DecodeSSHEd25519Pubkey extracts the raw 32-byte Ed25519 public key from
// an OpenSSH "ssh-ed25519 BASE64 [comment]" line.
func v6s1DecodeSSHEd25519Pubkey(t *testing.T, pubLine string) ed25519.PublicKey {
	t.Helper()
	fields := strings.Fields(strings.TrimSpace(pubLine))
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		t.Fatalf("v6s1DecodeSSHEd25519Pubkey: unexpected format: %q", pubLine)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatalf("v6s1DecodeSSHEd25519Pubkey: base64 decode: %v", err)
	}
	if len(blob) < 4 {
		t.Fatalf("v6s1DecodeSSHEd25519Pubkey: blob too short")
	}
	typeLen := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	keyOffset := 4 + typeLen + 4
	if keyOffset > len(blob) {
		t.Fatalf("v6s1DecodeSSHEd25519Pubkey: malformed blob: typeLen=%d", typeLen)
	}
	keyLen := int(blob[4+typeLen])<<24 | int(blob[5+typeLen])<<16 |
		int(blob[6+typeLen])<<8 | int(blob[7+typeLen])
	if keyOffset+keyLen > len(blob) || keyLen != ed25519.PublicKeySize {
		t.Fatalf("v6s1DecodeSSHEd25519Pubkey: key length %d != %d", keyLen, ed25519.PublicKeySize)
	}
	key := make([]byte, ed25519.PublicKeySize)
	copy(key, blob[keyOffset:keyOffset+keyLen])
	return key
}
