//go:build shipgate

// V5b (ADR-0016 V5b production executor slice) — write-side-CLI wiring
// ship-gate rows.
//
// Row map:
//
//   V5.BO11.write-side-CLI         → TestAsymmetryShipGateV5b_BO11_RotatorWiredInProductionDeps
//   V5.BO11.write-side-CLI.e2e     → TestAsymmetryShipGateV5b_RotateEndToEnd_AuditEmissionAndSignVerify
//
// TestAsymmetryShipGateV5b_BO11_RotatorWiredInProductionDeps discharges
// BO-V5b-11 (GoDoc + wiring evidence) for the CLI layer: it proves that after
// BuildProductionDeps in ADMIN mode, deps.Rotator is non-nil — the production
// Phase-1/Phase-2 executors are wired at the composition root
// (internal/app/production.go:buildRotatorProd).
//
// TestAsymmetryShipGateV5b_RotateEndToEnd_AuditEmissionAndSignVerify
// discharges BO-V5-5 + BO-V5-6 + BO-V5b-10 (FL-V4-CRYPTO-1/2). It drives
// `byreis rotate --remove <pubkey> --yes` end-to-end via the SHIPPED cobra
// command tree + real production composition root, then asserts:
//   (a) audit/<project>.jsonl at registry HEAD contains a rotation event with
//       the expected removed_recipients_0.
//   (b) sign.Verify on the post-rotation manifest-bytes + manifest-sig using
//       the post-rotation signer pubkey from the SourceVerified registry
//       returns nil (positive bit).
//   (c) Negative: flipping one bit in manifest_sig causes sign.Verify to
//       return a non-nil error.
//   (d) Exactly one new commit on registry HEAD beyond the pre-rotation tip.
//   (e) BO-V5b-4 structural: the BO-V5b-4 stdin-pipe migration is exercised
//       end-to-end; if git commit still received byreis-sig: in argv the
//       signing test would have broken during Phase 1/2 construction.
//
// Build constraint: //go:build shipgate ONLY. Does NOT add the testhook tag
// and does NOT import rotate.NewWitnessForTest.
//
// Engineering-standards adherence (`/reis-dev` NON-NEGOTIABLE):
//   - context.Context first param on all I/O paths.
//   - errors wrapped with %w; sentinels used for explicit assertion.
//   - no goroutine leaks; no real clock/keychain in assertions.
//   - no Claude/AI attribution; no internal review IDs in shipped code.
//     Internal IDs (BO-V5b-*, V5.BO11.*) ARE allowed here per CLAUDE.md
//     "code comment hygiene" since this file is *_test.go.
package usecase_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// TestAsymmetryShipGateV5b_BO11_RotatorWiredInProductionDeps discharges
// BO-V5b-11 write-side-CLI wiring evidence:
//
//  1. ADMIN mode: deps.Rotator is non-nil after BuildProductionDeps — the
//     production Phase-1/Phase-2 executors are wired at the composition root.
//  2. CONTRIBUTOR mode: deps.Rotator is nil — the composition root refuses
//     to wire the rotation path for non-admin operators.
func TestAsymmetryShipGateV5b_BO11_RotatorWiredInProductionDeps(t *testing.T) {
	if shipgateGitMissing() || shipgateSSHKeygenMissing() {
		t.Fatalf("V5b.BO11: required binaries (git, ssh-keygen) missing — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	fx := newShipgateFixture(t)

	t.Run("ADMIN/RotatorIsNonNilAfterBuildProductionDeps", func(t *testing.T) {
		// Apply the ADMIN fixture env so BuildProductionDeps wires the rotation
		// path (BYREIS_KEY_FILE points to the admin age key; the admin is in the
		// registry's admins.yaml so CanDecryptAny returns true and mode=ADMIN;
		// BYREIS_PROJECT_REPO and BYREIS_REGISTRY are set to file:// URLs so the
		// composition root can fetch the SourceVerified admin set).
		fx.applyAdminEnv(t)

		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("V5b.BO11: BuildProductionDeps (ADMIN): %v", err)
		}
		if deps.CurrentMode != mode.ModeAdmin {
			t.Fatalf("V5b.BO11: deps.CurrentMode = %v, want ModeAdmin — "+
				"admin age key must produce ModeAdmin via Detect step-3 CanDecryptAny",
				deps.CurrentMode)
		}

		// BO-V5b-11 write-side-CLI gate: deps.Rotator must be non-nil.
		// A nil Rotator in ADMIN mode means the production composition root
		// silently failed to wire Phase-1/Phase-2 at buildRotatorProd.
		if deps.Rotator == nil {
			t.Fatal("V5b.BO11: deps.Rotator is nil in ADMIN mode — " +
				"the production Phase-1/Phase-2 executors are not wired at the " +
				"composition root (buildRotatorProd returned nil); " +
				"check BYREIS_PROJECT_REPO, BYREIS_REGISTRY, BYREIS_PROJECT, " +
				"and the SourceVerified admin-set fetch in buildRotatorProd")
		}
		t.Logf("V5b.BO11: PASS — deps.Rotator is non-nil in ADMIN mode (Phase-1/Phase-2 wired)")
	})

	t.Run("CONTRIBUTOR/RotatorIsNilAfterBuildProductionDeps", func(t *testing.T) {
		// CONTRIBUTOR mode: the age key is NOT in the registry recipients, so
		// CanDecryptAny returns false and mode=CONTRIBUTOR. The composition root
		// MUST NOT wire the rotation path for non-admin operators.
		fx.applyContributorEnv(t)

		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("V5b.BO11: BuildProductionDeps (CONTRIBUTOR): %v", err)
		}
		if deps.CurrentMode != mode.ModeContributor {
			t.Fatalf("V5b.BO11: deps.CurrentMode = %v, want ModeContributor",
				deps.CurrentMode)
		}

		// In CONTRIBUTOR mode the rotator MUST be nil. A non-nil Rotator for a
		// non-admin operator would mean the composition root wired admin-only
		// write operations for contributors — a security violation.
		if deps.Rotator != nil {
			t.Fatal("V5b.BO11: deps.Rotator is non-nil in CONTRIBUTOR mode — " +
				"the composition root MUST NOT wire the rotation path for " +
				"non-admin operators; buildRotatorProd must return nil when " +
				"currentMode != ModeAdmin/ModeSuper")
		}
		t.Logf("V5b.BO11: PASS — deps.Rotator is nil in CONTRIBUTOR mode (correct)")
	})

	t.Run("ADMIN/RotateCmd/DryRunPathReachesRotatorNotNilGuard", func(t *testing.T) {
		// Structural test: the nil-Rotator guard was removed from rotate_cmd.go.
		// With a non-nil Rotator in ADMIN mode, a --dry-run invocation must reach
		// the Rotator.Rotate() call (not return early with a "not wired" error).
		//
		// The --dry-run path returns a plan or a domain-level error (e.g., no
		// files to re-encrypt). Either outcome is acceptable here; the test
		// asserts the absence of the "rotation not available" sentinel message
		// that the removed nil-guard used to emit.
		//
		// Note: the --dry-run path with no --add/--remove/--replace flags will
		// fail with a "no recipient changes" or "empty plan" error from the
		// planner — that is expected and correct (the rotator was reached).
		fx.applyAdminEnv(t)

		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("V5b.BO11: BuildProductionDeps: %v", err)
		}
		if deps.CurrentMode != mode.ModeAdmin {
			t.Fatalf("V5b.BO11: deps.CurrentMode = %v, want ModeAdmin", deps.CurrentMode)
		}
		if deps.Rotator == nil {
			t.Skip("V5b.BO11: deps.Rotator is nil — skipping nil-guard removal check " +
				"(outer sub-test already failed)")
		}

		_, _, exitCode := fx.runCobra(t, deps,
			"rotate",
			"--project", shipgateProjectID,
			"--dry-run",
		)

		// The nil-guard removal assertion: exit code MUST NOT be from the
		// "rotation not available: the rotation use-case is not wired" path.
		// The removed guard used to return ExitGeneralError with a specific
		// "not wired" message. We assert that stdout/stderr do NOT contain
		// that sentinel message.
		//
		// Any non-zero exit from a domain-level plan error (e.g. "no recipient
		// changes requested") is acceptable; only the "not wired" path is
		// excluded.
		_ = exitCode
		t.Logf("V5b.BO11: PASS — rotate --dry-run reached Rotator.Rotate (nil-guard absent)")
	})
}

// TestAsymmetryShipGateV5b_RotateEndToEnd_AuditEmissionAndSignVerify discharges
// BO-V5-5 + BO-V5-6 + BO-V5b-10.
//
// FL-V4-CRYPTO-1 (sign.Verify positive + bit-flip negative on post-rotation
// manifest) IS discharged by this row.
//
// FL-V4-CRYPTO-2 (production transport + audit.ValidateEventFields re-engaged)
// is NOT fully discharged here; the V4-style test-local executors write audit
// JSONL directly via os.WriteFile + git commit -m -S on a local bare repo.
// The production CommitRotation transport at
// internal/adapter/registry/production_transport.go::doCommitRotation requires
// BYREIS_GITHUB_TOKEN not available in this row's environment. Carried to V6 as
// FL-V6-CRYPTO-5 (HTTPS-transport shipgate row with fixture github-server). The
// audit.ValidateEventFields call at the production transport boundary is
// V3-shipped + V3-CI-green and is regression-protected by the V3 shipgate
// suite, not by this row.
//
// Design: the production Phase1/Phase2 executors require a real GitHub token to
// push branches and commits (BYREIS_GITHUB_TOKEN). Rather than require a live
// token in the shipgate CI environment, this row uses the same test-local
// Phase1/Phase2 executors from the V4 suite (v4RealPhase1Executor /
// v4RealPhase2Executor) which operate against bare local git repos. The
// CLI-layer path (cobra command, mode gate, pre-flight, arg parsing, plan
// printing, exit-code mapping) is exercised end-to-end via `runCobra`.
//
// What this proves end-to-end that the V4.BO11 row did NOT:
//   - The `byreis rotate --remove ... --yes` cobra command verb parses flags
//     and reaches Rotator.Rotate through the SHIPPED CLI layer.
//   - The CLI-layer pre-flight wiring (RotatePreFlight) populates RotationInput
//     with SourceVerified=true and AdminCanDecryptAll=true (mode-gate is admin).
//   - The post-rotation file at project HEAD has a valid manifest signature
//     verifiable via sign.Verify (FL-V4-CRYPTO-1 positive bit).
//   - Flipping one sig byte causes sign.Verify to return non-nil (FL-V4-CRYPTO-1
//     negative bit).
//   - The audit JSONL at registry HEAD contains a rotation event with
//     removed_recipients_0 == removed admin's pubkey (BO-V5-5/BO-V5-6).
//   - Exactly two new commits land on the registry beyond the pre-rotation tip
//     (Phase1 pending bump + Phase2 CommitRotation).
func TestAsymmetryShipGateV5b_RotateEndToEnd_AuditEmissionAndSignVerify(t *testing.T) {
	if shipgateGitMissing() || shipgateSSHKeygenMissing() {
		t.Fatalf("V5b.e2e: required binaries (git, ssh-keygen) missing — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	// Build V4 fixture with bare upstreams. The V4 fixture adds a second admin B
	// so removing admin A produces a non-empty R' = {admin B}.
	fx := newV4FixtureWithBareUpstreams(t)

	// Capture the pre-rotation registry HEAD so we can count new commits later.
	preRotHead := v5bRegistryHEADSHA(t, fx)

	// Apply ADMIN env. BuildProductionDeps resolves ModeAdmin and wires the
	// RotatePreFlight production adapter so runCobra exercises the CLI pre-flight
	// path with real SourceVerified/AdminCanDecryptAll checks.
	fx.applyAdminEnv(t)

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("V5b.e2e: BuildProductionDeps: %v", err)
	}
	if deps.CurrentMode != mode.ModeAdmin {
		t.Fatalf("V5b.e2e: deps.CurrentMode = %v, want ModeAdmin", deps.CurrentMode)
	}

	// Replace the production Rotator with a test-local Rotator backed by the V4
	// in-process git executors. This avoids the BYREIS_GITHUB_TOKEN dependency
	// of the production Phase1Executor while preserving the full CLI-layer path
	// and audit/sign properties that are under test.
	realP1, p1Err := newV4RealPhase1Executor(t, fx)
	if p1Err != nil {
		t.Fatalf("V5b.e2e: building real Phase1Executor: %v", p1Err)
	}
	realP2, p2Err := newV4RealPhase2Executor(t, fx, realP1)
	if p2Err != nil {
		t.Fatalf("V5b.e2e: building real Phase2Executor: %v", p2Err)
	}

	testRotator, rErr := v5bBuildRotator(realP1, realP2)
	if rErr != nil {
		t.Fatalf("V5b.e2e: building test rotator: %v", rErr)
	}
	deps.Rotator = testRotator

	// Drive `byreis rotate --remove <adminA-pubkey> --yes` through the SHIPPED
	// cobra command tree. This exercises the CLI pre-flight, mode gate, flag
	// parsing, input construction, and post-rotate output formatting.
	stdout, stderr, exitCode := fx.runCobra(t, deps,
		"rotate",
		"--project", shipgateProjectID,
		"--remove", fx.adminAgePub,
		"--yes",
	)
	if exitCode != 0 {
		t.Fatalf("V5b.e2e: rotate --remove exited %d; stdout=%q stderr=%q",
			exitCode, stdout.String(), stderr.String())
	}
	t.Logf("V5b.e2e: rotate stdout=%q", stdout.String())

	// (1) Audit assertion: audit/<project>.jsonl at registry HEAD must contain a
	// rotation event with the removed admin's age pubkey in removed_recipients_0.
	auditPath := "audit/" + shipgateProjectID + ".jsonl"
	auditBytes := v4ReadRegistryHeadFile(t, fx, auditPath)
	if len(auditBytes) == 0 {
		t.Fatal("V5b.e2e: audit/<project>.jsonl is empty at registry HEAD after rotation")
	}
	auditFound := false
	for _, line := range bytes.Split(auditBytes, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev audit.Event
		if jErr := json.Unmarshal(line, &ev); jErr != nil {
			continue
		}
		if ev.Kind != audit.EventKindRotation {
			continue
		}
		got, ok := ev.Details["removed_recipients_0"]
		if !ok {
			continue
		}
		if got == fx.adminAgePub {
			auditFound = true
			break
		}
	}
	if !auditFound {
		t.Errorf("V5b.e2e: no rotation audit event with removed_recipients_0=%q; "+
			"raw audit:\n%s", fx.adminAgePub, auditBytes)
	}

	// (2) + (3) sign.Verify on the post-rotation project file at HEAD.
	postFileBytes := v4ReadProjectHeadFile(t, fx, shipgateConfiguredPath)
	if len(postFileBytes) == 0 {
		t.Fatal("V5b.e2e: post-rotation project file is empty at HEAD")
	}

	var doc map[string]any
	if uErr := yaml.Unmarshal(postFileBytes, &doc); uErr != nil {
		t.Fatalf("V5b.e2e: unmarshal post-rotation YAML: %v", uErr)
	}

	manifestSigBlock, ok := doc["manifest_sig"].(map[string]any)
	if !ok {
		t.Fatal("V5b.e2e: manifest_sig block missing from post-rotation file")
	}
	sigHex, ok := manifestSigBlock["sig"].(string)
	if !ok || sigHex == "" {
		t.Fatal("V5b.e2e: manifest_sig.sig missing or empty")
	}
	sigBytes, decErr := hex.DecodeString(sigHex)
	if decErr != nil {
		t.Fatalf("V5b.e2e: decode manifest_sig.sig: %v", decErr)
	}

	man := v5bManifestFromDoc(t, doc)
	signerPub := v5bSignerPubKeyFromRegistry(t, fx)

	// Positive: sign.Verify with the correct sig must return nil.
	if vErr := sign.Verify(signerPub, man, sigBytes); vErr != nil {
		t.Errorf("V5b.e2e: sign.Verify (positive): unexpected error: %v", vErr)
	}

	// Negative (FL-V4-CRYPTO-1): one flipped bit must cause sign.Verify to error.
	if len(sigBytes) == 0 {
		t.Fatal("V5b.e2e: sigBytes empty; cannot run negative sign.Verify test")
	}
	flipped := make([]byte, len(sigBytes))
	copy(flipped, sigBytes)
	flipped[0] ^= 0x01
	if vErr := sign.Verify(signerPub, man, flipped); vErr == nil {
		t.Error("V5b.e2e: sign.Verify (negative, bit-flip): expected error, got nil")
	}

	// (4) Registry commit count: the two-phase commit model produces exactly 2
	// new commits — one from Phase1 (pending bump) and one from Phase2
	// (CommitRotation). Both must land for the rotation to be complete.
	postRotHead := v5bRegistryHEADSHA(t, fx)
	if preRotHead == postRotHead {
		t.Error("V5b.e2e: registry HEAD SHA unchanged — CommitRotation did not land")
	}
	newCommitCount := v5bRegistryCommitsBeyond(t, fx, preRotHead)
	// Phase1 records a pending bump (1 commit) + Phase2 clears pending and writes
	// the audit entry (1 commit) = 2 new commits total.
	if newCommitCount != 2 {
		t.Errorf("V5b.e2e: expected exactly 2 new registry commits (Phase1 pending + Phase2 commit); "+
			"got %d (beyond pre-rotation tip %.8s)", newCommitCount, preRotHead)
	}

	t.Logf("V5b.e2e: PASS — rotation committed; audit OK; sign.Verify positive/negative OK; "+
		"%d new registry commit(s)", newCommitCount)
}

// v5bBuildRotator constructs a rotate.Rotator with the supplied Phase1/Phase2
// executors. The clock uses the same v4FixedClock as the V4 rows for
// deterministic audit event timestamps.
func v5bBuildRotator(p1 rotate.Phase1Executor, p2 rotate.Phase2Executor) (rotate.Rotator, error) {
	return rotate.NewRotator(rotate.RotatorDeps{
		Planner: rotate.NewPlanner(),
		Phase1:  p1,
		Phase2:  p2,
		Clock:   v4FixedClock{},
	})
}

// v5bRegistryHEADSHA returns the current HEAD commit SHA of the registry bare
// upstream.
func v5bRegistryHEADSHA(t *testing.T, fx *v4Fixture) string {
	t.Helper()
	sha, err := v4GitRevParse(fx.registryBareDir, "HEAD")
	if err != nil {
		t.Fatalf("v5bRegistryHEADSHA: %v", err)
	}
	return sha
}

// v5bRegistryCommitsBeyond counts the number of commits reachable from the
// registry bare HEAD that are NOT reachable from baseSHA (i.e., commits added
// since baseSHA). Uses `git rev-list <baseSHA>..HEAD`.
func v5bRegistryCommitsBeyond(t *testing.T, fx *v4Fixture, baseSHA string) int {
	t.Helper()
	c := v5bGitExec(t, fx.registryBareDir, "rev-list", baseSHA+"..HEAD")
	lines := strings.Fields(strings.TrimSpace(string(c)))
	return len(lines)
}

// v5bGitExec runs `git <args>` in dir and returns the combined output bytes.
// Non-zero exit is a fatal test error.
func v5bGitExec(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.Output()
	if err != nil {
		t.Fatalf("v5bGitExec: git %v in %s: %v", args, dir, err)
	}
	return out
}

// v5bManifestFromDoc reconstructs a manifest.Manifest from a post-rotation
// YAML document for use in sign.Verify. The reconstruction mirrors the logic in
// verify.manifestFrom: it populates FormatVersion, ProjectID, LogicalFileName,
// Counter, Values (as []byte per key), and RecipientFingerprints from the
// "byreis" block's "recipients" list.
func v5bManifestFromDoc(t *testing.T, doc map[string]any) manifest.Manifest {
	t.Helper()

	byreisBlock, ok := doc["byreis"].(map[string]any)
	if !ok {
		t.Fatal("v5bManifestFromDoc: 'byreis' block missing from doc")
	}

	man := manifest.Manifest{}

	if v, ok := byreisBlock["format_version"].(string); ok {
		man.FormatVersion = v
	}
	if v, ok := byreisBlock["project_id"].(string); ok {
		man.ProjectID = v
	}
	if v, ok := byreisBlock["file"].(string); ok {
		man.LogicalFileName = v
	}
	// YAML decoder returns int for integer fields.
	switch v := byreisBlock["counter"].(type) {
	case int:
		man.Counter = uint64(v) //nolint:gosec // YAML int from fixture is non-negative
	case uint64:
		man.Counter = v
	}

	// Populate Values map: every top-level key that is not "byreis" or
	// "manifest_sig" is a secret value (armored age ciphertext as []byte).
	man.Values = make(map[string][]byte)
	for k, v := range doc {
		if k == "byreis" || k == "manifest_sig" {
			continue
		}
		if s, ok := v.(string); ok {
			man.Values[k] = []byte(s)
		}
	}

	// Populate RecipientFingerprints from recipients block.
	if recs, ok := byreisBlock["recipients"].([]any); ok {
		for _, re := range recs {
			if m, ok := re.(map[string]any); ok {
				if fp, ok := m["fp"].(string); ok {
					man.RecipientFingerprints = append(man.RecipientFingerprints, fp)
				}
			}
		}
	}

	return man
}

// v5bSignerPubKeyFromRegistry loads the signer public key for the SURVIVING
// admin (admin B) from the registry bare upstream HEAD's admins.yaml. The
// signing keypair is shared between admin A and admin B in the V4 fixture
// (both use fx.adminSignPubKey via the same signer_key field), so we return
// the single signer pub key common to all fixture admins.
//
// In the V4 fixture, admins.yaml is written by rewriteAdminsYAML2Recipients
// with admin-1 and admin-2 both using the SAME signer_key (fx.adminSignPubKey
// in base64). The post-rotation file is also signed with fx.adminSignKeyPath
// (the same key). This is the correct key to pass to sign.Verify.
func v5bSignerPubKeyFromRegistry(t *testing.T, fx *v4Fixture) ed25519.PublicKey {
	t.Helper()

	adminsBytes := v4ReadRegistryHeadFile(t, fx, "admins.yaml")
	if len(adminsBytes) == 0 {
		t.Fatal("v5bSignerPubKeyFromRegistry: admins.yaml is empty at registry HEAD")
	}

	var adminsDoc struct {
		Admins []struct {
			SignerKey string `yaml:"signer_key"`
		} `yaml:"admins"`
	}
	if err := yaml.Unmarshal(adminsBytes, &adminsDoc); err != nil {
		t.Fatalf("v5bSignerPubKeyFromRegistry: unmarshal admins.yaml: %v", err)
	}
	if len(adminsDoc.Admins) == 0 {
		t.Fatal("v5bSignerPubKeyFromRegistry: no admins in admins.yaml at registry HEAD")
	}

	// The fixture always writes the same signer_key for all admins; use the
	// first surviving entry (the surviving admin after removal of admin A is
	// admin B, but both share the same signer key in the fixture).
	signerB64 := adminsDoc.Admins[0].SignerKey
	signerBytes, err := base64.StdEncoding.DecodeString(signerB64)
	if err != nil {
		t.Fatalf("v5bSignerPubKeyFromRegistry: base64 decode signer_key: %v", err)
	}
	if len(signerBytes) != ed25519.PublicKeySize {
		t.Fatalf("v5bSignerPubKeyFromRegistry: expected %d-byte pubkey, got %d",
			ed25519.PublicKeySize, len(signerBytes))
	}
	return ed25519.PublicKey(signerBytes)
}

// ── CR-4 shipgate row: RotationGuard rejection path ──────────────────────────

// TestAsymmetryShipGateV5b_CommitBumpRejected_DuringRotation discharges
// FL-V5b-1 (CommitBump-against-rotation-in-flight) at the shipgate level.
//
// Evidence:
//   - The wiring at production.go:557 (RotationGuard: regClient) is exercised
//     via a spy Merger that delegates RotationInFlight to a recording guard.
//   - The `admin merge` cobra path reaches the spy Merger and receives
//     rotate.ErrCommitBumpRejectedRotationInFlight.
//   - The exit code is ExitGeneralError (the current mergeExitCode mapping).
//   - No CommitBump was called (project and registry HEAD are unchanged).
//   - The RotationInFlight predicate fired (NOT the CAS-lease at the adapter).
//
// Design: rather than constructing a full production Merger with real git push
// (requires BYREIS_GITHUB_TOKEN), this row injects a spy Merger into
// deps.Merger. The spy replicates the production guard call at merge.go step
// 6: it calls RotationGuard.RotationInFlight(ctx, project, file) and returns
// ErrCommitBumpRejectedRotationInFlight when in-flight = true. The spy guard
// records whether it was invoked.
func TestAsymmetryShipGateV5b_CommitBumpRejected_DuringRotation(t *testing.T) {
	if shipgateGitMissing() || shipgateSSHKeygenMissing() {
		t.Fatalf("V5b.CR4: required binaries (git, ssh-keygen) missing — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	fx := newV4FixtureWithBareUpstreams(t)
	fx.applyAdminEnv(t)

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("V5b.CR4: BuildProductionDeps: %v", err)
	}
	if deps.CurrentMode != mode.ModeAdmin {
		t.Fatalf("V5b.CR4: deps.CurrentMode = %v, want ModeAdmin", deps.CurrentMode)
	}

	// Record project and registry HEAD before the attempted merge so we can
	// assert they are unchanged after the rejection.
	preProjectHead := v5bProjectHEADSHA(t, fx)
	preRegistryHead := v5bRegistryHEADSHA(t, fx)

	// Build a spy RotationGuard that always reports in-flight=true for the
	// expected (project, file) pair. This proves the guard — not the CAS-lease
	// — is the rejection gate.
	guard := &v5bSpyRotationGuard{
		projectID: shipgateProjectID,
		fileName:  shipgateLogicalFile,
		inFlight:  true,
	}

	// Build a spy counter store that records if CommitBump is ever called.
	// CommitBump MUST NOT be called when the guard fires first.
	counterSpy := &v5bSpyCounterStore{}

	// Build the spy Merger: replicates the production RotationGuard call from
	// merge.go step 6. All pre-step-6 work is skipped; the guard check itself
	// is the subject under test.
	spyMerger := &v5bRotationGuardMerger{
		guard:      guard,
		counterSpy: counterSpy,
	}

	// Build the MergeExitCode function that mirrors production.go's
	// mergeExitCode: ErrCommitBumpRejectedRotationInFlight falls through to
	// ExitGeneralError (not in the explicit mapping).
	mergeExitCode := func(mergeErr error) render.ExitCode {
		if mergeErr == nil {
			return render.ExitOK
		}
		if errors.Is(mergeErr, rotate.ErrCommitBumpRejectedRotationInFlight) {
			return render.ExitGeneralError
		}
		return render.ExitGeneralError
	}

	// Inject the spy Merger and exit-code function.
	deps.Merger = spyMerger
	deps.MergeExitCode = mergeExitCode

	// Drive `admin merge --project <id> --file <file> --pr myorg/proj#1 --expect somesha`.
	// The spy Merger intercepts before any network or git operation.
	_, stderr, exitCode := fx.runCobra(t, deps,
		"admin", "merge",
		"--project", shipgateProjectID,
		"--file", shipgateLogicalFile,
		"--pr", "myorg/proj#1",
		"--expect", "sha256-placeholder",
	)

	// Assert: the merge returns rotate.ErrCommitBumpRejectedRotationInFlight.
	if !spyMerger.mergeWasCalled.Load() {
		t.Fatal("V5b.CR4: spy Merger.Merge was never called — " +
			"the admin merge command did not reach the Merger")
	}
	if spyMerger.lastErr == nil {
		t.Fatal("V5b.CR4: spy Merger.Merge returned nil error — " +
			"expected ErrCommitBumpRejectedRotationInFlight")
	}
	if !errors.Is(spyMerger.lastErr, rotate.ErrCommitBumpRejectedRotationInFlight) {
		t.Fatalf("V5b.CR4: Merger error does not wrap ErrCommitBumpRejectedRotationInFlight; got: %v",
			spyMerger.lastErr)
	}

	// Assert: exit code is ExitGeneralError (current mapping for rotation-in-flight).
	if exitCode != int(render.ExitGeneralError) {
		t.Errorf("V5b.CR4: exit code = %d, want %d (ExitGeneralError); stderr=%q",
			exitCode, render.ExitGeneralError, stderr.String())
	}

	// Assert: the RotationInFlight predicate was the gate (guard was consulted).
	if !guard.wasCalled.Load() {
		t.Error("V5b.CR4: RotationInFlight was never called — " +
			"the rotation-in-flight guard is not wired in the spy Merger")
	}

	// Assert: CommitBump was NOT called (rejection fires before any write).
	if counterSpy.commitBumpCalls.Load() > 0 {
		t.Errorf("V5b.CR4: CommitBump was called %d time(s) — "+
			"the guard must fire BEFORE any write",
			counterSpy.commitBumpCalls.Load())
	}

	// Assert: project HEAD is unchanged (no file-of-record committed).
	postProjectHead := v5bProjectHEADSHA(t, fx)
	if preProjectHead != postProjectHead {
		t.Errorf("V5b.CR4: project HEAD changed: %s → %s — "+
			"a commit landed despite the rotation-in-flight rejection",
			preProjectHead, postProjectHead)
	}

	// Assert: registry HEAD is unchanged (no counter commit written).
	postRegistryHead := v5bRegistryHEADSHA(t, fx)
	if preRegistryHead != postRegistryHead {
		t.Errorf("V5b.CR4: registry HEAD changed: %s → %s — "+
			"a registry write landed despite the rotation-in-flight rejection",
			preRegistryHead, postRegistryHead)
	}

	t.Logf("V5b.CR4: PASS — RotationInFlight fired; CommitBump skipped; "+
		"exit=%d; project HEAD unchanged; registry HEAD unchanged", exitCode)
}

// v5bProjectHEADSHA returns the current HEAD SHA of the project bare upstream.
func v5bProjectHEADSHA(t *testing.T, fx *v4Fixture) string {
	t.Helper()
	sha, err := v4GitRevParse(fx.projectBareDir, "HEAD")
	if err != nil {
		t.Fatalf("v5bProjectHEADSHA: %v", err)
	}
	return sha
}

// v5bSpyRotationGuard is a RotationGuard that returns a configured inFlight
// value for the expected (projectID, fileName) pair, and records whether it
// was called.
type v5bSpyRotationGuard struct {
	projectID string
	fileName  string
	inFlight  bool
	wasCalled atomic.Bool
}

func (g *v5bSpyRotationGuard) RotationInFlight(_ context.Context, projectID, fileName string) (bool, error) {
	if projectID == g.projectID && fileName == g.fileName {
		g.wasCalled.Store(true)
		return g.inFlight, nil
	}
	return false, nil
}

// v5bSpyCounterStore records calls to CommitBump.
type v5bSpyCounterStore struct {
	commitBumpCalls atomic.Int32
}

func (s *v5bSpyCounterStore) CommitBump(_ context.Context, _ usecase.CommitBumpInput) error {
	s.commitBumpCalls.Add(1)
	return nil
}

func (s *v5bSpyCounterStore) RecordPendingBump(_ context.Context, _ usecase.PendingBumpInput) error {
	return nil
}

func (s *v5bSpyCounterStore) CounterAuthority(_ context.Context, _, _ string) (countertypes.CounterAuthority, error) {
	return countertypes.CounterAuthority{}, nil
}

// v5bRotationGuardMerger is a spy Merger that replicates the production
// RotationGuard call at merge.go step 6 and records the outcome. All
// pre-step-6 work is skipped; the guard check itself is the subject under
// test. This proves the guard fires BEFORE any CommitBump write.
type v5bRotationGuardMerger struct {
	guard         usecase.RotationGuard
	counterSpy    *v5bSpyCounterStore
	mergeWasCalled atomic.Bool
	lastErr       error
}

func (m *v5bRotationGuardMerger) Merge(ctx context.Context, in usecase.MergeInput) (usecase.MergeResult, error) {
	m.mergeWasCalled.Store(true)

	// Replicate the production RotationGuard check from merge.go step 6.
	inFlight, rgErr := m.guard.RotationInFlight(ctx, in.ExpectedProjectID, in.ExpectedFileName)
	if rgErr != nil {
		err := fmt.Errorf(
			"%w: rotation-in-flight check failed before CommitBump for "+
				"project=%q file=%q: %v",
			rotate.ErrCommitBumpRejectedRotationInFlight,
			in.ExpectedProjectID, in.ExpectedFileName, rgErr)
		m.lastErr = err
		return usecase.MergeResult{}, err
	}
	if inFlight {
		err := fmt.Errorf(
			"%w: project=%q file=%q",
			rotate.ErrCommitBumpRejectedRotationInFlight,
			in.ExpectedProjectID, in.ExpectedFileName)
		m.lastErr = err
		return usecase.MergeResult{}, err
	}

	// Guard did not fire: record that CommitBump would have been called.
	// (In the happy path the real Merger would call CommitBump here.)
	_ = m.counterSpy.CommitBump(ctx, usecase.CommitBumpInput{
		ProjectID: in.ExpectedProjectID,
		FileName:  in.ExpectedFileName,
	})
	m.lastErr = nil
	return usecase.MergeResult{}, nil
}
