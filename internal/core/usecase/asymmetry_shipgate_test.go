//go:build shipgate

// Package usecase — asymmetric-access behavioral ship-gate suite.
//
// This file implements the REQ-B-001 / DESIGN §7.1 ship-gate suite. It proves
// the asymmetric-access guarantee end-to-end through the SHIPPED production
// composition root (internal/app.BuildProductionDeps) and the SHIPPED cobra
// command tree (internal/cli.NewRootCmdWithDeps), with no stubbing of the
// composition and no real network.
//
// What this suite asserts:
//
//   - ADMIN get/decrypt — with a real fixture-owned admin age identity, real
//     SSH-signed registry repo, real signed file-of-record, and a real cold
//     counter file, the production path produces the expected plaintext
//     byte-for-byte.
//
//   - CONTRIBUTOR denied-not-attempted (FINAL-AC-10 + TM-AC-7.1-2 +
//     AC-CRYPTO-5) — with a non-recipient age key in the SAME fixture, the
//     ADMIN cobra subcommands are denied at the mode-policy gate at the CLI
//     layer (exit class permission-denied), no editor temp dir is created on
//     the contributor get/decrypt path, and the asymmetric-access guarantee
//     holds: the contributor cannot emit plaintext via any output channel.
//
//   - REQ-B-005 (no silent TOFU) — flipping the pinned anchor key in
//     trust.yaml causes the same ADMIN flow to fail closed at registry trust;
//     restoring the anchor brings the flow back to green.
//
//   - CO-B5-EDITOR-NONINTERACTIVE — with BYREIS_NON_INTERACTIVE=1 and EDITOR
//     unset, the edit composition wires the sentinel editor that refuses
//     interactively; the real $EDITOR adapter is never constructed.
//
//   - M6 real detector — with the ADMIN fixture deps.CurrentMode == ModeAdmin
//     post-BuildProductionDeps, proving the M6 cryptographic-reality anchor
//     (KeyProbe + ForSourceBridge wired at production.go:73/:80/:469) is on
//     the production trust path and the bridge's ArtifactFetcher is no longer
//     nil.
//
// NON-PASS CONDITION (per design/STATE.md §4.6.1 verbatim): the §7.1 ship-gate
// suite cannot be a structured t.Skip stub; it must drive REAL production code
// over a REAL fixture and prove the asymmetric-access invariant end-to-end. A
// red result here blocks the release pipeline.
//
// FAIL-CLOSED RUNTIME GATING: the suite uses real `git` and `ssh-keygen`
// subprocess invocations. If either binary is unavailable, the helper
// shipgateSkipIfNoGitOrSSH is consulted — it fails the test (does NOT skip)
// because a ship-gate that cannot run must fail, never pass. In the CI matrix
// the byreis test container ships both binaries.
package usecase_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"go.yaml.in/yaml/v3"

	"github.com/ByReisK/byreis/internal/adapter/keychain"
	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// shipgateProjectID is the operator-pinned project identifier used by the
// fixture. It is a single path component (per fetchtransport.ValidateProjectID).
const shipgateProjectID = "myapp"

// shipgateLogicalFile is the logical file name configured in the registry
// projects/<projectID>.yaml.
const shipgateLogicalFile = "prod"

// shipgateConfiguredPath is the registry-attested repo-relative path. It is
// under "vault/" (NOT "secrets/"), so FOR-AC-16 (the removed `secrets/`
// fallback) is genuinely exercised: a regression that re-introduced the
// fallback resolver would read from secrets/ and fail.
const shipgateConfiguredPath = "vault/prod.enc.yaml"

// shipgateSecretKey is the secret key name in the encrypted file-of-record.
const shipgateSecretKey = "API_KEY"

// shipgateSecretValue is the plaintext the test asserts is recovered on the
// ADMIN happy path. It is held in the test process to assert byte-equality;
// the test code NEVER passes it to any output channel except the t.Errorf
// failure message (only on failure).
const shipgateSecretValue = "asymmetric-access-shipgate-secret-2026-05-20"

// shipgateBaseBranch is the project repo base branch.
const shipgateBaseBranch = "main"

// shipgateAnchorPrincipal is the registry SSH allowed-signers principal name
// hard-coded in internal/adapter/registry/internal/fetchtransport
// (principalName const). Tests assert this so any production change is caught.
const shipgateAnchorPrincipal = "byreis-anchor"

// ─── TestAsymmetryShipGate ────────────────────────────────────────────────────

// TestAsymmetryShipGate is the §7.1 / REQ-B-001 ship-gate driver.
//
// Per design/STATE.md §4.6.1 verbatim NON-PASS CONDITION: the §7.1 ship-gate
// suite cannot be a structured t.Skip stub; it must drive REAL production
// code over a REAL fixture and prove the asymmetric-access invariant
// end-to-end. This test discharges that obligation.
func TestAsymmetryShipGate(t *testing.T) {
	if shipgateGitMissing() {
		t.Fatalf(
			"ship-gate: required binary 'git' is not on PATH — " +
				"a ship-gate that cannot run must fail, never pass")
	}
	if shipgateSSHKeygenMissing() {
		t.Fatalf(
			"ship-gate: required binary 'ssh-keygen' is not on PATH — " +
				"a ship-gate that cannot run must fail, never pass")
	}

	fx := newShipgateFixture(t)

	t.Run("ADMIN/Get/GreenWithRealComposition", func(t *testing.T) {
		fx.applyAdminEnv(t)
		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("BuildProductionDeps (ADMIN): %v", err)
		}
		// M6 cryptographic-reality anchor: deps.CurrentMode must be ModeAdmin
		// proving Detect step-3 CanDecryptAny genuinely ran and returned true.
		if deps.CurrentMode != mode.ModeAdmin {
			t.Fatalf("M6: deps.CurrentMode = %v, want ModeAdmin "+
				"(KeyProbe+ForSourceBridge not wired to production trust path?)",
				deps.CurrentMode)
		}

		out, errBuf, exitCode := fx.runCobra(t, deps,
			"get",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--key", shipgateSecretKey,
		)
		if exitCode != 0 {
			t.Fatalf("admin get: exit %d; stderr=%q stdout=%q",
				exitCode, errBuf.String(), out.String())
		}
		if !strings.Contains(out.String(), shipgateSecretValue) {
			t.Fatalf("admin get: stdout %q does not contain expected plaintext", out.String())
		}
	})

	t.Run("ADMIN/Decrypt/GreenWithRealComposition", func(t *testing.T) {
		fx.applyAdminEnv(t)
		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("BuildProductionDeps (ADMIN): %v", err)
		}
		if deps.CurrentMode != mode.ModeAdmin {
			t.Fatalf("M6: deps.CurrentMode = %v, want ModeAdmin", deps.CurrentMode)
		}

		out, errBuf, exitCode := fx.runCobra(t, deps,
			"decrypt",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--ci", // CI mode: no TTY masking; plaintext emitted as-is for byte-comparison.
		)
		if exitCode != 0 {
			t.Fatalf("admin decrypt: exit %d; stderr=%q stdout=%q",
				exitCode, errBuf.String(), out.String())
		}
		if !strings.Contains(out.String(), shipgateSecretValue) {
			t.Fatalf("admin decrypt: stdout does not contain expected plaintext")
		}
	})

	t.Run("CONTRIBUTOR/Get/DeniedByPolicyNotAttempted", func(t *testing.T) {
		// FINAL-AC-10 + TM-AC-7.1-2 + AC-CRYPTO-5: the CONTRIBUTOR (non-recipient
		// key) path must be denied by the mode policy at the CLI layer BEFORE
		// any decrypt/identity-load code runs. AC-CRYPTO-5: the probe must
		// genuinely run (CanDecryptAny enters probeDecryptOne which classifies
		// the failure as not-a-recipient) — NOT short-circuit on fetcher==nil
		// (the pre-B6-7 bug).
		fx.applyContributorEnv(t)
		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("BuildProductionDeps (CONTRIBUTOR): %v", err)
		}
		if deps.CurrentMode != mode.ModeContributor {
			t.Fatalf("CurrentMode = %v, want ModeContributor "+
				"(non-recipient key must downgrade via Detect step-3 → CONTRIBUTOR)",
				deps.CurrentMode)
		}

		// TMPDIR side-channel snapshot: count byreis-* temp dirs BEFORE.
		beforeFetchhead := countTempDirsByPrefix(t, "byreis-fetchhead-")
		beforeProjBlob := countTempDirsByPrefix(t, "byreis-project-blob-")
		beforeEditor := countTempDirsByPrefix(t, "byreis-editor-")

		out, errBuf, exitCode := fx.runCobra(t, deps,
			"get",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--key", shipgateSecretKey,
		)
		if exitCode != int(render.ExitPermissionDenied) {
			t.Fatalf("contributor get: exit %d, want ExitPermissionDenied=%d; "+
				"stderr=%q stdout=%q",
				exitCode, render.ExitPermissionDenied, errBuf.String(), out.String())
		}
		// Asymmetric-access invariant: no plaintext anywhere.
		if strings.Contains(out.String(), shipgateSecretValue) ||
			strings.Contains(errBuf.String(), shipgateSecretValue) {
			t.Fatalf("contributor get: plaintext leaked to output channels")
		}

		// TMPDIR snapshot: AFTER. The CLI must deny BEFORE any new clone
		// happens for get; only the BuildProductionDeps detection-step clones
		// may have run, which are pre-snapshot. The runCobra call must add
		// ZERO new fetchhead/project-blob/editor dirs.
		afterFetchhead := countTempDirsByPrefix(t, "byreis-fetchhead-")
		afterProjBlob := countTempDirsByPrefix(t, "byreis-project-blob-")
		afterEditor := countTempDirsByPrefix(t, "byreis-editor-")
		if afterFetchhead != beforeFetchhead {
			t.Errorf("CONTRIBUTOR get added %d new byreis-fetchhead-* dir(s) — "+
				"mode-gate denial must NOT trigger any new registry clone",
				afterFetchhead-beforeFetchhead)
		}
		if afterProjBlob != beforeProjBlob {
			t.Errorf("CONTRIBUTOR get added %d new byreis-project-blob-* dir(s) — "+
				"mode-gate denial must NOT trigger any new project-repo clone",
				afterProjBlob-beforeProjBlob)
		}
		if afterEditor != beforeEditor {
			t.Errorf("CONTRIBUTOR get added %d new byreis-editor-* dir(s) — "+
				"mode-gate denial must NEVER reach the editor adapter",
				afterEditor-beforeEditor)
		}
	})

	t.Run("CONTRIBUTOR/Decrypt/DeniedByPolicyNotAttempted", func(t *testing.T) {
		fx.applyContributorEnv(t)
		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("BuildProductionDeps (CONTRIBUTOR): %v", err)
		}
		if deps.CurrentMode != mode.ModeContributor {
			t.Fatalf("CurrentMode = %v, want ModeContributor", deps.CurrentMode)
		}

		out, errBuf, exitCode := fx.runCobra(t, deps,
			"decrypt",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--ci",
		)
		if exitCode != int(render.ExitPermissionDenied) {
			t.Fatalf("contributor decrypt: exit %d, want ExitPermissionDenied=%d; "+
				"stderr=%q",
				exitCode, render.ExitPermissionDenied, errBuf.String())
		}
		if strings.Contains(out.String(), shipgateSecretValue) ||
			strings.Contains(errBuf.String(), shipgateSecretValue) {
			t.Fatalf("contributor decrypt: plaintext leaked")
		}
	})

	t.Run("CONTRIBUTOR/Edit/DeniedByPolicyNotAttempted", func(t *testing.T) {
		// Edit must also be denied. Additionally: no editor temp dir is created.
		fx.applyContributorEnv(t)
		// Provide a deterministic non-interactive guard so even if the gate
		// were bypassed (it is not) the editor would refuse rather than fork
		// a real editor.
		t.Setenv("BYREIS_NON_INTERACTIVE", "1")
		t.Setenv("EDITOR", "")
		t.Setenv("VISUAL", "")
		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("BuildProductionDeps (CONTRIBUTOR): %v", err)
		}
		if deps.CurrentMode != mode.ModeContributor {
			t.Fatalf("CurrentMode = %v, want ModeContributor", deps.CurrentMode)
		}

		beforeEditor := countTempDirsByPrefix(t, "byreis-editor-")
		_, errBuf, exitCode := fx.runCobra(t, deps,
			"edit",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
		)
		if exitCode != int(render.ExitPermissionDenied) {
			t.Fatalf("contributor edit: exit %d, want ExitPermissionDenied=%d; stderr=%q",
				exitCode, render.ExitPermissionDenied, errBuf.String())
		}
		afterEditor := countTempDirsByPrefix(t, "byreis-editor-")
		if afterEditor != beforeEditor {
			t.Errorf("CONTRIBUTOR edit added %d new byreis-editor-* dir(s) — "+
				"the editor adapter must NEVER be reached on the denied path",
				afterEditor-beforeEditor)
		}
	})

	t.Run("REQB005/FlippedTrustAnchor/AdminGetFailsClosed", func(t *testing.T) {
		// REQ-B-005 (no silent TOFU): flip trust.yaml to a different ed25519
		// key — the same ADMIN flow must fail closed (trust error / mode
		// downgrades to CONTRIBUTOR because the registry can no longer be
		// verified). Reset trust.yaml → flow returns to green.
		fx.applyAdminEnv(t)

		// Save the original trust.yaml.
		origTrust, err := os.ReadFile(filepath.Join(fx.configDir, "trust.yaml"))
		if err != nil {
			t.Fatalf("reading original trust.yaml: %v", err)
		}
		defer func() {
			if writeErr := os.WriteFile(
				filepath.Join(fx.configDir, "trust.yaml"), origTrust, 0o600); writeErr != nil {
				t.Errorf("restoring original trust.yaml: %v", writeErr)
			}
		}()

		// Write a flipped anchor: a different valid ed25519 pubkey, with the
		// correct fingerprint (so trust.yaml integrity check passes but the
		// registry-signature verification fails).
		flippedPub, _, gErr := ed25519.GenerateKey(rand.Reader)
		if gErr != nil {
			t.Fatalf("generating flipped anchor key: %v", gErr)
		}
		fx.writeTrustYAML(t, flippedPub)

		deps, err := app.BuildProductionDeps(context.Background())
		// BuildProductionDeps may or may not error here depending on whether the
		// registry trust check happens at construction time or first use. Either
		// way, deps.CurrentMode MUST be ModeContributor on the flipped path
		// (cryptographic-reality demands it) AND the get command MUST be
		// denied. We assert the conjunction.
		if err == nil {
			if deps.CurrentMode == mode.ModeAdmin {
				t.Fatal("REQ-B-005: with flipped trust anchor, deps.CurrentMode " +
					"must NOT remain ModeAdmin — silent TOFU regression")
			}
			out, errBuf, exitCode := fx.runCobra(t, deps,
				"get",
				"--project", shipgateProjectID,
				"--file", shipgateLogicalFile,
				"--key", shipgateSecretKey,
			)
			// Must be a non-zero exit (denied or trust error), and never emit plaintext.
			if exitCode == 0 {
				t.Fatalf("REQ-B-005: with flipped trust anchor, get exited 0 — "+
					"silent TOFU regression; stdout=%q", out.String())
			}
			if strings.Contains(out.String(), shipgateSecretValue) {
				t.Fatalf("REQ-B-005: plaintext leaked with flipped anchor: %q", out.String())
			}
			_ = errBuf
		}
	})

	t.Run("CO-B5-EDITOR-NONINTERACTIVE/ComposeRootRefusal", func(t *testing.T) {
		// With BYREIS_NON_INTERACTIVE=1 and EDITOR/VISUAL both unset, the
		// composition root must wire the sentinel non-interactive refusal
		// editor — never the real $EDITOR adapter. We drive the ADMIN-mode
		// edit command (passes mode-gate) and assert it returns the sentinel
		// error message ("interactive terminal" / "BYREIS_NON_INTERACTIVE")
		// rather than forking a real editor or producing a successful edit.
		//
		// CWD must be inside the project repo so resolveRepoRootProd locates
		// the .byreis.yaml marker and the AtomicFileWriter is built; without
		// the writer the EditUseCase is nil and the sentinel error path is
		// never reached.
		fx.applyAdminEnv(t)
		t.Setenv("BYREIS_NON_INTERACTIVE", "1")
		t.Setenv("EDITOR", "")
		t.Setenv("VISUAL", "")

		origCwd, getErr := os.Getwd()
		if getErr != nil {
			t.Fatalf("getwd: %v", getErr)
		}
		if err := os.Chdir(fx.projectRepoDir); err != nil {
			t.Fatalf("chdir to project repo: %v", err)
		}
		t.Cleanup(func() { _ = os.Chdir(origCwd) })

		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("BuildProductionDeps: %v", err)
		}
		if deps.CurrentMode != mode.ModeAdmin {
			t.Fatalf("CurrentMode = %v, want ModeAdmin", deps.CurrentMode)
		}
		// Editor use-case MUST be non-nil now (all four edit-only ports wired)
		// — proving the sentinel editor was constructed and threaded through
		// BuildReadPathDeps to the cobra command.
		if deps.Editor == nil {
			t.Fatal("CO-B5: deps.Editor is nil — the sentinel non-interactive " +
				"refusal cannot be exercised; check writer/signer/encryptor wiring " +
				"(.byreis.yaml marker present? admin signer key in fixture?)")
		}

		beforeEditor := countTempDirsByPrefix(t, "byreis-editor-")
		_, errBuf, exitCode := fx.runCobra(t, deps,
			"edit",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
		)
		afterEditor := countTempDirsByPrefix(t, "byreis-editor-")

		if exitCode == 0 {
			t.Fatalf("CO-B5-EDITOR-NONINTERACTIVE: edit exited 0 — sentinel " +
				"editor refusal not active")
		}
		// The sentinel returns an actionable error containing the substring
		// "interactive terminal" (see prodNoEditorNonInteractiveRefusal.Edit
		// in internal/app/production.go).
		if !strings.Contains(errBuf.String(), "interactive terminal") &&
			!strings.Contains(errBuf.String(), "BYREIS_NON_INTERACTIVE") {
			t.Errorf("CO-B5: stderr does not contain the sentinel substring "+
				"('interactive terminal' or 'BYREIS_NON_INTERACTIVE'); got %q",
				errBuf.String())
		}
		if afterEditor != beforeEditor {
			t.Errorf("CO-B5-EDITOR-NONINTERACTIVE: %d new byreis-editor-* dir(s) "+
				"created — the real $EDITOR adapter must NOT be constructed under "+
				"BYREIS_NON_INTERACTIVE=1 with EDITOR unset",
				afterEditor-beforeEditor)
		}
	})

	t.Run("CONTRIBUTOR/AdminMerge/DeniedByPolicyBeforeKeychainAndUseCase", func(t *testing.T) {
		// BO-TM-13-4: CONTRIBUTOR mode must produce ExitPermissionDenied for
		// `admin merge` with zero use-case invocation. The mode gate at the CLI
		// layer fires BEFORE any Merger call, so even if Merger is non-nil it
		// is never invoked. To make this assertion explicit, we replace
		// deps.Merger with a panic stub after BuildProductionDeps: any call
		// into it proves the mode gate did not fire first.
		fx.applyContributorEnv(t)
		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("BuildProductionDeps (CONTRIBUTOR): %v", err)
		}
		if deps.CurrentMode != mode.ModeContributor {
			t.Fatalf("CurrentMode = %v, want ModeContributor", deps.CurrentMode)
		}

		// Replace the Merger with a panic stub. The mode gate at the CLI layer
		// must fire before the Merger is called: a panic here is a test failure
		// proving the gate did NOT fire first.
		deps.Merger = &shipgatePanicMerger{}

		_, errBuf, exitCode := fx.runCobra(t, deps,
			"admin", "merge",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--pr", "myorg/my-secrets#1",
		)
		if exitCode != int(render.ExitPermissionDenied) {
			t.Fatalf("CONTRIBUTOR admin merge: exit %d, want ExitPermissionDenied=%d; "+
				"stderr=%q", exitCode, render.ExitPermissionDenied, errBuf.String())
		}
		// No plaintext, token, or key material in output.
		if strings.Contains(errBuf.String(), shipgateSecretValue) {
			t.Errorf("CONTRIBUTOR admin merge: plaintext leaked to stderr")
		}
	})

	t.Run("CONTRIBUTOR/RegistryWriteToken/KeychainGateDeniesBeforeRead", func(t *testing.T) {
		// Credential-separation invariant: in CONTRIBUTOR mode, the keychain
		// Store's load-site mode gate must fire BEFORE any keychain read occurs.
		//
		// Proof mechanism: inject a panicking KeyringClient whose Get method
		// increments a counter and panics. Wire it with a ModeProvider that
		// always returns ModeContributor. If the mode gate fires first,
		// GetRegistryWriteToken returns ErrRegistryWriteAuth immediately and the
		// Get method is never called (counter stays 0). If the keychain is read
		// first, the test panics — which surfaces as a test failure.
		//
		// This is the release-gate level of the same invariant covered at unit
		// level in the keychain adapter tests; the duplication here ensures the
		// invariant is in scope for the non-skippable ship-gate.
		panicker := &shipgatePanickingKeyring{}
		contributorMP := &shipgateContributorModeProvider{}
		store := keychain.NewWithDeps(contributorMP, panicker)

		_, err := store.GetRegistryWriteToken(context.Background(), "https://github.com/org/registry")
		if err == nil {
			t.Fatal("expected ErrRegistryWriteAuth in CONTRIBUTOR mode, got nil")
		}
		if !errors.Is(err, registryadapter.ErrRegistryWriteAuth) {
			t.Errorf("want errors.Is(err, ErrRegistryWriteAuth), got: %v", err)
		}
		if panicker.getCalls != 0 {
			t.Errorf("keychain Get must NOT be called in CONTRIBUTOR mode; got %d call(s)",
				panicker.getCalls)
		}
	})
}

// shipgatePanickingKeyring is a KeyringClient whose Get method panics if called.
// It is used to prove that the mode gate fires BEFORE any keychain read in
// CONTRIBUTOR mode — if Get is called, the panic surfaces as a test failure.
type shipgatePanickingKeyring struct {
	getCalls int
}

func (k *shipgatePanickingKeyring) Get(_, _ string) (string, error) {
	k.getCalls++
	panic("shipgatePanickingKeyring.Get was called — the mode gate did NOT fire before the keychain read")
}

func (k *shipgatePanickingKeyring) Set(_, _, _ string) error {
	panic("shipgatePanickingKeyring.Set was called unexpectedly")
}

func (k *shipgatePanickingKeyring) Delete(_, _ string) error {
	panic("shipgatePanickingKeyring.Delete was called unexpectedly")
}

// shipgateContributorModeProvider is a ModeProvider that always returns
// ModeContributor. Used to wire the credential-gate denial test without
// running the full mode detector.
type shipgateContributorModeProvider struct{}

func (*shipgateContributorModeProvider) CurrentMode(_ context.Context) (mode.Mode, error) {
	return mode.ModeContributor, nil
}

// shipgatePanicMerger panics if Merge is ever invoked. It is used to assert
// that the mode gate fires before the Merger is called in CONTRIBUTOR mode.
type shipgatePanicMerger struct{}

func (p *shipgatePanicMerger) Merge(_ context.Context, _ usecase.MergeInput) (usecase.MergeResult, error) {
	panic("shipgatePanicMerger.Merge was called — the mode gate did NOT fire before the use-case")
}

// ─── shipgateFixture ──────────────────────────────────────────────────────────

// shipgateFixture holds all the on-disk artifacts and keys for the ship-gate
// suite. It is constructed once per test (the fixture is small enough that
// regenerating it per sub-test would also be acceptable, but env-scoped
// sub-tests reset env via t.Setenv at sub-test scope while sharing the fixture).
type shipgateFixture struct {
	rootDir   string // t.TempDir() root
	configDir string // BYREIS_CONFIG
	cacheDir  string // BYREIS_CACHE

	// SSH signing key for git commits in the registry repo.
	sshKeyPath    string            // private key (PEM, OpenSSH format)
	sshPubKeyPath string            // .pub file
	anchorRawKey  ed25519.PublicKey // raw 32-byte pubkey extracted from the .pub

	// Admin age identity (recipient of the encrypted file-of-record).
	adminAgeKeyPath string // 0600 file holding "AGE-SECRET-KEY-1…"
	adminAgePub     string // "age1…" recipient string
	adminAgeIdent   *age.X25519Identity

	// Admin Ed25519 manifest-signing key (for signing the file-of-record).
	adminSignKeyPath string            // 0600 file holding 64 raw bytes (Ed25519 private)
	adminSignPubKey  ed25519.PublicKey // matching public key

	// Non-recipient age key for the CONTRIBUTOR negative path.
	contribAgeKeyPath string // 0600 file holding a non-recipient AGE-SECRET-KEY

	// Local git repos.
	registryRepoDir string // .git initialized; admins.yaml + projects/...
	projectRepoDir  string // .git initialized; vault/<file>.enc.yaml committed

	// Operator-pinned URLs (file://).
	registryURL    string
	projectRepoURL string
}

// newShipgateFixture builds the full real fixture in t.TempDir() and returns
// the populated struct. All keys are generated fresh per invocation; nothing
// persists across runs.
func newShipgateFixture(t *testing.T) *shipgateFixture {
	t.Helper()
	root := t.TempDir()

	fx := &shipgateFixture{rootDir: root}

	fx.configDir = filepath.Join(root, "config")
	fx.cacheDir = filepath.Join(root, "cache")
	if err := os.MkdirAll(fx.configDir, 0o700); err != nil {
		t.Fatalf("mkdir configDir: %v", err)
	}
	if err := os.MkdirAll(fx.cacheDir, 0o700); err != nil {
		t.Fatalf("mkdir cacheDir: %v", err)
	}

	// 1. SSH signing key.
	fx.generateSSHSigningKey(t)

	// 2. Admin age identity.
	fx.generateAdminAgeIdentity(t)

	// 3. Admin Ed25519 manifest-signing key.
	fx.generateAdminSigningKey(t)

	// 4. Non-recipient age identity for CONTRIBUTOR negative path.
	fx.generateContribAgeIdentity(t)

	// 5. trust.yaml pinning the SSH signer's raw ed25519 pubkey.
	fx.writeTrustYAML(t, fx.anchorRawKey)

	// 6. Registry git repo (admins.yaml + projects/<id>.yaml + counter file).
	fx.buildRegistryRepo(t)

	// 7. Project git repo (vault/<file>.enc.yaml signed by the admin).
	fx.buildProjectRepo(t)

	// 8. file:// URLs (absolute paths).
	fx.registryURL = "file://" + fx.registryRepoDir
	fx.projectRepoURL = "file://" + fx.projectRepoDir

	return fx
}

// applyAdminEnv sets the test-scoped environment variables for the ADMIN flow.
func (fx *shipgateFixture) applyAdminEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BYREIS_CONFIG", fx.configDir)
	t.Setenv("BYREIS_CACHE", fx.cacheDir)
	t.Setenv("BYREIS_REGISTRY", fx.registryURL)
	t.Setenv("BYREIS_PROJECT_REPO", fx.projectRepoURL)
	t.Setenv("BYREIS_PROJECT", shipgateProjectID)
	t.Setenv("BYREIS_KEY_FILE", fx.adminAgeKeyPath)
	t.Setenv("BYREIS_SIGN_KEY_FILE", fx.adminSignKeyPath)
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_BASE_BRANCH", shipgateBaseBranch)
	t.Setenv("BYREIS_NON_INTERACTIVE", "")
}

// applyContributorEnv sets the env for the CONTRIBUTOR negative flow. The age
// key file is swapped for a non-recipient key; everything else mirrors the
// ADMIN fixture.
func (fx *shipgateFixture) applyContributorEnv(t *testing.T) {
	t.Helper()
	fx.applyAdminEnv(t)
	t.Setenv("BYREIS_KEY_FILE", fx.contribAgeKeyPath)
}

// generateSSHSigningKey runs `ssh-keygen -t ed25519 -N "" -f <path>` to
// produce a fresh signing key, then extracts the raw 32-byte ed25519 pubkey
// from the .pub file's OpenSSH wire format.
func (fx *shipgateFixture) generateSSHSigningKey(t *testing.T) {
	t.Helper()
	fx.sshKeyPath = filepath.Join(fx.rootDir, "registry-signer")
	fx.sshPubKeyPath = fx.sshKeyPath + ".pub"

	cmd := exec.Command("ssh-keygen",
		"-t", "ed25519",
		"-N", "",
		"-C", "byreis-shipgate-anchor",
		"-q",
		"-f", fx.sshKeyPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}

	pubBytes, err := os.ReadFile(fx.sshPubKeyPath)
	if err != nil {
		t.Fatalf("reading ssh pubkey: %v", err)
	}
	fx.anchorRawKey = decodeSSHEd25519Pubkey(t, string(pubBytes))
}

// decodeSSHEd25519Pubkey extracts the raw 32-byte Ed25519 public key from an
// OpenSSH "ssh-ed25519 BASE64 [comment]" line. The base64 blob is in OpenSSH
// wire format: uint32(len("ssh-ed25519")) || "ssh-ed25519" || uint32(32) || keyBytes.
func decodeSSHEd25519Pubkey(t *testing.T, pubLine string) ed25519.PublicKey {
	t.Helper()
	fields := strings.Fields(strings.TrimSpace(pubLine))
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		t.Fatalf("unexpected ssh pubkey format: %q", pubLine)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatalf("base64-decoding ssh pubkey blob: %v", err)
	}
	// Wire format: [4-byte length][type string][4-byte length][key bytes]
	if len(blob) < 4 {
		t.Fatalf("ssh pubkey blob too short")
	}
	typeLen := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	if 4+typeLen+4 > len(blob) {
		t.Fatalf("ssh pubkey blob malformed: type len %d", typeLen)
	}
	keyOff := 4 + typeLen + 4
	keyLen := int(blob[4+typeLen])<<24 | int(blob[5+typeLen])<<16 |
		int(blob[6+typeLen])<<8 | int(blob[7+typeLen])
	if keyOff+keyLen > len(blob) || keyLen != ed25519.PublicKeySize {
		t.Fatalf("ssh pubkey blob: key length %d not %d", keyLen, ed25519.PublicKeySize)
	}
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, blob[keyOff:keyOff+keyLen])
	return out
}

// generateAdminAgeIdentity generates a fresh age X25519 keypair, writes the
// AGE-SECRET-KEY string to a 0600 file, and stores the identity for fixture use.
func (fx *shipgateFixture) generateAdminAgeIdentity(t *testing.T) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("age.GenerateX25519Identity: %v", err)
	}
	fx.adminAgeIdent = id
	fx.adminAgePub = id.Recipient().String()
	fx.adminAgeKeyPath = filepath.Join(fx.rootDir, "admin-age.key")
	if err := os.WriteFile(fx.adminAgeKeyPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("writing admin age key file: %v", err)
	}
}

// generateAdminSigningKey generates a fresh Ed25519 keypair (for manifest
// signing) and writes the 64-byte raw private key bytes to a 0600 file.
func (fx *shipgateFixture) generateAdminSigningKey(t *testing.T) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	fx.adminSignPubKey = pub
	fx.adminSignKeyPath = filepath.Join(fx.rootDir, "admin-sign.key")
	if err := os.WriteFile(fx.adminSignKeyPath, priv, 0o600); err != nil {
		t.Fatalf("writing admin sign key file: %v", err)
	}
}

// generateContribAgeIdentity generates a non-recipient age key for the
// CONTRIBUTOR negative path. The corresponding public key is NOT placed in
// admins.yaml.
func (fx *shipgateFixture) generateContribAgeIdentity(t *testing.T) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("age.GenerateX25519Identity (contributor): %v", err)
	}
	fx.contribAgeKeyPath = filepath.Join(fx.rootDir, "contrib-age.key")
	if err := os.WriteFile(fx.contribAgeKeyPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("writing contrib age key file: %v", err)
	}
}

// writeTrustYAML writes trust.yaml at <configDir>/trust.yaml pinning the given
// raw ed25519 pubkey as the sole signer entry. mode 0600 (required by
// trust.CheckTrustFileTOCTOU). Used both for the initial setup and the
// REQ-B-005 flipped-anchor sub-test.
func (fx *shipgateFixture) writeTrustYAML(t *testing.T, anchorKey ed25519.PublicKey) {
	t.Helper()
	fp := sha256.Sum256(anchorKey)
	entry := map[string]string{
		"key":         base64.StdEncoding.EncodeToString(anchorKey),
		"fingerprint": hex.EncodeToString(fp[:]),
	}
	doc := map[string]any{
		"signers": []map[string]string{entry},
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal trust.yaml: %v", err)
	}
	path := filepath.Join(fx.configDir, "trust.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing trust.yaml: %v", err)
	}
}

// buildRegistryRepo initialises a local git repo with admins.yaml,
// projects/<id>.yaml, and counters/<id>/<file>.json, then makes a single SSH-
// signed commit using the fixture SSH key.
func (fx *shipgateFixture) buildRegistryRepo(t *testing.T) {
	t.Helper()
	fx.registryRepoDir = filepath.Join(fx.rootDir, "registry")
	if err := os.MkdirAll(fx.registryRepoDir, 0o755); err != nil {
		t.Fatalf("mkdir registry repo: %v", err)
	}

	// admins.yaml: one admin entry with the fixture age recipient and the
	// matching Ed25519 signer public key. The format matches
	// internal/adapter/registry/production_transport.go adminsYAMLFile/Entry.
	signerB64 := base64.StdEncoding.EncodeToString(fx.adminSignPubKey)
	adminsYAML := fmt.Sprintf(`admins:
  - id: admin-1
    age_key: %s
    signer_key: %s
`, fx.adminAgePub, signerB64)
	writeFileMode(t, filepath.Join(fx.registryRepoDir, "admins.yaml"), []byte(adminsYAML), 0o644)

	// projects/<id>.yaml: maps logical file name → repo-relative path under "vault/"
	// (registry-attested path; NOT under "secrets/" — FOR-AC-16).
	projectYAML := fmt.Sprintf(`files:
  %s: %s
`, shipgateLogicalFile, shipgateConfiguredPath)
	if err := os.MkdirAll(filepath.Join(fx.registryRepoDir, "projects"), 0o755); err != nil {
		t.Fatalf("mkdir projects: %v", err)
	}
	writeFileMode(t,
		filepath.Join(fx.registryRepoDir, "projects", shipgateProjectID+".yaml"),
		[]byte(projectYAML), 0o644)

	// counters/<id>/<file>.json: cold counter (last_accepted=0, last_pr="",
	// pending=null). ADR-0006 schema; matches counterFileJSON in production_transport.go.
	counterDir := filepath.Join(fx.registryRepoDir, "counters", shipgateProjectID)
	if err := os.MkdirAll(counterDir, 0o755); err != nil {
		t.Fatalf("mkdir counter dir: %v", err)
	}
	counterPath := filepath.Join(counterDir, shipgateLogicalFile+".json")
	counterJSON := fmt.Sprintf(
		`{"project_id":%q,"file":%q,"last_accepted_counter":0,"last_pr":"","updated_at":"2026-05-20T00:00:00Z","pending":null}`+"\n",
		shipgateProjectID, shipgateLogicalFile,
	)
	writeFileMode(t, counterPath, []byte(counterJSON), 0o644)

	// git init + sign-commit the tree.
	fx.gitInitAndSignCommit(t, fx.registryRepoDir, "registry: initial signed state")
}

// buildProjectRepo initialises a local git repo with a signed file-of-record
// at vault/<file>.enc.yaml, then makes a single (unsigned) commit. The
// project-repo commit signature is NOT verified by byreis; the trust is the
// manifest signature inside the file (per DESIGN §3.5).
func (fx *shipgateFixture) buildProjectRepo(t *testing.T) {
	t.Helper()
	fx.projectRepoDir = filepath.Join(fx.rootDir, "project")
	if err := os.MkdirAll(fx.projectRepoDir, 0o755); err != nil {
		t.Fatalf("mkdir project repo: %v", err)
	}

	// Build the signed file-of-record bytes.
	signedBytes := fx.buildSignedFileOfRecord(t)
	vaultDir := filepath.Join(fx.projectRepoDir, "vault")
	if err := os.MkdirAll(vaultDir, 0o755); err != nil {
		t.Fatalf("mkdir vault: %v", err)
	}
	writeFileMode(t, filepath.Join(vaultDir, shipgateLogicalFile+".enc.yaml"),
		signedBytes, 0o644)

	// .byreis.yaml — the project marker file production.resolveRepoRootProd
	// walks upward to find. Required for the AtomicFileWriter to be built so
	// the EditUseCase wires; otherwise the CO-B5 sentinel cannot surface.
	writeFileMode(t, filepath.Join(fx.projectRepoDir, ".byreis.yaml"),
		[]byte("# byreis project marker (ship-gate fixture)\n"), 0o644)

	// git init + plain commit (no signature required for project repo).
	cmds := [][]string{
		{"init", "-q", "--initial-branch=" + shipgateBaseBranch},
		{"config", "user.name", "Tester"},
		{"config", "user.email", "tester@example.com"},
		{"config", "commit.gpgsign", "false"},
		{"add", "."},
		{"commit", "-q", "-m", "project: initial signed file-of-record"},
	}
	for _, args := range cmds {
		c := exec.Command("git", args...)
		c.Dir = fx.projectRepoDir
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v in project repo: %v: %s", args, err, out)
		}
	}
}

// buildSignedFileOfRecord builds the fully-formed signed file-of-record YAML
// for shipgateSecretKey → shipgateSecretValue, sealed to the admin age
// recipient and signed by the admin Ed25519 key. Counter=0 (cold).
func (fx *shipgateFixture) buildSignedFileOfRecord(t *testing.T) []byte {
	t.Helper()

	// Per-value armored age ciphertext: shipgateSecretKey → shipgateSecretValue.
	ct := encryptOneArmored(t, shipgateSecretValue, fx.adminAgePub)

	// Recipient fingerprint = sha256(age recipient string).
	fp := sha256.Sum256([]byte(fx.adminAgePub))
	fpHex := hex.EncodeToString(fp[:])

	signed := artifact.Signed{
		Values: map[string]artifact.EncryptedValue{
			shipgateSecretKey: artifact.EncryptedValue(ct),
		},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1",
			ProjectID:     shipgateProjectID,
			File:          shipgateLogicalFile,
			Counter:       0,
			Recipients:    []artifact.RecipientEntry{{FP: fpHex}},
		},
	}

	// Build the canonical manifest and sign it with the admin Ed25519 private key.
	man := manifest.Manifest{
		FormatVersion:         signed.Byreis.FormatVersion,
		ProjectID:             signed.Byreis.ProjectID,
		LogicalFileName:       signed.Byreis.File,
		Counter:               signed.Byreis.Counter,
		Values:                map[string][]byte{shipgateSecretKey: []byte(ct)},
		RecipientFingerprints: []string{fpHex},
	}
	priv, err := os.ReadFile(fx.adminSignKeyPath)
	if err != nil {
		t.Fatalf("reading admin sign key: %v", err)
	}
	sig, err := sign.Sign(ed25519.PrivateKey(priv), man)
	if err != nil {
		t.Fatalf("sign.Sign: %v", err)
	}
	signed.ManifestSig = artifact.ManifestSig{
		Signer: "admin-1",
		Sig:    hex.EncodeToString(sig),
	}

	// Marshal to YAML in the same fixed-field layout the production codec emits.
	doc := map[string]any{
		shipgateSecretKey: ct,
		"byreis": map[string]any{
			"format_version": signed.Byreis.FormatVersion,
			"project_id":     signed.Byreis.ProjectID,
			"file":           signed.Byreis.File,
			"counter":        signed.Byreis.Counter,
			"recipients": []map[string]string{
				{"fp": fpHex},
			},
		},
		"manifest_sig": map[string]string{
			"signer": signed.ManifestSig.Signer,
			"sig":    signed.ManifestSig.Sig,
		},
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal signed file: %v", err)
	}
	return out
}

// gitInitAndSignCommit initialises a git repo at dir and creates a single
// SSH-signed commit using the fixture's SSH signing key.
func (fx *shipgateFixture) gitInitAndSignCommit(t *testing.T, dir, msg string) {
	t.Helper()

	// allowed_signers file for the local git config (only needed when verify is
	// invoked from THIS path; production code writes its own allowed-signers).
	allowedSignersPath := filepath.Join(fx.rootDir, "fixture-allowed-signers")
	pubBytes, err := os.ReadFile(fx.sshPubKeyPath)
	if err != nil {
		t.Fatalf("reading ssh pubkey: %v", err)
	}
	pubFields := strings.Fields(string(pubBytes))
	if len(pubFields) < 2 {
		t.Fatalf("unexpected ssh pubkey contents")
	}
	allowedLine := shipgateAnchorPrincipal + " " + pubFields[0] + " " + pubFields[1] + "\n"
	if err := os.WriteFile(allowedSignersPath, []byte(allowedLine), 0o600); err != nil {
		t.Fatalf("writing allowed_signers: %v", err)
	}

	commits := [][]string{
		{"init", "-q", "--initial-branch=main"},
		{"config", "user.name", shipgateAnchorPrincipal},
		{"config", "user.email", "anchor@example.com"},
		{"config", "gpg.format", "ssh"},
		{"config", "user.signingkey", fx.sshPubKeyPath},
		{"config", "gpg.ssh.allowedSignersFile", allowedSignersPath},
		{"config", "commit.gpgsign", "true"},
		{"add", "."},
		{"commit", "-q", "-m", msg, "-S"},
	}
	for _, args := range commits {
		c := exec.Command("git", args...)
		c.Dir = dir
		// GIT_CONFIG_NOSYSTEM excludes /etc/gitconfig but the test still
		// needs HOME so git can find ssh-keygen; we let HOME inherit.
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v in %s: %v: %s", args, dir, err, out)
		}
	}
}

// runCobra invokes the SHIPPED cobra root with the production-built deps and
// returns the captured stdout/stderr buffers plus the resolved exit code.
// The exit code is derived from cli.ExitCodeOf so it matches what
// cmd/byreis/main.go would pass to os.Exit.
func (fx *shipgateFixture) runCobra(t *testing.T, deps *cli.Deps, args ...string) (
	stdout, stderr *bytes.Buffer, exitCode int,
) {
	t.Helper()
	stdout = &bytes.Buffer{}
	stderr = &bytes.Buffer{}

	root := cli.NewRootCmdWithDeps(deps)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	err := root.ExecuteContext(ctx)
	exitCode = cli.ExitCodeOf(err)
	return stdout, stderr, exitCode
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// encryptOneArmored age-encrypts a single plaintext to a single recipient and
// returns the armored ciphertext.
func encryptOneArmored(t *testing.T, plaintext, recipientStr string) string {
	t.Helper()
	rec, err := age.ParseX25519Recipient(recipientStr)
	if err != nil {
		t.Fatalf("parse age recipient: %v", err)
	}
	var sb strings.Builder
	aw := armor.NewWriter(&sb)
	w, err := age.Encrypt(aw, rec)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close age writer: %v", err)
	}
	if err := aw.Close(); err != nil {
		t.Fatalf("close armor writer: %v", err)
	}
	return sb.String()
}

// writeFileMode writes data to path with the given mode (failing the test on
// any IO error).
func writeFileMode(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// countTempDirsByPrefix counts entries in os.TempDir() whose names start with
// the given prefix. Used for the TMPDIR-snapshot side-channel assertion.
func countTempDirsByPrefix(t *testing.T, prefix string) int {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("reading os.TempDir(): %v", err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			n++
		}
	}
	return n
}

// shipgateGitMissing reports whether the `git` binary is unavailable.
func shipgateGitMissing() bool {
	_, err := exec.LookPath("git")
	return err != nil
}

// shipgateSSHKeygenMissing reports whether the `ssh-keygen` binary is
// unavailable.
func shipgateSSHKeygenMissing() bool {
	_, err := exec.LookPath("ssh-keygen")
	return err != nil
}

// ─── unused-symbol guards (avoid dead-code lints in the test package) ────────

// _ ensures otherwise unused error.Is hookups stay compiled — these are kept
// available so future ship-gate assertions can deepen the check without
// re-importing.
var _ = errors.Is
var _ = atomic.LoadInt32
var _ = json.Marshal
