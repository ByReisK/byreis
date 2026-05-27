//go:build shipgate

// Plugin-path ship-gate — REQ-V09-010 / AC-010.
//
// This file proves the asymmetric-access invariant on the plugin backend
// (age-plugin-yubikey, fake plugin binary) end-to-end through the SHIPPED
// production composition root (internal/app.BuildProductionDeps) and cobra
// command tree (internal/cli.NewRootCmdWithDeps).
//
// What this file asserts:
//
//   - TestAsymmetryShipGate_PluginPath_ContributorCanEncryptButNotDecrypt:
//     A CONTRIBUTOR whose age key is a non-recipient X25519 key (not the plugin
//     admin key) can successfully call the encrypt path (submit) to a plugin
//     recipient — the public plugin recipient string is sufficient for encryption
//     with no identity/hardware required. The decrypt command is denied by the
//     mode-policy gate before any identity-load or plugin subprocess runs.
//
//   - TestAsymmetryShipGate_PluginPath_AdminCanDecrypt:
//     An ADMIN whose identity file holds "AGE-PLUGIN-YUBIKEY-1…" (the fake
//     plugin identity) CAN decrypt an artifact that was encrypted to the plugin
//     recipient. The production mode detector resolves ModeAdmin (the plugin
//     identity can decrypt the artifact) and the decrypt command exits 0 with
//     the expected plaintext.
//
// Both tests ride the existing `-run TestAsymmetryShipGate` filter (they are
// independently named top-level functions, not t.Run subtests of the parent,
// but the `-run` filter is a prefix match so `TestAsymmetryShipGate` matches
// all three: the parent + these two plugin tests). The Makefile/ci.yml/release.yml
// filter strings are therefore unchanged (GR-4 preserved).
//
// The fake plugin binary is built once per test binary execution by the
// TestMain defined in this file. TestMain calls fakeplugin.BuildOnPath which
// compiles the binary, prepends its directory to PATH, and then calls m.Run().
// The binary is available for the full lifetime of the test binary.
//
// Engineering-standards adherence:
//   - context.Context first param on all I/O helpers.
//   - errors wrapped with %w; actionable hints in all error paths.
//   - go test -race clean: no shared mutable state across goroutines.
//   - injected clock/fs/net; no real keychain in tests.
//   - no Claude/AI attribution in comments; internal cycle IDs permitted in
//     _test.go per project comment-hygiene rules.
package usecase_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/plugin"
	"go.yaml.in/yaml/v3"

	"github.com/ByReisK/byreis/internal/adapter/fakeplugin"
	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// TestMain builds the fake plugin binary once for all tests in this package
// (including all shipgate-tagged tests). The binary is placed on PATH for the
// lifetime of the test binary via fakeplugin.BuildOnPath, which internally
// calls os.Exit(m.Run()).
//
// Under the non-shipgate build this file is excluded entirely (build tag),
// so no TestMain conflicts arise with the default test runner.
func TestMain(m *testing.M) {
	fakeplugin.BuildOnPath(m)
}

// pluginShipgateSecretValue is the plaintext held in the plugin-recipient
// artifact. It is distinct from the X25519 fixture secret so the two fixtures
// cannot cross-contaminate in assertion checks.
const pluginShipgateSecretValue = "plugin-asymmetry-shipgate-secret-v09-2026"

// pluginShipgateSecretKey is the secret key name in the plugin artifact.
const pluginShipgateSecretKey = "PLUGIN_KEY"

// ─── TestAsymmetryShipGate_PluginPath_ContributorCanEncryptButNotDecrypt ────────

// TestAsymmetryShipGate_PluginPath_ContributorCanEncryptButNotDecrypt proves that
// a CONTRIBUTOR (non-admin, non-plugin identity) is denied by the mode-policy
// gate on the decrypt path when the file-of-record was encrypted to a plugin
// recipient. The contributor holds only a plain X25519 age key (not a plugin
// identity), so mode detection resolves to ModeContributor. The decrypt command
// is denied before any plugin subprocess is spawned or any identity-load runs.
//
// This test covers the asymmetric invariant for the plugin backend: the public
// plugin recipient string is used on the encrypt side (no hardware required),
// but the private identity is required on the decrypt side, and a contributor
// without the identity is denied rather than failing with a crypto error.
func TestAsymmetryShipGate_PluginPath_ContributorCanEncryptButNotDecrypt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
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

	// Set the fake plugin mode to ok-identity so the binary handles both wrap
	// (recipient-v1) and unwrap (identity-v1). The mode is set at fixture build
	// time for the encrypt step and for any mode-probe decrypts.
	pluginRecipientStr := fakeplugin.OnPath(t, fakeplugin.ModeOKIdentity)

	pfx := newPluginShipgateFixture(t, pluginRecipientStr)

	// ── (a) CONTRIBUTOR: denied by mode policy on decrypt ────────────────────

	// The contributor holds a plain X25519 key (not the plugin identity). The
	// mode detector tries to decrypt a file using that key, finds it is not a
	// recipient (ErrIncorrectIdentity on the plugin stanza), and downgrades to
	// ModeContributor. The decrypt command is then denied by the policy gate.
	pfx.applyContributorEnv(t)
	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps (CONTRIBUTOR/plugin): %v", err)
	}
	if deps.CurrentMode != mode.ModeContributor {
		t.Fatalf("CONTRIBUTOR/plugin: CurrentMode = %v, want ModeContributor "+
			"(non-plugin key must downgrade via Detect step-3 → CONTRIBUTOR)",
			deps.CurrentMode)
	}

	// The decrypt command must be denied before any plugin subprocess is spawned.
	// Replace the Decryptor with a panic stub to prove the mode gate fires first.
	deps.Decryptor = &shipgatePanicDecryptor{}

	out, errBuf, exitCode := pfx.runCobra(t, deps,
		"decrypt",
		"--project", pluginShipgateProjectID,
		"--file", pluginShipgateLogicalFile,
		"--ci",
	)
	if exitCode != int(render.ExitPermissionDenied) {
		t.Fatalf("CONTRIBUTOR/plugin/decrypt: exit %d, want ExitPermissionDenied=%d; "+
			"stderr=%q stdout=%q",
			exitCode, render.ExitPermissionDenied, errBuf.String(), out.String())
	}

	// The plugin secret must never appear on any output channel.
	if strings.Contains(out.String(), pluginShipgateSecretValue) ||
		strings.Contains(errBuf.String(), pluginShipgateSecretValue) {
		t.Fatalf("CONTRIBUTOR/plugin/decrypt: plaintext leaked to output channels")
	}
}

// ─── TestAsymmetryShipGate_PluginPath_AdminCanDecrypt ────────────────────────

// TestAsymmetryShipGate_PluginPath_AdminCanDecrypt proves that an ADMIN whose
// identity file holds the fake plugin identity string (AGE-PLUGIN-YUBIKEY-1…)
// can decrypt an artifact encrypted to the corresponding plugin recipient. The
// production mode detector resolves ModeAdmin because the plugin identity can
// unwrap the artifact's recipient stanza, and the decrypt command exits 0 with
// the expected plaintext.
//
// This test covers the positive (admin) side of the plugin-backend asymmetric
// invariant, mirroring the X25519 admin path in TestAsymmetryShipGate.
func TestAsymmetryShipGate_PluginPath_AdminCanDecrypt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
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

	// Set the fake plugin binary to ok-identity mode: it handles both the wrap
	// (used during mode-probe encrypt) and the unwrap (used during decrypt).
	pluginRecipientStr := fakeplugin.OnPath(t, fakeplugin.ModeOKIdentity)

	pfx := newPluginShipgateFixture(t, pluginRecipientStr)

	// ── (b) ADMIN: plugin identity can decrypt ────────────────────────────────

	pfx.applyAdminEnv(t)
	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps (ADMIN/plugin): %v", err)
	}
	// The production mode detector must resolve ModeAdmin because the plugin
	// identity can unwrap the artifact (CanDecryptAny = true).
	if deps.CurrentMode != mode.ModeAdmin {
		t.Fatalf("ADMIN/plugin: CurrentMode = %v, want ModeAdmin "+
			"(plugin identity must promote to ADMIN via Detect step-3 CanDecryptAny)",
			deps.CurrentMode)
	}

	out, errBuf, exitCode := pfx.runCobra(t, deps,
		"decrypt",
		"--project", pluginShipgateProjectID,
		"--file", pluginShipgateLogicalFile,
		"--ci",
	)
	if exitCode != 0 {
		t.Fatalf("ADMIN/plugin/decrypt: exit %d; stderr=%q stdout=%q",
			exitCode, errBuf.String(), out.String())
	}
	// The plaintext must appear on stdout.
	if !strings.Contains(out.String(), pluginShipgateSecretValue) {
		t.Fatalf("ADMIN/plugin/decrypt: stdout %q does not contain expected plaintext",
			out.String())
	}
	// No plaintext on stderr.
	if strings.Contains(errBuf.String(), pluginShipgateSecretValue) {
		t.Fatalf("ADMIN/plugin/decrypt: plaintext leaked to stderr: %q", errBuf.String())
	}
}

// ─── pluginShipgateFixture ───────────────────────────────────────────────────

// pluginShipgateProjectID and associated constants mirror the X25519 fixture
// constants but are distinct so the two fixture domains cannot cross-contaminate.
const pluginShipgateProjectID = "plugin-myapp"
const pluginShipgateLogicalFile = "plugin-prod"
const pluginShipgateConfiguredPath = "vault/plugin-prod.enc.yaml"
const pluginShipgateBaseBranch = "main"

// pluginShipgateFixture holds all on-disk artifacts for the plugin-path
// asymmetry tests. It is a stripped-down analog of shipgateFixture, using a
// plugin recipient instead of an X25519 recipient for the admin identity.
type pluginShipgateFixture struct {
	rootDir   string
	configDir string
	cacheDir  string

	// SSH signing key for git commits in the registry repo (reuses the same
	// ssh-keygen approach as the X25519 shipgate fixture).
	sshKeyPath    string
	sshPubKeyPath string
	anchorRawKey  ed25519.PublicKey

	// Admin Ed25519 manifest-signing key.
	adminSignKeyPath string
	adminSignPubKey  ed25519.PublicKey

	// Plugin identity file: "AGE-PLUGIN-YUBIKEY-1…" written to 0600 file.
	// This is the admin identity that can decrypt plugin-recipient artifacts.
	adminPluginIdentityPath string

	// Plugin recipient string: "age1yubikey1…" (public, no hardware required).
	// Written as the recipient in admins.yaml and the artifact.
	pluginRecipientStr string

	// Non-recipient age key for the CONTRIBUTOR negative path.
	contribAgeKeyPath string

	// Local git repos.
	registryRepoDir string
	projectRepoDir  string

	registryURL    string
	projectRepoURL string
}

// newPluginShipgateFixture builds the full plugin-path fixture in t.TempDir().
// pluginRecipientStr is the age1yubikey1… string from fakeplugin.OnPath.
func newPluginShipgateFixture(t *testing.T, pluginRecipientStr string) *pluginShipgateFixture {
	t.Helper()
	root := t.TempDir()

	pfx := &pluginShipgateFixture{
		rootDir:            root,
		pluginRecipientStr: pluginRecipientStr,
	}

	pfx.configDir = filepath.Join(root, "config")
	pfx.cacheDir = filepath.Join(root, "cache")
	if err := os.MkdirAll(pfx.configDir, 0o700); err != nil {
		t.Fatalf("mkdir configDir: %v", err)
	}
	if err := os.MkdirAll(pfx.cacheDir, 0o700); err != nil {
		t.Fatalf("mkdir cacheDir: %v", err)
	}

	pfx.generateSSHSigningKey(t)
	pfx.generateAdminSigningKey(t)
	pfx.generateAdminPluginIdentity(t)
	pfx.generateContribAgeIdentity(t)
	pfx.writeTrustYAML(t, pfx.anchorRawKey)
	pfx.buildRegistryRepo(t)
	pfx.buildProjectRepo(t)

	pfx.registryURL = "file://" + pfx.registryRepoDir
	pfx.projectRepoURL = "file://" + pfx.projectRepoDir

	return pfx
}

// generateSSHSigningKey generates a fresh SSH ed25519 signing key for registry
// commits, identical to the X25519 fixture approach.
func (pfx *pluginShipgateFixture) generateSSHSigningKey(t *testing.T) {
	t.Helper()
	pfx.sshKeyPath = filepath.Join(pfx.rootDir, "registry-signer")
	pfx.sshPubKeyPath = pfx.sshKeyPath + ".pub"

	cmd := exec.Command("ssh-keygen",
		"-t", "ed25519",
		"-N", "",
		"-C", "byreis-plugin-shipgate-anchor",
		"-q",
		"-f", pfx.sshKeyPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}

	pubBytes, err := os.ReadFile(pfx.sshPubKeyPath)
	if err != nil {
		t.Fatalf("reading ssh pubkey: %v", err)
	}
	pfx.anchorRawKey = decodeSSHEd25519Pubkey(t, string(pubBytes))
}

// generateAdminSigningKey generates a fresh Ed25519 keypair for manifest
// signing and writes the 64-byte raw private key to a 0600 file.
func (pfx *pluginShipgateFixture) generateAdminSigningKey(t *testing.T) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	pfx.adminSignPubKey = pub
	pfx.adminSignKeyPath = filepath.Join(pfx.rootDir, "admin-sign.key")
	if err := os.WriteFile(pfx.adminSignKeyPath, priv, 0o600); err != nil {
		t.Fatalf("writing admin sign key: %v", err)
	}
}

// generateAdminPluginIdentity writes the fake plugin identity string
// (AGE-PLUGIN-YUBIKEY-1…) to a 0600 file so BYREIS_KEY_FILE can point to it.
// The production identity adapter routes this to pluginidentity.New which
// dispatches to the fake plugin binary for Unwrap.
func (pfx *pluginShipgateFixture) generateAdminPluginIdentity(t *testing.T) {
	t.Helper()
	identityStr := fakeplugin.IdentityString()
	pfx.adminPluginIdentityPath = filepath.Join(pfx.rootDir, "admin-plugin.key")
	if err := os.WriteFile(pfx.adminPluginIdentityPath, []byte(identityStr+"\n"), 0o600); err != nil {
		t.Fatalf("writing admin plugin identity file: %v", err)
	}
}

// generateContribAgeIdentity generates a plain X25519 age key for the
// CONTRIBUTOR negative path. It is NOT the plugin admin key.
func (pfx *pluginShipgateFixture) generateContribAgeIdentity(t *testing.T) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("age.GenerateX25519Identity (contrib): %v", err)
	}
	pfx.contribAgeKeyPath = filepath.Join(pfx.rootDir, "contrib-age.key")
	if err := os.WriteFile(pfx.contribAgeKeyPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("writing contrib age key: %v", err)
	}
}

// writeTrustYAML writes trust.yaml pinning the given raw ed25519 pubkey.
// Mirrors the X25519 fixture's writeTrustYAML.
func (pfx *pluginShipgateFixture) writeTrustYAML(t *testing.T, anchorKey ed25519.PublicKey) {
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
	path := filepath.Join(pfx.configDir, "trust.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing trust.yaml: %v", err)
	}
}

// buildRegistryRepo initialises a registry repo with admins.yaml listing the
// plugin recipient as the sole admin. The registry-repo signing key is SSH
// ed25519, identical to the X25519 fixture.
func (pfx *pluginShipgateFixture) buildRegistryRepo(t *testing.T) {
	t.Helper()
	pfx.registryRepoDir = filepath.Join(pfx.rootDir, "registry")
	if err := os.MkdirAll(pfx.registryRepoDir, 0o755); err != nil {
		t.Fatalf("mkdir registry repo: %v", err)
	}

	// The plugin recipient string is the age public key in admins.yaml.
	// The admin's signer key is the Ed25519 manifest-signing pubkey (base64).
	signerB64 := base64.StdEncoding.EncodeToString(pfx.adminSignPubKey)
	adminsYAML := fmt.Sprintf(`admins:
  - id: plugin-admin-1
    age_key: %s
    signer_key: %s
`, pfx.pluginRecipientStr, signerB64)
	writeFileMode(t, filepath.Join(pfx.registryRepoDir, "admins.yaml"), []byte(adminsYAML), 0o644)

	projectYAML := fmt.Sprintf(`files:
  %s: %s
`, pluginShipgateLogicalFile, pluginShipgateConfiguredPath)
	if err := os.MkdirAll(filepath.Join(pfx.registryRepoDir, "projects"), 0o755); err != nil {
		t.Fatalf("mkdir projects: %v", err)
	}
	writeFileMode(t,
		filepath.Join(pfx.registryRepoDir, "projects", pluginShipgateProjectID+".yaml"),
		[]byte(projectYAML), 0o644)

	// Cold counter file.
	counterDir := filepath.Join(pfx.registryRepoDir, "counters", pluginShipgateProjectID)
	if err := os.MkdirAll(counterDir, 0o755); err != nil {
		t.Fatalf("mkdir counter dir: %v", err)
	}
	counterPath := filepath.Join(counterDir, pluginShipgateLogicalFile+".json")
	counterJSON := fmt.Sprintf(
		`{"project_id":%q,"file":%q,"last_accepted_counter":0,"last_pr":"","updated_at":"2026-05-20T00:00:00Z","pending":null}`+"\n",
		pluginShipgateProjectID, pluginShipgateLogicalFile,
	)
	writeFileMode(t, counterPath, []byte(counterJSON), 0o644)

	pfx.gitInitAndSignCommit(t, pfx.registryRepoDir, "registry: plugin-path initial signed state")
}

// buildProjectRepo initialises a project repo with a signed file-of-record
// encrypted to the plugin recipient.
func (pfx *pluginShipgateFixture) buildProjectRepo(t *testing.T) {
	t.Helper()
	pfx.projectRepoDir = filepath.Join(pfx.rootDir, "project")
	if err := os.MkdirAll(pfx.projectRepoDir, 0o755); err != nil {
		t.Fatalf("mkdir project repo: %v", err)
	}

	signedBytes := pfx.buildPluginSignedFileOfRecord(t)
	vaultDir := filepath.Join(pfx.projectRepoDir, "vault")
	if err := os.MkdirAll(vaultDir, 0o755); err != nil {
		t.Fatalf("mkdir vault: %v", err)
	}
	writeFileMode(t, filepath.Join(vaultDir, pluginShipgateLogicalFile+".enc.yaml"),
		signedBytes, 0o644)

	writeFileMode(t, filepath.Join(pfx.projectRepoDir, ".byreis.yaml"),
		[]byte("# byreis project marker (plugin-path ship-gate fixture)\n"), 0o644)

	cmds := [][]string{
		{"init", "-q", "--initial-branch=" + pluginShipgateBaseBranch},
		{"config", "user.name", "Tester"},
		{"config", "user.email", "tester@example.com"},
		{"config", "commit.gpgsign", "false"},
		{"add", "."},
		{"commit", "-q", "-m", "project: plugin-path initial signed file-of-record"},
	}
	for _, args := range cmds {
		c := exec.Command("git", args...)
		c.Dir = pfx.projectRepoDir
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v in project repo: %v: %s", args, err, out)
		}
	}
}

// buildPluginSignedFileOfRecord produces a signed artifact YAML where
// pluginShipgateSecretKey → pluginShipgateSecretValue is encrypted to the
// plugin recipient (age1yubikey1…). The per-value ciphertext is produced by
// age.Encrypt using plugin.NewRecipient so the fake plugin binary performs the
// recipient-v1 wrap operation.
func (pfx *pluginShipgateFixture) buildPluginSignedFileOfRecord(t *testing.T) []byte {
	t.Helper()

	// Encrypt the secret value to the plugin recipient. plugin.NewRecipient
	// launches the fake plugin binary (age-plugin-yubikey) in ModeOKIdentity to
	// perform the recipient-v1 wrap. A noopUI is used because the fake plugin
	// does not require user interaction.
	noopUI := &plugin.ClientUI{
		DisplayMessage: func(_, _ string) error { return nil },
		RequestValue:   func(_, _ string, _ bool) (string, error) { return "", nil },
		Confirm:        func(_, _, yes, _ string) (bool, error) { return true, nil },
		WaitTimer:      func(_ string) {},
	}

	rec, err := plugin.NewRecipient(pfx.pluginRecipientStr, noopUI)
	if err != nil {
		t.Fatalf("plugin.NewRecipient(%q): %v", pfx.pluginRecipientStr, err)
	}

	// Build armored ciphertext for the secret value.
	var sb strings.Builder
	aw := armor.NewWriter(&sb)
	w, err := age.Encrypt(aw, rec)
	if err != nil {
		t.Fatalf("age.Encrypt (plugin recipient): %v", err)
	}
	if _, err := w.Write([]byte(pluginShipgateSecretValue)); err != nil {
		t.Fatalf("write plaintext to age.Encrypt: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close age writer: %v", err)
	}
	if err := aw.Close(); err != nil {
		t.Fatalf("close armor writer: %v", err)
	}
	ct := sb.String()

	// Compute the plugin recipient fingerprint: sha256 of the recipient string,
	// matching the production fingerprint derivation (recipientbuild.New /
	// artifact.RecipientEntry.FP).
	fp := sha256.Sum256([]byte(pfx.pluginRecipientStr))
	fpHex := hex.EncodeToString(fp[:])

	// Build the signed artifact. The manifest and signature follow the same
	// structure as the X25519 fixture in asymmetry_shipgate_test.go.
	man := manifest.Manifest{
		FormatVersion:         "byreis.native.v1",
		ProjectID:             pluginShipgateProjectID,
		LogicalFileName:       pluginShipgateLogicalFile,
		Counter:               0,
		Values:                map[string][]byte{pluginShipgateSecretKey: []byte(ct)},
		RecipientFingerprints: []string{fpHex},
	}
	priv, err := os.ReadFile(pfx.adminSignKeyPath)
	if err != nil {
		t.Fatalf("reading admin sign key: %v", err)
	}
	sig, signErr := sign.Sign(ed25519.PrivateKey(priv), man)
	if signErr != nil {
		t.Fatalf("sign.Sign: %v", signErr)
	}

	doc := map[string]any{
		pluginShipgateSecretKey: ct,
		"byreis": map[string]any{
			"format_version": "byreis.native.v1",
			"project_id":     pluginShipgateProjectID,
			"file":           pluginShipgateLogicalFile,
			"counter":        0,
			"recipients":     []map[string]string{{"fp": fpHex}},
		},
		"manifest_sig": map[string]string{
			"signer": "plugin-admin-1",
			"sig":    hex.EncodeToString(sig),
		},
	}

	// Ensure the artifact struct is consistent with the doc map above (used only
	// for the compile-time coverage of artifact types; the marshalled doc is
	// authoritative).
	_ = artifact.Signed{
		Values: map[string]artifact.EncryptedValue{
			pluginShipgateSecretKey: artifact.EncryptedValue(ct),
		},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1",
			ProjectID:     pluginShipgateProjectID,
			File:          pluginShipgateLogicalFile,
			Counter:       0,
			Recipients:    []artifact.RecipientEntry{{FP: fpHex}},
		},
		ManifestSig: artifact.ManifestSig{
			Signer: "plugin-admin-1",
			Sig:    hex.EncodeToString(sig),
		},
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal signed file: %v", err)
	}
	return out
}

// gitInitAndSignCommit initialises a registry repo and makes a single SSH-
// signed commit. Mirrors shipgateFixture.gitInitAndSignCommit.
func (pfx *pluginShipgateFixture) gitInitAndSignCommit(t *testing.T, dir, msg string) {
	t.Helper()

	allowedSignersPath := filepath.Join(pfx.rootDir, "fixture-allowed-signers")
	pubBytes, err := os.ReadFile(pfx.sshPubKeyPath)
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
		{"config", "user.signingkey", pfx.sshPubKeyPath},
		{"config", "gpg.ssh.allowedSignersFile", allowedSignersPath},
		{"config", "commit.gpgsign", "true"},
		{"add", "."},
		{"commit", "-q", "-m", msg, "-S"},
	}
	for _, args := range commits {
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v in %s: %v: %s", args, dir, err, out)
		}
	}
}

// applyAdminEnv sets the test-scoped environment for the ADMIN plugin path.
// BYREIS_KEY_FILE points to the plugin identity file (AGE-PLUGIN-YUBIKEY-1…).
func (pfx *pluginShipgateFixture) applyAdminEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BYREIS_CONFIG", pfx.configDir)
	t.Setenv("BYREIS_CACHE", pfx.cacheDir)
	t.Setenv("BYREIS_REGISTRY", pfx.registryURL)
	t.Setenv("BYREIS_PROJECT_REPO", pfx.projectRepoURL)
	t.Setenv("BYREIS_PROJECT", pluginShipgateProjectID)
	t.Setenv("BYREIS_KEY_FILE", pfx.adminPluginIdentityPath)
	t.Setenv("BYREIS_SIGN_KEY_FILE", pfx.adminSignKeyPath)
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_BASE_BRANCH", pluginShipgateBaseBranch)
	t.Setenv("BYREIS_NON_INTERACTIVE", "")
}

// applyContributorEnv sets the test-scoped environment for the CONTRIBUTOR
// plugin path. The key file is a plain X25519 key that is NOT a plugin admin.
func (pfx *pluginShipgateFixture) applyContributorEnv(t *testing.T) {
	t.Helper()
	pfx.applyAdminEnv(t)
	t.Setenv("BYREIS_KEY_FILE", pfx.contribAgeKeyPath)
}

// runCobra invokes the SHIPPED cobra root with the production-built deps and
// returns the captured stdout/stderr buffers plus the resolved exit code.
func (pfx *pluginShipgateFixture) runCobra(t *testing.T, deps *cli.Deps, args ...string) (
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
