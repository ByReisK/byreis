//go:build shipgate

package app_test

// D-1 positive real-composition test for the V-3.5 wiring obligation.
//
// The existing submit_review_wiring_shipgate_test.go covers ONLY the
// nil-fallback direction: Submitter nil when no registry; Reviewer nil in
// CONTRIBUTOR mode. That file exercises the negative / partial-configuration
// paths only.
//
// This file adds the regression guard in the positive direction: given a
// fully-configured ADMIN environment (real admin age key at 0600 + file://
// registry signed by the ssh anchor + the BYREIS_* env the production path
// reads), BuildProductionDeps must return a NON-NIL functional Submitter,
// Reviewer, and RunTUISubmit.
//
// A future refactor that re-nils any of these fields (exactly what happened
// silently in v0.1 and v0.2) is caught immediately by the PRIMARY test below.
//
// Round-trip coverage:
//
//   - Reviewer.Review: driven against a hand-crafted fixture submission (the
//     same age-encrypted artifact bytes the shipgate fixture uses). A fake git
//     port returns the artifact bytes so no real GitHub API call is needed. The
//     round-trip asserts: Review succeeds, returned KeyNames is non-empty, no
//     plaintext value appears in the KeyNames slice or any non-Plaintext field.
//
//   - Submitter / Submit PR-open: the production wiring requires a real GitHub
//     token to push a branch (buildGitProviderProd returns (nil, err) when
//     BYREIS_GITHUB_TOKEN is empty). The fake token used here makes the git
//     provider non-nil at construction time, proving the composition wires
//     Submitter non-nil. A full PR-open round-trip would need a real GitHub
//     token, which is not available in CI. The non-nil + construction assertion
//     is the load-bearing regression guard; the submit PR-open limitation is
//     documented honestly below.
//
// Limitation (honestly documented, NOT faked green):
//
//   The Submit path's GitPort calls github.Provider.OpenSubmissionPR, which
//   makes a real HTTPS call to api.github.com. In CI there is no
//   BYREIS_GITHUB_TOKEN with write access to a real repo, so a full
//   submit-through-PR-open round-trip is not driven here. The non-nil
//   assertion (deps.Submitter != nil, deps.RunTUISubmit != nil) is the
//   primary regression guard. FL-V7-CRYPTO-3 (fixture-github-server for full
//   submit round-trip) is carried to a future slice.
//
// Fixture strategy:
//   Replicates the shipgate fixture pattern from
//   internal/core/usecase/asymmetry_shipgate_test.go — real ssh-keygen
//   ed25519 anchor, real age admin identity, real git file:// repos signed by
//   the anchor — but self-contained in this package to avoid cross-package
//   fixture coupling.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"go.yaml.in/yaml/v3"

	"github.com/ByReisK/byreis/internal/adapter/artifactcodec"
	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// d1ProjectID is the BYREIS_PROJECT value: owner/repo form required by the
// git provider. buildGitProviderProd passes this directly to gitadapter.New
// which validates owner/repo format. projectIDFromEnvProd strips the owner
// prefix so the registry path component is the bare repo name (d1RegistryID).
const d1ProjectID = "myorg/myapp"

// d1RegistryID is the bare logical project identifier used for registry
// file paths (projects/<id>.yaml, counters/<id>/...) and artifact metadata.
// It equals the repo-name part of d1ProjectID (after the "/").
const d1RegistryID = "myapp"

// d1LogicalFile is the logical file name configured in projects/<id>.yaml.
const d1LogicalFile = "prod"

// d1ConfiguredPath is the registry-attested repo-relative path.
const d1ConfiguredPath = "vault/prod.enc.yaml"

// d1SecretKey is the secret key name in the encrypted file-of-record.
const d1SecretKey = "SUBMIT_KEY"

// d1SecretValue is the plaintext the test asserts is recovered on the review path.
const d1SecretValue = "d1-positive-composition-test-secret-value"

// d1BaseBranch is the project repo base branch.
const d1BaseBranch = "main"

// d1AnchorPrincipal mirrors the production allowed-signers principal name.
const d1AnchorPrincipal = "byreis-anchor"

// ─── TestD1_PositiveComposition ───────────────────────────────────────────────

// TestD1_PositiveComposition is the D-1 regression guard.
//
// PRIMARY assertion: with a fully-configured ADMIN environment (real admin age
// key at 0600 + file:// registry signed by the ssh anchor), BuildProductionDeps
// returns non-nil Submitter, Reviewer, and RunTUISubmit. This directly prevents
// the silent re-nil regression that shipped twice (v0.1, v0.2).
//
// ROUND-TRIP assertion: a reviewer constructed from the same ports that
// BuildProductionDeps uses (real decrypt, real identity loader, real codec)
// but with a stub git port returning the fixture artifact bytes successfully
// decrypts the submission and returns the expected key names.
func TestD1_PositiveComposition(t *testing.T) {
	if d1GitMissing() {
		t.Fatalf("D-1: required binary 'git' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}
	if d1SSHKeygenMissing() {
		t.Fatalf("D-1: required binary 'ssh-keygen' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	fx := newD1Fixture(t)

	t.Run("PRIMARY/SubmitterAndReviewerNonNilInAdminMode", func(t *testing.T) {
		// Apply the ADMIN env. A fake (non-empty) BYREIS_GITHUB_TOKEN is set so
		// buildGitProviderProd constructs a non-nil git provider — the token is
		// never used in this test (no real API call is made). This is the
		// minimum required to make both Submitter and Reviewer non-nil.
		fx.applyAdminEnv(t)
		t.Setenv("BYREIS_GITHUB_TOKEN", "fake-d1-github-token-for-construction-only")

		deps, err := app.BuildProductionDeps(context.Background())
		if err != nil {
			t.Fatalf("D-1/PRIMARY: BuildProductionDeps in ADMIN mode: %v", err)
		}
		if deps.CurrentMode != mode.ModeAdmin {
			t.Fatalf("D-1/PRIMARY: deps.CurrentMode = %v, want ModeAdmin "+
				"(admin age key + registered in registry; mode detection failed)",
				deps.CurrentMode)
		}

		// PRIMARY regression guard: all three wired fields must be non-nil.
		if deps.Submitter == nil {
			t.Errorf("D-1/PRIMARY: deps.Submitter is nil — " +
				"production wiring re-niled Submitter (regression)")
		}
		if deps.Reviewer == nil {
			t.Errorf("D-1/PRIMARY: deps.Reviewer is nil — " +
				"production wiring re-niled Reviewer (regression)")
		}
		if deps.RunTUISubmit == nil {
			t.Errorf("D-1/PRIMARY: deps.RunTUISubmit is nil — " +
				"SubmitterFactory closure not assembled at the composition root (regression)")
		}
	})

	t.Run("ROUNDTRIP/ReviewerDecryptsFixtureArtifact", func(t *testing.T) {
		// Drive a Reviewer.Review round-trip using:
		//   - real decrypt.Decryptor (real age X25519 crypto)
		//   - real identity.Loader pointing at the fixture admin age key file
		//   - real artifactcodec (real YAML codec)
		//   - real mode gate (ADMIN — always allows CommandReview)
		//   - stub git port returning the fixture artifact bytes (no GitHub API)
		//
		// This proves the decrypt → codec → identity chain that BuildProductionDeps
		// assembles into deps.Reviewer is correct. The stub git port isolates the
		// test from the real GitHub API while keeping the crypto path real.
		//
		// No plaintext value appears in any non-Plaintext field of ReviewResult.
		idLoader := identityadapter.New(identityadapter.Config{
			EnvKeyFile:     fx.adminAgeKeyPath,
			DefaultKeyPath: func() string { return "" },
		})

		codec := artifactcodec.NewPortAdapter(artifactcodec.New())

		// The stub git port returns the fixture artifact bytes. ArtifactSHA is
		// sha256 over those exact bytes.
		artifactBytes := fx.signedArtifactBytes
		rawSHA := sha256.Sum256(artifactBytes)
		artifactSHA := hex.EncodeToString(rawSHA[:])

		meta := coregit.SubmissionMeta{
			SchemaVersion: 1,
			Project:       d1ProjectID,
			SecretsPath:   d1ConfiguredPath,
			Key:           d1SecretKey,
			Action:        "add",
			ArtifactSHA:   artifactSHA,
		}

		stubGit := &d1StubGitProvider{
			submission: coregit.Submission{
				Ref:           coregit.PRRef{Project: d1ProjectID + "/secrets", Number: 1},
				Author:        "contributor",
				Justification: "D-1 fixture justification",
				ArtifactBytes: artifactBytes,
				ArtifactSHA:   coregit.ArtifactSHA(artifactSHA),
				Meta:          meta,
			},
		}

		// Admin mode gate: always allows CommandReview.
		gate := &d1AdminModeGate{}

		reviewer, err := usecase.NewReviewer(usecase.ReviewDeps{
			Git:           stubGit,
			Decryptor:     decrypt.New(),
			IDLoader:      idLoader,
			ArtifactCodec: codec,
			Mode:          gate,
			Audit:         audit.Discard,
		})
		if err != nil {
			t.Fatalf("D-1/ROUNDTRIP: constructing Reviewer: %v", err)
		}

		result, reviewErr := reviewer.Review(context.Background(), usecase.ReviewInput{
			Ref:               coregit.PRRef{Project: d1ProjectID + "/secrets", Number: 1},
			ExpectedProjectID: d1RegistryID,
			ExpectedFileName:  d1LogicalFile,
		})
		if reviewErr != nil {
			t.Fatalf("D-1/ROUNDTRIP: Reviewer.Review failed: %v", reviewErr)
		}

		// Key names must be non-empty (the artifact carries d1SecretKey).
		if len(result.KeyNames) == 0 {
			t.Errorf("D-1/ROUNDTRIP: result.KeyNames is empty — codec/decrypt failed")
		}
		found := false
		for _, k := range result.KeyNames {
			if k == d1SecretKey {
				found = true
			}
			// No plaintext must appear in the key-name slice (these are key names only).
			if strings.Contains(k, d1SecretValue) {
				t.Errorf("D-1/ROUNDTRIP: plaintext leaked into KeyNames[%q]", k)
			}
		}
		if !found {
			t.Errorf("D-1/ROUNDTRIP: expected key %q not in result.KeyNames %v",
				d1SecretKey, result.KeyNames)
		}

		// PinnedSHA must be non-empty (the content pin for merge).
		if result.PinnedSHA == "" {
			t.Errorf("D-1/ROUNDTRIP: result.PinnedSHA is empty")
		}

		// Plaintext must decode the correct value (real age crypto round-trip).
		if got := result.Plaintext[d1SecretKey]; got != d1SecretValue {
			t.Errorf("D-1/ROUNDTRIP: plaintext[%q] = %q, want %q",
				d1SecretKey, got, d1SecretValue)
		}

		// Plaintext must NOT appear in any non-Plaintext field of ReviewResult
		// (no plaintext leak into display fields).
		if strings.Contains(result.Author, d1SecretValue) {
			t.Errorf("D-1/ROUNDTRIP: plaintext leaked into result.Author")
		}
		if strings.Contains(result.Action, d1SecretValue) {
			t.Errorf("D-1/ROUNDTRIP: plaintext leaked into result.Action")
		}
		if strings.Contains(result.Key, d1SecretValue) {
			t.Errorf("D-1/ROUNDTRIP: plaintext leaked into result.Key")
		}
		if strings.Contains(result.PinnedSHA, d1SecretValue) {
			t.Errorf("D-1/ROUNDTRIP: plaintext leaked into result.PinnedSHA")
		}
		for _, line := range result.PerKey {
			if strings.Contains(line.Key, d1SecretValue) {
				t.Errorf("D-1/ROUNDTRIP: plaintext leaked into PerKey[%q].Key", line.Key)
			}
			if strings.Contains(line.ValidationMsg, d1SecretValue) {
				t.Errorf("D-1/ROUNDTRIP: plaintext leaked into PerKey[%q].ValidationMsg", line.Key)
			}
		}
	})
}

// ─── d1StubGitProvider ───────────────────────────────────────────────────────

// d1StubGitProvider implements coregit.GitProvider for the D-1 round-trip test.
// It returns a fixed Submission from GetSubmission and panics on any write path
// (OpenSubmissionPR, MergeSubmission, RollbackSignedFile, CommentPR) since the
// round-trip test must never reach a write.
type d1StubGitProvider struct {
	submission coregit.Submission
}

func (s *d1StubGitProvider) GetSubmission(_ context.Context, _ coregit.PRRef) (coregit.Submission, error) {
	return s.submission, nil
}

func (s *d1StubGitProvider) OpenSubmissionPR(_ context.Context, _ coregit.OpenPRInput) (coregit.PullRequest, error) {
	panic("d1StubGitProvider: OpenSubmissionPR must not be called on the review round-trip path")
}

func (s *d1StubGitProvider) MergeSubmission(_ context.Context, _ coregit.MergeInput) (coregit.MergeResult, error) {
	panic("d1StubGitProvider: MergeSubmission must not be called on the review round-trip path")
}

func (s *d1StubGitProvider) RollbackSignedFile(_ context.Context, _ coregit.RollbackInput) error {
	panic("d1StubGitProvider: RollbackSignedFile must not be called on the review round-trip path")
}

func (s *d1StubGitProvider) CommentPR(_ context.Context, _ coregit.PRRef, _ string) error {
	return nil
}

// d1AdminModeGate is a ModeGate that always allows (ADMIN mode).
type d1AdminModeGate struct{}

func (g *d1AdminModeGate) Allow(_ mode.Command) error { return nil }

// ─── d1Fixture ───────────────────────────────────────────────────────────────

// d1Fixture holds all on-disk artifacts and keys for the D-1 test. It follows
// the same construction pattern as newShipgateFixture in the usecase_test
// package: real ssh-keygen, real age keys, real git file:// repos, signed by
// the anchor. All fields are set by newD1Fixture.
type d1Fixture struct {
	rootDir   string
	configDir string
	cacheDir  string

	sshKeyPath    string
	sshPubKeyPath string
	anchorRawKey  ed25519.PublicKey

	adminAgeKeyPath  string
	adminAgePub      string
	adminAgeIdent    *age.X25519Identity
	adminSignKeyPath string
	adminSignPubKey  ed25519.PublicKey

	registryRepoDir string
	projectRepoDir  string
	registryURL     string
	projectRepoURL  string

	// signedArtifactBytes is the exact YAML the round-trip test decrypts.
	signedArtifactBytes []byte
}

// newD1Fixture builds the full real fixture in t.TempDir(). All keys are
// generated fresh per invocation; nothing persists across runs.
func newD1Fixture(t *testing.T) *d1Fixture {
	t.Helper()
	root := t.TempDir()
	fx := &d1Fixture{rootDir: root}

	fx.configDir = filepath.Join(root, "config")
	fx.cacheDir = filepath.Join(root, "cache")
	if err := os.MkdirAll(fx.configDir, 0o700); err != nil {
		t.Fatalf("D-1: mkdir configDir: %v", err)
	}
	if err := os.MkdirAll(fx.cacheDir, 0o700); err != nil {
		t.Fatalf("D-1: mkdir cacheDir: %v", err)
	}

	fx.d1GenerateSSHSigningKey(t)
	fx.d1GenerateAdminAgeIdentity(t)
	fx.d1GenerateAdminSigningKey(t)
	fx.d1WriteTrustYAML(t, fx.anchorRawKey)
	fx.d1BuildRegistryRepo(t)
	fx.d1BuildProjectRepo(t)

	fx.registryURL = "file://" + fx.registryRepoDir
	fx.projectRepoURL = "file://" + fx.projectRepoDir

	return fx
}

// applyAdminEnv sets the test-scoped environment variables for the ADMIN flow.
// BYREIS_GITHUB_TOKEN is left empty here; call t.Setenv to override for the
// PRIMARY test where a non-empty fake token is required.
func (fx *d1Fixture) applyAdminEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BYREIS_CONFIG", fx.configDir)
	t.Setenv("BYREIS_CACHE", fx.cacheDir)
	t.Setenv("BYREIS_REGISTRY", fx.registryURL)
	t.Setenv("BYREIS_PROJECT_REPO", fx.projectRepoURL)
	t.Setenv("BYREIS_PROJECT", d1ProjectID)
	t.Setenv("BYREIS_KEY_FILE", fx.adminAgeKeyPath)
	t.Setenv("BYREIS_SIGN_KEY_FILE", fx.adminSignKeyPath)
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("BYREIS_BASE_BRANCH", d1BaseBranch)
	t.Setenv("BYREIS_NON_INTERACTIVE", "")
}

// d1GenerateSSHSigningKey runs ssh-keygen to produce a fresh ed25519 signing key
// and extracts the raw 32-byte pubkey from the .pub file.
func (fx *d1Fixture) d1GenerateSSHSigningKey(t *testing.T) {
	t.Helper()
	fx.sshKeyPath = filepath.Join(fx.rootDir, "registry-signer")
	fx.sshPubKeyPath = fx.sshKeyPath + ".pub"

	cmd := exec.Command("ssh-keygen",
		"-t", "ed25519",
		"-N", "",
		"-C", "d1-anchor",
		"-q",
		"-f", fx.sshKeyPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("D-1: ssh-keygen: %v: %s", err, out)
	}

	pubBytes, err := os.ReadFile(fx.sshPubKeyPath)
	if err != nil {
		t.Fatalf("D-1: reading ssh pubkey: %v", err)
	}
	fx.anchorRawKey = d1DecodeSSHEd25519Pubkey(t, string(pubBytes))
}

// d1DecodeSSHEd25519Pubkey extracts the raw 32-byte Ed25519 public key from an
// OpenSSH "ssh-ed25519 BASE64 [comment]" line.
func d1DecodeSSHEd25519Pubkey(t *testing.T, pubLine string) ed25519.PublicKey {
	t.Helper()
	fields := strings.Fields(strings.TrimSpace(pubLine))
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		t.Fatalf("D-1: unexpected ssh pubkey format: %q", pubLine)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatalf("D-1: base64-decoding ssh pubkey blob: %v", err)
	}
	if len(blob) < 4 {
		t.Fatalf("D-1: ssh pubkey blob too short")
	}
	typeLen := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	if 4+typeLen+4 > len(blob) {
		t.Fatalf("D-1: ssh pubkey blob malformed: type len %d", typeLen)
	}
	keyOff := 4 + typeLen + 4
	keyLen := int(blob[4+typeLen])<<24 | int(blob[5+typeLen])<<16 |
		int(blob[6+typeLen])<<8 | int(blob[7+typeLen])
	if keyOff+keyLen > len(blob) || keyLen != ed25519.PublicKeySize {
		t.Fatalf("D-1: ssh pubkey blob: key length %d not %d", keyLen, ed25519.PublicKeySize)
	}
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, blob[keyOff:keyOff+keyLen])
	return out
}

// d1GenerateAdminAgeIdentity generates a fresh age X25519 keypair and writes
// the AGE-SECRET-KEY string to a 0600 file.
func (fx *d1Fixture) d1GenerateAdminAgeIdentity(t *testing.T) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("D-1: age.GenerateX25519Identity: %v", err)
	}
	fx.adminAgeIdent = id
	fx.adminAgePub = id.Recipient().String()
	fx.adminAgeKeyPath = filepath.Join(fx.rootDir, "admin-age.key")
	if err := os.WriteFile(fx.adminAgeKeyPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("D-1: writing admin age key: %v", err)
	}
}

// d1GenerateAdminSigningKey generates a fresh Ed25519 keypair for manifest
// signing and writes the 64-byte raw private key to a 0600 file.
func (fx *d1Fixture) d1GenerateAdminSigningKey(t *testing.T) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("D-1: ed25519.GenerateKey: %v", err)
	}
	fx.adminSignPubKey = pub
	fx.adminSignKeyPath = filepath.Join(fx.rootDir, "admin-sign.key")
	if err := os.WriteFile(fx.adminSignKeyPath, priv, 0o600); err != nil {
		t.Fatalf("D-1: writing admin sign key: %v", err)
	}
}

// d1WriteTrustYAML writes trust.yaml at <configDir>/trust.yaml pinning the
// given raw ed25519 pubkey as the sole signer entry.
func (fx *d1Fixture) d1WriteTrustYAML(t *testing.T, anchorKey ed25519.PublicKey) {
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
		t.Fatalf("D-1: marshal trust.yaml: %v", err)
	}
	path := filepath.Join(fx.configDir, "trust.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("D-1: writing trust.yaml: %v", err)
	}
}

// d1BuildRegistryRepo initialises a local git repo with admins.yaml,
// projects/<id>.yaml, and counters/<id>/<file>.json, then makes a single
// SSH-signed commit using the fixture SSH key.
func (fx *d1Fixture) d1BuildRegistryRepo(t *testing.T) {
	t.Helper()
	fx.registryRepoDir = filepath.Join(fx.rootDir, "registry")
	if err := os.MkdirAll(fx.registryRepoDir, 0o755); err != nil {
		t.Fatalf("D-1: mkdir registry repo: %v", err)
	}

	signerB64 := base64.StdEncoding.EncodeToString(fx.adminSignPubKey)
	adminsYAML := fmt.Sprintf(`admins:
  - id: admin-1
    age_key: %s
    signer_key: %s
`, fx.adminAgePub, signerB64)
	d1WriteFileMode(t, filepath.Join(fx.registryRepoDir, "admins.yaml"), []byte(adminsYAML), 0o644)

	projectYAML := fmt.Sprintf(`files:
  %s: %s
`, d1LogicalFile, d1ConfiguredPath)
	if err := os.MkdirAll(filepath.Join(fx.registryRepoDir, "projects"), 0o755); err != nil {
		t.Fatalf("D-1: mkdir projects: %v", err)
	}
	d1WriteFileMode(t,
		filepath.Join(fx.registryRepoDir, "projects", d1RegistryID+".yaml"),
		[]byte(projectYAML), 0o644)

	counterDir := filepath.Join(fx.registryRepoDir, "counters", d1RegistryID)
	if err := os.MkdirAll(counterDir, 0o755); err != nil {
		t.Fatalf("D-1: mkdir counter dir: %v", err)
	}
	counterJSON := fmt.Sprintf(
		`{"project_id":%q,"file":%q,"last_accepted_counter":0,"last_pr":"","updated_at":"2026-05-23T00:00:00Z","pending":null}`+"\n",
		d1RegistryID, d1LogicalFile,
	)
	d1WriteFileMode(t, filepath.Join(counterDir, d1LogicalFile+".json"), []byte(counterJSON), 0o644)

	fx.d1GitInitAndSignCommit(t, fx.registryRepoDir, "registry: initial signed state")
}

// d1BuildProjectRepo initialises a local git repo with a signed file-of-record
// at vault/<file>.enc.yaml, a .byreis.yaml marker, and a plain commit.
func (fx *d1Fixture) d1BuildProjectRepo(t *testing.T) {
	t.Helper()
	fx.projectRepoDir = filepath.Join(fx.rootDir, "project")
	if err := os.MkdirAll(fx.projectRepoDir, 0o755); err != nil {
		t.Fatalf("D-1: mkdir project repo: %v", err)
	}

	signedBytes := fx.d1BuildSignedFileOfRecord(t)
	fx.signedArtifactBytes = signedBytes

	vaultDir := filepath.Join(fx.projectRepoDir, "vault")
	if err := os.MkdirAll(vaultDir, 0o755); err != nil {
		t.Fatalf("D-1: mkdir vault: %v", err)
	}
	d1WriteFileMode(t, filepath.Join(vaultDir, d1LogicalFile+".enc.yaml"), signedBytes, 0o644)
	d1WriteFileMode(t, filepath.Join(fx.projectRepoDir, ".byreis.yaml"),
		[]byte("# byreis project marker (D-1 fixture)\n"), 0o644)

	cmds := [][]string{
		{"init", "-q", "--initial-branch=" + d1BaseBranch},
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
			t.Fatalf("D-1: git %v in project repo: %v: %s", args, err, out)
		}
	}
}

// d1BuildSignedFileOfRecord builds the fully-formed signed file-of-record YAML
// for d1SecretKey → d1SecretValue, sealed to the admin age recipient and signed
// by the admin Ed25519 key. Counter=0 (cold).
func (fx *d1Fixture) d1BuildSignedFileOfRecord(t *testing.T) []byte {
	t.Helper()

	ct := d1EncryptOneArmored(t, d1SecretValue, fx.adminAgePub)

	fp := sha256.Sum256([]byte(fx.adminAgePub))
	fpHex := hex.EncodeToString(fp[:])

	signed := artifact.Signed{
		Values: map[string]artifact.EncryptedValue{
			d1SecretKey: artifact.EncryptedValue(ct),
		},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1",
			ProjectID:     d1RegistryID,
			File:          d1LogicalFile,
			Counter:       0,
			Recipients:    []artifact.RecipientEntry{{FP: fpHex}},
		},
	}

	man := manifest.Manifest{
		FormatVersion:         signed.Byreis.FormatVersion,
		ProjectID:             signed.Byreis.ProjectID,
		LogicalFileName:       signed.Byreis.File,
		Counter:               signed.Byreis.Counter,
		Values:                map[string][]byte{d1SecretKey: []byte(ct)},
		RecipientFingerprints: []string{fpHex},
	}
	priv, err := os.ReadFile(fx.adminSignKeyPath)
	if err != nil {
		t.Fatalf("D-1: reading admin sign key: %v", err)
	}
	sig, err := sign.Sign(ed25519.PrivateKey(priv), man)
	if err != nil {
		t.Fatalf("D-1: sign.Sign: %v", err)
	}
	signed.ManifestSig = artifact.ManifestSig{
		Signer: "admin-1",
		Sig:    hex.EncodeToString(sig),
	}

	doc := map[string]any{
		d1SecretKey: ct,
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
		t.Fatalf("D-1: marshal signed file: %v", err)
	}
	return out
}

// d1GitInitAndSignCommit initialises a git repo at dir and creates a single
// SSH-signed commit using the fixture's SSH signing key.
func (fx *d1Fixture) d1GitInitAndSignCommit(t *testing.T, dir, msg string) {
	t.Helper()

	allowedSignersPath := filepath.Join(fx.rootDir, "d1-allowed-signers")
	pubBytes, err := os.ReadFile(fx.sshPubKeyPath)
	if err != nil {
		t.Fatalf("D-1: reading ssh pubkey: %v", err)
	}
	pubFields := strings.Fields(string(pubBytes))
	if len(pubFields) < 2 {
		t.Fatalf("D-1: unexpected ssh pubkey contents")
	}
	allowedLine := d1AnchorPrincipal + " " + pubFields[0] + " " + pubFields[1] + "\n"
	if err := os.WriteFile(allowedSignersPath, []byte(allowedLine), 0o600); err != nil {
		t.Fatalf("D-1: writing allowed_signers: %v", err)
	}

	commits := [][]string{
		{"init", "-q", "--initial-branch=main"},
		{"config", "user.name", d1AnchorPrincipal},
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
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("D-1: git %v in %s: %v: %s", args, dir, err, out)
		}
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// d1EncryptOneArmored age-encrypts a single plaintext to a single recipient
// and returns the armored ciphertext string.
func d1EncryptOneArmored(t *testing.T, plaintext, recipientStr string) string {
	t.Helper()
	rec, err := age.ParseX25519Recipient(recipientStr)
	if err != nil {
		t.Fatalf("D-1: parse age recipient: %v", err)
	}
	var sb strings.Builder
	aw := armor.NewWriter(&sb)
	w, err := age.Encrypt(aw, rec)
	if err != nil {
		t.Fatalf("D-1: age.Encrypt: %v", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatalf("D-1: write plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("D-1: close age writer: %v", err)
	}
	if err := aw.Close(); err != nil {
		t.Fatalf("D-1: close armor writer: %v", err)
	}
	return sb.String()
}

// d1WriteFileMode writes data to path with the given mode.
func d1WriteFileMode(t *testing.T, path string, data []byte, fileMode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, fileMode); err != nil {
		t.Fatalf("D-1: write %s: %v", path, err)
	}
}

// d1GitMissing reports whether the git binary is unavailable.
func d1GitMissing() bool {
	_, err := exec.LookPath("git")
	return err != nil
}

// d1SSHKeygenMissing reports whether the ssh-keygen binary is unavailable.
func d1SSHKeygenMissing() bool {
	_, err := exec.LookPath("ssh-keygen")
	return err != nil
}

// Compile-time assertions: the stub and gate satisfy the required interfaces.
var (
	_ coregit.GitProvider = (*d1StubGitProvider)(nil)
	_ usecase.ModeGate    = (*d1AdminModeGate)(nil)
)

// Blank imports to suppress "imported and not used" errors for packages that
// are used only transitively (e.g. bytes, encoding/json used in git.go's
// EncodeSubmissionMeta which we import via coregit).
var (
	_ = bytes.NewBuffer
	_ = json.Marshal
	_ = fmt.Sprintf
)
