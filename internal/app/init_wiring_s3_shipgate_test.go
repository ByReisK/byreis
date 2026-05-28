//go:build shipgate

package app_test

// TestS3_InitVerbWiredWhenConfigured is the S3 positive-composition guard for
// the init verb and the Initializer use-case field.
//
// Problem class: a dropped wiring like deps.Initializer = nil (exactly what
// shipped invisibly in v0.1 through v0.9) is structurally invisible to all
// existing shipgate tests because they wire cli.Deps fields directly and bypass
// BuildProductionDeps.  This test closes that gap.
//
// What this test asserts:
//
//  1. EVERY unconditionally-wired use-case field in cli.Deps is non-nil after
//     a real BuildProductionDeps call against a fully-configured ADMIN
//     environment.  A future refactor that drops any wiring fails this guard
//     immediately.
//
//  2. deps.Initializer is specifically non-nil (the field that was missing
//     across all releases).
//
//  3. The cobra tree produced by NewRootCmdWithDeps includes an "init"
//     subcommand.  A dropped AddCommand call would silently remove the verb.
//
//  4. An end-to-end init round-trip: deps.Initializer.Init against a
//     file:// registry signed by the fixture SSH key succeeds and writes
//     trust.yaml + .byreis.yaml to a fresh config directory.  This is the
//     missing hermetic coverage for the user entry path.
//
// Strategy: reuses the D-1 fixture (file:// registry, ssh anchor, admin age
// key, project repo).  The init call uses --accept-signer to bypass the
// interactive confirmation prompt, matching the non-interactive production path
// (BYREIS_NON_INTERACTIVE=1 + --accept-signer).
//
// Naming: the TestS3_ prefix places this test inside the existing app-leg
// shipgate -run filter ('TestD1_PositiveComposition|TestV35_|TestS1_|TestS3_')
// so it is automatically included in `make test-shipgate`, ci.yml, and
// release.yml without any filter string change.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// TestS3_InitVerbWiredWhenConfigured asserts that BuildProductionDeps wires
// deps.Initializer and that all unconditionally-wired use-case fields are
// non-nil in a fully-configured ADMIN environment with a file:// registry.
func TestS3_InitVerbWiredWhenConfigured(t *testing.T) {
	if d1GitMissing() {
		t.Fatalf("required binary 'git' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}
	if d1SSHKeygenMissing() {
		t.Fatalf("required binary 'ssh-keygen' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	fx := newD1Fixture(t)
	fx.applyAdminEnv(t)

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps returned error: %v", err)
	}

	// Primary guard: Initializer must be non-nil in a configured environment.
	// This is the field that was missing across all releases v0.1–v0.9.
	if deps.Initializer == nil {
		t.Fatalf("deps.Initializer is nil when registry and config dir are set — " +
			"the Initializer wiring at the composition root was silently dropped; " +
			"byreis init cannot function (silent-nil regression class)")
	}

	// Comprehensive nil-field guard: every use-case field that MUST be non-nil
	// in a fully-wired ADMIN environment with file:// registry + project repo.
	//
	// Intentionally nil with a file:// project slug (no GitHub API available):
	//   Submitter, Reviewer, Rejecter, Merger, RequestAccessReader,
	//   RequestAccessOpener, RunTUISubmit, RunTUIReview — git provider nil
	//   for file:// project repo (by design, documented in D-1 comments).
	//
	// Conditionally non-nil (depends on BYREIS_SIGN_KEY_FILE being present
	// AND the admin key being registered in the registry):
	//   Editor — nil when manifestSigner is nil (signing key not configured or
	//   not registered); the CLI surfaces "not configured" at command time.
	s3RequireNonNil(t, "Policy", deps.Policy)
	s3RequireNonNil(t, "Doctor", deps.Doctor)
	s3RequireNonNil(t, "RunChild", deps.RunChild)
	s3RequireNonNil(t, "Initializer", deps.Initializer)
	s3RequireNonNil(t, "Getter", deps.Getter)
	s3RequireNonNil(t, "Decryptor", deps.Decryptor)
	s3RequireNonNil(t, "AuditReader", deps.AuditReader)
	s3RequireNonNil(t, "AuditVerifier", deps.AuditVerifier)

	// Cobra tree guard: "init" subcommand must be registered.
	root := cli.NewRootCmdWithDeps(deps)
	initFound := false
	for _, sub := range root.Commands() {
		if sub.Name() == "init" {
			initFound = true
			break
		}
	}
	if !initFound {
		t.Fatalf("cobra tree does not contain an 'init' subcommand — " +
			"the AddCommand call was dropped or the command name was changed; " +
			"verify newInitCmd is registered in NewRootCmdWithDeps")
	}
}

// TestS3_InitRoundTrip drives a complete hermetic byreis init round-trip
// against a file:// registry signed by the D-1 fixture SSH anchor key.
//
// The test:
//  1. Creates a fresh config directory (no pre-existing trust anchor).
//  2. Calls deps.Initializer.Init with NonInteractive=true + AcceptSigner=<fp>.
//  3. Asserts trust.yaml and .byreis.yaml are written with correct content.
//  4. Calls Init again (repeat-init path) and asserts the existing pin is
//     verified, not re-written (PinWritten=false).
func TestS3_InitRoundTrip(t *testing.T) {
	if d1GitMissing() {
		t.Fatalf("required binary 'git' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}
	if d1SSHKeygenMissing() {
		t.Fatalf("required binary 'ssh-keygen' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	fx := newD1Fixture(t)

	// Use a fresh config dir for init so the D-1 fixture's trust.yaml does
	// not pre-pin the anchor (which would make this the repeat-init path).
	initConfigDir := filepath.Join(fx.rootDir, "init-config")
	if err := os.MkdirAll(initConfigDir, 0o700); err != nil {
		t.Fatalf("mkdir initConfigDir: %v", err)
	}

	// Apply the admin env, override BYREIS_CONFIG to the fresh dir.
	fx.applyAdminEnv(t)
	t.Setenv("BYREIS_CONFIG", initConfigDir)
	t.Setenv("BYREIS_CACHE", filepath.Join(fx.rootDir, "init-cache"))

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps: %v", err)
	}
	if deps.Initializer == nil {
		t.Fatalf("deps.Initializer is nil — cannot drive init round-trip")
	}

	// Derive the expected signer fingerprint from the fixture's SSH anchor key.
	// This matches signerprobe.computeFingerprint (hex sha256 of the raw key).
	anchorFP := s3HexSHA256(fx.anchorRawKey)

	// ── First init: no existing trust anchor ───────────────────────────────────
	// InitInput.ConfigDir is the project working directory where .byreis.yaml
	// is written; the trust anchor is written to the TrustStore's configDir
	// (BYREIS_CONFIG, i.e. initConfigDir here).
	projectWorkDir := filepath.Join(fx.rootDir, "project-workdir")
	if err := os.MkdirAll(projectWorkDir, 0o755); err != nil {
		t.Fatalf("mkdir projectWorkDir: %v", err)
	}

	res, initErr := deps.Initializer.Init(context.Background(), usecase.InitInput{
		RegistryURL:    fx.registryURL,
		ProjectID:      d1ProjectID,
		AcceptSigner:   anchorFP,
		NonInteractive: true,
		ConfigDir:      projectWorkDir,
	})
	if initErr != nil {
		t.Fatalf("first init failed: %v", initErr)
	}
	if !res.PinWritten {
		t.Errorf("first init: PinWritten = false, want true")
	}
	if !res.ProjectConfigWritten {
		t.Errorf("first init: ProjectConfigWritten = false, want true")
	}
	if res.SignerFingerprint != anchorFP {
		t.Errorf("first init: SignerFingerprint = %q, want %q", res.SignerFingerprint, anchorFP)
	}

	// trust.yaml must exist at initConfigDir (written by the TrustAnchorStore).
	trustPath := filepath.Join(initConfigDir, "trust.yaml")
	if _, statErr := os.Stat(trustPath); os.IsNotExist(statErr) {
		t.Errorf("trust.yaml not written at %s", trustPath)
	}

	// .byreis.yaml must be written to projectWorkDir and contain project ID + URL.
	configPath := filepath.Join(projectWorkDir, ".byreis.yaml")
	configData, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf(".byreis.yaml not written at %s: %v", configPath, readErr)
	}
	configText := string(configData)
	if !s3Contains(configText, d1ProjectID) {
		t.Errorf(".byreis.yaml does not contain project ID %q:\n%s", d1ProjectID, configText)
	}
	if !s3Contains(configText, fx.registryURL) {
		t.Errorf(".byreis.yaml does not contain registry URL %q:\n%s", fx.registryURL, configText)
	}

	// ── Second init: existing pin must be verified, not re-written ─────────────
	res2, init2Err := deps.Initializer.Init(context.Background(), usecase.InitInput{
		RegistryURL:    fx.registryURL,
		ProjectID:      d1ProjectID,
		AcceptSigner:   anchorFP,
		NonInteractive: true,
		ConfigDir:      projectWorkDir,
	})
	if init2Err != nil {
		t.Fatalf("second init failed: %v", init2Err)
	}
	if res2.PinWritten {
		t.Errorf("second init: PinWritten = true, want false (pin already exists)")
	}
	if !res2.ProjectConfigWritten {
		t.Errorf("second init: ProjectConfigWritten = false, want true")
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// s3RequireNonNil fails the test when v is nil (interface comparison).
func s3RequireNonNil(t *testing.T, name string, v interface{}) {
	t.Helper()
	if v == nil {
		t.Errorf("deps.%s is nil in a fully-wired ADMIN environment — "+
			"wiring was silently dropped at the composition root (silent-nil regression)", name)
	}
}

// s3HexSHA256 returns the hex-encoded sha256 of b.  This matches the
// derivation in signerprobe.computeFingerprint and usecase.fingerprintOf.
func s3HexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// s3Contains reports whether s contains substr.
func s3Contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
