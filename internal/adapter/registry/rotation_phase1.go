package registry

// rotationPhaseAdapter is the production Phase1Executor + Phase2Executor.
//
// Phase-1 runs the REVERSIBLE leg of rotation:
//   - Creates an isolated 0700 workspace and shallow-clones the project repo.
//   - Captures ProjectParentSHA at main HEAD before branch creation (CAS lease
//     for Phase-2's fast-forward push).
//   - Creates the byreis/rotate-<ts> branch.
//   - For each FileSnapshot in the plan: decrypt → re-encrypt to R' → sign →
//     encode → write (ciphertext only) → commit via -F temp-file (never -m).
//   - Pushes the rotation branch.
//   - Per-file RecordPendingBump; file-K's CAS = registry HEAD after (K-1)'s
//     bump. Captures RegistryParentSHA after all N bumps land.
//
// Phase-2 runs the TERMINAL leg:
//   - CAS fast-forward push: --force-with-lease=refs/heads/main:<ProjectParentSHA>.
//   - Calls RegistryClient.CommitRotation with BuildRotationAuditEvent.
//   - Returns Phase2Result (MergedSHA from branch HEAD before the push).
//
// Security invariants:
//   - Plaintext zeroed in defer after re-encrypt.
//   - Plaintext never touches disk; only ciphertext written.
//   - NO plaintext in errors, logs, or argv.
//   - Commit message written to temp file; git commit -F (never -m).
//   - NO bare --force. NO rebase. CAS rejection surfaces clean sentinel.
//   - NO auto-rollback; errors surface ErrRotationReconcile.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/git"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// rotationManifestSigner is a local structural alias of usecase.ManifestSigner.
// Defined here to avoid importing internal/core/usecase (which transitively
// imports internal/core/crypto/verify, violating the allowlist gate for this
// adapter). Callers pass any value that satisfies usecase.ManifestSigner; Go
// structural typing ensures compatibility without an explicit type assertion.
type rotationManifestSigner interface {
	Sign(ctx context.Context, m manifest.Manifest) (signerID string, sig []byte, err error)
}

// rotationArtifactCodec is a local structural alias of usecase.ArtifactCodec.
// Same rationale as rotationManifestSigner above.
type rotationArtifactCodec interface {
	DecodeSigned(b []byte) (artifact.Signed, error)
	DecodeUnsigned(b []byte) (artifact.Unsigned, error)
	EncodeSigned(s artifact.Signed) ([]byte, error)
}

// RotationPhaseAdapterDeps carries the constructor-injected ports for the
// rotationPhaseAdapter. All fields are required unless noted.
type RotationPhaseAdapterDeps struct {
	// ProjectRepoURL is the project secrets repo clone URL. Must be operator-
	// pinned (same trust tier as BYREIS_REGISTRY); never derived from content.
	ProjectRepoURL string

	// RegistryURL is the registry repo URL, used for capturing RegistryParentSHA.
	RegistryURL string

	// RegistryClient is the ADMIN-mode registry client for RecordPendingBump
	// and CommitRotation.
	RegistryClient coreregistry.RegistryClient

	// ProjectID is the registry-canonical project identifier.
	ProjectID string

	// ConfiguredFiles maps logical_file_name → registry-configured repo-relative
	// path. Sourced from SourceVerified AdminSet.ConfiguredFiles at the
	// composition root. Must cover every file in the rotation plan.
	ConfiguredFiles map[string]string

	// Decryptor is the admin decrypt port (called once per file).
	Decryptor decrypt.Decryptor

	// Encryptor is the contributor encrypt port (called once per file to R').
	Encryptor encrypt.Encryptor

	// ManifestSigner is the admin Ed25519 signing port (called once per file).
	// The field accepts any value that satisfies usecase.ManifestSigner (or the
	// local rotationManifestSigner alias above — structurally identical).
	ManifestSigner rotationManifestSigner

	// Codec encodes/decodes artifact domain types to/from on-disk bytes.
	// Accepts any value satisfying usecase.ArtifactCodec / rotationArtifactCodec.
	Codec rotationArtifactCodec

	// IdentityLoader loads the admin's age identity for decryption. Never
	// called more than once per Execute; identity goes out of scope on return.
	IdentityLoader identity.Loader

	// TokenProvider supplies the project-repo and registry write credentials.
	TokenProvider RegistryWriteTokenProvider

	// Runner is the git subprocess runner.
	Runner fetchtransport.CommandRunner

	// MkdirTemp is os.MkdirTemp in production; inject a fake in tests.
	MkdirTemp func(dir, pattern string) (string, error)

	// RemoveAll is os.RemoveAll in production; inject a fake in tests.
	RemoveAll func(path string) error
}

// rotationPhaseShared holds the shared mutable state between the Phase-1 and
// Phase-2 adapters. It is guarded by planMu so concurrent Execute calls do
// not race.
type rotationPhaseShared struct {
	planMu   sync.Mutex
	lastPlan *rotate.RotationPlan
}

// rotationPhase1Adapter implements rotate.Phase1Executor. It shares
// rotationPhaseShared with rotationPhase2Adapter so Phase-2 can read the plan
// that Phase-1 stored (BuildRotationAuditEvent needs plan.RemovedRecipients,
// which is absent from Phase2Executor.Execute's call signature).
type rotationPhase1Adapter struct {
	d      RotationPhaseAdapterDeps
	shared *rotationPhaseShared
}

// rotationPhase2Adapter implements rotate.Phase2Executor. It shares
// rotationPhaseShared with rotationPhase1Adapter to access the stored plan.
type rotationPhase2Adapter struct {
	d      RotationPhaseAdapterDeps
	shared *rotationPhaseShared
}

// RotationPhaseAdapters holds both executor adapters as a pair. The caller
// wires Phase1 and Phase2 into RotatorDeps.
type RotationPhaseAdapters struct {
	Phase1 *rotationPhase1Adapter
	Phase2 *rotationPhase2Adapter
}

// NewRotationPhaseAdapters constructs both Phase-1 and Phase-2 adapters sharing
// the same plan-state mutex. Returns an error if any required field is absent.
func NewRotationPhaseAdapters(d RotationPhaseAdapterDeps) (*RotationPhaseAdapters, error) {
	if d.ProjectRepoURL == "" {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: ProjectRepoURL is required — " +
				"set BYREIS_PROJECT_REPO or run `byreis init`")
	}
	if d.RegistryURL == "" {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: RegistryURL is required — " +
				"set BYREIS_REGISTRY or run `byreis init`")
	}
	if d.RegistryClient == nil {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: RegistryClient is required")
	}
	if d.ProjectID == "" {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: ProjectID is required — " +
				"set BYREIS_PROJECT or pass --project")
	}
	if d.Decryptor == nil {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: Decryptor is required")
	}
	if d.Encryptor == nil {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: Encryptor is required")
	}
	if d.ManifestSigner == nil {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: ManifestSigner is required")
	}
	if d.Codec == nil {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: Codec is required")
	}
	if d.IdentityLoader == nil {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: IdentityLoader is required")
	}
	if d.TokenProvider == nil {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: TokenProvider is required")
	}
	if d.Runner == nil {
		return nil, fmt.Errorf(
			"RotationPhaseAdapter: Runner is required — " +
				"pass SubprocessRunner{} for production")
	}
	mkdirTemp := d.MkdirTemp
	if mkdirTemp == nil {
		mkdirTemp = os.MkdirTemp
	}
	removeAll := d.RemoveAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	deps := RotationPhaseAdapterDeps{
		ProjectRepoURL:  d.ProjectRepoURL,
		RegistryURL:     d.RegistryURL,
		RegistryClient:  d.RegistryClient,
		ProjectID:       d.ProjectID,
		ConfiguredFiles: d.ConfiguredFiles,
		Decryptor:       d.Decryptor,
		Encryptor:       d.Encryptor,
		ManifestSigner:  d.ManifestSigner,
		Codec:           d.Codec,
		IdentityLoader:  d.IdentityLoader,
		TokenProvider:   d.TokenProvider,
		Runner:          d.Runner,
		MkdirTemp:       mkdirTemp,
		RemoveAll:       removeAll,
	}
	shared := &rotationPhaseShared{}
	return &RotationPhaseAdapters{
		Phase1: &rotationPhase1Adapter{d: deps, shared: shared},
		Phase2: &rotationPhase2Adapter{d: deps, shared: shared},
	}, nil
}

// Compile-time assertions.
var _ rotate.Phase1Executor = (*rotationPhase1Adapter)(nil)
var _ rotate.Phase2Executor = (*rotationPhase2Adapter)(nil)

// Execute runs Phase-1: clone project repo, create rotation branch, per-file
// decrypt→re-encrypt→sign→encode→write→commit, push branch, per-file
// RecordPendingBump with per-file CAS leases, capture RegistryParentSHA.
func (a *rotationPhase1Adapter) Execute(ctx context.Context, plan rotate.RotationPlan) (rotate.Phase1Result, error) {
	if err := ctx.Err(); err != nil {
		return rotate.Phase1Result{}, fmt.Errorf("Phase1.Execute: context cancelled: %w", err)
	}
	if len(plan.FilesToReencrypt) == 0 {
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: plan contains no files to re-encrypt — " +
				"the rotation plan must contain at least one file")
	}

	// Load the project-repo write credential ONCE upfront.
	token, tokenErr := a.d.TokenProvider.RegistryWriteToken(ctx, a.d.ProjectRepoURL)
	if tokenErr != nil {
		return rotate.Phase1Result{}, fmt.Errorf(
			"%w: Phase1.Execute: retrieving project-repo token: %v",
			ErrRegistryWriteAuth, tokenErr)
	}

	// Load the admin age identity ONCE; never stored, never logged.
	adminID, idErr := a.d.IdentityLoader.Load(ctx)
	if idErr != nil {
		return rotate.Phase1Result{}, fmt.Errorf(
			"%w: Phase1.Execute: loading admin identity: %v — "+
				"run `byreis auth login` to configure credentials",
			ErrRegistryWriteAuth, idErr)
	}

	// Create an isolated 0700 workspace.
	tmpDir, mkErr := a.d.MkdirTemp("", "byreis-rotation-phase1-*")
	if mkErr != nil {
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: creating workspace: %w — check filesystem permissions", mkErr)
	}
	defer func() { _ = a.d.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: chmod workspace: %w", chErr)
	}

	cloneDir := filepath.Join(tmpDir, "project")

	// buildEnv constructs the git isolation environment with exactly one
	// GIT_CONFIG_COUNT entry. When withAuth is true AND gitAuthEnvBlock confirms
	// the project repo is a GitHub HTTPS URL, count is 3 with the Authorization
	// header scoped to github.com; otherwise count is 2 (no auth header). The
	// scoped key ensures a cross-host redirect never carries the token.
	// The auth header uses Basic base64(x-access-token:<token>) as required by
	// GitHub's git-over-HTTPS endpoint; Bearer is rejected by that endpoint.
	buildEnv := func(withAuth bool) []string {
		base := fetchtransport.CleanGitEnv()
		if withAuth && gitAuthEnvBlock(a.d.ProjectRepoURL, token) != nil {
			encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
			return append(base,
				"GIT_CONFIG_NOSYSTEM=1",
				"HOME="+tmpDir,
				"GIT_TERMINAL_PROMPT=0",
				"GIT_ALLOW_PROTOCOL=file:https:ssh",
				"GIT_CONFIG_COUNT=3",
				"GIT_CONFIG_KEY_0=core.hooksPath",
				"GIT_CONFIG_VALUE_0=/dev/null",
				"GIT_CONFIG_KEY_1=core.fsmonitor",
				"GIT_CONFIG_VALUE_1=",
				"GIT_CONFIG_KEY_2=http."+gitHubHTTPSBase+".extraHeader",
				"GIT_CONFIG_VALUE_2=Authorization: Basic "+encoded,
			)
		}
		return append(base,
			"GIT_CONFIG_NOSYSTEM=1",
			"HOME="+tmpDir,
			"GIT_TERMINAL_PROMPT=0",
			"GIT_ALLOW_PROTOCOL=file:https:ssh",
			"GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=core.hooksPath",
			"GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=core.fsmonitor",
			"GIT_CONFIG_VALUE_1=",
		)
	}

	// Step 1: shallow clone the project repo.
	cloneCtx, cloneCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := a.d.Runner.Run(
		cloneCtx, tmpDir, buildEnv(true),
		"git", "clone", "--depth=1", "--no-local", "--", a.d.ProjectRepoURL, cloneDir,
	)
	if cloneErr != nil {
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: git clone error: %w — run `byreis doctor`", cloneErr)
	}
	if cloneExit != 0 {
		return rotate.Phase1Result{}, fmt.Errorf(
			"%w: Phase1.Execute: git clone exited %d: %s",
			ErrRegistryWriteAuth, cloneExit, fetchtransport.SanitizeOutput(cloneStderr))
	}

	// Step 2: configure git identity in the clone.
	configCtx, configCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer configCancel()
	for _, cfg := range [][]string{
		{"git", "config", "user.name", "byreis-admin"},
		{"git", "config", "user.email", "byreis-admin@localhost"},
	} {
		_, _, cfgExit, cfgErr := a.d.Runner.Run(configCtx, cloneDir, buildEnv(false), cfg[0], cfg[1:]...)
		if cfgErr != nil || cfgExit != 0 {
			return rotate.Phase1Result{}, fmt.Errorf(
				"Phase1.Execute: git config %s failed", cfg[2])
		}
	}

	// Step 3: capture ProjectParentSHA BEFORE branch creation.
	revCtx, revCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer revCancel()

	revStdout, _, revExit, revErr := a.d.Runner.Run(
		revCtx, cloneDir, buildEnv(false),
		"git", "rev-parse", "HEAD",
	)
	if revErr != nil {
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: git rev-parse HEAD error: %w", revErr)
	}
	if revExit != 0 {
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: git rev-parse HEAD exited %d", revExit)
	}
	projectParentSHA := strings.TrimSpace(string(revStdout))
	if !fetchtransport.IsValidSHA(projectParentSHA) {
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: git rev-parse returned non-SHA %q", projectParentSHA)
	}

	// Step 4: create the rotation branch from the current HEAD.
	branchName := fmt.Sprintf("byreis/rotate-%d", time.Now().UTC().UnixNano())

	branchCtx, branchCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer branchCancel()

	_, branchStderr, branchExit, branchErr := a.d.Runner.Run(
		branchCtx, cloneDir, buildEnv(false),
		"git", "checkout", "-b", branchName,
	)
	if branchErr != nil {
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: git checkout -b error: %w", branchErr)
	}
	if branchExit != 0 {
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: git checkout -b exited %d: %s",
			branchExit, fetchtransport.SanitizeOutput(branchStderr))
	}

	// Step 5: per-file loop: decrypt → re-encrypt → sign → encode → write → commit.
	perFileResults := make([]rotate.PerFileResult, 0, len(plan.FilesToReencrypt))
	for _, snapshot := range plan.FilesToReencrypt {
		pfr, loopErr := a.processOneFile(ctx, tmpDir, cloneDir, snapshot, plan, adminID, func() []string { return buildEnv(false) })
		if loopErr != nil {
			return rotate.Phase1Result{}, loopErr
		}
		perFileResults = append(perFileResults, pfr)
	}

	// Step 6: push the rotation branch.
	pushCtx, pushCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer pushCancel()

	_, pushStderr, pushExit, pushErr := a.d.Runner.Run(
		pushCtx, cloneDir, buildEnv(true),
		"git", "push", "--set-upstream", "origin", branchName,
	)
	if pushErr != nil {
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: git push branch error: %w — run `byreis doctor`", pushErr)
	}
	if pushExit != 0 {
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "403") || strings.Contains(stderrStr, "401") ||
			strings.Contains(stderrStr, "Authentication") {
			return rotate.Phase1Result{}, fmt.Errorf(
				"%w: Phase1.Execute: push branch authentication failure: %s",
				ErrRegistryWriteAuth, stderrStr)
		}
		return rotate.Phase1Result{}, fmt.Errorf(
			"%w: Phase1.Execute: push branch exited %d: %s",
			ErrRegistryWriteRejected, pushExit, stderrStr)
	}

	// Build the PRRef for the rotation branch (Number=0: branches are not PRs).
	branchPRRef := git.PRRef{
		Project: projectIDFromURL(a.d.ProjectRepoURL) + "/" + branchName,
		Number:  0,
	}

	// Step 7: per-file RecordPendingBump with per-file CAS leases.
	// RecordPendingBump → WriteCounter → CAS push advances the registry HEAD
	// by one commit each call. File-K's CAS is managed internally by the
	// RegistryClient's WriteCounter which re-fetches HEAD before each push.
	targetPR := fmt.Sprintf("%s#%d", branchPRRef.Project, branchPRRef.Number)
	for i := range perFileResults {
		bumpErr := a.d.RegistryClient.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
			ProjectID:         a.d.ProjectID,
			FileName:          perFileResults[i].LogicalName,
			PendingCounter:    perFileResults[i].PendingCounter,
			TargetArtifactSHA: perFileResults[i].ContentSHA,
			TargetPR:          targetPR,
		})
		if bumpErr != nil {
			return rotate.Phase1Result{}, fmt.Errorf(
				"Phase1.Execute: RecordPendingBump for %q: %w — "+
					"run `byreis admin rotation reconcile` to inspect state",
				perFileResults[i].LogicalName, bumpErr)
		}
	}

	// Capture RegistryParentSHA: the registry HEAD after all N pending bumps.
	// This becomes the CAS lease for CommitRotation in Phase-2.
	registryToken, regTokenErr := a.d.TokenProvider.RegistryWriteToken(ctx, a.d.RegistryURL)
	if regTokenErr != nil {
		return rotate.Phase1Result{}, fmt.Errorf(
			"%w: Phase1.Execute: retrieving registry token for HEAD capture: %v",
			ErrRegistryWriteAuth, regTokenErr)
	}
	registryParentSHA, rpsErr := a.captureRepoHEAD(ctx, a.d.RegistryURL, registryToken, tmpDir)
	if rpsErr != nil {
		return rotate.Phase1Result{}, fmt.Errorf(
			"Phase1.Execute: capturing post-bump registry HEAD: %w", rpsErr)
	}

	// Store the plan so Phase-2.Execute can read it.
	a.shared.planMu.Lock()
	p := plan
	a.shared.lastPlan = &p
	a.shared.planMu.Unlock()

	return rotate.Phase1Result{
		BranchRef:         branchPRRef,
		ProjectParentSHA:  projectParentSHA,
		RegistryParentSHA: registryParentSHA,
		PerFileResults:    perFileResults,
		PlannedEpoch:      plan.NewEpoch,
	}, nil
}

// processOneFile handles the per-file loop body: decrypt → re-encrypt to R' →
// sign → encode → write (ciphertext only, never plaintext) → commit via -F.
//
// Plaintext is zeroed in a defer after all uses complete.
func (a *rotationPhase1Adapter) processOneFile(
	ctx context.Context,
	tmpDir, cloneDir string,
	snapshot rotate.FileSnapshot,
	plan rotate.RotationPlan,
	adminID identity.Identity,
	noAuthEnv func() []string,
) (rotate.PerFileResult, error) {
	if err := ctx.Err(); err != nil {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: context cancelled: %w", snapshot.LogicalName, err)
	}

	// 5a: Decrypt the existing ciphertext.
	plaintext, decErr := a.d.Decryptor.Decrypt(ctx, snapshot.SignedArtifact, adminID)
	if decErr != nil {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: decrypt failed: %w — "+
				"run `byreis auth login` or check your admin key",
			snapshot.LogicalName, decErr)
	}
	// Plaintext zeroization on scope exit. Best-effort: Go strings
	// are immutable, but we overwrite the backing slice where we can access it.
	defer func() {
		for k := range plaintext {
			b := []byte(plaintext[k])
			for i := range b {
				b[i] = 0
			}
			plaintext[k] = ""
		}
	}()

	// 5b: Re-encrypt to R'. pendingCounter = CurrentCounter + 1.
	pendingCounter := snapshot.CurrentCounter + 1

	unsignedArt, encErr := a.d.Encryptor.Encrypt(ctx, encrypt.EncryptInput{
		ProjectID:       plan.ProjectID,
		LogicalFileName: snapshot.LogicalName,
		Counter:         pendingCounter,
		Recipients:      plan.NewRecipientSet,
		Values:          plaintext,
	})
	if encErr != nil {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: encrypt failed: %w", snapshot.LogicalName, encErr)
	}

	// 5c: Build the canonical manifest for signing. Mirrors the private
	// manifestFromSigned in usecase/merge.go; must stay in sync.
	man := manifestFromUnsigned(unsignedArt)

	// 5d: Sign the manifest.
	signerID, sig, signErr := a.d.ManifestSigner.Sign(ctx, man)
	if signErr != nil {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: sign failed: %w — check admin signing key",
			snapshot.LogicalName, signErr)
	}

	// 5e: Assemble the signed artifact.
	signedBody := artifact.Signed{
		Values: unsignedArt.Values,
		Byreis: unsignedArt.Byreis,
		ManifestSig: artifact.ManifestSig{
			Signer: signerID,
			Sig:    hex.EncodeToString(sig),
		},
	}

	// 5f: Compute canonical content SHA (used as TargetArtifactSHA).
	// Inline equivalent of verify.ContentSHA: sha256(manifest-stream || 0x1f ||
	// raw-sig-bytes). The adapter must NOT import internal/core/crypto/verify
	// per the allowlist gate; the algorithm is replicated here from the same
	// source of truth (verify.go:ContentSHA).
	contentSHA := signedArtifactContentSHA(signedBody)

	// 5g: Encode to on-disk bytes.
	encodedBytes, encodeErr := a.d.Codec.EncodeSigned(signedBody)
	if encodeErr != nil {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: encode signed artifact: %w", snapshot.LogicalName, encodeErr)
	}

	// 5h: Resolve the registry-configured repo-relative path.
	repoRelPath, hasPath := a.d.ConfiguredFiles[snapshot.LogicalName]
	if !hasPath || repoRelPath == "" {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: no registry-configured repo path for this file — "+
				"check the registry projects config: run `byreis doctor`",
			snapshot.LogicalName)
	}

	// 5i: Write ciphertext to working tree (plaintext NEVER touches disk).
	filePath := filepath.Join(cloneDir, filepath.FromSlash(repoRelPath))
	if mkdirErr := os.MkdirAll(filepath.Dir(filePath), 0o700); mkdirErr != nil {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: creating parent directory: %w", snapshot.LogicalName, mkdirErr)
	}
	if writeErr := os.WriteFile(filePath, encodedBytes, 0o600); writeErr != nil { //nolint:gosec
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: writing encrypted file: %w", snapshot.LogicalName, writeErr)
	}

	// 5j: Stage the file.
	addCtx, addCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer addCancel()

	_, addStderr, addExit, addErr := a.d.Runner.Run(
		addCtx, cloneDir, noAuthEnv(),
		"git", "add", "--", repoRelPath,
	)
	if addErr != nil {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: git add error: %w", snapshot.LogicalName, addErr)
	}
	if addExit != 0 {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: git add exited %d: %s",
			snapshot.LogicalName, addExit, fetchtransport.SanitizeOutput(addStderr))
	}

	// 5k: write the full commit message to a temp file so the
	// byreis-sig: footer NEVER appears in argv.
	commitMsgBody := fmt.Sprintf(
		"byreis: rotation re-encrypt\n\n"+
			"project_id: %s\n"+
			"file: %s\n"+
			"pending_counter: %d\n"+
			"content_sha: %s\n",
		plan.ProjectID, snapshot.LogicalName, pendingCounter, contentSHA,
	)
	fullMessage := commitMsgBody + "\n\nbyreis-signer: " + signerID +
		"\nbyreis-sig: " + hex.EncodeToString(sig) + "\n"

	msgFile := filepath.Join(tmpDir, "commitmsg-"+sanitizeForFilename(snapshot.LogicalName)+".txt")
	if wErr := os.WriteFile(msgFile, []byte(fullMessage), 0o600); wErr != nil { //nolint:gosec
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: writing commit message file: %w", snapshot.LogicalName, wErr)
	}
	defer func() { _ = os.Remove(msgFile) }()

	commitCtx, commitCancel := fetchtransport.WithBoundedDeadline(ctx, 30*time.Second)
	defer commitCancel()

	_, commitStderr, commitExit, commitErr := a.d.Runner.Run(
		commitCtx, cloneDir, noAuthEnv(),
		"git", "commit", "-F", msgFile,
	)
	if commitErr != nil {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: git commit error: %w — run `byreis doctor`",
			snapshot.LogicalName, commitErr)
	}
	if commitExit != 0 {
		return rotate.PerFileResult{}, fmt.Errorf(
			"Phase1.processOneFile %q: git commit exited %d: %s",
			snapshot.LogicalName, commitExit, fetchtransport.SanitizeOutput(commitStderr))
	}

	return rotate.PerFileResult{
		LogicalName:    snapshot.LogicalName,
		SignedBytes:    encodedBytes,
		ContentSHA:     contentSHA,
		PendingCounter: pendingCounter,
	}, nil
}

// captureRepoHEAD uses git ls-remote to fetch the current HEAD SHA of the
// given repo. Used to capture the post-bump RegistryParentSHA for Phase-2's
// CommitRotation CAS lease.
func (a *rotationPhase1Adapter) captureRepoHEAD(
	ctx context.Context,
	repoURL, token, tmpDir string,
) (string, error) {
	base := fetchtransport.CleanGitEnv()
	var env []string
	// Scope the Authorization header to the target repoURL host. For GitHub
	// HTTPS URLs the scoped key prevents the token from leaking on a redirect;
	// for non-GitHub or file:// URLs gitAuthEnvBlock returns nil and we omit
	// the auth header entirely, letting git use SSH or anonymous access.
	// The auth header uses Basic base64(x-access-token:<token>) as required by
	// GitHub's git-over-HTTPS endpoint; Bearer is rejected by that endpoint.
	if gitAuthEnvBlock(repoURL, token) != nil {
		encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		env = append(base,
			"GIT_CONFIG_NOSYSTEM=1",
			"HOME="+tmpDir,
			"GIT_TERMINAL_PROMPT=0",
			"GIT_ALLOW_PROTOCOL=file:https:ssh",
			"GIT_CONFIG_COUNT=3",
			"GIT_CONFIG_KEY_0=core.hooksPath",
			"GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=core.fsmonitor",
			"GIT_CONFIG_VALUE_1=",
			"GIT_CONFIG_KEY_2=http."+gitHubHTTPSBase+".extraHeader",
			"GIT_CONFIG_VALUE_2=Authorization: Basic "+encoded,
		)
	} else {
		env = append(base,
			"GIT_CONFIG_NOSYSTEM=1",
			"HOME="+tmpDir,
			"GIT_TERMINAL_PROMPT=0",
			"GIT_ALLOW_PROTOCOL=file:https:ssh",
			"GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=core.hooksPath",
			"GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=core.fsmonitor",
			"GIT_CONFIG_VALUE_1=",
		)
	}

	lsCtx, lsCancel := fetchtransport.WithBoundedDeadline(ctx, 20*time.Second)
	defer lsCancel()

	lsStdout, lsStderr, lsExit, lsErr := a.d.Runner.Run(
		lsCtx, tmpDir, env,
		"git", "ls-remote", "--symref", "--", repoURL, "HEAD",
	)
	if lsErr != nil {
		return "", fmt.Errorf(
			"captureRepoHEAD: git ls-remote error: %w — run `byreis doctor`", lsErr)
	}
	if lsExit != 0 {
		return "", fmt.Errorf(
			"%w: captureRepoHEAD: git ls-remote exited %d: %s",
			ErrRegistryWriteAuth, lsExit, fetchtransport.SanitizeOutput(lsStderr))
	}

	// ls-remote --symref output lines:
	//   ref: refs/heads/main\tHEAD
	//   <sha>\tHEAD
	//   <sha>\trefs/heads/main
	for _, line := range strings.Split(strings.TrimSpace(string(lsStdout)), "\n") {
		if line == "" || strings.HasPrefix(line, "ref:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == "HEAD" && fetchtransport.IsValidSHA(parts[0]) {
			return parts[0], nil
		}
	}

	return "", fmt.Errorf(
		"captureRepoHEAD: could not parse HEAD SHA from ls-remote output for %q — "+
			"run `byreis doctor`", repoURL)
}

// signedArtifactContentSHA computes the canonical content SHA of a signed
// artifact. Algorithm: sha256(manifest-stream || 0x1f separator || raw-sig-bytes),
// hex-encoded. Returns "" on any encoding failure (caller treats as non-match).
//
// This is an adapter-local equivalent of verify.ContentSHA. The registry
// adapter must NOT import internal/core/crypto/verify (allowlist gate); this
// function replicates the algorithm from verify.go:ContentSHA verbatim so the
// computed SHA is wire-identical to the value the verify package produces.
func signedArtifactContentSHA(s artifact.Signed) string {
	man := manifestFromSigned(s)
	stream, err := manifest.Encode(man)
	if err != nil {
		return ""
	}
	sig, err := hex.DecodeString(s.ManifestSig.Sig)
	if err != nil {
		sig = nil
	}
	h := sha256.New()
	h.Write(stream)
	h.Write([]byte{0x1f})
	h.Write(sig)
	return hex.EncodeToString(h.Sum(nil))
}

// manifestFromSigned maps a signed artifact to manifest.Manifest for SHA
// computation and commit-body building. Matches the verify.manifestFrom
// algorithm so the SHA is identical.
func manifestFromSigned(s artifact.Signed) manifest.Manifest {
	man := manifest.Manifest{
		FormatVersion:   s.Byreis.FormatVersion,
		ProjectID:       s.Byreis.ProjectID,
		LogicalFileName: s.Byreis.File,
		Counter:         s.Byreis.Counter,
		Values:          make(map[string][]byte, len(s.Values)),
	}
	for k, v := range s.Values {
		man.Values[k] = []byte(v)
	}
	for _, re := range s.Byreis.Recipients {
		man.RecipientFingerprints = append(man.RecipientFingerprints, re.FP)
	}
	return man
}

// manifestFromUnsigned builds the canonical manifest.Manifest from an
// artifact.Unsigned value for Ed25519 signing. This mirrors the private
// manifestFromSigned function in internal/core/usecase/merge.go.
func manifestFromUnsigned(u artifact.Unsigned) manifest.Manifest {
	man := manifest.Manifest{
		FormatVersion:   u.Byreis.FormatVersion,
		ProjectID:       u.Byreis.ProjectID,
		LogicalFileName: u.Byreis.File,
		Counter:         u.Byreis.Counter,
		Values:          make(map[string][]byte, len(u.Values)),
	}
	for k, v := range u.Values {
		man.Values[k] = []byte(v)
	}
	for _, re := range u.Byreis.Recipients {
		man.RecipientFingerprints = append(man.RecipientFingerprints, re.FP)
	}
	return man
}

// sanitizeForFilename replaces path-separator characters with underscores to
// produce a safe filesystem component from a logical file name.
func sanitizeForFilename(name string) string {
	return strings.NewReplacer("/", "_", "\\", "_").Replace(name)
}
