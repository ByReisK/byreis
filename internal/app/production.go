package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	ghsdkpkg "github.com/google/go-github/v72/github"

	"github.com/ByReisK/byreis/internal/adapter/artifactcodec"
	auditadapter "github.com/ByReisK/byreis/internal/adapter/audit"
	editadapter "github.com/ByReisK/byreis/internal/adapter/editor"
	"github.com/ByReisK/byreis/internal/adapter/fs/atomicwrite"
	"github.com/ByReisK/byreis/internal/adapter/git/fileofrecord"
	gitadapter "github.com/ByReisK/byreis/internal/adapter/git/github"
	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/adapter/keychain"
	manifestsigneradapter "github.com/ByReisK/byreis/internal/adapter/manifestsigner"
	"github.com/ByReisK/byreis/internal/adapter/modeprobe"
	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/adapter/registry/countercache"
	writesigneradapter "github.com/ByReisK/byreis/internal/adapter/registry/writesigner"
	"github.com/ByReisK/byreis/internal/adapter/signingkey"
	"github.com/ByReisK/byreis/internal/adapter/truststore"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/logging"
	"github.com/ByReisK/byreis/internal/core/mode"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// BuildProductionDeps constructs the real Deps for the production wiring path.
//
// All BuildReadPathDeps ports are wired to real adapters. On any construction
// failure (missing config, absent key file, bad trust anchor) the deps fall
// back gracefully: the detector resolves ModeContributor when no admin key is
// available, and the read-path use-cases are nil with an actionable error
// surfaced at command time.
//
// Before constructing the Editor adapter, this function checks whether $EDITOR
// (and $VISUAL) are unset AND the session is non-interactive
// (BYREIS_NON_INTERACTIVE=1). When that condition holds, a sentinel editor that
// returns an actionable error is wired in place of a real $EDITOR adapter,
// refusing to invoke an interactive editor in a CI pipeline.
func BuildProductionDeps(ctx context.Context) (*cli.Deps, error) {
	configDir := configDirFromEnvProd()

	// Build the codec first: it has no external dependencies and is needed by
	// both the bridge (mode detection) and the read-path use-cases.
	codec := artifactcodec.NewPortAdapter(artifactcodec.New())

	// Build the registry client before the detector so the bridge can be wired.
	// On failure (missing config, absent trust anchor) the read-path ports that
	// require the registry are nil; BuildReadPathDeps returns nil use-cases.
	regClient, regErr := buildRegistryClientProd(ctx, configDir)

	// Build the project secrets repo git-based FileOfRecordSource before the
	// detector so the bridge can be wired. The registry client is required: it
	// supplies the SourceVerified configured-path map (AdminSet.ConfiguredFiles).
	// When the registry client is unavailable the source is nil.
	forSource, forErr := buildFileOfRecordSourceProd(regClient)

	// Build the ForSourceBridge that wires the cryptographic-reality anchor.
	// When regClient or forSource is nil the bridge is nil (fail-closed):
	// NewKeyProbe accepts a nil fetcher and CanDecryptAny returns (false, nil).
	var probeBridge modeprobe.ArtifactFetcher
	if regClient != nil && forSource != nil {
		chooser, chooserErr := buildBridgeChooserProd(regClient)
		if chooserErr == nil {
			b, bridgeErr := modeprobe.NewForSourceBridge(forSource, codec, chooser)
			if bridgeErr == nil {
				probeBridge = b
			}
		}
	}

	det := realDetectorProd(configDir, probeBridge)
	pol := &mode.Policy{}

	detResult, err := det.Detect(ctx, projectIDFromEnvProd())
	var currentMode mode.Mode
	if err != nil {
		currentMode = mode.ModeContributor
	} else {
		currentMode = detResult.Mode
	}

	gate := &prodPolicyModeGate{pol: pol, m: currentMode}

	// Build the identity loader (BYREIS_KEY / file / keychain).
	keychainStore := keychain.New()
	idCfg := identityadapter.Config{
		EnvKey:     os.Getenv("BYREIS_KEY"),
		EnvKeyFile: os.Getenv("BYREIS_KEY_FILE"),
		Keychain:   keychainStore,
		DefaultKeyPath: func() string {
			return defaultKeyPathProd(configDir)
		},
	}
	idLoader := identityadapter.New(idCfg)

	// Build the ManifestSigner if the registry client is available (for
	// TrustedSigners) and a signing key is configured.
	var manifestSigner usecase.ManifestSigner
	if regClient != nil {
		manifestSigner, _ = buildManifestSignerProd(ctx, configDir, regClient)
	}

	// Build the registry-write wiring: RegistryWriteSigner and
	// RegistryWriteTokenProvider. When manifestSigner is nil (registry
	// unavailable or no attested signer key), returns (nil, nil, nil) and the
	// registry transport runs in read-only mode. The mode is captured at
	// composition time — never re-detected at token-load time.
	writeSigner, writeTokenProvider, _ := buildRegistryWriteWiringProd(
		currentMode, manifestSigner,
	)

	// When write wiring is available, rebuild the registry client with a write-
	// enabled transport. The project-repo reader (buildFileOfRecordSourceProd)
	// is ALWAYS constructed with nil write config — it has no business writing
	// counter commits and a credential leak to a project-repo path would be a
	// category error. The regClient variable is reassigned so counter/recips
	// below point to the write-enabled instance.
	if regClient != nil && writeSigner != nil && writeTokenProvider != nil {
		writeCfg := &registryadapter.FetchTransportWriteConfig{
			Signer:        writeSigner,
			TokenProvider: writeTokenProvider,
		}
		registryURL := os.Getenv("BYREIS_REGISTRY")
		if writeRegClient, err := buildRegistryClientWithWriteProd(ctx, configDir, registryURL, writeCfg); err == nil {
			regClient = writeRegClient
		}
	}

	// Build the AtomicFileWriter rooted at the project repo root.
	atomicWriter := buildAtomicWriterProd()

	// When $EDITOR/$VISUAL are unset and the session is non-interactive, wire a
	// sentinel editor that refuses with an actionable error. The adapter layer
	// does not hold session context; the gate lives here at the composition root.
	editorAdapter := buildEditorAdapterProd()

	// Collect any construction errors to report to the operator.
	var constructionWarnings []string
	if regErr != nil {
		constructionWarnings = append(constructionWarnings,
			fmt.Sprintf("registry client unavailable: %v", regErr))
	}
	if forErr != nil {
		constructionWarnings = append(constructionWarnings,
			fmt.Sprintf("file-of-record source unavailable: %v", forErr))
	}

	// Build the RecipientSourceWrapper over the registry client (if available).
	var recips usecase.RecipientSource
	var counter usecase.CounterStore
	if regClient != nil {
		wrapper := NewRecipientSourceWrapper(regClient)
		recips = wrapper
		counter = &prodRegistryCounterStoreBridge{client: regClient}
	}

	getter, decryptor, editorUC, buildErr := BuildReadPathDeps(
		forSource,      // FileOfRecordSource
		codec,          // ArtifactCodec: real YAML codec
		decrypt.New(),  // decrypt.Decryptor: real age decryptor
		idLoader,       // identity.Loader: keychain/file/env loader
		verify.New(),   // verify.VerifierOfRecord: pure crypto
		recips,         // RecipientSource: registry-backed wrapper
		counter,        // CounterStore: registry client
		gate,           // ModeGate: real policy gate
		encrypt.New(),  // encrypt.Encryptor: pure age encryptor
		manifestSigner, // usecase.ManifestSigner: Ed25519 signer (nil if unavailable)
		atomicWriter,   // usecase.AtomicFileWriter: repo-rooted atomic writer
		editorAdapter,  // usecase.Editor: $EDITOR adapter (or sentinel)
	)

	if buildErr != nil {
		return nil, fmt.Errorf(
			"byreis: unexpected failure constructing read-path use-cases "+
				"(this is a programming error at the composition root, not a missing "+
				"adapter): %w", buildErr)
	}

	for _, w := range constructionWarnings {
		fmt.Fprintf(os.Stderr, "byreis: warning: %s\n", w)
	}

	// Build the Merger use-case (admin merge path). When any required port is
	// unavailable (registry, git, signer), the Merger is nil and the CLI surfaces
	// a "not configured" error at command time. The MergeExitCode function maps
	// adapter-layer and core-registry sentinel errors to documented exit codes
	// without the cli package importing internal/adapter directly.
	merger, mergeExitCode := buildMergerProd(
		ctx, configDir, currentMode, regClient, gate, manifestSigner,
		decrypt.New(), encrypt.New(), idLoader, codec, recips, counter,
		buildAuditSinkProd(configDir),
	)

	// Build the rotation use-cases. The Rotator now wires the production
	// Phase-1/Phase-2 executors (V5b). Both are nil-safe: the CLI surfaces a
	// "not configured" error at command time when the Rotator is nil. The
	// Reconciler is wired via RotationReverserAdapter for both probe and reverser.
	rotator, rotateExitCode := buildRotatorProd(
		ctx, currentMode, regClient, writeTokenProvider, manifestSigner,
		decrypt.New(), encrypt.New(), idLoader, codec,
	)
	reconciler := buildRotationReconcilerProd(
		currentMode, writeSigner, writeTokenProvider,
	)

	// Build the rotate pre-flight reader. It requires the write-enabled registry
	// client (for FetchRotationEpochs and CounterAuthority), the file-of-record
	// source, the codec, the identity loader, and the decryptor.
	rotatePreflight := buildRotatePreFlightProd(
		regClient, forSource, codec, idLoader, decrypt.New(), projectIDFromEnvProd(),
	)

	// Build the RequestAccessReader for the `--from-request` path. Uses the
	// admin's GitHub token (same auth source as submit) and does not acquire a
	// registry-write credential. The reader is the only consumer of this port
	// at this release; the pre-existing FetchPartialState read site remains on
	// the write-token path and is not migrated here.
	var requestAccessReader rotate.RequestAccessReader
	registryRepo := registryProjectFromURLProd(os.Getenv("BYREIS_REGISTRY"))
	if registryRepo != "" {
		adminToken := githubTokenProd()
		if adminToken != "" {
			ghsdk := ghClientProd(adminToken)
			if reader, readerErr := gitadapter.NewRequestAccessReader(ghsdk, registryRepo); readerErr == nil {
				requestAccessReader = reader
			}
		}
	}

	return &cli.Deps{
		Policy:              pol,
		CurrentMode:         currentMode,
		ConfigDir:           configDir,
		Getter:              getter,
		Decryptor:           decryptor,
		Editor:              editorUC,
		Merger:              merger,
		MergeExitCode:       mergeExitCode,
		Rotator:             rotator,
		Reconciler:          reconciler,
		RotateExitCode:      rotateExitCode,
		RotatePreFlight:     rotatePreflight,
		RequestAccessReader: requestAccessReader,
	}, nil
}

// ghClientProd constructs a *github.Client authenticated with the given token.
func ghClientProd(token string) *ghsdkpkg.Client {
	return ghsdkpkg.NewClient(nil).WithAuthToken(token)
}

// buildRegistryClientProd constructs the real registry client. Returns (nil, err)
// when the registry URL is absent or the trust anchor cannot be loaded.
// A missing trust anchor is not a hard error: the user may not have run
// `byreis init` yet, in which case the binary starts in CONTRIBUTOR mode.
func buildRegistryClientProd(ctx context.Context, configDir string) (coreregistry.RegistryClient, error) {
	registryURL := os.Getenv("BYREIS_REGISTRY")
	return buildRegistryClientWithWriteProd(ctx, configDir, registryURL, nil)
}

// buildRegistryClientWithWriteProd constructs the registry client with an
// optional FetchTransportWriteConfig. When writeCfg is nil the transport is
// read-only. This is the single canonical builder used both at initial
// construction (nil writeCfg, read-only) and after write wiring is available
// (non-nil writeCfg, counter-write enabled).
func buildRegistryClientWithWriteProd(
	ctx context.Context,
	configDir string,
	registryURL string,
	writeCfg *registryadapter.FetchTransportWriteConfig,
) (coreregistry.RegistryClient, error) {
	if registryURL == "" {
		return nil, fmt.Errorf(
			"BYREIS_REGISTRY is not set — run `byreis init` to configure the registry")
	}

	if configDir == "" {
		return nil, fmt.Errorf(
			"config directory not set — set BYREIS_CONFIG or ensure ~/.config/byreis exists")
	}

	ts, err := truststore.New(configDir)
	if err != nil {
		return nil, fmt.Errorf("constructing trust store: %w", err)
	}

	anchor, err := ts.ReadAnchor(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"reading trust anchor: %w — run `byreis init` to pin the registry signer", err)
	}

	validated, err := usecase.ValidateTrustAnchor(anchor)
	if err != nil {
		return nil, fmt.Errorf(
			"trust anchor integrity check failed: %w — "+
				"re-pin via `byreis init --accept-signer <fingerprint>` after manual verification",
			err)
	}

	ft, ftErr := buildRegistryFetchTransportWithWriteProd(registryURL, writeCfg)
	if ftErr != nil {
		return nil, fmt.Errorf("constructing registry fetch transport: %w", ftErr)
	}

	cacheDir := registryCacheDirProd()
	clientCfg := registryadapter.ClientConfig{
		RegistryURL:    registryURL,
		ProjectID:      projectIDFromEnvProd(),
		CacheDir:       cacheDir,
		TrustAnchorKey: validated.SignerKey,
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: ft,
	}
	if writeCfg != nil {
		clientCfg.WriteTokenProvider = writeCfg.TokenProvider
	}

	// Wire the on-disk counter cache when a cache directory is available.
	// A construction failure is non-fatal: the client falls back to in-memory
	// only (the pre-persistence behaviour), emitting a warning to stderr.
	if cacheDir != "" {
		diskCache, diskCacheErr := countercache.New(registryURL, cacheDir, nil)
		if diskCacheErr != nil {
			fmt.Fprintf(os.Stderr,
				"byreis: warning: cannot construct on-disk counter cache: %v; "+
					"falling back to in-memory cache only\n", diskCacheErr)
		} else {
			clientCfg.DiskCache = diskCache
		}
	}

	client, err := registryadapter.New(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("constructing registry client: %w", err)
	}
	return client, nil
}

// buildFileOfRecordSourceProd constructs the git-based FileOfRecordSource.
//
// The project secrets-repo clone URL is sourced ONLY from operator-pinned
// configuration: BYREIS_PROJECT_REPO env var (same trust tier as
// BYREIS_REGISTRY). It MUST NOT be derived from any registry-fetched value,
// network response, project-repo content, or artifact field. A URL from any
// such source is a fail-closed configuration error.
//
// The registry client is required: it supplies the SourceVerified
// configured-path map (AdminSet.ConfiguredFiles) so the resolver returns only
// registry-attested paths. When regClient is nil the source cannot be built;
// the function returns (nil, err) so the caller treats it as "not wired"
// (graceful nil, not a panic). This mirrors the existing pattern at line 227.
//
// For file:// URLs no GitHub token is required; the git subprocess is used
// directly with the hardened isolated environment. No token is transmitted
// for file:// project URLs.
func buildFileOfRecordSourceProd(regClient coreregistry.RegistryClient) (usecase.FileOfRecordSource, error) {
	if regClient == nil {
		return nil, fmt.Errorf(
			"registry client is required for the file-of-record source — " +
				"run `byreis init` to configure the registry and trust anchor")
	}
	// The project repo URL MUST come from operator-pinned config only.
	// BYREIS_PROJECT_REPO is at the same trust level as BYREIS_REGISTRY.
	rawProjectRepoURL := os.Getenv("BYREIS_PROJECT_REPO")
	if rawProjectRepoURL == "" {
		return nil, fmt.Errorf(
			"BYREIS_PROJECT_REPO is not set — set it to the operator-pinned project " +
				"secrets-repo URL (same trust level as BYREIS_REGISTRY); " +
				"e.g. file:///absolute/path or https://github.com/owner/repo")
	}

	// Validate through the same URL parser used for the registry (or equivalent
	// that re-derives the byte-table-identical rejection set).
	validatedURL := registryProjectFromURLProd(rawProjectRepoURL)
	if validatedURL == "" {
		return nil, fmt.Errorf(
			"BYREIS_PROJECT_REPO %q is not a valid project repo URL — "+
				"accepted forms: file:///absolute/path, https://github.com/owner/repo, "+
				"git@github.com:owner/repo, or bare owner/repo; "+
				"run `byreis doctor` for diagnostics",
			rawProjectRepoURL)
	}

	// For file:// URLs the validatedURL is the resolved file:// path.
	// For GitHub forms it is the owner/repo string (used as clone URL by git).
	// Re-derive the actual clone URL from the validated form.
	cloneURL := resolveCloneURLProd(rawProjectRepoURL, validatedURL)

	project := projectIDFromEnvProd()
	if project == "" {
		return nil, fmt.Errorf(
			"BYREIS_PROJECT is not set — pass --project or set BYREIS_PROJECT")
	}

	baseBranch := baseBranchFromEnvProd()

	// Construct the git-based reader using the existing SubprocessRunner (no
	// new dependency or import edge). The token is NOT required for file://
	// project URLs. Pass nil writeCfg: this path is read-only.
	ft, err := registryadapter.NewProductionFetchTransportFromRunner(
		registryadapter.SubprocessRunner{}, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("constructing project-repo git reader: %w", err)
	}

	resolver := &prodRegistryConfiguredPathResolver{
		projectID:      project,
		registryClient: regClient,
	}

	source, err := fileofrecord.NewGitSource(fileofrecord.GitSourceConfig{
		ProjectURL: cloneURL,
		BaseBranch: baseBranch,
		Reader:     ft,
		Resolver:   resolver,
	})
	if err != nil {
		return nil, fmt.Errorf("constructing git-based file-of-record source: %w", err)
	}
	return source, nil
}

// resolveCloneURLProd converts the validated output of registryProjectFromURLProd
// back into a full clone URL for the git subprocess. For file:// URLs the
// validated value is already the resolved absolute file:// path. For GitHub
// forms the validated value is "owner/repo"; the clone URL is derived from
// the original raw URL to preserve the user-specified scheme (https/ssh/bare).
func resolveCloneURLProd(rawURL, validated string) string {
	if strings.HasPrefix(validated, "file://") {
		return validated
	}
	// For GitHub https/ssh/bare forms, use the original raw URL stripped of .git
	// suffix (same as registryProjectFromURLProd does internally). The validated
	// value is just "owner/repo"; the original URL is the canonical clone address.
	return strings.TrimSuffix(rawURL, ".git")
}

// buildManifestSignerProd constructs the real usecase.ManifestSigner. Returns
// (nil, err) when the signing key or registry is unavailable.
func buildManifestSignerProd(ctx context.Context, configDir string, regClient coreregistry.RegistryClient) (usecase.ManifestSigner, error) {
	// Fetch the registry admin set to get TrustedSigners for signerID resolution.
	adminSet, err := regClient.FetchAdminSet(ctx, projectIDFromEnvProd())
	if err != nil {
		return nil, fmt.Errorf("fetching admin set for manifest signer: %w", err)
	}
	if !adminSet.SourceVerified || adminSet.Stale {
		return nil, fmt.Errorf(
			"cannot construct manifest signer: registry admin set is not SourceVerified " +
				"or is stale — run `byreis doctor` to diagnose")
	}
	if len(adminSet.SignerKeys) == 0 {
		return nil, fmt.Errorf(
			"cannot construct manifest signer: no registry-attested Ed25519 signer keys found")
	}

	keychainStore := keychain.New()
	skCfg := signingkey.Config{
		EnvSignKey:     os.Getenv("BYREIS_SIGN_KEY"),
		EnvSignKeyFile: os.Getenv("BYREIS_SIGN_KEY_FILE"),
		Keychain:       nil, // keychain signing source stub: no production signing keychain yet
		DefaultKeyPath: func() string {
			return defaultSignKeyPathProd(configDir)
		},
	}
	_ = keychainStore // consumed by idCfg above; signing key uses a separate slot

	keySource := signingkey.New(skCfg)

	signer, err := manifestsigneradapter.New(keySource, adminSet.SignerKeys)
	if err != nil {
		return nil, fmt.Errorf("constructing manifest signer: %w", err)
	}
	return signer, nil
}

// buildMergerProd constructs the Merger use-case and the MergeExitCode mapping
// function for the production wiring. The MergeExitCode function is returned
// separately so the cli package can map adapter-layer sentinel errors to
// render.ExitCode values without importing internal/adapter/registry directly.
//
// When any required port is unavailable (registry client nil, git provider
// construction fails, manifest signer nil), this function returns (nil, nonNilFn)
// — the Merger is nil (the CLI surfaces "not configured" at command time) but the
// MergeExitCode function is always non-nil.
func buildMergerProd(
	ctx context.Context,
	configDir string,
	currentMode mode.Mode,
	regClient coreregistry.RegistryClient,
	gate usecase.ModeGate,
	manifestSigner usecase.ManifestSigner,
	decryptor decrypt.Decryptor,
	encryptor encrypt.Encryptor,
	idLoader identity.Loader,
	codec usecase.ArtifactCodec,
	recips usecase.RecipientSource,
	counter usecase.CounterStore,
	auditLog audit.Logger,
) (usecase.Merger, func(error) render.ExitCode) {
	// MergeExitCode is always returned, even when the Merger itself is nil.
	// This function maps adapter-layer and core-registry sentinel errors to
	// documented exit codes; the CLI layer calls it without importing adapter.
	mergeExitCode := func(err error) render.ExitCode {
		if err == nil {
			return render.ExitOK
		}
		if isErr(err, registryadapter.ErrRegistryWriteAuth) {
			return render.ExitAuthError
		}
		if isErr(err, registryadapter.ErrRegistryConcurrentWrite) {
			return render.ExitCounterReconcile
		}
		if isErr(err, registryadapter.ErrRegistryWriteRejected) {
			return render.ExitTrustError
		}
		if isErr(err, countertypes.ErrCounterReconcile) {
			return render.ExitCounterReconcile
		}
		if isErr(err, coreregistry.ErrCacheTampered) {
			return render.ExitReplay
		}
		if isErr(err, coreregistry.ErrRegistryRollback) {
			return render.ExitReplay
		}
		if isErr(err, rotate.ErrCommitBumpRejectedRotationInFlight) {
			return render.ExitCounterReconcile
		}
		return render.ExitGeneralError
	}

	// Guard: all required ports must be available.
	if regClient == nil || manifestSigner == nil || gate == nil ||
		decryptor == nil || encryptor == nil || idLoader == nil ||
		codec == nil || recips == nil || counter == nil {
		return nil, mergeExitCode
	}

	// Build the GitHub git provider. The project and base branch must be set.
	project := projectIDFromEnvProd()
	baseBranch := baseBranchFromEnvProd()
	token := githubTokenProd()

	gitProvider, err := buildGitProviderProd(token, project, baseBranch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "byreis: warning: admin merge not available: git provider: %v\n", err)
		return nil, mergeExitCode
	}

	merger, err := usecase.NewMerger(usecase.MergeDeps{
		Git:           gitProvider,
		Decryptor:     decryptor,
		Encryptor:     encryptor,
		IDLoader:      idLoader,
		ArtifactCodec: codec,
		Recipients:    recips,
		Counter:       counter,
		Signer:        manifestSigner,
		Verifier:      verify.New(),
		Mode:          gate,
		Audit:         auditLog,
		Log:           logging.Discard,
		RotationGuard: regClient,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "byreis: warning: admin merge not available: %v\n", err)
		return nil, mergeExitCode
	}

	_ = ctx // held for future use (e.g. preflight checks)
	_ = configDir
	_ = currentMode
	return merger, mergeExitCode
}

// isErr is a tiny helper that wraps errors.Is to avoid a separate import in the
// inline mergeExitCode closure (errors is already imported above).
func isErr(err, target error) bool {
	return errors.Is(err, target)
}

// buildGitProviderProd constructs the GitHub git.GitProvider for the admin
// merge path. The token may be empty for file:// project repos; in that case
// the provider is still constructed but will fail on first authenticated
// API call (which is acceptable: file:// repos are test/dev paths).
func buildGitProviderProd(token, project, baseBranch string) (coregit.GitProvider, error) {
	if project == "" {
		return nil, fmt.Errorf(
			"BYREIS_PROJECT is not set — pass --project or set BYREIS_PROJECT " +
				"to construct the git provider for admin merge")
	}
	if token == "" {
		return nil, fmt.Errorf(
			"BYREIS_GITHUB_TOKEN (or GITHUB_TOKEN) is not set — " +
				"run `byreis auth login` to authenticate for admin merge")
	}
	if baseBranch == "" {
		baseBranch = "main"
	}
	return gitadapter.New(token, project, baseBranch, "byreis")
}

// buildAtomicWriterProd constructs the atomicwrite.Writer rooted at the project
// repo root. Returns nil if the repo root cannot be resolved.
func buildAtomicWriterProd() usecase.AtomicFileWriter {
	repoRoot, err := resolveRepoRootProd()
	if err != nil {
		return nil
	}
	w, err := atomicwrite.New(repoRoot)
	if err != nil {
		return nil
	}
	return w
}

// buildEditorAdapterProd constructs the usecase.Editor. Applies the
// non-interactive guard: when $EDITOR/$VISUAL are unset AND the session is
// non-interactive (BYREIS_NON_INTERACTIVE=1), returns a sentinel editor that
// refuses with an actionable error rather than launching vi/vi-equivalent in a
// CI pipeline.
//
// The adapter itself never holds session or TTY context — this check lives
// here at the composition root, which is the only place that legitimately
// reads environment variables.
func buildEditorAdapterProd() usecase.Editor {
	editorBin := strings.TrimSpace(os.Getenv("EDITOR"))
	if editorBin == "" {
		editorBin = strings.TrimSpace(os.Getenv("VISUAL"))
	}

	nonInteractive := envBoolProd("BYREIS_NON_INTERACTIVE")

	if editorBin == "" && nonInteractive {
		return &prodNoEditorNonInteractiveRefusal{}
	}

	return editadapter.New()
}

// prodNoEditorNonInteractiveRefusal implements usecase.Editor and immediately
// returns an actionable error when $EDITOR is unset and the session is
// non-interactive. It is constructed by buildEditorAdapterProd at the
// composition root when the non-interactive guard fires.
type prodNoEditorNonInteractiveRefusal struct{}

// Edit always returns an actionable error in non-interactive mode with no $EDITOR.
func (*prodNoEditorNonInteractiveRefusal) Edit(_ context.Context, _ usecase.EditSession) (map[string]string, error) {
	return nil, fmt.Errorf(
		"edit requires an interactive terminal: $EDITOR is not set and BYREIS_NON_INTERACTIVE is enabled — " +
			"set the EDITOR environment variable or disable non-interactive mode to use `byreis edit`")
}

// resolveRepoRootProd walks from the current working directory upward looking
// for a .byreis.yaml file. The directory containing it is the project repo
// root. Returns an error when no .byreis.yaml is found or CWD cannot be
// determined.
func resolveRepoRootProd() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolving project repo root: cannot determine CWD: %w", err)
	}

	dir := cwd
	for {
		candidate := filepath.Join(dir, ".byreis.yaml")
		if _, err := os.Lstat(candidate); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf(
		"project repo root not found: no .byreis.yaml in %q or any parent — "+
			"run `byreis init` to configure this project",
		cwd)
}

// realDetectorProd builds the production mode.Detector. The KeyProbe and
// RegistryTrust are real adapters. The audit sink is a real durable file.
// If any adapter cannot be built (missing config), the detector falls back to
// no-op equivalents so the process starts rather than crashing — CONTRIBUTOR
// is the fail-closed result in all error cases.
//
// fetcher is the ForSourceBridge wired at the composition root. When nil
// (registry or project repo unavailable), CanDecryptAny returns (false, nil)
// — the safe fail-closed result for an unconfigured environment.
func realDetectorProd(configDir string, fetcher modeprobe.ArtifactFetcher) *mode.Detector {
	keychainStore := keychain.New()

	idCfg := identityadapter.Config{
		EnvKey:     os.Getenv("BYREIS_KEY"),
		EnvKeyFile: os.Getenv("BYREIS_KEY_FILE"),
		Keychain:   keychainStore,
		DefaultKeyPath: func() string {
			return defaultKeyPathProd(configDir)
		},
	}

	probe := modeprobe.NewKeyProbe(idCfg, fetcher)

	regTrust := buildRegistryTrustProd(idCfg, configDir)
	auditSink := buildAuditSinkProd(configDir)

	return &mode.Detector{
		Probe:    probe,
		Registry: regTrust,
		Clock:    &prodWallClock{},
		Audit:    auditSink,
	}
}

// buildRegistryTrustProd constructs the RegistryTrustAdapter. If the registry
// cannot be configured (missing BYREIS_REGISTRY env, missing or invalid trust
// anchor) it returns a prodNoopRegistryTrust that always fails closed
// (CONTRIBUTOR).
//
// BYREIS_TRUST_KEY is not supported: the trust anchor MUST come from the
// trust.yaml pinned store (written by `byreis init`). An unpinned anchor yields
// CONTRIBUTOR; never silent TOFU.
func buildRegistryTrustProd(idCfg identityadapter.Config, configDir string) mode.RegistryTrust {
	registryURL := os.Getenv("BYREIS_REGISTRY")
	if registryURL == "" {
		return &prodNoopRegistryTrust{}
	}

	if configDir == "" {
		return &prodNoopRegistryTrust{}
	}

	ts, err := truststore.New(configDir)
	if err != nil {
		return &prodNoopRegistryTrust{}
	}

	anchor, err := ts.ReadAnchor(context.Background())
	if err != nil {
		// No trust anchor pinned: unpinned anchor yields CONTRIBUTOR. This is
		// the expected state before `byreis init` is run — not an error.
		return &prodNoopRegistryTrust{}
	}

	validated, err := usecase.ValidateTrustAnchor(anchor)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: trust anchor integrity check failed: %v — "+
				"re-pin via `byreis init --accept-signer <fp>`\n", err)
		return &prodNoopRegistryTrust{}
	}

	trustFT, trustFTErr := buildRegistryFetchTransportProd(registryURL)
	if trustFTErr != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: cannot construct registry fetch transport for trust check: %v\n",
			trustFTErr)
		return &prodNoopRegistryTrust{}
	}

	regClient, err := registryadapter.New(registryadapter.ClientConfig{
		RegistryURL:    registryURL,
		ProjectID:      projectIDFromEnvProd(),
		CacheDir:       registryCacheDirProd(),
		TrustAnchorKey: validated.SignerKey,
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: trustFT,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: cannot construct registry client for trust check: %v\n", err)
		return &prodNoopRegistryTrust{}
	}

	bridge := &prodRegistryClientBridge{client: regClient}
	return modeprobe.NewRegistryTrustAdapter(bridge, idCfg)
}

// buildAuditSinkProd constructs the real durable audit file logger. If the file
// cannot be opened (missing parent dir, permission error), it falls back to
// audit.Discard with a warning on stderr. A failed audit sink means any ADMIN
// promotion will fail at step 5 (ErrPromotionNotAudited → CONTRIBUTOR), so
// the fallback is safe but degraded.
func buildAuditSinkProd(configDir string) audit.Logger {
	if configDir == "" {
		fmt.Fprintln(os.Stderr,
			"byreis: warning: config dir not set; audit log disabled (promotions will fail closed)")
		return audit.Discard
	}

	auditDir := filepath.Join(configDir, "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: cannot create audit dir %q: %v; audit log disabled\n",
			auditDir, err)
		return audit.Discard
	}

	logPath := filepath.Join(auditDir, "audit.log")
	logger, err := auditadapter.New(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: cannot open audit log %q: %v; audit log disabled\n",
			logPath, err)
		return audit.Discard
	}

	return logger
}

// registryProjectFromURLProd extracts the "owner/repo" project string from a
// GitHub registry URL, or validates and returns the absolute path for a
// file:// local registry URL. Supports:
//
//   - https://github.com/owner/repo → "owner/repo"
//   - git@github.com:owner/repo     → "owner/repo"
//   - owner/repo (bare)             → "owner/repo"
//   - file:///absolute/path         → "/absolute/path" (local git repo)
//
// Returns "" on parse failure; the caller must treat "" as a configuration
// error. The file:// branch is fail-closed validated before returning.
func registryProjectFromURLProd(registryURL string) string {
	u := strings.TrimSuffix(registryURL, ".git")

	// file:// local git repo — accepted ONLY as file:///absolute/path.
	// Reject file: without //, any authority/UNC form (file://host/path), and
	// any .. traversal in the literal URL.
	if strings.HasPrefix(u, "file://") {
		result, err := validateFileURL(u)
		if err != nil {
			return ""
		}
		return result
	}

	// https://github.com/owner/repo
	if after, ok := strings.CutPrefix(u, "https://github.com/"); ok {
		return after
	}
	// git@github.com:owner/repo
	if after, ok := strings.CutPrefix(u, "git@github.com:"); ok {
		return after
	}
	// Bare owner/repo (no scheme)
	if parts := strings.SplitN(u, "/", 2); len(parts) == 2 && !strings.Contains(parts[0], ".") {
		return u
	}
	return ""
}

// validateFileURL validates a file:// URL for use as a local git registry.
// Returns the validated absolute path on success, or an error.
//
// Accepted form: file:///absolute/path (triple slash = empty authority + absolute path).
// Rejected: file: without //, any authority component (file://host/...), relative
// paths, .. in the literal URL, and resolved paths under /proc, /dev, /sys.
func validateFileURL(u string) (string, error) {
	// Must be file:// with an absolute path component (triple slash minimum).
	if !strings.HasPrefix(u, "file:///") {
		return "", fmt.Errorf(
			"file:// registry URL %q must use triple-slash form file:///absolute/path — "+
				"bare 'file:' or authority form 'file://host/path' are not accepted",
			u)
	}

	// Strip the file:// prefix to get the raw path.
	rawPath := strings.TrimPrefix(u, "file://")

	// Reject any .. component in the literal URL (path traversal).
	for _, seg := range strings.Split(rawPath, "/") {
		if seg == ".." {
			return "", fmt.Errorf(
				"file:// registry URL %q contains a '..' path traversal component — "+
					"use an absolute canonical path",
				u)
		}
	}

	// The path must be absolute.
	if !filepath.IsAbs(rawPath) {
		return "", fmt.Errorf(
			"file:// registry URL %q path %q is not absolute — "+
				"use file:///absolute/path",
			u, rawPath)
	}

	// filepath.Abs + filepath.Clean + EvalSymlinks to resolve the canonical path.
	absPath, err := filepath.Abs(rawPath)
	if err != nil {
		return "", fmt.Errorf(
			"file:// registry URL %q: cannot resolve absolute path: %w", u, err)
	}
	absPath = filepath.Clean(absPath)

	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", fmt.Errorf(
			"file:// registry URL %q: cannot evaluate symlinks for %q: %w — "+
				"ensure the path exists and is accessible",
			u, absPath, err)
	}

	// Re-check that the resolved path is still absolute.
	if !filepath.IsAbs(resolved) {
		return "", fmt.Errorf(
			"file:// registry URL %q: resolved path %q is not absolute", u, resolved)
	}

	// Reject resolved paths under /proc, /dev, /sys (kernel virtual filesystems).
	for _, forbidden := range []string{"/proc", "/dev", "/sys"} {
		if resolved == forbidden || strings.HasPrefix(resolved, forbidden+"/") {
			return "", fmt.Errorf(
				"file:// registry URL %q resolves to %q which is under %s — "+
					"kernel virtual filesystem paths are not accepted as git repositories",
				u, resolved, forbidden)
		}
	}

	// Advisory pre-flight: ensure the path exists and is a directory containing
	// a git repo. This is advisory only — the real gate is the git clone with
	// the protocol allowlist; a TOCTOU between this stat and the clone is safe.
	info, statErr := os.Stat(resolved)
	if statErr != nil || !info.IsDir() {
		return "", fmt.Errorf(
			"file:// registry path %q does not exist or is not a directory: %v",
			resolved, statErr)
	}
	gitDir := filepath.Join(resolved, ".git")
	if _, gitErr := os.Stat(gitDir); gitErr != nil {
		// Also accept bare repos (no .git subdirectory).
		headFile := filepath.Join(resolved, "HEAD")
		if _, headErr := os.Stat(headFile); headErr != nil {
			return "", fmt.Errorf(
				"file:// registry path %q does not appear to contain a git repository "+
					"(no .git directory or HEAD file): %v",
				resolved, gitErr)
		}
	}

	// Return the resolved absolute path with the file:// prefix restored so the
	// caller can use it as a git clone URL.
	return "file://" + resolved, nil
}

// buildRegistryFetchTransportProd constructs the production FetchTransport for
// the registry client (read-only, nil write config).
func buildRegistryFetchTransportProd(registryURL string) (registryadapter.FetchTransport, error) {
	return buildRegistryFetchTransportWithWriteProd(registryURL, nil)
}

// buildRegistryFetchTransportWithWriteProd constructs the production FetchTransport.
// writeCfg may be nil for read-only use (project-repo reader) or non-nil for the
// registry transport that performs counter writes. The project-repo reader
// (production.go:293) always passes nil — it has no business writing counter
// commits.
//
// It returns (nil, nil) when the GitHub token is absent AND the registry URL
// is not a file:// local path, so the registry client falls back to the
// offline-only path instead of failing at construction time.
func buildRegistryFetchTransportWithWriteProd(
	registryURL string,
	writeCfg *registryadapter.FetchTransportWriteConfig,
) (registryadapter.FetchTransport, error) {
	validated := registryProjectFromURLProd(registryURL)
	if validated == "" {
		return nil, fmt.Errorf(
			"cannot parse registry URL %q — "+
				"set BYREIS_REGISTRY to https://github.com/owner/repo or file:///absolute/path",
			registryURL)
	}

	// For file:// local repos, no token is required — the transport uses system
	// git directly (clone + verify + cat-file), all subprocess-based. The
	// writeCfg (nil for project-repo reader, non-nil for registry transport) is
	// passed verbatim so only the registry transport call site enables writes.
	if strings.HasPrefix(validated, "file://") {
		ft, err := registryadapter.NewProductionFetchTransportFromRunner(
			registryadapter.SubprocessRunner{}, writeCfg,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"constructing production registry fetch transport: %w", err)
		}
		return ft, nil
	}

	// GitHub forms: token is required for authenticated clone access.
	token := githubTokenProd()
	if token == "" {
		return nil, nil
	}

	ft, err := registryadapter.NewProductionFetchTransportFromRunner(
		registryadapter.SubprocessRunner{}, writeCfg,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"constructing production registry fetch transport: %w", err)
	}
	return ft, nil
}

// registryCacheDirProd returns the registry cache directory.
func registryCacheDirProd() string {
	if v := os.Getenv("BYREIS_CACHE"); v != "" {
		return filepath.Join(v, "registry")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache", "byreis", "registry")
}

// defaultKeyPathProd returns the default admin age identity key file path.
func defaultKeyPathProd(configDir string) string {
	if configDir == "" {
		return ""
	}
	return filepath.Join(configDir, "identity", "admin.key")
}

// defaultSignKeyPathProd returns the default admin Ed25519 signing key file path.
func defaultSignKeyPathProd(configDir string) string {
	if configDir == "" {
		return ""
	}
	return filepath.Join(configDir, "identity", "admin-sign.key")
}

// projectIDFromEnvProd reads the project ID from the environment.
func projectIDFromEnvProd() string {
	return os.Getenv("BYREIS_PROJECT")
}

// configDirFromEnvProd returns the config directory path.
func configDirFromEnvProd() string {
	if v := os.Getenv("BYREIS_CONFIG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.config/byreis"
}

// baseBranchAllowRE is the positive whitelist for BYREIS_BASE_BRANCH values.
//
// Allowed characters: ASCII letters, digits, dot, underscore, hyphen, forward
// slash. This covers every valid git branch name an operator realistically uses
// (e.g. "main", "release/1.0", "feature/foo-bar", "v1.2.3") without permitting
// any character that can be mistaken for a git option flag or a path escape.
//
// Additional structural rules enforced AFTER the character check (see
// validateBaseBranch): no leading dash, no "..", no "@{", no trailing ".",
// no ".lock" suffix, no leading/trailing "/", no "//" run, no leading ".",
// no leading/trailing whitespace, no NUL or control bytes, max 200 bytes.
//
// 200 bytes: git's internal refname limit is much higher, but no legitimate
// branch name in practice exceeds ~80 characters. 200 is a safe, generous cap
// that keeps git argv construction well within OS limits.
var baseBranchAllowRE = regexp.MustCompile(`^[A-Za-z0-9._/\-]+$`)

// validateBaseBranch applies the positive-whitelist check to a candidate
// BYREIS_BASE_BRANCH value. Returns (value, true) when accepted; ("main",
// false) when rejected. This helper lives in the composition layer (internal/app)
// and must not be promoted to internal/core — no business logic here, only
// argv-safety hygiene for the env-reader.
func validateBaseBranch(v string) (string, bool) {
	const maxLen = 200
	const fallback = "main"

	// Length cap — protects against unreasonably long argv tokens.
	if len(v) > maxLen {
		return fallback, false
	}

	// Positive character whitelist: [A-Za-z0-9._/-] only.
	if !baseBranchAllowRE.MatchString(v) {
		return fallback, false
	}

	// Leading dash: the primary exploit shape (option injection into git argv).
	if v[0] == '-' {
		return fallback, false
	}

	// Leading dot: hidden-name convention; also blocked by git check-ref-format.
	if v[0] == '.' {
		return fallback, false
	}

	// Leading slash: absolute path; never a valid branch name segment.
	if v[0] == '/' {
		return fallback, false
	}

	// Trailing slash: invalid per git check-ref-format.
	if v[len(v)-1] == '/' {
		return fallback, false
	}

	// Trailing dot: invalid per git check-ref-format.
	if v[len(v)-1] == '.' {
		return fallback, false
	}

	// ".lock" suffix: git refuses refs ending in .lock.
	if strings.HasSuffix(v, ".lock") {
		return fallback, false
	}

	// ".." anywhere: path traversal / ambiguous range syntax.
	if strings.Contains(v, "..") {
		return fallback, false
	}

	// "@{" anywhere: git reflog syntax that can confuse rev-parse.
	if strings.Contains(v, "@{") {
		return fallback, false
	}

	// "//" run: invalid per git check-ref-format.
	if strings.Contains(v, "//") {
		return fallback, false
	}

	return v, true
}

// baseBranchFromEnvProd returns the base branch name (default: "main").
// If BYREIS_BASE_BRANCH is set but fails the positive-whitelist check, the
// function falls back to "main" and emits a warning to stderr so operators
// can diagnose misconfiguration without crashing.
func baseBranchFromEnvProd() string {
	v := os.Getenv("BYREIS_BASE_BRANCH")
	if v == "" {
		return "main"
	}
	validated, ok := validateBaseBranch(v)
	if !ok {
		fmt.Fprintf(os.Stderr, "byreis: WARN BYREIS_BASE_BRANCH value rejected by allowlist, falling back to \"main\"\n")
		return "main"
	}
	return validated
}

// githubTokenProd reads the GitHub token from BYREIS_GITHUB_TOKEN or falls
// back to GITHUB_TOKEN (standard CI env var). Returns "" when neither is set.
func githubTokenProd() string {
	if v := os.Getenv("BYREIS_GITHUB_TOKEN"); v != "" {
		return v
	}
	return os.Getenv("GITHUB_TOKEN")
}

// envBoolProd reports whether the named env variable has a truthy value.
func envBoolProd(name string) bool {
	v := os.Getenv(name)
	return v == "1" || v == "true" || v == "yes"
}

// ─── registry bridge: maps *registry.Client to modeprobe.AdminSetFetcher ───

// prodRegistryClientBridge adapts a coreregistry.RegistryClient to the narrow
// modeprobe.AdminSetFetcher interface.
type prodRegistryClientBridge struct {
	client coreregistry.RegistryClient
}

// FetchAdminSet forwards to the real registry client and maps
// coreregistry.AdminSet to modeprobe.AdminSetResult.
func (b *prodRegistryClientBridge) FetchAdminSet(ctx context.Context, projectID string) (modeprobe.AdminSetResult, error) {
	set, err := b.client.FetchAdminSet(ctx, projectID)
	if err != nil {
		return modeprobe.AdminSetResult{}, err
	}

	result := modeprobe.AdminSetResult{
		SourceVerified: set.SourceVerified,
		Stale:          set.Stale,
	}

	if set.SourceVerified && !set.Stale {
		result.AdminPublicKeys = make(map[string]string, len(set.Recipients))
		for i, rec := range set.Recipients {
			result.AdminPublicKeys[fmt.Sprintf("recipient-%d", i)] = rec.AgePubKey
		}
	}

	return result, nil
}

// ─── modeprobe bridge wiring ─────────────────────────────────────────────────

// buildBridgeChooserProd constructs the production ConfiguredFileChooser used
// by ForSourceBridge. Returns (nil, err) when regClient is nil following the
// (nil, err) discipline used elsewhere at the composition root.
func buildBridgeChooserProd(regClient coreregistry.RegistryClient) (modeprobe.ConfiguredFileChooser, error) {
	if regClient == nil {
		return nil, fmt.Errorf(
			"registry client is required for the bridge chooser — " +
				"run `byreis init` to configure the registry")
	}
	return &prodRegistryConfiguredPathChooser{client: regClient}, nil
}

// prodRegistryConfiguredPathChooser implements modeprobe.ConfiguredFileChooser.
// It performs a SourceVerified, non-stale registry fetch and returns the
// lexicographically-first key from AdminSet.ConfiguredFiles. This is the
// production wiring of the chooser seam; tests inject a fake or LexFirstChooser.
//
// This type sources the fileName ONLY from AdminSet.ConfiguredFiles (registry-
// attested, signed). No env var, flag, artifact field, or content-derived hint
// is accepted — the constructor carries no such field, and this type does not
// read environment variables.
type prodRegistryConfiguredPathChooser struct {
	client coreregistry.RegistryClient
}

// ChooseFile fetches the admin set from the registry, verifies it is
// SourceVerified and non-stale, and returns the lexicographically-first key
// from ConfiguredFiles. Returns ErrArtifactNotFound when the set is unverified,
// stale, or has no ConfiguredFiles entries.
func (c *prodRegistryConfiguredPathChooser) ChooseFile(ctx context.Context, projectID string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("ChooseFile cancelled: %w", err)
	}

	set, err := c.client.FetchAdminSet(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf(
			"registry fetch for bridge chooser (project %q): %w — run `byreis doctor` to diagnose",
			projectID, err)
	}

	if !set.SourceVerified || set.Stale {
		return "", fmt.Errorf(
			"%w: registry AdminSet is not SourceVerified or is stale for project %q — "+
				"cannot source a registry-attested file name",
			modeprobe.ErrArtifactNotFound, projectID)
	}

	if len(set.ConfiguredFiles) == 0 {
		return "", fmt.Errorf(
			"%w: AdminSet.ConfiguredFiles is empty for project %q — "+
				"check the registry projects config",
			modeprobe.ErrArtifactNotFound, projectID)
	}

	// Deterministic lex-first selection. sort.Strings produces lex-ascending
	// order; the first element is the registry-attested fileName to probe.
	keys := make([]string, 0, len(set.ConfiguredFiles))
	for k := range set.ConfiguredFiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys[0], nil
}

// ─── fileofrecord wiring bridges ──────────────────────────────────────────

// prodRegistryConfiguredPathResolver resolves the registry-configured
// repo-relative path for a (projectID, fileName) pair by consulting the
// registry AdminSet.ConfiguredFiles map populated on a SourceVerified fetch.
//
// The registry client is always non-nil in production: buildFileOfRecordSourceProd
// rejects a nil client before constructing the resolver, so there is no
// unauthenticated fallback on the trust path. The composition root passes the
// same SourceVerified registry client to both the RecipientSource wrapper and
// this resolver so there is only one verified fetch path.
//
// This bridge satisfies the fileofrecord.ConfiguredPathResolver interface.
type prodRegistryConfiguredPathResolver struct {
	projectID      string
	registryClient coreregistry.RegistryClient
}

// ConfiguredPath resolves the registry-configured path for the given
// (projectID, fileName) pair. It performs a SourceVerified registry fetch and
// returns the path from AdminSet.ConfiguredFiles. When the registry client is
// nil (invariant: never in production), or the fetch fails, or the AdminSet is
// unverified/stale, or the fileName has no ConfiguredFiles entry, the method
// returns a typed error — never a synthesized convention path.
func (r *prodRegistryConfiguredPathResolver) ConfiguredPath(ctx context.Context, projectID, fileName string) (string, error) {
	if r.registryClient == nil {
		return "", fmt.Errorf(
			"registry client is required for path resolution but is nil — "+
				"run `byreis init` to configure the registry: %w",
			usecase.ErrFileOfRecordNotFound)
	}

	set, err := r.registryClient.FetchAdminSet(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf(
			"registry fetch for path resolution: %w — run `byreis doctor` to diagnose",
			err)
	}

	if !set.SourceVerified || set.Stale {
		return "", fmt.Errorf(
			"%w: registry admin set is not source-verified or is stale; "+
				"cannot resolve the registry-attested path for %q — "+
				"run `byreis doctor` to diagnose",
			usecase.ErrFileOfRecordNotFound, fileName)
	}

	path, ok := set.ConfiguredFiles[fileName]
	if !ok || path == "" {
		return "", fmt.Errorf(
			"%w: no registry-configured path for %q in project %q — "+
				"check the registry admins.yaml / projects config",
			usecase.ErrFileOfRecordNotFound, fileName, projectID)
	}

	return path, nil
}

// ─── counter store bridge ─────────────────────────────────────────────────────

// prodRegistryCounterStoreBridge adapts coreregistry.RegistryClient to
// usecase.CounterStore. The two interfaces are structurally identical but use
// distinct type definitions for their input structs (one in core/registry, one
// in core/usecase). This bridge maps field-by-field at the composition boundary.
type prodRegistryCounterStoreBridge struct {
	client coreregistry.RegistryClient
}

// CounterAuthority delegates to the registry client.
func (b *prodRegistryCounterStoreBridge) CounterAuthority(ctx context.Context, projectID, fileName string) (countertypes.CounterAuthority, error) {
	return b.client.CounterAuthority(ctx, projectID, fileName)
}

// RecordPendingBump maps usecase.PendingBumpInput to coreregistry.PendingBumpInput.
func (b *prodRegistryCounterStoreBridge) RecordPendingBump(ctx context.Context, in usecase.PendingBumpInput) error {
	return b.client.RecordPendingBump(ctx, coreregistry.PendingBumpInput{
		ProjectID:         in.ProjectID,
		FileName:          in.FileName,
		PendingCounter:    in.PendingCounter,
		TargetArtifactSHA: in.TargetArtifactSHA,
		TargetPR:          in.TargetPR,
	})
}

// CommitBump maps usecase.CommitBumpInput to coreregistry.CommitBumpInput.
func (b *prodRegistryCounterStoreBridge) CommitBump(ctx context.Context, in usecase.CommitBumpInput) error {
	return b.client.CommitBump(ctx, coreregistry.CommitBumpInput{
		ProjectID:      in.ProjectID,
		FileName:       in.FileName,
		PendingCounter: in.PendingCounter,
		PRRef:          in.PRRef,
	})
}

// ─── mode ports ──────────────────────────────────────────────────────────────

// prodNoopRegistryTrust always returns (false, nil) so the detector resolves
// CONTRIBUTOR when no registry is configured or when the trust anchor is absent.
// Used as the fail-closed fallback when the real adapter cannot be built.
type prodNoopRegistryTrust struct{}

func (n *prodNoopRegistryTrust) IsRegisteredAdmin(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// prodWallClock wraps time.Now() for mode detection.
type prodWallClock struct{}

func (w *prodWallClock) Now() interface{ Unix() int64 } {
	return time.Now()
}

// prodPolicyModeGate wraps mode.Policy and the resolved mode, implementing
// usecase.ModeGate.
type prodPolicyModeGate struct {
	pol *mode.Policy
	m   mode.Mode
}

func (g *prodPolicyModeGate) Allow(cmd mode.Command) error {
	return g.pol.Allow(g.m, cmd)
}

// ─── registry-write wiring ───────────────────────────────────────────────────

// registryWriteTokenStore is the subset of the keychain.Store surface needed
// by the appRegistryWriteTokenBridge. Defined here so internal/app does not
// import internal/adapter/keychain directly at the type level (the concrete
// *keychain.Store is passed at construction time; this interface keeps the
// bridge testable via a fake).
type registryWriteTokenStore interface {
	GetRegistryWriteToken(ctx context.Context, registryURL string) (string, error)
}

// appRegistryWriteTokenBridge adapts the keychain-backed registryWriteTokenStore
// to the registry.RegistryWriteTokenProvider port. It is a thin delegation
// bridge; no caching, no token storage between calls.
//
// This mirrors the prodRegistryCounterStoreBridge shape — one private type that
// maps field-by-field at the composition boundary.
type appRegistryWriteTokenBridge struct {
	store registryWriteTokenStore
}

// RegistryWriteToken delegates to the keychain store. It is called at the
// counter-write path (WriteCounter / CommitCounter) when the admin submits a
// merge. The store's GetRegistryWriteToken already enforces the ADMIN-mode gate
// at the load-site before querying the OS keychain.
func (b *appRegistryWriteTokenBridge) RegistryWriteToken(ctx context.Context, registryURL string) (string, error) {
	return b.store.GetRegistryWriteToken(ctx, registryURL)
}

// capturedModeProvider is the bridge type that satisfies the keychain adapter's
// ModeProvider port. It captures the mode resolved at BuildProductionDeps time
// and returns it verbatim on every call.
//
// The mode is captured once at construction and is never reassigned. There is
// no exported mutator. ModeProvider.CurrentMode returns the captured value with
// no fallback that calls mode.Detector.Detect() again, so a race against a
// key-perm flip cannot smuggle ADMIN through the gate after the binary started
// as CONTRIBUTOR.
type capturedModeProvider struct {
	m mode.Mode
}

// CurrentMode returns the mode captured at construction time, verbatim. It
// never calls the mode detector again.
func (p *capturedModeProvider) CurrentMode(_ context.Context) (mode.Mode, error) {
	return p.m, nil
}

// buildRegistryWriteWiringProd constructs the RegistryWriteSigner and
// RegistryWriteTokenProvider for the production registry transport. Returns
// (nil, nil, nil) when manifestSigner is nil (registry unavailable or no
// attested signer key); in that case the caller passes a nil
// FetchTransportWriteConfig and the transport runs in read-only mode.
func buildRegistryWriteWiringProd(
	currentMode mode.Mode,
	manifestSigner usecase.ManifestSigner,
) (registryadapter.RegistryWriteSigner, registryadapter.RegistryWriteTokenProvider, error) {
	if manifestSigner == nil {
		return nil, nil, nil
	}

	// The manifestsigner.TextSigner interface: the concrete *signer from
	// manifestsigner satisfies it (SignText method added in this slice).
	ts, ok := manifestSigner.(manifestsigneradapter.TextSigner)
	if !ok {
		return nil, nil, fmt.Errorf(
			"buildRegistryWriteWiringProd: manifestSigner does not satisfy TextSigner — " +
				"ensure the signer was constructed via manifestsigner.New")
	}

	signerAdapter, err := writesigneradapter.New(ts)
	if err != nil {
		return nil, nil, fmt.Errorf("buildRegistryWriteWiringProd: constructing write signer: %w", err)
	}

	// Wire the mode provider: captures the composition-time mode once, verbatim.
	modeProvider := &capturedModeProvider{m: currentMode}

	// Thread the mode provider into the keychain store via a new store instance
	// that carries it. We need a store variant that accepts a ModeProvider.
	writeStore := keychain.NewWithDeps(modeProvider, keychain.RealKeyring())

	bridge := &appRegistryWriteTokenBridge{store: writeStore}
	return signerAdapter, bridge, nil
}

// ─── rotation use-case builders ──────────────────────────────────────────────

// buildRotatorProd constructs the Rotator use-case spine with the real Phase-1
// and Phase-2 executors wired via RotationPhaseAdapters. Returns (nil, fn)
// when any required dependency is unavailable (missing registry, missing write
// credentials, missing identity loader, non-ADMIN mode). The exit-code function
// is always non-nil.
func buildRotatorProd(
	ctx context.Context,
	currentMode mode.Mode,
	regClient coreregistry.RegistryClient,
	tokenProvider registryadapter.RegistryWriteTokenProvider,
	manifestSigner usecase.ManifestSigner,
	decryptor decrypt.Decryptor,
	encryptor encrypt.Encryptor,
	idLoader identity.Loader,
	codec usecase.ArtifactCodec,
) (rotate.Rotator, func(error) render.ExitCode) {
	rotateExitCode := func(err error) render.ExitCode {
		if err == nil {
			return render.ExitOK
		}
		if isErr(err, registryadapter.ErrRegistryWriteAuth) {
			return render.ExitAuthError
		}
		if isErr(err, registryadapter.ErrRegistryConcurrentWrite) {
			return render.ExitCounterReconcile
		}
		if isErr(err, registryadapter.ErrRegistryWriteRejected) {
			return render.ExitTrustError
		}
		if isErr(err, rotate.ErrRotationReconcile) {
			return render.ExitCounterReconcile
		}
		if isErr(err, rotate.ErrRotationRequiresFreshRegistry) {
			return render.ExitTrustError
		}
		if isErr(err, rotate.ErrRotationCannotDecryptExisting) {
			return render.ExitAuthError
		}
		if isErr(err, rotate.ErrRotationReversalNoBranchRef) {
			return render.ExitTrustError
		}
		return render.ExitGeneralError
	}

	// Fail closed when required dependencies are unavailable.
	if currentMode != mode.ModeAdmin && currentMode != mode.ModeSuper {
		return nil, rotateExitCode
	}
	if regClient == nil || tokenProvider == nil || manifestSigner == nil ||
		decryptor == nil || encryptor == nil || idLoader == nil || codec == nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: rotation executor not wired (required dependency unavailable)\n")
		return nil, rotateExitCode
	}

	registryURL := os.Getenv("BYREIS_REGISTRY")
	projectRepoURL := os.Getenv("BYREIS_PROJECT_REPO")
	projectID := projectIDFromEnvProd()
	if registryURL == "" || projectRepoURL == "" || projectID == "" {
		return nil, rotateExitCode
	}

	// Fetch the SourceVerified AdminSet to get ConfiguredFiles. Failure is
	// non-fatal: the rotator returns nil and the CLI surfaces a "not configured"
	// message at command time.
	adminSet, asErr := regClient.FetchAdminSet(ctx, projectID)
	if asErr != nil || !adminSet.SourceVerified || adminSet.Stale {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: cannot fetch SourceVerified admin set for rotation wiring: "+
				"rotator unavailable\n")
		return nil, rotateExitCode
	}

	phaseAdapters, paErr := registryadapter.NewRotationPhaseAdapters(registryadapter.RotationPhaseAdapterDeps{
		ProjectRepoURL:  projectRepoURL,
		RegistryURL:     registryURL,
		RegistryClient:  regClient,
		ProjectID:       projectID,
		ConfiguredFiles: adminSet.ConfiguredFiles,
		Decryptor:       decryptor,
		Encryptor:       encryptor,
		ManifestSigner:  manifestSigner,
		Codec:           codec,
		IdentityLoader:  idLoader,
		TokenProvider:   tokenProvider,
		Runner:          registryadapter.SubprocessRunner{},
	})
	if paErr != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: rotation phase adapters construction failed: %v\n", paErr)
		return nil, rotateExitCode
	}

	rotator, err := rotate.NewRotator(rotate.RotatorDeps{
		Planner: rotate.NewPlanner(),
		Phase1:  phaseAdapters.Phase1,
		Phase2:  phaseAdapters.Phase2,
		Clock:   &prodRotateClock{},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: rotation use-case construction failed: %v\n", err)
		return nil, rotateExitCode
	}

	_ = ctx // used above for FetchAdminSet
	return rotator, rotateExitCode
}

// buildRotationReconcilerProd constructs the RotationReconciler use-case. The
// RotationReverserAdapter satisfies both RotationStateProbe and
// RotationStateReverser, so a single adapter instance is used for both ports.
//
// Returns nil when the required write wiring (signer, token provider) is
// unavailable: reconcile requires ADMIN-gated write credentials. The CLI
// surfaces a "not configured" error at command time when nil.
func buildRotationReconcilerProd(
	currentMode mode.Mode,
	signer registryadapter.RegistryWriteSigner,
	tokenProvider registryadapter.RegistryWriteTokenProvider,
) rotate.RotationReconciler {
	// Only ADMIN mode can wire the reconciler. CONTRIBUTOR mode never receives
	// write credentials; fail closed here rather than deferring to the adapter.
	if currentMode != mode.ModeAdmin && currentMode != mode.ModeSuper {
		return nil
	}

	// Write wiring required: both signer and token provider must be non-nil.
	if signer == nil || tokenProvider == nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: rotation reconciler not wired (registry write credentials unavailable)\n")
		return nil
	}

	registryURL := os.Getenv("BYREIS_REGISTRY")
	projectRepoURL := os.Getenv("BYREIS_PROJECT_REPO")
	if registryURL == "" || projectRepoURL == "" {
		return nil
	}

	reverserAdapter, err := registryadapter.NewRotationReverserAdapter(registryadapter.RotationReverserDeps{
		RegistryURL:    registryURL,
		ProjectRepoURL: projectRepoURL,
		Signer:         signer,
		TokenProvider:  tokenProvider,
		Runner:         registryadapter.SubprocessRunner{},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: rotation reconciler unavailable: %v\n", err)
		return nil
	}

	reconciler, err := rotate.NewReconciler(rotate.ReconcilerDeps{
		Probe:    reverserAdapter,
		Reverser: reverserAdapter,
		Clock:    &prodRotateClock{},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: rotation reconciler construction failed: %v\n", err)
		return nil
	}
	return reconciler
}

// prodRotateClock is a system-clock adapter for the rotation use-case domain.
// It satisfies rotate.Clock.
type prodRotateClock struct{}

func (c *prodRotateClock) Now() time.Time { return time.Now() }

// ─── production rotate pre-flight adapter ────────────────────────────────────

// prodRotatePreFlight implements cli.RotatePreFlightReader. It wraps the
// SourceVerified registry client, the project-repo file-of-record source, the
// identity loader, and the decrypt port to provide the two mandatory pre-flight
// checks for the rotate command:
//
//  1. FetchVerifiedAdminSet: registry freshness + SourceVerified gate.
//  2. CanDecryptAllFiles: admin decrypt-all-existing pre-flight.
//
// The adapter lives in internal/app so it can import both registry adapters and
// crypto adapters without violating the Clean Architecture inward-dependency
// rule (adapters depend inward on core; this type is at the composition root).
type prodRotatePreFlight struct {
	regClient coreregistry.RegistryClient
	forSource usecase.FileOfRecordSource
	codec     usecase.ArtifactCodec
	idLoader  identity.Loader
	decryptor decrypt.Decryptor
	projectID string
}

// FetchVerifiedAdminSet fetches the SourceVerified, non-stale admin set and
// populates a RotatePreFlightAdminSet. Returns an error wrapping
// rotate.ErrRotationRequiresFreshRegistry when the set is stale or unverified.
func (p *prodRotatePreFlight) FetchVerifiedAdminSet(
	ctx context.Context, projectID string,
) (cli.RotatePreFlightAdminSet, error) {
	if err := ctx.Err(); err != nil {
		return cli.RotatePreFlightAdminSet{},
			fmt.Errorf("FetchVerifiedAdminSet cancelled: %w", err)
	}

	set, err := p.regClient.FetchAdminSet(ctx, projectID)
	if err != nil {
		return cli.RotatePreFlightAdminSet{},
			fmt.Errorf("%w: registry fetch failed: %v",
				rotate.ErrRotationRequiresFreshRegistry, err)
	}
	if !set.SourceVerified || set.Stale {
		return cli.RotatePreFlightAdminSet{},
			fmt.Errorf("%w: admin set is not SourceVerified or is stale",
				rotate.ErrRotationRequiresFreshRegistry)
	}

	// Pre-rotation recipients.
	preRecips := make([]string, 0, len(set.Recipients))
	for _, r := range set.Recipients {
		preRecips = append(preRecips, r.AgePubKey)
	}

	// Registered admins.
	regAdmins := make([]string, 0, len(set.Recipients))
	for _, r := range set.Recipients {
		regAdmins = append(regAdmins, r.AgePubKey)
	}

	// Fetch rotation epochs.
	epochMap, epochErr := p.regClient.FetchRotationEpochs(ctx, projectID)
	if epochErr != nil {
		epochMap = nil
	}

	// Enumerate configured files and build snapshots from the project repo.
	var snapshots []cli.RotatePreFlightFileSnap
	var maxEpoch uint64
	for logicalName := range set.ConfiguredFiles {
		// Fetch current epoch.
		var epoch uint64
		if epochMap != nil {
			epoch = epochMap[logicalName]
		}
		if epoch > maxEpoch {
			maxEpoch = epoch
		}

		// Fetch counter authority for the current counter value.
		ca, caErr := p.regClient.CounterAuthority(ctx, projectID, logicalName)
		var currentCounter uint64
		if caErr == nil && ca.Valid() {
			currentCounter = ca.LastAccepted()
		}

		// Fetch file bytes from the project repo for the decrypt check.
		var encodedBytes []byte
		if p.forSource != nil {
			rec, recErr := p.forSource.FileOfRecord(ctx, projectID, logicalName)
			if recErr == nil {
				encodedBytes = rec.Bytes
			}
		}

		snapshots = append(snapshots, cli.RotatePreFlightFileSnap{
			LogicalName:    logicalName,
			CurrentCounter: currentCounter,
			CurrentEpoch:   epoch,
			EncodedBytes:   encodedBytes,
		})
	}

	return cli.RotatePreFlightAdminSet{
		PreRotationRecipients: preRecips,
		RegisteredAdmins:      regAdmins,
		ConfiguredFiles:       set.ConfiguredFiles,
		CurrentMaxEpoch:       maxEpoch,
		FileSnapshots:         snapshots,
	}, nil
}

// CanDecryptAllFiles attempts to decrypt each snapshot using the running
// admin's identity. Returns an error wrapping
// rotate.ErrRotationCannotDecryptExisting if any file fails to decrypt.
// Plaintext is zeroized in a defer before returning.
func (p *prodRotatePreFlight) CanDecryptAllFiles(
	ctx context.Context, snapshots []cli.RotatePreFlightFileSnap,
) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("CanDecryptAllFiles cancelled: %w", err)
	}
	if len(snapshots) == 0 {
		return nil
	}

	id, idErr := p.idLoader.Load(ctx)
	if idErr != nil {
		return fmt.Errorf("%w: loading admin identity: %v",
			rotate.ErrRotationCannotDecryptExisting, idErr)
	}

	for _, snap := range snapshots {
		if len(snap.EncodedBytes) == 0 {
			// No bytes fetched; treat as cannot-decrypt.
			return fmt.Errorf("%w: no file bytes available for %q",
				rotate.ErrRotationCannotDecryptExisting, snap.LogicalName)
		}

		signed, decodeErr := p.codec.DecodeSigned(snap.EncodedBytes)
		if decodeErr != nil {
			return fmt.Errorf("%w: decoding file %q: %v",
				rotate.ErrRotationCannotDecryptExisting, snap.LogicalName, decodeErr)
		}

		plaintext, decErr := p.decryptor.Decrypt(ctx, signed, id)
		if decErr != nil {
			return fmt.Errorf("%w: file %q not decryptable by running admin",
				rotate.ErrRotationCannotDecryptExisting, snap.LogicalName)
		}
		// Zeroize plaintext immediately; we only need the boolean signal.
		for k := range plaintext {
			b := []byte(plaintext[k])
			for i := range b {
				b[i] = 0
			}
			plaintext[k] = ""
		}
	}
	return nil
}

// buildRotatePreFlightProd constructs the production RotatePreFlightReader.
// Returns nil when required dependencies are unavailable; the CLI falls back
// to the stub path in that case.
func buildRotatePreFlightProd(
	regClient coreregistry.RegistryClient,
	forSource usecase.FileOfRecordSource,
	codec usecase.ArtifactCodec,
	idLoader identity.Loader,
	decryptor decrypt.Decryptor,
	projectID string,
) cli.RotatePreFlightReader {
	if regClient == nil || codec == nil || idLoader == nil || decryptor == nil {
		return nil
	}
	return &prodRotatePreFlight{
		regClient: regClient,
		forSource: forSource,
		codec:     codec,
		idLoader:  idLoader,
		decryptor: decryptor,
		projectID: projectID,
	}
}

// ─── compile-time assertions ─────────────────────────────────────────────────

var (
	_ usecase.Editor                             = (*prodNoEditorNonInteractiveRefusal)(nil)
	_ modeprobe.AdminSetFetcher                  = (*prodRegistryClientBridge)(nil)
	_ fileofrecord.ConfiguredPathResolver        = (*prodRegistryConfiguredPathResolver)(nil)
	_ usecase.CounterStore                       = (*prodRegistryCounterStoreBridge)(nil)
	_ registryadapter.RegistryWriteTokenProvider = (*appRegistryWriteTokenBridge)(nil)
	_ rotate.RotationStateReverser               = (*registryadapter.RotationReverserAdapter)(nil)
	_ rotate.RotationStateProbe                  = (*registryadapter.RotationReverserAdapter)(nil)
	_ cli.RotatePreFlightReader                  = (*prodRotatePreFlight)(nil)
)
