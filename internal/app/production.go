package app

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/ByReisK/byreis/internal/adapter/fs/resumestore"
	"github.com/ByReisK/byreis/internal/adapter/git/fileofrecord"
	gitadapter "github.com/ByReisK/byreis/internal/adapter/git/github"
	"github.com/ByReisK/byreis/internal/adapter/git/keyprobe"
	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/adapter/keychain"
	manifestsigneradapter "github.com/ByReisK/byreis/internal/adapter/manifestsigner"
	"github.com/ByReisK/byreis/internal/adapter/modeprobe"
	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/adapter/registry/countercache"
	writesigneradapter "github.com/ByReisK/byreis/internal/adapter/registry/writesigner"
	"github.com/ByReisK/byreis/internal/adapter/signingkey"
	"github.com/ByReisK/byreis/internal/adapter/truststore"
	validatoradapter "github.com/ByReisK/byreis/internal/adapter/validator"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/prompt"
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
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
	"github.com/ByReisK/byreis/internal/tui"
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
	// wrapper is declared at function scope so buildSubmitterProd and
	// buildRunTUISubmitProd can receive the concrete type (which satisfies both
	// usecase.RecipientSource and submit.RecipientSource).
	var wrapper *RecipientSourceWrapper
	var recips usecase.RecipientSource
	var counter usecase.CounterStore
	if regClient != nil {
		wrapper = NewRecipientSourceWrapper(regClient)
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
	// Phase-1/Phase-2 executors. Both are nil-safe: the CLI surfaces a
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

	// Build the RequestAccessReader (admin read path, --from-request) and the
	// RequestAccessOpener (contributor write path, request-access verb). Both
	// use the same GitHub token gate and the same registry project coordinates.
	// The opener uses ONLY the contributor's own token; it acquires no
	// registry-write credential or signing key.
	var requestAccessReader rotate.RequestAccessReader
	var requestAccessOpener rotate.RequestAccessOpener
	registryRepo := registryProjectFromURLProd(os.Getenv("BYREIS_REGISTRY"))
	if registryRepo != "" {
		contribToken := contribGitHubTokenProd()
		if contribToken != "" {
			ghClient := ghClientProd(contribToken)
			if reader, readerErr := gitadapter.NewRequestAccessReader(ghClient, registryRepo); readerErr == nil {
				requestAccessReader = reader
			}
			if opener, openerErr := gitadapter.NewRequestAccessOpener(ghClient, registryRepo); openerErr == nil {
				requestAccessOpener = opener
			}
		}
	}

	// Build the ValueValidator shared by the submit and review use-cases.
	valValidator := valueValidatorProd()

	// Build the git provider for the submit and review paths. A nil provider is
	// safe: buildReviewerProd and buildSubmitterProd each nil-fallback.
	// The git provider requires the owner/repo slug from BYREIS_PROJECT_REPO.
	// Registry paths use the logical name from BYREIS_PROJECT (no slash).
	gitProjectSlug := gitSlugFromProjectRepoURLProd()
	baseBranch := baseBranchFromEnvProd()
	token := githubTokenProd()

	// Build the ProjectSubmissionsReader for the TUI submission queue (ADMIN-only).
	// It lists open submission PRs on the project secrets repo and is threaded
	// into the review TUI via buildRunTUIReviewProd. When the mode is not admin,
	// or the project-repo slug or GitHub token are unavailable, it is nil and the
	// review TUI falls back to the v0.3 access-request queue screen.
	var projectSubmissionsReader tui.SubmissionQueueSource
	if (currentMode == mode.ModeAdmin || currentMode == mode.ModeSuper) && gitProjectSlug != "" && token != "" {
		ghClient := ghClientProd(token)
		if pr, prErr := gitadapter.NewProjectSubmissionsReader(ghClient, gitProjectSlug); prErr == nil {
			projectSubmissionsReader = pr
		} else {
			fmt.Fprintf(os.Stderr,
				"byreis: warning: submission queue reader unavailable: %v\n", prErr)
		}
	}

	gitProvider, gpErr := buildGitProviderProd(token, gitProjectSlug, baseBranch)
	if gpErr != nil {
		fmt.Fprintf(os.Stderr, "byreis: warning: git provider unavailable: %v\n", gpErr)
	}

	// Build the Reviewer use-case (admin-only; nil in contributor mode).
	reviewer := buildReviewerProd(
		currentMode, gitProvider, decrypt.New(), idLoader, codec, gate,
		valValidator, buildAuditSinkProd(configDir),
	)

	// Build the RequestRejecter use-case (admin-only; nil in contributor mode).
	// The PR-API token (githubTokenProd) is used — NOT the registry-write or
	// signing credential. Two repo-bound PRCloser adapters are constructed:
	// one for the project secrets repo (submission PRs) and one for the registry
	// repo (access-request PRs). The use-case selects the correct adapter via
	// the repo-bound SourceRepo stamp.
	rejecter := buildRejecterProd(
		currentMode, token, gitProjectSlug, registryRepo, gate, buildAuditSinkProd(configDir),
	)

	// Build the shared submit adapter deps once so that both the CLI Submitter
	// and the TUI SubmitterFactory consume identical instances. Constructing
	// these independently in each builder is the maintenance hazard eliminated
	// by this single construction site.
	submitShared, submitSharedErr := buildSubmitSharedDepsProd(forSource, codec, cacheDirProd())
	if submitSharedErr != nil {
		fmt.Fprintf(os.Stderr, "byreis: warning: submit shared deps unavailable: %v\n", submitSharedErr)
	}

	// Build the Submitter use-case (all modes).
	submitter, submitGitPort, subErr := buildSubmitterProd(
		wrapper, gitProvider, codec, submitShared,
	)
	if subErr != nil {
		fmt.Fprintf(os.Stderr, "byreis: warning: submit use-case unavailable: %v\n", subErr)
	}

	// Build the Doctor use-case and the rotation-history variant.
	registryURL := os.Getenv("BYREIS_REGISTRY")
	doctor, rotationHistoryDoctor := buildDoctorProd(
		det, projectIDFromEnvProd(), registryURL, configDir, regClient,
	)

	// Wire the AuditReader. The concrete *registry.Client implements
	// rotate.AuditReader via its FetchAuditLog method; the coreregistry.RegistryClient
	// interface does not embed the method (it is a read-side addition not visible
	// to core). Type-assert to the narrow AuditReader port; when the assertion
	// fails (test double or future alternate client) the field stays nil and the
	// CLI surfaces a "not configured" error at command time.
	var auditReader rotate.AuditReader
	if regClient != nil {
		if ar, ok := regClient.(rotate.AuditReader); ok {
			auditReader = ar
		}
	}

	// Build the TUI RunTUISubmit factory. The composition root assembles the
	// SubmitterFactory closure so internal/cli stays free of any internal/tui
	// import (the cli↛tui boundary). The closure reuses the same shared deps as
	// the CLI's Submitter; only the Prompter differs (supplied by the TUI at
	// factory-call time).
	var runTUISubmit func(ctx context.Context, out interface{ Write([]byte) (int, error) }, preFilledKey string, base submit.Input) error
	if submitGitPort != nil && wrapper != nil {
		runTUISubmit = buildRunTUISubmitProd(wrapper, submitGitPort, submitShared)
	}

	// Build the TUI RunTUIReview factory. The closure is assembled here so
	// internal/cli stays free of any internal/tui import (cli↛tui boundary).
	// Review is only available in ADMIN mode; a nil reviewer means the TUI
	// review path is not wired (the cli surfaces "not configured" at command time).
	// projectSubmissionsReader is threaded in so the TUI can open on the
	// submission queue screen when it is available (nil is safe: falls back to
	// the v0.3 access-request queue).
	runTUIReview := buildRunTUIReviewProd(
		pol, currentMode, reviewer, merger, rejecter, requestAccessReader, projectSubmissionsReader,
	)

	return &cli.Deps{
		Policy:                pol,
		CurrentMode:           currentMode,
		ConfigDir:             configDir,
		Getter:                getter,
		Decryptor:             decryptor,
		Editor:                editorUC,
		Merger:                merger,
		MergeExitCode:         mergeExitCode,
		Rotator:               rotator,
		Reconciler:            reconciler,
		RotateExitCode:        rotateExitCode,
		RotatePreFlight:       rotatePreflight,
		RequestAccessReader:   requestAccessReader,
		RequestAccessOpener:   requestAccessOpener,
		AuditReader:           auditReader,
		Doctor:                doctor,
		RotationHistoryDoctor: rotationHistoryDoctor,
		Submitter:             submitter,
		Reviewer:              reviewer,
		Rejecter:              rejecter,
		RunTUISubmit:          runTUISubmit,
		RunTUIReview:          runTUIReview,
		ErrTUISubmitAborted:   tui.ErrSubmitAborted,
	}, nil
}

// buildDoctorProd constructs the Doctor use-case and a rotation-history variant.
// Both are nil-safe: when the required ports cannot be constructed the function
// returns (nil, nil) and the CLI surfaces "not configured" at command time.
func buildDoctorProd(
	det *mode.Detector,
	projectID, registryURL, configDir string,
	regClient coreregistry.RegistryClient,
) (usecase.Doctor, usecase.Doctor) {
	if det == nil {
		return nil, nil
	}

	trustFilePath := ""
	if configDir != "" {
		trustFilePath = filepath.Join(configDir, "trust.yaml")
	}

	// Build the registry status probe (wraps the registry client).
	var registryProbe usecase.RegistryStatusProbe
	if regClient != nil && registryURL != "" {
		registryProbe = &prodRegistryStatusProbe{client: regClient}
	}

	// Build the base Doctor (no rotation-history probe).
	baseDeps := usecase.DoctorDeps{
		ModeDetector:  det,
		ProjectID:     projectID,
		RegistryURL:   registryURL,
		ConfigDir:     configDir,
		TrustFilePath: trustFilePath,
		RegistryProbe: registryProbe,
	}
	baseDoc, err := usecase.NewDoctor(baseDeps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "byreis: warning: cannot construct doctor use-case: %v\n", err)
		return nil, nil
	}

	// Build the rotation-history Doctor. It is identical to the base Doctor
	// except RotationHistoryRequested=true and RotationEpochProbe is wired.
	// When the registry client is unavailable, the probe is nil and the
	// rotation-history report is silently skipped (probe errors are informational).
	var epochProbe usecase.RotationEpochProbe
	if regClient != nil {
		epochProbe = &prodRotationEpochProbe{client: regClient}
	}

	rhDeps := usecase.DoctorDeps{
		ModeDetector:             det,
		ProjectID:                projectID,
		RegistryURL:              registryURL,
		ConfigDir:                configDir,
		TrustFilePath:            trustFilePath,
		RegistryProbe:            registryProbe,
		RotationEpochProbe:       epochProbe,
		RotationHistoryRequested: true,
	}
	rhDoc, rhErr := usecase.NewDoctor(rhDeps)
	if rhErr != nil {
		// Rotation-history variant failed to construct; return only the base doctor.
		return baseDoc, nil
	}

	return baseDoc, rhDoc
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

	// Build the GitHub git provider. The owner/repo slug comes from
	// BYREIS_PROJECT_REPO; the logical project ID used for registry paths
	// comes from BYREIS_PROJECT (slash-free, no derivation needed).
	baseBranch := baseBranchFromEnvProd()
	token := githubTokenProd()

	gitProvider, err := buildGitProviderProd(token, gitSlugFromProjectRepoURLProd(), baseBranch)
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
			"BYREIS_PROJECT_REPO is not set or not a valid owner/repo slug — " +
				"set BYREIS_PROJECT_REPO to the secrets-repo location (e.g. owner/repo) " +
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
	p, err := gitadapter.New(token, project, baseBranch, "byreis")
	if err != nil {
		return nil, err
	}
	return p, nil
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

// projectIDFromEnvProd reads the logical project ID from BYREIS_PROJECT.
// This value is the pure registry project identifier — slash-free, exactly the
// registry_project_id signed-manifest field. It must not contain a slash; the
// registry path guard (fetchtransport.ValidateProjectID) rejects slash-bearing
// values. For the git provider slug, use gitSlugFromProjectRepoURLProd instead.
func projectIDFromEnvProd() string {
	return os.Getenv("BYREIS_PROJECT")
}

// gitSlugFromProjectRepoURLProd extracts the owner/repo slug from
// BYREIS_PROJECT_REPO for use with the GitHub git provider. Only GitHub forms
// are accepted (https://github.com/owner/repo, git@github.com:owner/repo, or
// bare owner/repo). A file:// URL returns "" — the git provider is only
// meaningful for real GitHub repos and is safely nil-fallback for file:// paths.
func gitSlugFromProjectRepoURLProd() string {
	raw := strings.TrimSuffix(os.Getenv("BYREIS_PROJECT_REPO"), ".git")
	if after, ok := strings.CutPrefix(raw, "https://github.com/"); ok {
		return after
	}
	if after, ok := strings.CutPrefix(raw, "git@github.com:"); ok {
		return after
	}
	// Bare owner/repo: two path components, no dot in the first (not a hostname).
	if parts := strings.SplitN(raw, "/", 2); len(parts) == 2 && !strings.Contains(parts[0], ".") {
		return raw
	}
	return ""
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

// contribGitHubTokenProd reads the contributor GitHub token. It checks
// BYREIS_GITHUB_TOKEN first, then GH_TOKEN. The contributor path uses GH_TOKEN
// (the gh-cli conventional variable) as a fallback in addition to GITHUB_TOKEN
// because contributors typically authenticate via the gh CLI, not CI pipelines.
// Returns "" when neither is set — the opener is not wired.
func contribGitHubTokenProd() string {
	if v := os.Getenv("BYREIS_GITHUB_TOKEN"); v != "" {
		return v
	}
	if v := os.Getenv("GH_TOKEN"); v != "" {
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
		AuditEntry:     in.AuditEntry,
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

// ─── doctor adapter bridges ───────────────────────────────────────────────────

// prodRegistryStatusProbe adapts a coreregistry.RegistryClient to the
// usecase.RegistryStatusProbe port consumed by the Doctor use-case. It performs
// a FetchAdminSet call to determine registry connectivity and signature state,
// mapping the result to the domain-typed usecase.RegistryStatus struct. No
// SDK or transport types cross this boundary.
type prodRegistryStatusProbe struct {
	client coreregistry.RegistryClient
}

// RegistryStatus probes the registry and returns the doctor-layer status.
// An offline registry (ErrRegistryOffline) is reported as Offline=true with
// the cache age from the stale AdminSet, not as an error. Only unexpected
// failures return a non-nil error.
func (p *prodRegistryStatusProbe) RegistryStatus(ctx context.Context, registryURL string) (usecase.RegistryStatus, error) {
	if err := ctx.Err(); err != nil {
		return usecase.RegistryStatus{}, fmt.Errorf("registry status probe cancelled: %w", err)
	}

	set, fetchErr := p.client.FetchAdminSet(ctx, registryURL)

	// Transport/network failure or offline-with-cache.
	if fetchErr != nil {
		if errors.Is(fetchErr, coreregistry.ErrRegistryOffline) {
			var age time.Duration
			if !set.FetchedAt.IsZero() {
				age = time.Since(set.FetchedAt)
			}
			return usecase.RegistryStatus{
				Offline:     true,
				Reachable:   false,
				CacheAge:    age,
				StaleReason: set.StaleReason,
			}, nil
		}
		if errors.Is(fetchErr, coreregistry.ErrUnsignedRegistry) {
			return usecase.RegistryStatus{
				Reachable:         true,
				SignatureVerified: false,
				Offline:           false,
			}, nil
		}
		// Other errors: propagate with a hint.
		return usecase.RegistryStatus{}, fmt.Errorf(
			"registry status check failed: %w — run `byreis doctor` to diagnose", fetchErr)
	}

	return usecase.RegistryStatus{
		Reachable:         true,
		SignatureVerified: set.SourceVerified,
		Offline:           false,
	}, nil
}

// prodRotationEpochProbe adapts a coreregistry.RegistryClient to the
// usecase.RotationEpochProbe port. It delegates to FetchRotationEpochs.
// When the result wraps ErrRegistryOffline, the stale epoch map is still
// returned so the doctor use-case can evaluate forward-secrecy and
// partial-rotation findings against the cached data.
type prodRotationEpochProbe struct {
	client coreregistry.RegistryClient
}

// FetchRotationEpochs delegates to the registry client. When the result wraps
// ErrRegistryOffline (stale-serve), both the map and the error are returned so
// the doctor use-case can distinguish "served from cache" from "no data at all".
// The doctor use-case treats any non-nil error as informational, not fatal.
func (p *prodRotationEpochProbe) FetchRotationEpochs(ctx context.Context, projectID string) (map[string]uint64, error) {
	return p.client.FetchRotationEpochs(ctx, projectID)
}

// ─── submit / review builder helpers ─────────────────────────────────────────

// valueValidatorProd returns the shared ValueValidator adapter wired into both
// the submit and review use-cases. The adapter is stateless; a single instance
// is safe for concurrent use.
func valueValidatorProd() *validatoradapter.Adapter {
	return validatoradapter.New()
}

// cacheDirProd returns the user cache directory for byreis.
func cacheDirProd() string {
	if v := os.Getenv("BYREIS_CACHE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache", "byreis")
}

// buildReviewerProd constructs the Reviewer use-case for the admin review path.
// Returns nil in CONTRIBUTOR mode or when any required dependency is unavailable
// (fail-closed, mirroring buildRotatorProd).
//
// Review is ADMIN-only: a contributor binary holds no Reviewer at all. This is
// defense-in-depth; the use-case also re-checks the mode gate at Review time.
func buildReviewerProd(
	currentMode mode.Mode,
	gitProvider coregit.GitProvider,
	decryptor decrypt.Decryptor,
	idLoader identity.Loader,
	codec usecase.ArtifactCodec,
	gate usecase.ModeGate,
	validator usecase.ValueValidator,
	auditSink audit.Logger,
) usecase.Reviewer {
	if currentMode != mode.ModeAdmin && currentMode != mode.ModeSuper {
		return nil
	}
	if gitProvider == nil || decryptor == nil || idLoader == nil || codec == nil || gate == nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: review use-case not wired (required dependency unavailable)\n")
		return nil
	}
	reviewer, err := usecase.NewReviewer(usecase.ReviewDeps{
		Git:           gitProvider,
		Decryptor:     decryptor,
		IDLoader:      idLoader,
		ArtifactCodec: codec,
		Mode:          gate,
		Validator:     validator,
		Audit:         auditSink,
		Log:           logging.Discard,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: review use-case construction failed: %v\n", err)
		return nil
	}
	return reviewer
}

// buildRejecterProd constructs the RequestRejecter use-case (admin-only; nil
// in CONTRIBUTOR mode or when required adapters cannot be constructed).
//
// Two repo-bound PRCloser adapters are constructed: one for the project secrets
// repo (submission PRs) and one for the admin registry repo (access-request PRs).
// Both adapters use the PR-API token (githubTokenProd) — NOT the registry-write
// or signing credential (never held by this builder).
func buildRejecterProd(
	currentMode mode.Mode,
	prAPIToken string,
	projectRepo string,
	registryRepo string,
	gate usecase.ModeGate,
	auditSink audit.Logger,
) usecase.RequestRejecter {
	if currentMode != mode.ModeAdmin && currentMode != mode.ModeSuper {
		return nil
	}
	if prAPIToken == "" || gate == nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: reject use-case not wired "+
				"(GitHub token or mode gate unavailable)\n")
		return nil
	}

	// Guard against operator misconfiguration where BYREIS_PROJECT_REPO and
	// BYREIS_REGISTRY resolve to the same GitHub repo. In a correct two-repo
	// deployment the project secrets repo and the admin registry repo are
	// distinct. When they are the same, routing by repo slug is ambiguous:
	// every PR would be treated as a project submission PR and registry-side
	// access-request PRs would never reach the registry adapter. Warn loudly
	// and refuse to build the dual-repo closer so the misconfiguration is
	// visible rather than silently misrouted.
	if projectRepo != "" && registryRepo != "" && projectRepo == registryRepo {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: BYREIS_PROJECT_REPO and BYREIS_REGISTRY resolve to the same "+
				"repo %q — project and registry repos must be distinct; "+
				"reject use-case not wired\n",
			projectRepo)
		return nil
	}

	ghClient := ghClientProd(prAPIToken)

	// Build the project-repo PRCloser (submission PRs: byreis/add-*, byreis/replace-*, etc.).
	var projCloser usecase.PRCloser
	if projectRepo != "" {
		c, err := gitadapter.NewProjectRepoPRCloser(ghClient, projectRepo)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"byreis: warning: project-repo PR closer unavailable: %v\n", err)
		} else {
			projCloser = c
		}
	}

	// Build the registry-repo PRCloser (access-request PRs: requests/<handle>.yaml).
	var regCloser usecase.PRCloser
	if registryRepo != "" {
		c, err := gitadapter.NewRegistryRepoPRCloser(ghClient, registryRepo)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"byreis: warning: registry-repo PR closer unavailable: %v\n", err)
		} else {
			regCloser = c
		}
	}

	// Select the wiring strategy based on which closers are available.
	// When both are present, a dualRepoPRCloser dispatches by repo slug:
	// a PRRef whose Project matches projectRepo goes to the project adapter;
	// all other PRefs (registry-side access-request PRs) go to the registry
	// adapter. This repo-bound routing matches the SourceRepo stamp set by
	// each adapter at FetchPRStateForReject time (RepoKindProject vs
	// RepoKindRegistry), so classifyPRType corroborates the routing at use-case
	// entry. When only one closer is available, that closer is used directly;
	// reject calls for the absent repo type will fail at the adapter boundary
	// with an actionable error surfaced to the operator.
	var closer usecase.PRCloser
	if projCloser != nil && regCloser != nil {
		closer = &dualRepoPRCloser{
			projectCloser:  projCloser,
			registryCloser: regCloser,
			projectRepo:    projectRepo,
		}
	} else if projCloser != nil {
		closer = projCloser
	} else if regCloser != nil {
		closer = regCloser
	} else {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: reject use-case not wired (no PR closer available)\n")
		return nil
	}

	rejecter, err := usecase.NewRequestRejecter(usecase.RejectDeps{
		Closer: closer,
		Mode:   gate,
		Audit:  auditSink,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"byreis: warning: reject use-case construction failed: %v\n", err)
		return nil
	}
	return rejecter
}

// dualRepoPRCloser routes FetchPRStateForReject and CloseWithComment to the
// correct repo-bound adapter based on the project coordinate in the PRRef.
// The project-repo adapter handles submission PRs (ref.Project == projectRepo);
// the registry-repo adapter handles access-request PRs (all other refs).
// The SourceRepo stamp set by each adapter (RepoKindProject / RepoKindRegistry)
// corroborates this routing at use-case entry via classifyPRType. Both adapters
// must target distinct repos; the caller (buildRejecterProd) enforces this.
type dualRepoPRCloser struct {
	projectCloser  usecase.PRCloser
	registryCloser usecase.PRCloser
	projectRepo    string
}

func (d *dualRepoPRCloser) FetchPRStateForReject(
	ctx context.Context, ref coregit.PRRef,
) (usecase.RejectPRState, error) {
	if ref.Project == d.projectRepo {
		return d.projectCloser.FetchPRStateForReject(ctx, ref)
	}
	return d.registryCloser.FetchPRStateForReject(ctx, ref)
}

func (d *dualRepoPRCloser) CloseWithComment(
	ctx context.Context, ref coregit.PRRef, sanitizedReason string,
) error {
	if ref.Project == d.projectRepo {
		return d.projectCloser.CloseWithComment(ctx, ref, sanitizedReason)
	}
	return d.registryCloser.CloseWithComment(ctx, ref, sanitizedReason)
}

// submitSharedDeps holds the adapter instances shared between the CLI Submitter
// and the TUI SubmitterFactory. Both paths must consume the same constructed
// instances so that a dependency added to one path is never silently absent
// from the other.
type submitSharedDeps struct {
	keyProbe    submit.KeyExistenceProbe
	resumeStore submit.ResumeStore
	validator   submit.ValueValidator
	clock       submit.Clock
}

// buildSubmitSharedDepsProd constructs the adapter instances that are shared
// by both the CLI Submitter and the TUI SubmitterFactory. Callers MUST call
// this once and pass the result to both buildSubmitterProd and
// buildRunTUISubmitProd; constructing these adapters independently in each
// builder is the maintenance hazard this helper eliminates.
//
// The forSourceBytesAdapter bridges usecase.FileOfRecordSource to
// keyprobe.FileOfRecordBytesSource so the keyprobe package stays free of the
// core/usecase import that would transitively pull in crypto/identity and
// crypto/decrypt (the allowlist gate enforces this boundary).
func buildSubmitSharedDepsProd(
	forSrc usecase.FileOfRecordSource,
	codec *artifactcodec.PortAdapter,
	cacheDir string,
) (submitSharedDeps, error) {
	var keyProbe submit.KeyExistenceProbe
	if forSrc != nil {
		probe, probeErr := keyprobe.New(&forSourceBytesAdapter{src: forSrc}, codec)
		if probeErr != nil {
			return submitSharedDeps{}, fmt.Errorf("constructing key existence probe: %w", probeErr)
		}
		keyProbe = probe
	} else {
		// File-of-record source is not configured: the key-existence probe
		// cannot distinguish ADD from REPLACE, so every submission is treated
		// as a new key. Operators who see unexpected ADD actions when they
		// expected REPLACE should verify that the file-of-record source is
		// wired in their registry configuration.
		fmt.Fprintln(os.Stderr, "byreis: warning: file-of-record source not configured; "+
			"submit cannot detect existing keys (all submissions treated as new)")
		keyProbe = &prodNoopKeyProbe{}
	}

	resumeStore, rsErr := resumestore.New(cacheDir)
	if rsErr != nil {
		return submitSharedDeps{}, fmt.Errorf("constructing resume store: %w", rsErr)
	}

	return submitSharedDeps{
		keyProbe:    keyProbe,
		resumeStore: resumeStore,
		validator:   valueValidatorProd(),
		clock:       &prodRotateClock{},
	}, nil
}

// buildSubmitterProd constructs the Submitter use-case and the underlying
// submit.GitPort. Submit is wired in all modes (an admin can also submit).
// Returns (nil, nil, nil) when required dependencies are unavailable.
//
// The shared parameter carries the adapter instances built by
// buildSubmitSharedDepsProd; both this function and buildRunTUISubmitProd
// receive the same submitSharedDeps so each dep is constructed exactly once.
func buildSubmitterProd(
	recipsWrapper *RecipientSourceWrapper,
	gitProvider coregit.GitProvider,
	codec *artifactcodec.PortAdapter,
	shared submitSharedDeps,
) (submit.Submitter, submit.GitPort, error) {
	if recipsWrapper == nil {
		return nil, nil, nil
	}
	if gitProvider == nil {
		return nil, nil, nil
	}

	// Build the submit git port using the existing SubmitGitPort (wrapper.go).
	// The codec's EncodeUnsignedFromValues is the artifact encoder.
	codecEncoder := &prodArtifactCodecEncoder{codec: codec}
	gitPort, err := NewSubmitGitPort(gitProvider, codecEncoder)
	if err != nil {
		return nil, nil, fmt.Errorf("constructing submit git port: %w", err)
	}

	submitter, newErr := submit.New(submit.Deps{
		Recipients: recipsWrapper,
		Encryptor:  encrypt.New(),
		Validator:  shared.validator,
		KeyProbe:   shared.keyProbe,
		Git:        gitPort,
		Resume:     shared.resumeStore,
		Prompter:   prompt.New(),
		Clock:      shared.clock,
	})
	if newErr != nil {
		return nil, nil, fmt.Errorf("constructing submit use-case: %w", newErr)
	}
	return submitter, gitPort, nil
}

// prodArtifactCodecEncoder adapts the *artifactcodec.PortAdapter to the
// app.ArtifactEncoder interface required by SubmitGitPort.
type prodArtifactCodecEncoder struct {
	codec *artifactcodec.PortAdapter
}

// EncodeUnsigned implements app.ArtifactEncoder.
func (e *prodArtifactCodecEncoder) EncodeUnsigned(in submit.OpenPRInput) ([]byte, error) {
	return e.codec.EncodeUnsignedFromValues(in.Artifact)
}

// Compile-time assertion.
var _ ArtifactEncoder = (*prodArtifactCodecEncoder)(nil)

// buildRunTUISubmitProd builds the RunTUISubmit closure that the submit CLI
// command calls when ShouldLaunchTUI returns true. The closure is assembled
// here at the composition root so internal/cli stays free of any internal/tui
// import (the cli↛tui boundary is enforced by depguard).
//
// The SubmitterFactory re-creates a submit.Submitter with the TUI-supplied
// Prompter (a prefilledPrompter), reusing all other adapter deps from shared.
// shared MUST be the same submitSharedDeps instance passed to buildSubmitterProd
// so both paths consume identical adapter instances.
func buildRunTUISubmitProd(
	recipsWrapper *RecipientSourceWrapper,
	gitPort submit.GitPort,
	shared submitSharedDeps,
) func(ctx context.Context, out interface{ Write([]byte) (int, error) }, preFilledKey string, base submit.Input) error {
	factory := tui.SubmitterFactory(func(p submit.Prompter) (submit.Submitter, error) {
		return submit.New(submit.Deps{
			Recipients: recipsWrapper,
			Encryptor:  encrypt.New(),
			Validator:  shared.validator,
			KeyProbe:   shared.keyProbe,
			Git:        gitPort,
			Resume:     shared.resumeStore,
			Prompter:   p,
			Clock:      shared.clock,
		})
	})

	return func(ctx context.Context, out interface{ Write([]byte) (int, error) }, preFilledKey string, base submit.Input) error {
		var w io.Writer
		if out != nil {
			w = out
		} else {
			w = os.Stdout
		}
		return tui.RunSubmit(ctx, tui.Deps{
			SubmitterFactory: factory,
		}, w, preFilledKey, base)
	}
}

// buildRunTUIReviewProd builds the RunTUIReview closure that the review CLI
// command calls when ShouldLaunchTUI returns true. The closure is assembled
// here at the composition root so internal/cli stays free of any internal/tui
// import (the cli↛tui boundary).
//
// When reviewer is nil (e.g. contributor mode or adapters unavailable), the
// function returns nil so the CLI falls through to the headless "not configured"
// error path at command time. When reviewer is non-nil, the closure is wired
// with the Reviewer, Merger, Rejecter, RequestAccessReader, and
// SubmissionQueueSource ports. Merger, Rejecter, and submissionQueueSource are
// optional (nil is safe: the TUI omits the corresponding affordance).
func buildRunTUIReviewProd(
	pol *mode.Policy,
	currentMode mode.Mode,
	reviewer usecase.Reviewer,
	merger usecase.Merger,
	rejecter usecase.RequestRejecter,
	requestAccessReader rotate.RequestAccessReader,
	submissionQueueSource tui.SubmissionQueueSource,
) func(ctx context.Context, out interface{ Write([]byte) (int, error) }, prRef string) error {
	if reviewer == nil {
		// No reviewer: TUI review path is not available in this mode / configuration.
		return nil
	}

	return func(ctx context.Context, out interface{ Write([]byte) (int, error) }, prRef string) error {
		var w io.Writer
		if out != nil {
			w = out
		} else {
			w = os.Stdout
		}
		return tui.RunReview(ctx, tui.Deps{
			Reviewer:              reviewer,
			Merger:                merger,
			Rejecter:              rejecter,
			RequestAccessReader:   requestAccessReader,
			SubmissionQueueSource: submissionQueueSource,
			Policy:                pol,
			CurrentMode:           currentMode,
		}, w, prRef)
	}
}

// prodNoopKeyProbe is a fail-open KeyExistenceProbe used when no
// file-of-record source is wired (e.g. on first-ever submission with no live
// secrets file). It always returns (false, nil) so the submit use-case
// classifies the key as ADD. This is safe: a false ADD for a key that already
// exists is harmless (the merge step enforces the authoritative state).
type prodNoopKeyProbe struct{}

func (p *prodNoopKeyProbe) KeyExists(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}

// forSourceBytesAdapter bridges usecase.FileOfRecordSource (which returns
// usecase.FileOfRecord) to keyprobe.FileOfRecordBytesSource (which returns
// only []byte). This keeps the keyprobe package free of the core/usecase
// import that would transitively pull in crypto/identity and crypto/decrypt,
// violating the contributor-path import allowlist.
type forSourceBytesAdapter struct {
	src usecase.FileOfRecordSource
}

func (a *forSourceBytesAdapter) FileOfRecordBytes(ctx context.Context, projectID, fileName string) ([]byte, error) {
	rec, err := a.src.FileOfRecord(ctx, projectID, fileName)
	if err != nil {
		// Map the usecase not-found sentinel to keyprobe's sentinel so the
		// probe can distinguish "no file yet" from a hard fetch error.
		if errors.Is(err, usecase.ErrFileOfRecordNotFound) {
			return nil, fmt.Errorf("%w: %v", keyprobe.ErrFileNotFound, err)
		}
		return nil, err
	}
	return rec.Bytes, nil
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
	_ usecase.RegistryStatusProbe                = (*prodRegistryStatusProbe)(nil)
	_ usecase.RotationEpochProbe                 = (*prodRotationEpochProbe)(nil)
	_ submit.KeyExistenceProbe                   = (*prodNoopKeyProbe)(nil)
	_ keyprobe.FileOfRecordBytesSource           = (*forSourceBytesAdapter)(nil)
)
