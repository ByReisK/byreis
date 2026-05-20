package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/artifactcodec"
	auditadapter "github.com/ByReisK/byreis/internal/adapter/audit"
	editadapter "github.com/ByReisK/byreis/internal/adapter/editor"
	"github.com/ByReisK/byreis/internal/adapter/fs/atomicwrite"
	"github.com/ByReisK/byreis/internal/adapter/git/fileofrecord"
	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/adapter/keychain"
	manifestsigneradapter "github.com/ByReisK/byreis/internal/adapter/manifestsigner"
	"github.com/ByReisK/byreis/internal/adapter/modeprobe"
	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/adapter/signingkey"
	"github.com/ByReisK/byreis/internal/adapter/truststore"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/mode"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
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

	// Build the ForSourceBridge that wires the M6 cryptographic-reality anchor.
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

	return &cli.Deps{
		Policy:      pol,
		CurrentMode: currentMode,
		ConfigDir:   configDir,
		Getter:      getter,
		Decryptor:   decryptor,
		Editor:      editorUC,
	}, nil
}

// buildRegistryClientProd constructs the real registry client. Returns (nil, err)
// when the registry URL is absent or the trust anchor cannot be loaded.
// A missing trust anchor is not a hard error: the user may not have run
// `byreis init` yet, in which case the binary starts in CONTRIBUTOR mode.
func buildRegistryClientProd(ctx context.Context, configDir string) (coreregistry.RegistryClient, error) {
	registryURL := os.Getenv("BYREIS_REGISTRY")
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

	ft, ftErr := buildRegistryFetchTransportProd(registryURL)
	if ftErr != nil {
		return nil, fmt.Errorf("constructing registry fetch transport: %w", ftErr)
	}

	client, err := registryadapter.New(registryadapter.ClientConfig{
		RegistryURL:    registryURL,
		ProjectID:      projectIDFromEnvProd(),
		CacheDir:       registryCacheDirProd(),
		TrustAnchorKey: validated.SignerKey,
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: ft,
	})
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
	// project URLs.
	ft, err := registryadapter.NewProductionFetchTransportFromRunner(
		registryadapter.SubprocessRunner{},
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
// the registry client. It returns (nil, nil) when the GitHub token is absent
// AND the registry URL is not a file:// local path, so the registry client
// falls back to the offline-only path instead of failing at construction time.
//
// For file:// registry URLs the transport uses only the system git subprocess
// (no GitHub token required). For GitHub URLs (https://github.com/... etc.) the
// GitHub token is required and an HTTP provider is used for authentication;
// however the actual file reads now come from the git clone (not the HTTP API).
func buildRegistryFetchTransportProd(registryURL string) (registryadapter.FetchTransport, error) {
	validated := registryProjectFromURLProd(registryURL)
	if validated == "" {
		return nil, fmt.Errorf(
			"cannot parse registry URL %q — "+
				"set BYREIS_REGISTRY to https://github.com/owner/repo or file:///absolute/path",
			registryURL)
	}

	// For file:// local repos, no token is required — the transport uses system
	// git directly (clone + verify + cat-file), all subprocess-based.
	if strings.HasPrefix(validated, "file://") {
		ft, err := registryadapter.NewProductionFetchTransportFromRunner(
			registryadapter.SubprocessRunner{},
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
		registryadapter.SubprocessRunner{},
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

// ─── compile-time assertions ─────────────────────────────────────────────────

var (
	_ usecase.Editor                      = (*prodNoEditorNonInteractiveRefusal)(nil)
	_ modeprobe.AdminSetFetcher           = (*prodRegistryClientBridge)(nil)
	_ fileofrecord.ConfiguredPathResolver = (*prodRegistryConfiguredPathResolver)(nil)
	_ usecase.CounterStore                = (*prodRegistryCounterStoreBridge)(nil)
)
