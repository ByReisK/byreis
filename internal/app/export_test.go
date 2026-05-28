// export_test.go exposes unexported helpers for black-box unit tests in
// package app_test. Nothing in this file is compiled into production binaries.
package app

import (
	"context"

	"github.com/ByReisK/byreis/internal/adapter/artifactcodec"
	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// BaseBranchFromEnvForTest calls baseBranchFromEnvProd so that app_test
// package tests can exercise the env-reader + validator without exporting the
// production function.
var BaseBranchFromEnvForTest = baseBranchFromEnvProd

// ValidateBaseBranchForTest exposes validateBaseBranch for direct unit testing
// of inputs that cannot be set via t.Setenv (e.g. NUL bytes, which the OS
// rejects at the setenv(3) syscall level before userspace code can observe
// them through os.Getenv).
var ValidateBaseBranchForTest = validateBaseBranch

// registryWriteTokenStoreForTest is the interface the test bridge needs.
type registryWriteTokenStoreForTest interface {
	GetRegistryWriteToken(ctx context.Context, registryURL string) (string, error)
}

// NewAppRegistryWriteTokenBridgeForTest exposes the appRegistryWriteTokenBridge
// for unit tests in app_test.
func NewAppRegistryWriteTokenBridgeForTest(store registryWriteTokenStoreForTest) registryadapter.RegistryWriteTokenProvider {
	return &appRegistryWriteTokenBridge{store: store}
}

// NewCapturedModeProviderForTest exposes the capturedModeProvider for unit tests.
func NewCapturedModeProviderForTest(m mode.Mode) interface {
	CurrentMode(ctx context.Context) (mode.Mode, error)
} {
	return &capturedModeProvider{m: m}
}

// BuildGitProviderProdForTest calls buildGitProviderProd so that app_test
// package tests can assert the typed-nil invariant without importing the
// production adapter directly.
var BuildGitProviderProdForTest = func(token, project, baseBranch string) (coregit.GitProvider, error) {
	return buildGitProviderProd(token, project, baseBranch)
}

// BuildReviewerProdForTest calls buildReviewerProd so that app_test package
// tests can assert the positive composition leg (ADMIN mode + non-nil git
// provider → non-nil Reviewer) and its mode gate (CONTRIBUTOR → nil) directly,
// without needing a real GitHub repo to satisfy both ADMIN-promotion and a
// non-nil git provider simultaneously through full mode detection.
var BuildReviewerProdForTest = func(
	currentMode mode.Mode,
	gitProvider coregit.GitProvider,
	decryptor decrypt.Decryptor,
	idLoader identity.Loader,
	codec usecase.ArtifactCodec,
	gate usecase.ModeGate,
	validator usecase.ValueValidator,
	auditSink audit.Logger,
) usecase.Reviewer {
	return buildReviewerProd(currentMode, gitProvider, decryptor, idLoader, codec, gate, validator, auditSink)
}

// SubmitSharedDepsForTest is the exported view of submitSharedDeps for the
// AC-007-A equivalence test. It exposes the interface fields so the test can
// assert pointer identity across the CLI and TUI paths.
type SubmitSharedDepsForTest struct {
	KeyProbe    submit.KeyExistenceProbe
	ResumeStore submit.ResumeStore
	Validator   submit.ValueValidator
	Clock       submit.Clock
}

// NewProdCounterStoreBridgeForTest wraps client in a prodRegistryCounterStoreBridge
// and returns it as a usecase.CounterStore. Tests use this to drive CommitBump
// through the production bridge and assert that every field — including AuditEntry —
// is forwarded to the underlying coreregistry.RegistryClient unchanged.
func NewProdCounterStoreBridgeForTest(client coreregistry.RegistryClient) usecase.CounterStore {
	return &prodRegistryCounterStoreBridge{client: client}
}

// BuildSubmitSharedDepsProdForTest calls buildSubmitSharedDepsProd so that the
// AC-007-A equivalence test can construct the shared deps once and pass them
// to both BuildSubmitterProdForTest and BuildRunTUISubmitProdForTest, asserting
// that both paths receive identical instances.
func BuildSubmitSharedDepsProdForTest(
	forSrc usecase.FileOfRecordSource,
	codec *artifactcodec.PortAdapter,
	cacheDir string,
) (SubmitSharedDepsForTest, error) {
	sd, err := buildSubmitSharedDepsProd(forSrc, codec, cacheDir)
	if err != nil {
		return SubmitSharedDepsForTest{}, err
	}
	return SubmitSharedDepsForTest{
		KeyProbe:    sd.keyProbe,
		ResumeStore: sd.resumeStore,
		Validator:   sd.validator,
		Clock:       sd.clock,
	}, nil
}

// BuildModeDowngradeWarningForTest exposes buildModeDowngradeWarning so that
// app_test package tests can drive the helper directly without relying on
// full production wiring.
var BuildModeDowngradeWarningForTest = func(detResult mode.Result, detErr error) string {
	return buildModeDowngradeWarning(detResult, detErr)
}

// AuditVerifierIsReadOnlyForTest reports whether the given AuditVerifier is
// backed by a read-only *registryadapter.Client (i.e. a client whose
// WriteTokenProvider is nil). The second return value indicates whether the
// type-assertion to *registryadapter.Client succeeded; a false second return
// means the verifier is not the production client (e.g. a test double) and
// the first value should be ignored. Used by T-S1-C to assert that the
// contributor-mode AuditVerifier has no write credential — non-nil alone is
// insufficient.
func AuditVerifierIsReadOnlyForTest(av interface{}) (readOnly bool, isProductionClient bool) {
	client, ok := av.(*registryadapter.Client)
	if !ok {
		return false, false
	}
	return client.WriteTokenProviderIsNilForTest(), true
}

// BuildGitAuthEnvForTest exposes buildGitAuthEnv for white-box tests that
// verify the host-scoping predicate and the resulting GIT_CONFIG env block.
func BuildGitAuthEnvForTest(registryURL, token string) []string {
	return buildGitAuthEnv(registryURL, token)
}
