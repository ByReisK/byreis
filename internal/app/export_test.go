// export_test.go exposes unexported helpers for black-box unit tests in
// package app_test. Nothing in this file is compiled into production binaries.
package app

import (
	"context"

	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/core/mode"
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
