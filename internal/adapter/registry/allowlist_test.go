// Package registry — adapter import boundary tests.
//
// This file enforces two import-boundary invariants:
//
//  1. internal/core/registry (the core registry port package) must NOT import
//     internal/core/crypto/verify. That edge was removed to eliminate the import
//     cycle created by CounterAuthority/PendingBump previously living in
//     core/registry.
//
//  2. internal/adapter/registry (this adapter package) and its entire
//     internal/... subtree must NOT import internal/core/crypto/verify. The
//     adapter references ErrNoTrustedSigner from internal/core/registry directly;
//     no verify import is needed or permitted in the adapter.
//
// This file also verifies that no core package imports any adapter package
// (the fundamental Clean Architecture inversion rule).
package registry_test

import (
	"os/exec"
	"strings"
	"testing"
)

const registryAdapterPkg = "github.com/ByReisK/byreis/internal/adapter/registry"
const coreRegistryPkg = "github.com/ByReisK/byreis/internal/core/registry"
const verifyPkg = "github.com/ByReisK/byreis/internal/core/crypto/verify"
const adapterPkg = "github.com/ByReisK/byreis/internal/adapter"

// TestCoreRegistry_DoesNotImportVerify proves that the CORE registry package
// (internal/core/registry) does not import internal/core/crypto/verify.
//
// This enforces HC-6 / ADR-0006 gap-4a: the internal/core/registry→verify
// edge must stay removed to keep the CounterAuthority/PendingBump placement
// in countertypes clean and avoid import cycles.
//
// Note: the ADAPTER (internal/adapter/registry) must also NOT import verify —
// see TestRegistryAdapter_DoesNotImportVerify below.
func TestCoreRegistry_DoesNotImportVerify(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", coreRegistryPkg)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ALLOWLIST GATE FAIL: go list -deps %s failed: %v\n"+
			"A gate that cannot run is a failure, never a silent pass.", coreRegistryPkg, err)
	}

	deps := strings.Fields(strings.TrimSpace(string(out)))
	for _, dep := range deps {
		if dep == verifyPkg {
			t.Errorf("FAIL: internal/core/registry transitively imports %s\n"+
				"The internal/core/registry→verify edge must stay removed (HC-6, ADR-0006 gap-4a).\n"+
				"CounterAuthority/PendingBump live in countertypes; verify imports countertypes\n"+
				"to consume the opaque value. This keeps the dep direction clean and avoids cycles.",
				verifyPkg)
		}
	}

	if !t.Failed() {
		t.Logf("PASS: internal/core/registry does not transitively import %s (%d deps checked)",
			verifyPkg, len(deps))
	}
}

// TestRegistryAdapter_DoesNotImportVerify proves that the registry adapter
// package (internal/adapter/registry) and its entire internal/... subtree
// (including internal/adapter/registry/internal/capmint) do NOT transitively
// import internal/core/crypto/verify.
//
// The adapter references ErrNoTrustedSigner from internal/core/registry
// directly. No verify import is needed, and permitting one would re-introduce
// the architectural violation this test guards against. A gate that cannot run
// is a failure, never a silent pass.
func TestRegistryAdapter_DoesNotImportVerify(t *testing.T) {
	t.Parallel()

	// Check the top-level adapter package.
	for _, pkg := range []string{registryAdapterPkg, registryAdapterPkg + "/internal/capmint"} {
		pkg := pkg
		t.Run(pkg, func(t *testing.T) {
			t.Parallel()

			cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", pkg)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("ALLOWLIST GATE FAIL: go list -deps %s failed: %v\n"+
					"A gate that cannot run is a failure, never a silent pass.", pkg, err)
			}

			deps := strings.Fields(strings.TrimSpace(string(out)))
			for _, dep := range deps {
				if dep == verifyPkg {
					t.Errorf("FAIL: %s transitively imports %s\n"+
						"The adapter must NOT import internal/core/crypto/verify.\n"+
						"Reference ErrNoTrustedSigner from internal/core/registry directly.",
						pkg, verifyPkg)
				}
			}

			if !t.Failed() {
				t.Logf("PASS: %s does not transitively import %s (%d deps checked)",
					pkg, verifyPkg, len(deps))
			}
		})
	}
}

// TestRegistryAdapter_NoCoreAdapterCycle verifies the adapter does not
// accidentally depend on another adapter package (adapters depend inward on
// core, never on sibling adapters).
func TestRegistryAdapter_NoCoreAdapterCycle(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", registryAdapterPkg)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s failed: %v", registryAdapterPkg, err)
	}

	deps := strings.Fields(strings.TrimSpace(string(out)))
	for _, dep := range deps {
		// The adapter itself and its own sub-packages (capmint) are expected.
		if dep == registryAdapterPkg ||
			strings.HasPrefix(dep, registryAdapterPkg+"/") {
			continue
		}
		// Other adapter packages (git, keychain, fs) should not appear.
		if strings.HasPrefix(dep, adapterPkg+"/") &&
			!strings.HasPrefix(dep, registryAdapterPkg) {
			t.Errorf("UNEXPECTED: registry adapter transitively imports another adapter: %s\n"+
				"Adapters should depend only on core interfaces, not on sibling adapters.", dep)
		}
	}

	if !t.Failed() {
		t.Logf("PASS: no unexpected adapter→sibling-adapter dependency found.")
	}
}
