package submit_test

// Closed-world allowlist import test for the Submit compilation unit.
//
// This file implements the active CI gate for the internal/core/usecase/submit
// sub-package (the Submit compilation unit — not the whole
// internal/core/usecase).
//
// The gate must target this sub-package (internal/core/usecase/submit), not the
// parent package (internal/core/usecase), because Decrypt/Edit/Merge live in
// the parent and are off the Submit allowlist by construction. A
// package-scoped transitive-subset allowlist test cannot honour a "only Submit
// symbols" qualifier on the parent package.
//
// It asserts:
//  1. The full transitive dep set of internal/core/usecase/submit contains no
//     package from the explicitly-forbidden set (identity, decrypt, registry,
//     crypto/ed25519, countertypes). This is the primary security property.
//  2. Every non-stdlib, non-internal byreis-module package in the transitive
//     set must be on the allowlist.
//  3. Negative test: an injected forbidden import (crypto/ed25519) makes the
//     check fail — proving the guard actually fires rather than silently
//     passing. A gate that silently passes is itself a defect.
//
// This gate must not silently pass: a missing/uncompilable test, a go list
// error, or a skipped test is treated as a failure by the CI job (which uses
// -run TestAllowlist with no -short, so a skip causes go test to exit non-zero
// via the t.Fatal path in goListDeps).
//
// Wired by: make check-allowlist / CI allowlist job.

import (
	"strings"
	"testing"

	"os/exec"
)

const module = "github.com/ByReisK/byreis"

// explicitlyForbiddenSubmit lists packages that must not appear in the
// transitive set of internal/core/usecase/submit.
//
// Adding any of these to the allowlist to make a test green defeats the
// asymmetric-access guarantee and must be rejected at review.
var explicitlyForbiddenSubmit = map[string]bool{
	"crypto/ed25519": true, // private key constructor
	module + "/internal/core/crypto/identity":       true, // admin private key material
	module + "/internal/core/crypto/decrypt":        true, // admin decrypt path
	module + "/internal/core/registry":              true, // carries SignerKey=ed25519.PublicKey / CounterStore
	module + "/internal/core/registry/countertypes": true, // counter authority — not on Submit path
	"golang.org/x/crypto/ed25519":                   true, // alias to crypto/ed25519
}

// allowedByreisPkgsSubmit enumerates the byreis-module packages permitted in
// the transitive dep set of usecase/submit. Only pure/domain packages with no
// identity-bearing or counter-authority dependencies may be here.
var allowedByreisPkgsSubmit = map[string]bool{
	module + "/internal/core/usecase/submit":    true,
	module + "/internal/core/crypto/encrypt":    true,
	module + "/internal/core/crypto/manifest":   true,
	module + "/internal/core/crypto/artifact":   true,
	module + "/internal/core/registry/rectypes": true,
	// Note: module + "/internal/core/registry" is NOT here (it transitively
	// reaches crypto/ed25519 via SignerKey/CounterStore).
	// Note: module + "/internal/core/registry/countertypes" is NOT here
	// (counter authority is for verify/admin, not the contributor submit path).
	// The git/audit/config port packages are added here when they are wired.
}

// allowedThirdPartyPkgsSubmit enumerates the non-stdlib, non-byreis packages
// permitted in the transitive set of usecase/submit. Only age recipient/encrypt
// surface.
var allowedThirdPartyPkgsSubmit = map[string]bool{
	"filippo.io/age":                        true,
	"filippo.io/age/armor":                  true,
	"golang.org/x/crypto/chacha20":          true,
	"golang.org/x/crypto/chacha20poly1305":  true,
	"golang.org/x/crypto/hkdf":              true,
	"golang.org/x/crypto/curve25519":        true,
	"golang.org/x/crypto/internal/alias":    true,
	"golang.org/x/crypto/internal/poly1305": true,
	"golang.org/x/sys/cpu":                  true,
}

// isStdlibOrInternal returns true if the package is a standard library package.
func isStdlibOrInternal(pkg string) bool {
	parts := strings.SplitN(pkg, "/", 2)
	return !strings.Contains(parts[0], ".")
}

// checkAllowlistSubmit checks a list of deps against the allowlist rules.
func checkAllowlistSubmit(deps []string) []string {
	var violations []string
	for _, dep := range deps {
		if explicitlyForbiddenSubmit[dep] {
			violations = append(violations, dep+" [FORBIDDEN: identity/counter/private-key material]")
			continue
		}
		if strings.HasPrefix(dep, module+"/") {
			if !allowedByreisPkgsSubmit[dep] {
				violations = append(violations, dep+" [byreis pkg not on Submit allowlist]")
			}
			continue
		}
		if isStdlibOrInternal(dep) {
			continue
		}
		if !allowedThirdPartyPkgsSubmit[dep] {
			violations = append(violations, dep+" [third-party pkg not on Submit allowlist]")
		}
	}
	return violations
}

// TestAllowlist_Submit_SubsetOfImportAllowlist asserts that the full transitive
// dep set of internal/core/usecase/submit is a subset of the Submit import
// allowlist.
func TestAllowlist_Submit_SubsetOfImportAllowlist(t *testing.T) {
	deps := goListDepsSubmit(t, module+"/internal/core/usecase/submit")
	violations := checkAllowlistSubmit(deps)
	if len(violations) == 0 {
		t.Logf("PASS: internal/core/usecase/submit transitive set is a subset of the Submit import allowlist (%d deps checked)", len(deps))
		return
	}
	for _, v := range violations {
		t.Errorf("FAIL: transitive dep NOT on the Submit import allowlist: %s\n"+
			"  Adding crypto/ed25519, internal/core/registry, or\n"+
			"  internal/core/registry/countertypes to the allowlist defeats the\n"+
			"  asymmetric-access guarantee and must be rejected at review.\n"+
			"  Amend the allowlist only under explicit review before adding any entry.", v)
	}
}

// TestAllowlist_Submit_ExplicitForbiddenAbsent is a defense-in-depth check that
// the explicitly forbidden packages do not appear in submit's transitive set.
func TestAllowlist_Submit_ExplicitForbiddenAbsent(t *testing.T) {
	deps := goListDepsSubmit(t, module+"/internal/core/usecase/submit")
	depSet := make(map[string]bool, len(deps))
	for _, d := range deps {
		depSet[d] = true
	}
	for pkg := range explicitlyForbiddenSubmit {
		if depSet[pkg] {
			t.Errorf("FAIL: internal/core/usecase/submit transitively imports FORBIDDEN package: %s\n"+
				"  This import gives the contributor submit path a route to\n"+
				"  private-key/counter material and defeats the asymmetric-access\n"+
				"  guarantee. Remove it; allowlisting it must be rejected at review.", pkg)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: no explicitly-forbidden packages appear in submit transitive set")
	}
}

// TestAllowlist_Submit_NegativeTest_ForbiddenImportFails is the negative test
// for the Submit compilation unit: an injected unknown/identity-bearing
// dependency must fail the test, and a gate that cannot run is a failure,
// never a silent pass.
//
// It verifies checkAllowlistSubmit correctly fires on an injected forbidden dep.
func TestAllowlist_Submit_NegativeTest_ForbiddenImportFails(t *testing.T) {
	// --- Part A: pure in-process check (fast, no temp dir) ---
	injectedDeps := []string{
		module + "/internal/core/usecase/submit",
		module + "/internal/core/crypto/encrypt",
		module + "/internal/core/registry/rectypes",
		"context",
		"errors",
		"crypto/ed25519", // FORBIDDEN — must cause a violation
	}
	violations := checkAllowlistSubmit(injectedDeps)
	if len(violations) == 0 {
		t.Errorf("NEGATIVE TEST FAIL: checkAllowlistSubmit silently accepted crypto/ed25519\n" +
			"The guard is broken — it would NOT detect a forbidden identity-bearing import.\n" +
			"Fix: ensure checkAllowlistSubmit rejects crypto/ed25519.\n" +
			"(A guard that silently passes a forbidden import is itself a defect.)")
	} else {
		found := false
		for _, v := range violations {
			if strings.Contains(v, "crypto/ed25519") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("NEGATIVE TEST FAIL: violations detected but crypto/ed25519 not among them: %v", violations)
		} else {
			t.Logf("PASS (part A): checkAllowlistSubmit correctly detected forbidden import crypto/ed25519\nviolations: %v", violations)
		}
	}

	// --- Part B: inject internal/core/registry (transitively reaches crypto/ed25519) ---
	injectedDeps2 := []string{
		module + "/internal/core/usecase/submit",
		module + "/internal/core/registry", // FORBIDDEN
	}
	violations2 := checkAllowlistSubmit(injectedDeps2)
	if len(violations2) == 0 {
		t.Errorf("NEGATIVE TEST FAIL: checkAllowlistSubmit silently accepted internal/core/registry\n" +
			"The parent registry package is forbidden on the Submit allowlist (transitively\n" +
			"reaches crypto/ed25519 via SignerKey/CounterStore).\n" +
			"Fix: ensure checkAllowlistSubmit rejects internal/core/registry.")
	} else {
		t.Logf("PASS (part B): checkAllowlistSubmit correctly rejected internal/core/registry\nviolations: %v", violations2)
	}

	// --- Part C: inject countertypes (not on Submit path) ---
	injectedDeps3 := []string{
		module + "/internal/core/usecase/submit",
		module + "/internal/core/registry/countertypes", // FORBIDDEN on Submit allowlist
	}
	violations3 := checkAllowlistSubmit(injectedDeps3)
	if len(violations3) == 0 {
		t.Errorf("NEGATIVE TEST FAIL: checkAllowlistSubmit silently accepted registry/countertypes\n" +
			"countertypes is NOT on the Submit allowlist (counter authority is for verify/admin,\n" +
			"not the contributor submit path).\n" +
			"Fix: ensure checkAllowlistSubmit rejects registry/countertypes.")
	} else {
		t.Logf("PASS (part C): checkAllowlistSubmit correctly rejected registry/countertypes\nviolations: %v", violations3)
	}
}

// goListDepsSubmit runs `go list -deps <pkg>` and returns the transitive dep list.
// If go list fails, the test fails loudly and never skips silently: a gate
// that cannot run must fail rather than pass as a no-op.
func goListDepsSubmit(t *testing.T, pkg string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", pkg)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ALLOWLIST GATE FAIL: go list -deps %s failed: %v (output: %s)\n"+
			"A gate that cannot run is a failure, never a silent pass.\n"+
			"Run 'go mod tidy' and ensure all deps are available.", pkg, err, out)
		return nil
	}
	return strings.Fields(strings.TrimSpace(string(out)))
}
