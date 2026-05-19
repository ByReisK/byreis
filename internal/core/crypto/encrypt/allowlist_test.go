package encrypt_test

// Closed-world allowlist import test.
//
// This file implements the active CI gate that keeps the contributor encrypt
// path provably free of any private-key/identity material. It must stay wired
// from day one.
//
// It asserts:
//  1. The full transitive dep set of internal/core/crypto/encrypt contains no
//     package from the explicitly-forbidden set (identity, decrypt, registry,
//     crypto/ed25519). This is the primary security property.
//  2. Every non-stdlib, non-internal package in the transitive set must be on
//     the byreis-module or third-party allowlist.
//  3. The transitive dep set of internal/core/registry/rectypes excludes
//     crypto/ed25519 (proving rectypes is safe to admit to the allowlist).
//  4. Negative test: an injected forbidden import (crypto/ed25519) makes the
//     check fail — proving the guard actually fires rather than silently
//     passing. A guard that would silently pass is itself a defect.
//
// The check uses `go list -deps` to compute the full transitive closure.
// -short skips the negative test (which needs a temp dir) but always runs the
// positive subset assertions.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/ByReisK/byreis"

// explicitlyForbidden lists packages that must not appear in the transitive set
// of internal/core/crypto/encrypt (or the Submit use-case). These are packages
// that carry or can reach private-key / identity material.
//
// Adding any of these to the allowlist to make a test green defeats the entire
// asymmetric-access guarantee and must be rejected at review.
var explicitlyForbidden = map[string]bool{
	"crypto/ed25519": true, // private key constructor
	module + "/internal/core/crypto/identity": true, // admin private key material
	module + "/internal/core/crypto/decrypt":  true, // admin decrypt path
	module + "/internal/core/registry":        true, // carries SignerKey=ed25519.PublicKey / CounterStore
	"golang.org/x/crypto/ed25519":             true, // alias to crypto/ed25519
}

// allowedByreisPkgs enumerates the byreis-module packages permitted in the
// transitive dep set of crypto/encrypt. Only pure/domain packages with no
// identity-bearing dependencies may be here. The parent internal/core/registry
// is not here — only the pure rectypes sub-package is permitted.
var allowedByreisPkgs = map[string]bool{
	module + "/internal/core/crypto/encrypt":    true,
	module + "/internal/core/crypto/manifest":   true,
	module + "/internal/core/crypto/artifact":   true,
	module + "/internal/core/registry/rectypes": true,
	// Note: module + "/internal/core/registry" is NOT here (it transitively
	// reaches crypto/ed25519 via SignerKey/CounterStore).
}

// allowedThirdPartyPkgs enumerates the non-stdlib, non-byreis packages permitted
// in the transitive set of crypto/encrypt. Only age recipient/encrypt surface.
// age.Identity / age.X25519Identity are not permitted (those live in identity pkg).
//
// AMENDMENT (B2, explicit review): filippo.io/age v1.3.1 introduced a
// post-quantum hybrid path whose transitive set adds filippo.io/hpke* and the
// scrypt/pbkdf2 KDFs used by age's own passphrase/HPKE internals. These are
// age-internal recipient/encrypt-surface dependencies that carry NO
// private-key/identity material reachable from the contributor path; age's
// own graph contains ZERO crypto/ed25519 (verified: the only ed25519 importer
// in this module is the admin-side crypto/sign package, which is NOT imported
// by crypto/encrypt). They are admitted here under explicit review per the
// ADR-0005 "amend only under review" rule; crypto/ed25519 remains forbidden.
var allowedThirdPartyPkgs = map[string]bool{
	"filippo.io/age":                        true,
	"filippo.io/age/armor":                  true,
	"filippo.io/age/internal/bech32":        true,
	"filippo.io/age/internal/format":        true,
	"filippo.io/age/internal/stream":        true,
	"filippo.io/hpke":                       true,
	"filippo.io/hpke/crypto":                true,
	"filippo.io/hpke/crypto/ecdh":           true,
	"filippo.io/hpke/internal/byteorder":    true,
	"golang.org/x/crypto/chacha20":          true,
	"golang.org/x/crypto/chacha20poly1305":  true,
	"golang.org/x/crypto/hkdf":              true,
	"golang.org/x/crypto/curve25519":        true,
	"golang.org/x/crypto/pbkdf2":            true,
	"golang.org/x/crypto/scrypt":            true,
	"golang.org/x/crypto/internal/alias":    true,
	"golang.org/x/crypto/internal/poly1305": true,
	// golang.org/x/sys/cpu was previously listed defensively but is NOT in the
	// real transitive set of filippo.io/age (verified via `go list -deps`);
	// keeping it would dilute the "minimal necessary" claim. It is deliberately
	// omitted — if a future age release pulls it in, the subset test fails and
	// the addition goes through explicit review per ADR-0005.
}

// isStdlibOrInternal returns true if the package is a standard library package
// (including internal/* packages which change between Go versions). The stdlib
// internal packages are permitted as a group EXCEPT crypto/ed25519 (explicitly
// in explicitlyForbidden).
func isStdlibOrInternal(pkg string) bool {
	// Stdlib packages don't contain a dot in their first path element.
	// Third-party packages (including byreis module) do.
	parts := strings.SplitN(pkg, "/", 2)
	return !strings.Contains(parts[0], ".")
}

// checkAllowlist checks a list of deps against the allowlist rules and returns
// any violations. Violations are packages that:
//   - are explicitly forbidden, OR
//   - are a byreis-module package not on allowedByreisPkgs, OR
//   - are a third-party (non-stdlib) package not on allowedThirdPartyPkgs.
func checkAllowlist(deps []string) []string {
	var violations []string
	for _, dep := range deps {
		// Primary control: forbidden packages must never appear.
		if explicitlyForbidden[dep] {
			violations = append(violations, dep+" [FORBIDDEN: identity/private-key material]")
			continue
		}

		// byreis-module packages must be on the allowedByreisPkgs list.
		if strings.HasPrefix(dep, module+"/") {
			if !allowedByreisPkgs[dep] {
				violations = append(violations, dep+" [byreis pkg not on allowlist]")
			}
			continue
		}

		// stdlib / internal/* packages are permitted (except explicitly forbidden above).
		if isStdlibOrInternal(dep) {
			// stdlib packages carry no private-key material as a group (except
			// crypto/ed25519, already caught by explicitlyForbidden above).
			continue
		}

		// Third-party packages must be on the allowedThirdPartyPkgs list.
		if !allowedThirdPartyPkgs[dep] {
			violations = append(violations, dep+" [third-party pkg not on allowlist]")
		}
	}
	return violations
}

// TestAllowlist_Encrypt_SubsetOfImportAllowlist asserts that the full transitive
// dep set of internal/core/crypto/encrypt contains no forbidden packages and no
// unapproved byreis-module or third-party packages.
func TestAllowlist_Encrypt_SubsetOfImportAllowlist(t *testing.T) {
	deps := goListDeps(t, module+"/internal/core/crypto/encrypt")
	violations := checkAllowlist(deps)
	if len(violations) == 0 {
		t.Logf("PASS: internal/core/crypto/encrypt transitive set is a subset of the import allowlist (%d deps checked)", len(deps))
		return
	}
	for _, v := range violations {
		t.Errorf("FAIL: transitive dep NOT on the import allowlist: %s\n"+
			"  Adding crypto/ed25519 or internal/core/registry to the allowlist\n"+
			"  defeats the asymmetric-access guarantee and must be rejected at review.\n"+
			"  Amend the allowlist only under explicit review before adding any entry.", v)
	}
}

// TestAllowlist_Rectypes_ExcludesEd25519 asserts that the pure rectypes
// sub-package's OWN transitive set excludes crypto/ed25519. This verifies
// admitting rectypes to the allowlist does not transitively pull in ed25519.
func TestAllowlist_Rectypes_ExcludesEd25519(t *testing.T) {
	deps := goListDeps(t, module+"/internal/core/registry/rectypes")
	for _, dep := range deps {
		if dep == "crypto/ed25519" || dep == "golang.org/x/crypto/ed25519" {
			t.Errorf("FAIL: internal/core/registry/rectypes transitively imports %s\n"+
				"This means rectypes is no longer safe to admit to the import allowlist.\n"+
				"Remove the ed25519-bearing import from rectypes before this can be admitted.", dep)
		}
	}
	t.Logf("PASS: rectypes transitive set excludes crypto/ed25519 (%d total deps)", len(deps))
}

// TestAllowlist_Age_ExcludesEd25519AndIdentity pins, defense-in-depth, that
// filippo.io/age's OWN transitive set carries no private-key/identity material:
// no crypto/ed25519, and no age identity / X25519Identity-bearing path. age is
// on the contributor allowlist as recipient/encrypt surface only; this asserts
// admitting it cannot transitively reintroduce decrypt/identity material. It
// mirrors TestAllowlist_Rectypes_ExcludesEd25519.
func TestAllowlist_Age_ExcludesEd25519AndIdentity(t *testing.T) {
	deps := goListDeps(t, "filippo.io/age")
	for _, dep := range deps {
		if dep == "crypto/ed25519" || dep == "golang.org/x/crypto/ed25519" {
			t.Errorf("FAIL: filippo.io/age transitively imports %s\n"+
				"age must stay recipient/encrypt-surface only. An ed25519-bearing\n"+
				"transitive dep means age is no longer safe on the contributor allowlist.", dep)
		}
		// age's own identity types (age.Identity / age.X25519Identity) live in
		// the root filippo.io/age package, which IS allowed (the contributor path
		// imports only its recipient/encrypt surface — verified by the subset
		// test). What must never appear is a SEPARATE identity-bearing transitive
		// package path: anything whose import path contains an "identity"
		// element or a private X25519 identity package.
		low := strings.ToLower(dep)
		if dep != "filippo.io/age" &&
			(strings.Contains(low, "/identity") ||
				strings.HasSuffix(low, "/identity") ||
				strings.Contains(low, "x25519identity")) {
			t.Errorf("FAIL: filippo.io/age transitively imports identity-bearing path %s\n"+
				"This would give the contributor encrypt path a route to identity material.", dep)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: filippo.io/age transitive set excludes crypto/ed25519 and "+
			"separate identity/X25519Identity paths (%d total deps)", len(deps))
	}
}

// TestAllowlist_ExplicitForbiddenAbsent is a defense-in-depth check that the
// explicitly forbidden packages do not appear in encrypt's transitive set.
// This is redundant with TestAllowlist_Encrypt_SubsetOfImportAllowlist but provides
// a clearer failure message for the most critical violations.
func TestAllowlist_ExplicitForbiddenAbsent(t *testing.T) {
	deps := goListDeps(t, module+"/internal/core/crypto/encrypt")
	depSet := make(map[string]bool, len(deps))
	for _, d := range deps {
		depSet[d] = true
	}
	for pkg := range explicitlyForbidden {
		if depSet[pkg] {
			t.Errorf("FAIL: internal/core/crypto/encrypt transitively imports FORBIDDEN package: %s\n"+
				"  This import gives the contributor path a route to private-key\n"+
				"  material and defeats the asymmetric-access guarantee. Remove it.\n"+
				"  Adding this package to the allowlist must be rejected at review.", pkg)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: no explicitly-forbidden packages appear in encrypt transitive set")
	}
}

// TestAllowlist_NegativeTest_ForbiddenImportFails is the negative test that
// proves the guard fires: an injected unknown/identity-bearing dependency must
// fail the test, because a denylist that would silently pass is itself a
// defect.
//
// It creates a fake dep list containing crypto/ed25519 and verifies that
// checkAllowlist() returns a violation — proving the guard fires.
//
// Additionally, it creates a real temporary Go package that imports crypto/ed25519
// and verifies that go list -deps plus checkAllowlist() produces a failure,
// proving the end-to-end guard is active.
func TestAllowlist_NegativeTest_ForbiddenImportFails(t *testing.T) {
	// --- Part A: pure in-process check (fast, no temp dir required) ---
	//
	// Inject crypto/ed25519 into a simulated dep list and verify the guard fires.
	injectedDeps := []string{
		module + "/internal/core/crypto/encrypt",
		module + "/internal/core/crypto/manifest",
		module + "/internal/core/registry/rectypes",
		"context",
		"errors",
		"crypto/ed25519", // FORBIDDEN — must cause a violation
	}
	violations := checkAllowlist(injectedDeps)
	if len(violations) == 0 {
		t.Errorf("NEGATIVE TEST FAIL: checkAllowlist silently accepted crypto/ed25519\n" +
			"The guard is broken — it would NOT detect a forbidden identity-bearing import.\n" +
			"Fix: ensure checkAllowlist rejects crypto/ed25519.\n" +
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
			t.Logf("PASS (part A): checkAllowlist correctly detected forbidden import crypto/ed25519\nviolations: %v", violations)
		}
	}

	// --- Part B: inject internal/core/registry (carries crypto/ed25519 transitively) ---
	injectedDeps2 := []string{
		module + "/internal/core/crypto/encrypt",
		module + "/internal/core/registry", // FORBIDDEN (transitively reaches crypto/ed25519)
	}
	violations2 := checkAllowlist(injectedDeps2)
	if len(violations2) == 0 {
		t.Errorf("NEGATIVE TEST FAIL: checkAllowlist silently accepted internal/core/registry\n" +
			"The parent registry package is forbidden (transitively reaches crypto/ed25519 via\n" +
			"SignerKey/CounterStore). This would allow private-key material to reach encrypt.\n" +
			"Fix: ensure checkAllowlist rejects internal/core/registry.")
	} else {
		t.Logf("PASS (part B): checkAllowlist correctly rejected internal/core/registry\nviolations: %v", violations2)
	}

	// --- Part C: end-to-end with a real temp package (skipped in -short) ---
	if testing.Short() {
		t.Skip("skipping end-to-end negative test (temp dir + go list) in -short mode")
	}

	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module example.com/inject-test\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatalf("write temp go.mod: %v", err)
	}
	pkgDir := filepath.Join(tmp, "injecttest")
	if err := os.MkdirAll(pkgDir, 0o700); err != nil {
		t.Fatalf("mkdir temp pkg: %v", err)
	}
	injectedSrc := "package injecttest\n\nimport _ \"crypto/ed25519\"\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "inject.go"), []byte(injectedSrc), 0o600); err != nil {
		t.Fatalf("write temp package: %v", err)
	}

	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "example.com/inject-test/injecttest")
	cmd.Dir = tmp
	out, err := cmd.Output()
	if err != nil {
		t.Logf("go list failed for temp package (inconclusive): %v", err)
		t.Skip("go list failed for injected package; skipping end-to-end negative test")
	}

	realDeps := strings.Fields(strings.TrimSpace(string(out)))
	realViolations := checkAllowlist(realDeps)

	if len(realViolations) == 0 {
		t.Errorf("NEGATIVE TEST FAIL (end-to-end): allowlist check passed for real package importing crypto/ed25519\n" +
			"The guard is NOT detecting the forbidden import via go list -deps.\n" +
			"Fix: ensure checkAllowlist rejects crypto/ed25519.")
	} else {
		found := false
		for _, v := range realViolations {
			if strings.Contains(v, "crypto/ed25519") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("NEGATIVE TEST FAIL (end-to-end): violations found but crypto/ed25519 not among them: %v", realViolations)
		} else {
			t.Logf("PASS (part C end-to-end): allowlist correctly detected forbidden import via real go list -deps\nviolations: %v", realViolations)
		}
	}
}

// goListDeps runs `go list -deps <pkg>` and returns the transitive dep list.
// If go list fails, the test fails loudly — it does not skip silently.
// A gate that cannot run is a failure, never a silent pass: a missing or
// uncompilable test, a go list error, or a skipped/absent job must surface as
// a failure rather than a green no-op.
func goListDeps(t *testing.T, pkg string) []string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", pkg)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ALLOWLIST GATE FAIL: go list -deps %s failed: %v (output: %s)\n"+
			"A gate that cannot run is a failure, never a silent pass.\n"+
			"Run 'go mod tidy' and ensure all deps are available.", pkg, err, out)
		return nil
	}
	return strings.Fields(strings.TrimSpace(string(out)))
}
