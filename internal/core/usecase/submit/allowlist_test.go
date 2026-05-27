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
	"os"
	"os/exec"
	"strings"
	"testing"
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
	// filippo.io/age/plugin (recipient-v1/identity-v1 protocol + os/exec plugin
	// subprocess) is the admin read-path's recipient/identity construction
	// surface, behind an adapter. It must never reach the contributor submit
	// path, or the write-only wedge gains a compile-time route to backend
	// identity construction. The negative test below proves the guard fires.
	"filippo.io/age/plugin": true,
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
	// AMENDMENT (B3c, explicit review): the Submit spine consumes the
	// append-only audit port and the structured-log port. Both packages have a
	// transitive set of EXACTLY themselves (stdlib-only; verified via
	// `go list -deps`): zero third-party, and provably no crypto/ed25519,
	// crypto/identity, crypto/decrypt, or internal/core/registry reachable.
	// They are pure consumer-defined domain ports with no identity-bearing or
	// counter-authority dependency, so admitting them cannot reintroduce
	// decrypt/identity material on the contributor path. crypto/ed25519,
	// internal/core/registry, and internal/core/registry/countertypes remain
	// forbidden.
	module + "/internal/core/audit":   true,
	module + "/internal/core/logging": true,
	// AMENDMENT (bulk submit, explicit review): the .env bulk-submit parser is a
	// pure tokeniser fed raw bytes. Its full transitive set is EXACTLY itself
	// (stdlib-only; verified via `go list -deps`): zero third-party, zero other
	// byreis package, and provably no crypto/ed25519, crypto/identity,
	// crypto/decrypt, internal/core/registry, or registry/countertypes
	// reachable. It produces only (key, value) pairs and judges no value
	// content, so admitting it cannot reintroduce decrypt/identity material on
	// the contributor path. The forbidden set is unchanged.
	module + "/internal/core/usecase/submit/envparse": true,
	// Note: module + "/internal/core/registry" is NOT here (it transitively
	// reaches crypto/ed25519 via SignerKey/CounterStore).
	// Note: module + "/internal/core/registry/countertypes" is NOT here
	// (counter authority is for verify/admin, not the contributor submit path).
	// The git/config port packages are consumer-defined INSIDE this sub-package
	// (submit.GitPort etc.) so internal/core/git is deliberately not pulled in.
}

// allowedThirdPartyPkgsSubmit enumerates the non-stdlib, non-byreis packages
// permitted in the transitive set of usecase/submit. Only age recipient/encrypt
// surface.
//
// AMENDMENT (B2, explicit review): mirrors the crypto/encrypt allowlist
// amendment for filippo.io/age v1.3.1 (post-quantum hybrid path adds
// filippo.io/hpke* + scrypt/pbkdf2 + age-internal bech32/format/stream). These
// are age-internal recipient/encrypt-surface deps with NO private-key/identity
// material reachable from the contributor path; age's graph has ZERO
// crypto/ed25519 (the only ed25519 importer is the admin-side crypto/sign,
// not reachable from submit). crypto/ed25519 remains forbidden.
var allowedThirdPartyPkgsSubmit = map[string]bool{
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
	// AMENDMENT (reviewed amendment): golang.org/x/sys/cpu is pulled transitively
	// by golang.org/x/crypto chacha20/chacha20poly1305 for CPU-feature detection
	// on linux/amd64 and windows/amd64 (absent on darwin/arm64). It is a
	// CPU-feature-flag package carrying no identity, ed25519, private-key, or
	// counter material. The darwin-only verification that previously supported
	// omitting it was incomplete; this entry brings the allowlist to the
	// platform-union required for deterministic CI evaluation under a pinned
	// GOOS=linux GOARCH=amd64. crypto/ed25519, internal/core/registry,
	// internal/core/crypto/identity, internal/core/crypto/decrypt, and
	// internal/core/registry/countertypes remain forbidden and unchanged.
	"golang.org/x/sys/cpu": true,
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

// TestAllowlist_Age_ExcludesEd25519AndIdentity pins, defense-in-depth, that
// filippo.io/age's OWN transitive set carries no private-key/identity material:
// no crypto/ed25519, and no separate age identity / X25519Identity-bearing
// path. age is on the Submit allowlist as recipient/encrypt surface only; this
// asserts admitting it cannot transitively reintroduce decrypt/identity
// material. It mirrors the rectypes ed25519 pin.
func TestAllowlist_Age_ExcludesEd25519AndIdentity(t *testing.T) {
	deps := goListDepsSubmit(t, "filippo.io/age")
	for _, dep := range deps {
		if dep == "crypto/ed25519" || dep == "golang.org/x/crypto/ed25519" {
			t.Errorf("FAIL: filippo.io/age transitively imports %s\n"+
				"age must stay recipient/encrypt-surface only on the Submit allowlist.", dep)
		}
		low := strings.ToLower(dep)
		if dep != "filippo.io/age" &&
			(strings.Contains(low, "/identity") ||
				strings.HasSuffix(low, "/identity") ||
				strings.Contains(low, "x25519identity")) {
			t.Errorf("FAIL: filippo.io/age transitively imports identity-bearing path %s\n"+
				"This would give the contributor submit path a route to identity material.", dep)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: filippo.io/age transitive set excludes crypto/ed25519 and "+
			"separate identity/X25519Identity paths (%d total deps)", len(deps))
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

	// --- Part D: inject filippo.io/age/plugin (forbidden — admin read-path
	// recipient/identity construction surface; must never reach submit) ---
	//
	// Proves the guard FIRES on the plugin package by NAME, not merely that it
	// is absent today.
	injectedPlugin := []string{
		module + "/internal/core/usecase/submit",
		module + "/internal/core/crypto/encrypt",
		"filippo.io/age",
		"filippo.io/age/plugin", // FORBIDDEN — must cause a violation
	}
	pluginViolations := checkAllowlistSubmit(injectedPlugin)
	if len(pluginViolations) == 0 {
		t.Errorf("NEGATIVE TEST FAIL: checkAllowlistSubmit silently accepted filippo.io/age/plugin\n" +
			"The plugin protocol/os-exec surface must never reach the contributor submit\n" +
			"path. Fix: ensure checkAllowlistSubmit rejects it.")
	} else {
		found := false
		for _, v := range pluginViolations {
			if strings.Contains(v, "filippo.io/age/plugin") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("NEGATIVE TEST FAIL: violations detected but filippo.io/age/plugin not among them: %v", pluginViolations)
		} else {
			t.Logf("PASS (part D): checkAllowlistSubmit correctly detected forbidden import filippo.io/age/plugin\nviolations: %v", pluginViolations)
		}
	}

	// --- Part E: inject the plugin-backend ADAPTERS (byreis pkgs NOT on the
	// Submit allowlist). They import filippo.io/age/plugin and are adapters,
	// never core; if they leaked into the submit transitive set they must trip
	// the "byreis pkg not on Submit allowlist" branch. ---
	for _, adapter := range []string{
		module + "/internal/adapter/recipientbuild",
		module + "/internal/adapter/pluginidentity",
	} {
		injectedAdapter := []string{
			module + "/internal/core/usecase/submit",
			adapter, // byreis pkg NOT on Submit allowlist — must cause a violation
		}
		av := checkAllowlistSubmit(injectedAdapter)
		if len(av) == 0 {
			t.Errorf("NEGATIVE TEST FAIL: checkAllowlistSubmit silently accepted adapter %s\n"+
				"The plugin-backend adapters must never appear in the contributor submit\n"+
				"transitive set. Fix: ensure non-allowlisted byreis pkgs are rejected.", adapter)
			continue
		}
		found := false
		for _, v := range av {
			if strings.Contains(v, adapter) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("NEGATIVE TEST FAIL: violations detected but %s not among them: %v", adapter, av)
		} else {
			t.Logf("PASS (part E): checkAllowlistSubmit correctly rejected non-allowlisted adapter %s\nviolations: %v", adapter, av)
		}
	}
}

// TestAllowlist_EnvParse_StdlibOnly pins, defense-in-depth, that the .env
// bulk-submit parser's OWN transitive set is stdlib-only: it imports no
// third-party package and no other byreis-module package, so admitting it to
// the Submit allowlist cannot transitively reintroduce identity/decrypt/counter
// material. This is the mechanical proof behind the allowlist amendment.
func TestAllowlist_EnvParse_StdlibOnly(t *testing.T) {
	pkg := module + "/internal/core/usecase/submit/envparse"
	deps := goListDepsSubmit(t, pkg)
	for _, dep := range deps {
		if dep == pkg {
			continue // the package itself
		}
		if strings.HasPrefix(dep, module+"/") {
			t.Errorf("FAIL: envparse transitively imports byreis package %s — it must be stdlib-only", dep)
			continue
		}
		if !isStdlibOrInternal(dep) {
			t.Errorf("FAIL: envparse transitively imports non-stdlib package %s — it must be stdlib-only", dep)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: envparse transitive set is stdlib-only (%d deps)", len(deps))
	}
}

// goListDepsSubmit runs `go list -deps <pkg>` pinned to GOOS=linux GOARCH=amd64
// and returns the transitive dep list. Pinning the evaluation platform makes
// the gate produce the same dep set on every dev host as in CI (ubuntu-latest,
// linux/amd64). The allowlist is the platform-union satisfying all supported
// platforms, so a linux/amd64 evaluation is the correct authoritative superset.
// If go list fails, the test fails loudly and never skips silently: a gate
// that cannot run must fail rather than pass as a no-op.
func goListDepsSubmit(t *testing.T, pkg string) []string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", pkg)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ALLOWLIST GATE FAIL: go list -deps %s failed: %v (output: %s)\n"+
			"A gate that cannot run is a failure, never a silent pass.\n"+
			"Run 'go mod tidy' and ensure all deps are available.", pkg, err, out)
		return nil
	}
	return strings.Fields(strings.TrimSpace(string(out)))
}
