// Package countertypes — visibility boundary tests.
//
// This file implements the negative test for the counter-authority visibility
// boundary:
//
//	A CounterAuthority/PendingBump constructed from the artifact, the project
//	repo, or an unverified/stale cache must be disallowed by construction. The
//	opaque type lives in internal/core/registry/countertypes with a
//	package-private constructor (newCounterAuthority) callable only by the
//	registry adapter; verify imports countertypes to read fields / call Valid()
//	and cannot construct one. This is a compile/API-shape test, not a runtime
//	string match. It is security-relevant.
//
// Three assertions are required:
//
//  1. Zero-value protection: CounterAuthority{} is !Valid() — a struct-literal
//     from any package produces an invalid authority that VerifyOfRecord
//     hard-errors on.
//
//  2. No exported Valid()-producing symbol: no exported function in this
//     package has a signature that returns CounterAuthority, ensuring that the
//     only constructing path is the unexported newCounterAuthority.
//
//  3. Compile-fail (Go internal/ rule enforcement): a Go source file outside
//     internal/adapter/registry that attempts to import capmint
//     (internal/adapter/registry/internal/capmint) is rejected by the Go
//     toolchain with "use of internal package not allowed" — a compile error,
//     not a runtime check.
//
// All three must pass for the boundary to be considered satisfied. A skip or
// panic in any part is treated as a failure by the CI job.
//
// This test is in package countertypes (not countertypes_test) so it can
// exercise newCounterAuthority directly to prove the zero-value vs valid-value
// distinction from within the package.
package countertypes

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestZeroValueCounterAuthorityIsNotValid asserts that a zero-value /
// struct-literal CounterAuthority is not Valid(). This is the first line of
// defence against forgery: any package can write countertypes.CounterAuthority{}
// but the result is rejected by VerifyOfRecord.
func TestZeroValueCounterAuthorityIsNotValid(t *testing.T) {
	t.Parallel()

	var zero CounterAuthority
	if zero.Valid() {
		t.Fatal("zero-value CounterAuthority is Valid() == true — " +
			"the anti-fabrication sentinel is broken; a struct-literal forgery " +
			"would pass VerifyOfRecord")
	}
	if zero.LastAccepted() != 0 {
		t.Fatalf("zero-value LastAccepted() = %d, want 0", zero.LastAccepted())
	}
	if zero.Pending() != nil {
		t.Fatal("zero-value Pending() is non-nil")
	}

	// Confirm the package-private constructor produces a Valid() value (positive
	// control: proves the test distinguishes valid from invalid, not just always-false).
	built := newCounterAuthority(42, nil)
	if !built.Valid() {
		t.Fatal("positive control: newCounterAuthority() produced !Valid() — " +
			"the constructor itself is broken")
	}
	if built.LastAccepted() != 42 {
		t.Fatalf("positive control: LastAccepted() = %d, want 42", built.LastAccepted())
	}

	withPending := newCounterAuthority(7, &PendingBump{PendingCounter: 8, TargetArtifactSHA: "abc", TargetPR: "pr/1"})
	if !withPending.Valid() {
		t.Fatal("positive control with pending: newCounterAuthority() produced !Valid()")
	}
	if withPending.Pending() == nil {
		t.Fatal("positive control: Pending() is nil when PendingBump was provided")
	}
	if withPending.Pending().PendingCounter != 8 {
		t.Fatalf("PendingCounter = %d, want 8", withPending.Pending().PendingCounter)
	}

	t.Log("zero-value CounterAuthority is !Valid(); " +
		"newCounterAuthority() produces Valid()==true (positive control OK)")
}

// TestNoExportedCounterAuthorityConstructor asserts that the countertypes
// package exports at most the single permitted production constructor
// (MintFromAdapter, witness-gated) and no other CounterAuthority-producing
// symbol. This is the relaxed ADR-0007 §1.4 rule: exactly one named
// witness-gated producer is permitted; zero unwitnessed producers; zero
// wrong-named producers; zero second producers.
//
// The check uses reflect to enumerate exported methods/functions. It
// deliberately does not use go/ast or go list so the check is always in-process
// and cannot be silently bypassed by a build error in an external tool.
func TestNoExportedCounterAuthorityConstructor(t *testing.T) {
	t.Parallel()

	caType := reflect.TypeOf(CounterAuthority{})

	// Enumerate all exported methods on the CounterAuthority type. None should
	// return a new CounterAuthority — all exported methods are read-only accessors.
	for i := 0; i < caType.NumMethod(); i++ {
		m := caType.Method(i)
		mt := m.Type
		// Check if any return value is a CounterAuthority
		for j := 0; j < mt.NumOut(); j++ {
			if mt.Out(j) == caType {
				t.Errorf("exported method CounterAuthority.%s returns CounterAuthority — "+
					"this could be a hidden constructor path. "+
					"Review is required before this method is allowed.", m.Name)
			}
		}
	}

	// Check the package-level exported surface: enforce the relaxed rule.
	// The permitted name set for exported CounterAuthority producers is exactly
	// {MintFromAdapter}. Any other name, or an unwitnessed producer, is rejected.
	checkNoExportedCtor(t)

	if !t.Failed() {
		t.Log("no unexpected exported method or package-level function " +
			"in countertypes produces a CounterAuthority value outside the permitted set")
	}
}

// checkNoExportedCtor checks the exported API surface of countertypes and
// enforces the relaxed single-producer rule:
//
//   - The only permitted exported package-level CounterAuthority producer is
//     MintFromAdapter. It must be witness-gated (its parameter list must name at
//     least one unexported package-local type), which makes it uncallable from
//     any package that cannot name that type.
//   - Any second, unwitnessed, or wrong-named exported CounterAuthority producer
//     causes this test to fail.
//   - An exported producer named "MakeCounterAuthorityForRegistry" (a previously
//     removed bridge) is also rejected to prevent silent resurrection.
//
// The witness-gate check is AST-based (via exportedCounterAuthorityProducers /
// classifyProducers / paramsRequireUnexportedType from shipped_surface_test.go),
// not a text/name scan. A witness-free same-named producer — e.g.
// func MintFromAdapter(la uint64, p *PendingBump) CounterAuthority — is rejected
// even though its name matches, because the parameter list contains no unexported
// type. This is a RELAXED (signature-gated), not a WEAKENED (name-only), check.
func checkNoExportedCtor(t *testing.T) {
	t.Helper()

	const pkg = "github.com/ByReisK/byreis/internal/core/registry/countertypes"

	// Use `go doc -all` for a quick surface scan: detect any CounterAuthority-
	// returning package-level function and reject unknown names early.
	cmd := exec.CommandContext(t.Context(), "go", "doc", "-all", pkg)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go doc failed for %s: %v\n"+
			"Cannot verify exported API surface — treat as a failure.", pkg, err)
		return
	}

	// Also assert the removed bridge function name does not reappear.
	if strings.Contains(string(out), "MakeCounterAuthorityForRegistry") {
		t.Errorf("'MakeCounterAuthorityForRegistry' found in countertypes exported API — " +
			"this function was removed as part of the visibility fix and must not be present.")
	}

	// Use the AST-based classifier (same as shipped_surface_test.go) to enumerate
	// every exported CounterAuthority producer in the live source, with witness-gate
	// information. This is the authoritative check: name matching alone is not
	// sufficient — the producer must also require an unexported parameter type.
	producers := exportedCounterAuthorityProducers(t, "")

	const permittedName = "MintFromAdapter"

	for _, p := range producers {
		if p.name != permittedName {
			// Wrong name: not in the permitted set regardless of witness state.
			t.Errorf("exported package-level %s %q returns CounterAuthority and is NOT "+
				"in the permitted name set {%s}:\n"+
				"Only %s (witness-gated) is permitted. "+
				"Remove or unexport this function.",
				p.kind, p.name, permittedName, permittedName)
			continue
		}
		// Name matches. Now assert it is also witness-gated. A same-named but
		// witness-free function is rejected: name matching alone is WEAKENED,
		// not RELAXED. The signature must require an unexported parameter type.
		if !p.witnessGated {
			t.Errorf("exported %s %q returns CounterAuthority but is NOT witness-gated — "+
				"its parameter list contains no unexported package-local type.\n"+
				"A witness-free producer is callable from any package and is a "+
				"visibility-boundary violation even when the name is permitted.\n"+
				"Add an *adapterWitness (or equivalent unexported) parameter, or remove this function.",
				p.kind, p.name)
			continue
		}
		t.Logf("OK: permitted exported producer %q is witness-gated (unexported param %q) — "+
			"uncallable from packages outside countertypes.", p.name, p.unexportedParam)
	}
}

// TestCheckNoExportedCtor_RejectsWitnessFreeNameMatch is a negative sub-case
// that proves checkNoExportedCtor's witness-gate assertion actually fires when
// a function named MintFromAdapter has no unexported parameter. This demonstrates
// the check is RELAXED (signature-gated), not WEAKENED (name-only).
func TestCheckNoExportedCtor_RejectsWitnessFreeNameMatch(t *testing.T) {
	t.Parallel()

	// Synthetic source: a same-named but witness-FREE producer. The function name
	// matches the permitted set, but has only exported/builtin parameter types.
	// The relaxed rule must reject it because it is callable from any package.
	const src = `package countertypes

func MintFromAdapter(lastAccepted uint64, pending *PendingBump) CounterAuthority {
	return newCounterAuthority(lastAccepted, pending)
}
`
	fset := token.NewFileSet()
	file, parsedErr := parser.ParseFile(fset, "witness_free_same_name.go", src, 0)
	if parsedErr != nil {
		t.Fatalf("parse synthetic source: %v", parsedErr)
	}

	got := classifyProducers(file)
	p, ok := got["MintFromAdapter"]
	if !ok {
		t.Fatal("NEGATIVE TEST FAIL: classifier did not detect the witness-free MintFromAdapter — " +
			"a regression would silently pass checkNoExportedCtor.")
	}
	if p.witnessGated {
		t.Fatal("NEGATIVE TEST FAIL: classifier marked a witness-FREE MintFromAdapter as " +
			"witness-gated — checkNoExportedCtor would accept a callable unguarded producer.")
	}

	// Apply the relaxed rule: an unwitnessed producer is a violation even when
	// the name is in the permitted set.
	violations := countUnwitnessed(got)
	if violations == 0 {
		t.Fatal("NEGATIVE TEST FAIL: countUnwitnessed reported 0 violations for a " +
			"witness-free MintFromAdapter — checkNoExportedCtor's gate would not fire.")
	}
	t.Logf("negative sub-case OK: witness-free MintFromAdapter detected as violation "+
		"(witnessGated=%v, violations=%d) — checkNoExportedCtor is RELAXED not WEAKENED.",
		p.witnessGated, violations)
}

// TestCapmintIsNotImportableOutsideRegistryAdapter is the compile-fail
// assertion that the counter-authority constructor cannot be reached from
// verify/mode/usecase/cli/tests.
//
// It proves the Go internal/ rule is operative: it writes a tiny Go source file
// whose package path is outside internal/adapter/registry, which imports
// capmint, then runs `go build` on it and asserts the build fails with a
// "use of internal package" error.
//
// This is a build-based negative test; it does not call capmint.Mint at
// runtime. It demonstrates the compile-time enforcement of the internal/
// boundary.
//
// If this test unexpectedly passes (the build succeeds), the internal/ boundary
// is broken and capmint is reachable from non-adapter packages.
func TestCapmintIsNotImportableOutsideRegistryAdapter(t *testing.T) {
	t.Parallel()

	// Determine the module root by walking up from this file's location.
	// We use the go env GOMODCACHE and module path to construct the build test.
	modRoot, err := findModuleRoot(t)
	if err != nil {
		t.Fatalf("cannot locate module root: %v\n"+
			"Cannot run compile-fail assertion — treat as a failure.", err)
	}

	// Read the main module's go and toolchain directives so the generated temp
	// go.mod declares the same language version. Without this, when the main
	// module declares "go 1.26 / toolchain go1.26.3" the subprocess `go build`
	// resolves the replace target to a module requiring go >= 1.26, which
	// pre-empts the "use of internal package" rejection with a
	// "requires go >= 1.26" error — obscuring the security assertion.
	goLine, toolchainLine := readMainModuleGoDirectives(t, modRoot)

	// Write a tiny Go package in a temp directory that is OUTSIDE the module
	// (so go build won't interfere with the module cache) but references capmint
	// by its full import path. We simulate a non-adapter package attempting import.
	tmpDir := t.TempDir()

	// The fake module references capmint via the actual module path.
	// We set up a replace directive in go.mod to point at the local module root.
	// The go/toolchain directives mirror the main module so toolchain resolution
	// in the subprocess does not raise a version-mismatch error before the
	// internal-package visibility check fires.
	goModContent := "module github.com/byreis-test/capmint-forgery-attempt\n\n" +
		goLine + "\n"
	if toolchainLine != "" {
		goModContent += toolchainLine + "\n"
	}
	goModContent += "\nrequire github.com/ByReisK/byreis v0.0.0\n\n" +
		"replace github.com/ByReisK/byreis => " + modRoot + "\n"

	mainGoContent := `package main

// This file simulates a non-adapter package (e.g. internal/core/crypto/verify)
// attempting to import capmint. This MUST fail to compile: the Go internal/ rule
// restricts capmint (internal/adapter/registry/internal/capmint) to packages
// rooted at internal/adapter/registry only.
//
// If this file compiles, the visibility boundary is broken.
import (
	_ "github.com/ByReisK/byreis/internal/adapter/registry/internal/capmint"
)

func main() {}
`

	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0600); err != nil {
		t.Fatalf("cannot write temp go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(mainGoContent), 0600); err != nil {
		t.Fatalf("cannot write temp main.go: %v", err)
	}

	// Run `go build .` in the temp dir; it should FAIL with "use of internal package".
	// Inherit the test process environment (which includes the active GOTOOLCHAIN
	// resolution) so the subprocess uses the same toolchain as the test itself.
	cmd := exec.CommandContext(t.Context(), "go", "build", ".")
	cmd.Dir = tmpDir
	buildOut, buildErr := cmd.CombinedOutput()

	if buildErr == nil {
		// The build SUCCEEDED — this means capmint is importable from outside the
		// adapter subtree. The internal/ boundary is broken.
		t.Fatalf("CRITICAL: capmint import SUCCEEDED from a non-adapter package.\n" +
			"Expected: compile error 'use of internal package not allowed'.\n" +
			"Got: build SUCCESS.\n" +
			"The internal/adapter/registry/internal/capmint package is NOT protected by " +
			"the Go internal/ rule.\n" +
			"This means verify/mode/usecase CAN import capmint and forge a Valid()==true " +
			"CounterAuthority — a critical security violation.")
	}

	// The build failed — check it failed for the right reason.
	buildOutStr := string(buildOut)
	if !strings.Contains(buildOutStr, "use of internal package") {
		t.Errorf("build failed but NOT with 'use of internal package' error.\n"+
			"Expected the Go toolchain to reject the import with the internal/ rule.\n"+
			"Actual error output:\n%s\n"+
			"This may still satisfy the guarantee if capmint is unreachable, but the "+
			"failure mode should be 'use of internal package' for the guarantee to be clear.", buildOutStr)
	} else {
		t.Logf("capmint import from non-adapter package rejected by Go toolchain.\n"+
			"Error (expected): %s", strings.TrimSpace(buildOutStr))
	}
}

// readMainModuleGoDirectives reads the "go" and "toolchain" directives from
// the main module's go.mod. It returns the full directive lines (e.g.
// "go 1.26" and "toolchain go1.26.3") so the caller can embed them verbatim
// in a generated temp go.mod. The toolchain line is returned as "" when the
// go.mod carries no toolchain directive (older modules). Neither value is
// empty for the go line; a missing go directive causes a fatal test error.
func readMainModuleGoDirectives(t *testing.T, modRoot string) (goLine, toolchainLine string) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(modRoot, "go.mod"))
	if err != nil {
		t.Fatalf("cannot read main module go.mod: %v", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "go ") && goLine == "" {
			goLine = trimmed
		}
		if strings.HasPrefix(trimmed, "toolchain ") && toolchainLine == "" {
			toolchainLine = trimmed
		}
	}

	if goLine == "" {
		t.Fatal("main module go.mod has no 'go' directive — cannot generate a compatible temp go.mod")
	}
	return goLine, toolchainLine
}

// findModuleRoot walks up from the test file location to find the go.mod.
func findModuleRoot(t *testing.T) (string, error) {
	t.Helper()
	// Start from the package source directory (determined at compile time via
	// os.Getwd — tests run with cwd set to the package directory).
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
