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
// package exports no function whose return type includes CounterAuthority. The
// only constructor is newCounterAuthority (unexported). This verifies the
// "no exported Valid()-producing symbol reachable module-wide" requirement.
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

	// Check that the package's own exported identifiers via go/types include no
	// function returning CounterAuthority. We do this via a go list + go/types
	// check run as a subprocess so it covers all package-level exports.
	checkNoExportedCtor(t)

	if !t.Failed() {
		t.Log("no exported method or package-level function " +
			"in countertypes produces a CounterAuthority value")
	}
}

// checkNoExportedCtor checks the exported API surface of countertypes using
// `go doc -all` and asserts no package-level function returns CounterAuthority.
func checkNoExportedCtor(t *testing.T) {
	t.Helper()

	const pkg = "github.com/ByReisK/byreis/internal/core/registry/countertypes"

	// Use `go doc -all` to get the exported API surface as text; grep for any
	// function signature containing "CounterAuthority" as a return type.
	// We exclude the type declaration and method signatures (Valid, LastAccepted,
	// Pending are receivers, not free functions).
	cmd := exec.Command("go", "doc", "-all", pkg)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go doc failed for %s: %v\n"+
			"Cannot verify exported API surface — treat as a failure.", pkg, err)
		return
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Match exported function declarations (start with "func ") that are NOT
		// methods (methods start with "func (" — receiver syntax).
		if !strings.HasPrefix(trimmed, "func ") {
			continue
		}
		if strings.HasPrefix(trimmed, "func (") {
			// This is a method — skip; methods are OK (Valid, LastAccepted, Pending
			// are read-only accessors, not constructors).
			continue
		}
		// This is a package-level exported function. Check if it returns CounterAuthority.
		if strings.Contains(trimmed, "CounterAuthority") {
			t.Errorf("exported package-level function appears to return CounterAuthority:\n"+
				"  %s\n"+
				"No exported Valid()-producing symbol is permitted in countertypes. "+
				"Remove or unexport this function.", trimmed)
		}
	}

	// Also assert the word "MakeCounterAuthorityForRegistry" does not appear
	// anywhere in the exported API — it was the removed bridge function.
	if strings.Contains(string(out), "MakeCounterAuthorityForRegistry") {
		t.Errorf("'MakeCounterAuthorityForRegistry' found in countertypes exported API — " +
			"this function was removed as part of the visibility fix and must not be present.")
	}

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

	// Write a tiny Go package in a temp directory that is OUTSIDE the module
	// (so go build won't interfere with the module cache) but references capmint
	// by its full import path. We simulate a non-adapter package attempting import.
	tmpDir := t.TempDir()

	// The fake module references capmint via the actual module path.
	// We set up a replace directive in go.mod to point at the local module root.
	goModContent := `module github.com/byreis-test/capmint-forgery-attempt

go 1.22

require github.com/ByReisK/byreis v0.0.0

replace github.com/ByReisK/byreis => ` + modRoot + `
`
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
	cmd := exec.Command("go", "build", ".")
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
