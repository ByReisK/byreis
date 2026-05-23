package keyprobe_test

// Negative transitive-import test for the KeyExistenceProbe package.
//
// BO-V35-2: the transitive dependency set of this package must contain NO
// route to crypto/decrypt, crypto/identity, core/registry,
// core/registry/countertypes, or crypto/ed25519.
//
// The probe reads key NAMES only; it must have no compile-time route to
// private-key material or counter authority. This test is the mechanical proof.
//
// Evaluation is pinned to GOOS=linux GOARCH=amd64 so results are identical on
// every dev host and in CI.

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	probePkg = "github.com/ByReisK/byreis/internal/adapter/git/keyprobe"
	module   = "github.com/ByReisK/byreis"
)

// forbiddenInProbe lists packages that must not appear in the probe's
// transitive dependency set. Their presence would give the contributor
// submit path a route to private-key, decrypt, or counter-authority material.
var forbiddenInProbe = []string{
	"crypto/ed25519",
	module + "/internal/core/crypto/identity",
	module + "/internal/core/crypto/decrypt",
	module + "/internal/core/registry",
	module + "/internal/core/registry/countertypes",
	"golang.org/x/crypto/ed25519",
}

// TestKeyProbe_TransitiveDepsContainNoDecryptOrIdentity (BO-V35-2):
// asserts that the keyprobe package's transitive dependency set contains none
// of the forbidden packages.
func TestKeyProbe_TransitiveDepsContainNoDecryptOrIdentity(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(context.Background(), "go", "list", "-deps", probePkg)
	cmd.Env = testEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s failed: %v\nstderr: %s",
			probePkg, err, goListStderr(probePkg))
	}

	deps := strings.Split(strings.TrimSpace(string(out)), "\n")
	depSet := make(map[string]bool, len(deps))
	for _, d := range deps {
		depSet[strings.TrimSpace(d)] = true
	}

	for _, forbidden := range forbiddenInProbe {
		if depSet[forbidden] {
			t.Errorf(
				"SECURITY VIOLATION (BO-V35-2): keyprobe transitively imports FORBIDDEN package: %s\n"+
					"The KeyExistenceProbe must have NO compile-time route to "+
					"private-key, decrypt, or counter-authority material. "+
					"Remove the import chain; this failure blocks the V-3.5 gate.",
				forbidden)
		}
	}

	if !t.Failed() {
		t.Logf("PASS: keyprobe transitive set contains none of the %d forbidden packages (%d deps checked)",
			len(forbiddenInProbe), len(deps))
	}
}

// testEnv returns the process environment with GOOS and GOARCH overridden.
// Using os.Environ() preserves GOROOT, PATH, GOPATH, and all other settings
// that the running toolchain needs; the cross-compile-target overrides are
// appended last and take precedence (the last duplicate wins on most platforms).
func testEnv() []string {
	base := os.Environ()
	return append(base, "GOOS=linux", "GOARCH=amd64")
}

// goListStderr runs go list -deps and captures stderr for diagnostics.
func goListStderr(pkg string) string {
	cmd := exec.CommandContext(context.Background(), "go", "list", "-deps", pkg)
	cmd.Env = testEnv()
	out, _ := cmd.CombinedOutput()
	return string(out)
}
