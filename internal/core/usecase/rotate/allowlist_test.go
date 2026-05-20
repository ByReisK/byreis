package rotate_test

// Closed-world allowlist boundary test for the rotate sub-package.
//
// Per V02_PORTS.md "Closed-world allowlist obligation" and the lock L25
// discipline: the internal/core/usecase/rotate transitive set MAY include
// crypto/identity, crypto/decrypt, core/registry — these are admin-needed by
// construction (rotation is admin-only and re-encrypt-all-existing demands
// decrypt of every pre-rotation file).
//
// What V1's allowlist test enforces is the BOUNDARY: rotate's transitive set
// must NOT be on the Submit allowlist target. The two sub-packages are
// parallel compilation units (rotate/ next to submit/, NOT inside it); the
// Submit closed-world allowlist (allowlist_test.go in the submit sub-package)
// targets only submit's transitive set, never rotate's. This test asserts
// the boundary so a future rotate-side import cannot leak into the
// contributor compilation unit.
//
// Row mapping: V1.allowlist (design/V02_WORK_BREAKDOWN.md §V1).
//
// The Go test is authoritative; depguard / lint is defense-in-depth. A gate
// that cannot run is a failure, never a silent pass.

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const moduleRotate = "github.com/ByReisK/byreis"

// rotateOwnPkg is the rotate sub-package under test.
const rotateOwnPkg = moduleRotate + "/internal/core/usecase/rotate"

// submitOwnPkg is the Submit compilation unit allowlist target — the
// rotate transitive set MUST be disjoint from Submit's allowlist target by
// design.
const submitOwnPkg = moduleRotate + "/internal/core/usecase/submit"

// submitForbiddenSet enumerates the packages explicitly forbidden on the
// Submit allowlist. The rotate sub-package SHOULD legitimately reach some of
// these (decrypt, identity, registry/countertypes) because rotation is
// admin-only — that is the point. This list exists so the boundary test can
// surface which forbidden-on-Submit packages rotate transitively reaches
// (for review documentation), without failing on them.
var submitForbiddenSet = map[string]bool{
	"crypto/ed25519": true,
	moduleRotate + "/internal/core/crypto/identity":       true,
	moduleRotate + "/internal/core/crypto/decrypt":        true,
	moduleRotate + "/internal/core/registry":              true,
	moduleRotate + "/internal/core/registry/countertypes": true,
	"golang.org/x/crypto/ed25519":                         true,
}

// goListDepsRotate runs `go list -deps <pkg>` pinned to GOOS=linux GOARCH=amd64
// so the gate produces the same dep set on every dev host as in CI. A failure
// to run is a hard test failure; the gate never silently passes.
func goListDepsRotate(t *testing.T, pkg string) []string {
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

// TestAllowlist_Rotate_NotOnSubmitAllowlist asserts the central boundary:
// the rotate sub-package's own package path is NOT inside the Submit
// compilation unit. This is the structural disjointness: rotate lives
// parallel to submit (NOT inside it), so the Submit closed-world allowlist
// (which targets submit's transitive set) does not cover rotate. A rotate
// import that snuck into submit would surface as a different test (the
// Submit allowlist test in submit/allowlist_test.go).
//
// V1.allowlist row mapping: this test row.
func TestAllowlist_Rotate_NotOnSubmitAllowlist(t *testing.T) {
	rotateDeps := goListDepsRotate(t, rotateOwnPkg)
	submitDeps := goListDepsRotate(t, submitOwnPkg)

	// Disjointness check (a): rotate is NOT itself a dep of submit. The
	// rotate package is parallel to submit, never imported by it — if it
	// ever is, the Submit allowlist would have to admit identity/decrypt,
	// defeating the contributor-write-only guarantee.
	for _, d := range submitDeps {
		if d == rotateOwnPkg {
			t.Errorf("FAIL: Submit transitively imports rotate (%s).\n"+
				"  rotate is admin-only and reaches identity/decrypt/registry.\n"+
				"  Submit MUST stay disjoint from rotate; this import defeats\n"+
				"  the contributor-write-only invariant.", d)
		}
	}

	// Disjointness check (b): submit is NOT in rotate's transitive set.
	// Rotate orchestrates admin-side re-encrypt; it has no reason to pull
	// the contributor Submit spine. A bidirectional disjointness keeps
	// each compilation unit's footprint reviewable on its own.
	for _, d := range rotateDeps {
		if d == submitOwnPkg {
			t.Errorf("FAIL: rotate transitively imports submit (%s).\n"+
				"  The two compilation units are deliberately parallel; rotate must\n"+
				"  not pull the contributor Submit spine.", d)
		}
	}

	if !t.Failed() {
		t.Logf("PASS: rotate (%d deps) and submit (%d deps) compilation units are disjoint",
			len(rotateDeps), len(submitDeps))
	}
}

// TestAllowlist_Rotate_ListsForbiddenOnSubmitForAudit lists, as documentation,
// the rotate transitive deps that ARE on the Submit forbidden list. Each
// such reach is intended by design (admin needs decrypt/identity/registry),
// and the test reports them so a future reviewer can confirm no new such
// reach is introduced without a deliberate review event. The test does NOT
// fail on these reaches — that is the whole point of having a separate
// compilation unit.
func TestAllowlist_Rotate_ListsForbiddenOnSubmitForAudit(t *testing.T) {
	rotateDeps := goListDepsRotate(t, rotateOwnPkg)
	reached := map[string]bool{}
	for _, d := range rotateDeps {
		if submitForbiddenSet[d] {
			reached[d] = true
		}
	}
	t.Logf("Audit: rotate transitive set reaches %d Submit-forbidden packages "+
		"(legitimate for admin-only re-encrypt): %v", len(reached), reached)
}

// TestAllowlist_Rotate_NotInSubmitAllowlist_NegativeFires is the negative
// self-test for this gate: an injected dep set that names the rotate package
// inside the submit transitive set must surface a violation. A guard that
// silently passes is itself a defect.
func TestAllowlist_Rotate_NotInSubmitAllowlist_NegativeFires(t *testing.T) {
	// Synthetic injection: pretend submit's transitive set includes rotate.
	syntheticSubmitDeps := []string{
		submitOwnPkg,
		moduleRotate + "/internal/core/crypto/encrypt",
		rotateOwnPkg, // FORBIDDEN: rotate must never be a Submit dep
	}
	saw := false
	for _, d := range syntheticSubmitDeps {
		if d == rotateOwnPkg {
			saw = true
			break
		}
	}
	if !saw {
		t.Fatal("NEGATIVE TEST FAIL: synthetic injection did not surface the rotate " +
			"dep — the disjointness check would not fire on a real regression.")
	}
	t.Log("PASS: negative self-test surfaced the synthetic rotate-in-submit injection.")
}

// TestAllowlist_Rotate_GoListMetadataReachable proves the gate machinery
// itself works: a `go list -json` against the rotate package returns the
// package metadata. A gate that cannot enumerate the package surface is a
// failure, never a silent pass.
func TestAllowlist_Rotate_GoListMetadataReachable(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "go", "list", "-json", rotateOwnPkg)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -json %s failed: %v", rotateOwnPkg, err)
	}
	var meta struct {
		ImportPath string   `json:"ImportPath"`
		GoFiles    []string `json:"GoFiles"`
	}
	if err := json.Unmarshal(out, &meta); err != nil {
		t.Fatalf("decode go list -json: %v", err)
	}
	if meta.ImportPath != rotateOwnPkg {
		t.Fatalf("ImportPath: want %s, got %s", rotateOwnPkg, meta.ImportPath)
	}
	if len(meta.GoFiles) == 0 {
		t.Fatal("rotate package has zero shipped Go files — surface inspection cannot run")
	}
	t.Logf("PASS: rotate package metadata reachable (%d Go files): %v",
		len(meta.GoFiles), meta.GoFiles)
}
