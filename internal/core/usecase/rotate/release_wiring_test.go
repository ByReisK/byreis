//go:build docgate

// V4 (REQ-R-003-DOC R4-constant + BO-V4-T4 §V4 ship-gate addendum) —
// release-workflow wiring assertion under the docgate suite.
//
// Per BO-V4-T4 the docgate suite contains a structural test that reads
// .github/workflows/release.yml (parsed via go.yaml.in/yaml/v3 — already a
// module dep used by adapter/truststore and the V4 shipgate spine; NO new
// third-party import is introduced by this file) and asserts the release
// job's needs: array carries BOTH "shipgate" AND "docgate" as gating legs.
//
// Why this test exists: the release workflow's two-leg needs: array is the
// single non-bypassable wiring that turns the docgate suite into a release
// gate at all. If a future PR drops "docgate" from the needs: array, the
// docgate suite continues to run on CI but no longer blocks release — a
// silent downgrade of the gate. This test makes that downgrade a docgate
// red, surfaced inside the suite the wiring is meant to protect.
//
// Mutation-test note (per BO-V4-T4 brief): the assertion's failure mode IS
// the mutation test. Removing either "shipgate" or "docgate" from the
// release job's needs: list causes this test to fail with a precise message
// naming the missing leg. No sibling mutation-test file is required.
//
// Path-resolution discipline: this test must find .github/workflows/release.yml
// regardless of where `go test` is invoked. It walks upward from the test's
// CWD looking for the module root (the directory containing go.mod) and
// resolves the workflow path relative to that. A failure to locate either
// the module root or the workflow file is a hard test failure — a gate
// that cannot run must fail loudly, never silently pass.

package rotate_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// releaseWorkflowRelPath is the on-disk location of the release workflow,
// relative to the module root.
const releaseWorkflowRelPath = ".github/workflows/release.yml"

// releaseJobID is the workflow key under jobs: whose needs: array is the
// release-blocking gate.
const releaseJobID = "release"

// requiredReleaseNeeds is the set of jobs that MUST appear in the release
// job's needs: array. Sorted for deterministic error messages.
var requiredReleaseNeeds = []string{"docgate", "shipgate"}

// releaseWorkflowYAML mirrors only the parts of release.yml this test cares
// about: the jobs map, and within each job its needs: array (which YAML
// permits as either a single string or a sequence of strings — both shapes
// are handled by the parsing below).
type releaseWorkflowYAML struct {
	Jobs map[string]releaseJobYAML `yaml:"jobs"`
}

// releaseJobYAML captures the needs: field of one job. yaml.Node is used
// so we can accept BOTH the scalar shape (`needs: shipgate`) and the
// sequence shape (`needs: [shipgate, docgate]`) without two structs.
type releaseJobYAML struct {
	Needs yaml.Node `yaml:"needs"`
}

// TestReleaseWorkflow_DocgateGateWiringIntact is the BO-V4-T4 assertion:
// the release job exists, and its needs: array contains every entry in
// requiredReleaseNeeds. A missing entry is a release-blocker-class defect
// surfaced inside the docgate suite itself.
func TestReleaseWorkflow_DocgateGateWiringIntact(t *testing.T) {
	t.Parallel()

	workflowPath := resolveReleaseWorkflowPath(t)
	raw, err := os.ReadFile(workflowPath) //nolint:gosec // G304: workflow path is computed from module root, not user input
	if err != nil {
		t.Fatalf("WIRING GATE FAIL: cannot read %s: %v.\n"+
			"A gate that cannot run is a failure, never a silent pass.",
			workflowPath, err)
	}
	var doc releaseWorkflowYAML
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("WIRING GATE FAIL: cannot parse %s as YAML: %v.\n"+
			"raw content head: %q",
			workflowPath, err, headSample(raw))
	}

	releaseJob, ok := doc.Jobs[releaseJobID]
	if !ok {
		var names []string
		for k := range doc.Jobs {
			names = append(names, k)
		}
		sort.Strings(names)
		t.Fatalf("WIRING GATE FAIL: %s has no job named %q. Jobs found: %v.\n"+
			"The release pipeline must have a release job whose needs: array "+
			"gates the build on shipgate + docgate.",
			workflowPath, releaseJobID, names)
	}

	got, err := decodeNeedsField(releaseJob.Needs)
	if err != nil {
		t.Fatalf("WIRING GATE FAIL: cannot decode jobs.%s.needs in %s: %v",
			releaseJobID, workflowPath, err)
	}

	gotSet := map[string]bool{}
	for _, n := range got {
		gotSet[n] = true
	}
	var missing []string
	for _, req := range requiredReleaseNeeds {
		if !gotSet[req] {
			missing = append(missing, req)
		}
	}
	if len(missing) > 0 {
		sort.Strings(got)
		t.Fatalf("WIRING GATE FAIL: jobs.%s.needs in %s is missing required entries %v.\n"+
			"got needs: %v\n"+
			"required:  %v\n\n"+
			"Mutation-test note: this failure mode IS the BO-V4-T4 wiring "+
			"assertion. A PR that removes %q from the needs: array would "+
			"silently downgrade the release gate (the docgate suite would "+
			"still run on CI but no longer block release). This test "+
			"surfaces that downgrade.",
			releaseJobID, workflowPath, missing,
			got, requiredReleaseNeeds, missing)
	}
	t.Logf("OK: jobs.%s.needs contains all required gate legs: %v",
		releaseJobID, requiredReleaseNeeds)
}

// resolveReleaseWorkflowPath walks upward from the test's CWD looking for
// the module root (the directory containing go.mod) and returns the
// absolute path to the release workflow file. A failure at any step is a
// hard test failure — the gate cannot silently pass.
func resolveReleaseWorkflowPath(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("WIRING GATE FAIL: cannot get working directory: %v", err)
	}
	root, err := findModuleRoot(cwd)
	if err != nil {
		t.Fatalf("WIRING GATE FAIL: cannot find module root from %s: %v.\n"+
			"The release-wiring assertion needs the module root to locate "+
			"%s; if this test is being run from a detached worktree without "+
			"a go.mod ancestor, the gate cannot run.",
			cwd, err, releaseWorkflowRelPath)
	}
	abs := filepath.Join(root, releaseWorkflowRelPath)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		t.Fatalf("WIRING GATE FAIL: release workflow not found at %s: %v.\n"+
			"Either the workflow was deleted (release pipeline broken) or "+
			"the path constant is stale.", abs, statErr)
	}
	if info.IsDir() {
		t.Fatalf("WIRING GATE FAIL: expected %s to be a file, got a directory", abs)
	}
	return abs
}

// findModuleRoot walks up from start looking for a directory containing
// go.mod. It returns the directory path on success, ErrModuleRootNotFound
// on reaching the filesystem root without finding go.mod.
func findModuleRoot(start string) (string, error) {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errModuleRootNotFound
		}
		dir = parent
	}
}

var errModuleRootNotFound = errors.New("go.mod not found in any ancestor directory")

// decodeNeedsField accepts either a scalar (single dependency, treated as
// a one-element slice) or a sequence node. Both shapes are valid in
// GitHub Actions YAML; a missing/empty node is treated as zero deps.
func decodeNeedsField(n yaml.Node) ([]string, error) {
	if n.Kind == 0 {
		return nil, nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		var s string
		if err := n.Decode(&s); err != nil {
			return nil, fmt.Errorf("decode scalar needs: %w", err)
		}
		return []string{s}, nil
	case yaml.SequenceNode:
		var s []string
		if err := n.Decode(&s); err != nil {
			return nil, fmt.Errorf("decode sequence needs: %w", err)
		}
		return s, nil
	default:
		return nil, fmt.Errorf("unsupported needs: node kind %d (line %d, col %d)",
			n.Kind, n.Line, n.Column)
	}
}

func headSample(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}

// V5a (BO-V5-T10 RULING-V5-T3 shape-(a) confirmation) — closed-world structural
// check on the rotate CLI handler.
//
// The V5a slice ships internal/cli/rotate_cmd.go as a CLI verb whose
// --from-request flag is deferred: the handler refuses the flag with an
// actionable error before any port is invoked (RULING-V5-T3 shape (a),
// "CLI-handler refusal"). The alternative shape (b), "wired-but-port-nil-fail",
// would have required importing a placeholder V6 read-side port that does not
// yet exist (internal/adapter/git/github/pr_read.go is the V6 read helper).
//
// This test structurally confirms shape (a) by AST-inspecting rotate_cmd.go
// and asserting it does NOT import the V6 read helper. The V6 path does not
// exist in the tree at V5a, so any future PR that imports it via a placeholder
// would be a structural deviation from RULING-V5-T3 shape (a). This test
// surfaces that deviation as a docgate red before the change can ship.
//
// Discipline:
//   - stdlib go/parser only; no new third-party deps.
//   - Built under //go:build docgate (same constraint as the rest of this
//     file); never compiled into a shipped binary.
//   - Path-resolves rotate_cmd.go via the module root walker already in
//     this file, so the test runs deterministically from any cwd.
const rotateCmdRelPath = "internal/cli/rotate_cmd.go"

// forbiddenRotateCmdImports lists Go package import paths that
// internal/cli/rotate_cmd.go must NOT import at V5a. The V6 read helper
// (pr_read.go) is the canonical candidate: it does not exist in the V5a
// tree, and structurally confirming its absence in rotate_cmd.go's import
// set is how this test pins RULING-V5-T3 shape (a).
//
// The check is over import PATHS (the string in the import declaration),
// not files. Including the file basename "pr_read.go" in the rationale is
// for human readers; the assertion's mechanism is the path-string match.
var forbiddenRotateCmdImports = []string{
	"github.com/ByReisK/byreis/internal/adapter/git/github/pr_read",
}

// TestRotateCmd_ShapeAConfirmation_NoV6ReadHelperImport asserts that
// internal/cli/rotate_cmd.go does not import the V6 read helper. A
// regression on this assertion is a deliberate review event: the V6
// read helper does not exist in the V5a tree, and an import of it would
// be a structural change to the deferred --from-request handling shape
// that the V5a slice locked in.
func TestRotateCmd_ShapeAConfirmation_NoV6ReadHelperImport(t *testing.T) {
	t.Parallel()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("WIRING GATE FAIL: cannot get working directory: %v", err)
	}
	root, err := findModuleRoot(cwd)
	if err != nil {
		t.Fatalf("WIRING GATE FAIL: cannot find module root from %s: %v.\n"+
			"This test requires a go.mod ancestor to locate %s.",
			cwd, err, rotateCmdRelPath)
	}
	abs := filepath.Join(root, rotateCmdRelPath)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		t.Fatalf("WIRING GATE FAIL: %s not found at %s: %v.\n"+
			"Either the file was removed (V5a CLI scaffold is broken) or "+
			"the path constant is stale.", rotateCmdRelPath, abs, statErr)
	}
	if info.IsDir() {
		t.Fatalf("WIRING GATE FAIL: expected %s to be a file, got a directory", abs)
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, abs, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("WIRING GATE FAIL: cannot parse %s: %v.\n"+
			"The structural-check gate fails closed when the source cannot be parsed.",
			abs, err)
	}

	imports := make([]string, 0, len(f.Imports))
	for _, spec := range f.Imports {
		if spec == nil || spec.Path == nil {
			continue
		}
		raw := spec.Path.Value
		path, unquoteErr := strconv.Unquote(raw)
		if unquoteErr != nil {
			t.Fatalf("WIRING GATE FAIL: malformed import literal %q in %s: %v",
				raw, abs, unquoteErr)
		}
		imports = append(imports, path)
	}
	sort.Strings(imports)

	for _, forbidden := range forbiddenRotateCmdImports {
		if containsImport(imports, forbidden) {
			t.Fatalf("WIRING GATE FAIL: %s imports %q.\n"+
				"V5a locked --from-request as a CLI-handler refusal (no V6 read-side "+
				"port wired). An import of the V6 read helper is a structural deviation "+
				"from that shape — it must land alongside the V6 slice that ships the "+
				"actual read-side port, not as a placeholder in V5a.\n\n"+
				"observed imports:\n  %s",
				rotateCmdRelPath, forbidden, strings.Join(imports, "\n  "))
		}
	}

	// Defense-in-depth: also confirm that no observed import in rotate_cmd.go
	// references a path containing the basename "pr_read". This catches a
	// future move/rename of the V6 read helper that would otherwise slip past
	// the exact-path match above. The basename is a stable signal: any file
	// purposed as the rotate-from-request reader will carry it.
	for _, imp := range imports {
		if strings.Contains(imp, "pr_read") {
			t.Fatalf("WIRING GATE FAIL: %s imports a path containing \"pr_read\" (%q).\n"+
				"V5a does not wire a V6 read-side port for --from-request; an import "+
				"matching this basename is a structural deviation from RULING-V5-T3 shape (a).\n\n"+
				"observed imports:\n  %s",
				rotateCmdRelPath, imp, strings.Join(imports, "\n  "))
		}
	}

	t.Logf("OK: %s does not import any V6 read helper; --from-request is "+
		"deferred via CLI-handler refusal (RULING-V5-T3 shape (a)). "+
		"imports observed: %d", rotateCmdRelPath, len(imports))
}

// containsImport returns true iff target is in imports. Linear scan is fine —
// rotate_cmd.go has a small fixed number of imports.
func containsImport(imports []string, target string) bool {
	for _, imp := range imports {
		if imp == target {
			return true
		}
	}
	return false
}

// ast import is referenced indirectly via parser.ParseFile; this blank usage
// keeps the import explicit so a future refactor that drops the *ast.File
// return value notices the import is no longer needed.
var _ = (*ast.File)(nil)
