package rotate

// Shipped-surface mechanical guard for the rotate sub-package.
//
// This file is the rotate-side extension of the BO-9 4-control set (mirroring
// the precedent at internal/core/registry/countertypes/shipped_surface_test.go):
//
//   1. Go-visibility witness gate — rotationTestHookWitness is unexported,
//      declared only under -tags testhook (see testhook.go).
//   2. Default-tag AST guard — THIS file. Runs under the default tag set and
//      asserts that under every shipped-candidate tag set, no exported
//      package-level func produces or modifies a Rotator without requiring an
//      unexported witness parameter.
//   3. CI build/release exclusion — covered by the existing release.yml
//      configuration; no new build tag is introduced (the rotation hook
//      reuses the testhook lane per ADR-0016 D10).
//   4. Proven-firing self-test — TestShippedSurface_Rotate_GuardFires below.
//
// The invariant enforced, fail-closed, under EVERY shipped-candidate tag set:
//
//	No package-level exported func produces a Rotator (or returns a Rotator
//	wrapper) using only parameter types an outer package (cli/tui/usecase)
//	can name. The only permitted exported Rotator-producer is NewRotator;
//	every Rotator-modifier (e.g., the testhook Crash* wrappers) MUST require
//	at least one parameter typed as a package-local unexported type — the
//	rotationTestHookWitness witness pattern. Such a function is uncallable
//	from any package that cannot name the witness, even if it is compiled in.
//
// If an exported, witness-free Rotator-modifier ever appears under any
// shipped-candidate tag set, this test FAILS. The negative self-test proves
// the guard fires rather than silently passing.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const rotateOwnPkgGuard = "github.com/ByReisK/byreis/internal/core/usecase/rotate"

// rotateShippedCandidateTagSets enumerates the build-tag sets a shipped or
// release build could compile this package under. The default (no-tag) set
// is the real shipped configuration. testhook is included precisely because
// the gap was that a tagged exported producer/modifier could go unseen.
var rotateShippedCandidateTagSets = []struct {
	name string
	tags string
}{
	{name: "default (real shipped build)", tags: ""},
	{name: "testhook (must stay test-only and witness-gated)", tags: "testhook"},
}

// TestShippedSurface_Rotate_NoUnwitnessedRotatorModifier is the mechanical
// gate. For each shipped-candidate tag set it lists this package's Go files
// via `go list -tags`, parses them, and asserts:
//
//   - The only permitted Rotator-producing exported package-level func name
//     under the default tag set is "NewRotator"; it produces a fresh Rotator
//     and is not a wrapper.
//   - Every other exported package-level func that takes a Rotator and
//     returns a Rotator (a Rotator-MODIFIER, e.g. the testhook Crash*
//     wrappers) MUST require at least one parameter typed as a package-local
//     unexported type (the witness).
//   - Under -tags testhook, the delta over the default tag set MUST consist
//     only of witness-gated Rotator-modifiers.
//
// A second producer of a fresh Rotator under any tag set, or an unwitnessed
// Rotator-modifier, is a violation.
func TestShippedSurface_Rotate_NoUnwitnessedRotatorModifier(t *testing.T) {
	t.Parallel()

	for _, ts := range rotateShippedCandidateTagSets {
		ts := ts
		t.Run(ts.name, func(t *testing.T) {
			t.Parallel()
			producers := exportedRotatorSurface(t, ts.tags)

			// Rule 1: every Rotator-MODIFIER must be witness-gated.
			for _, p := range producers {
				if !p.isModifier {
					continue
				}
				if !p.witnessGated {
					t.Errorf("FAIL: exported func %q under tags %q is a Rotator-modifier "+
						"(takes a Rotator and returns a Rotator) but is NOT witness-gated.\n"+
						"  Zero unwitnessed Rotator-modifiers are permitted under any "+
						"shipped-candidate tag set.\n"+
						"  Gate it behind an unexported witness type or remove it.",
						p.name, tagLabelRotate(ts.tags))
					continue
				}
				t.Logf("OK: exported Rotator-modifier %q under tags %q is witness-gated "+
					"(unexported param type %q).", p.name, tagLabelRotate(ts.tags), p.unexportedParam)
			}

			// Rule 2: under the default tag set, the only permitted Rotator
			// PRODUCER (returns Rotator, no Rotator parameter) is NewRotator.
			if ts.tags == "" {
				var producerNames []string
				for _, p := range producers {
					if p.isProducer {
						producerNames = append(producerNames, p.name)
					}
				}
				if len(producerNames) != 1 || producerNames[0] != "NewRotator" {
					t.Errorf("FAIL: under default tag set, the only permitted Rotator producer is "+
						"NewRotator; got %v", producerNames)
				} else {
					t.Logf("OK: under default tag set, NewRotator is the sole Rotator producer.")
				}
			}

			// Rule 3: under testhook, every delta producer/modifier must be
			// witness-gated.
			if ts.tags == "testhook" {
				defaultSurface := exportedRotatorSurface(t, "")
				defaultNames := map[string]bool{}
				for _, p := range defaultSurface {
					defaultNames[p.name] = true
				}
				deltaCount := 0
				for _, p := range producers {
					if defaultNames[p.name] {
						continue
					}
					deltaCount++
					if !p.witnessGated {
						t.Errorf("FAIL: testhook delta exported func %q is NOT witness-gated; "+
							"the testhook delta MUST be strictly test-scoped.", p.name)
					}
				}
				if deltaCount == 0 {
					t.Logf("note: testhook delta is empty (the rotation hook may have been " +
						"removed; if not, this guard is no longer observing the testhook surface)")
				}
			}
		})
	}
}

// TestShippedSurface_Rotate_GuardFires is the negative self-test. It proves
// the AST classifier fires on:
//
//	(a) a witness-FREE exported Rotator-modifier (the modifier-without-witness case),
//	(b) a SECOND Rotator producer (returns a fresh Rotator with no Rotator param)
//	    alongside NewRotator under the default tag set.
//
// A guard that silently accepts either of (a)/(b) is itself a defect.
func TestShippedSurface_Rotate_GuardFires(t *testing.T) {
	t.Parallel()

	// (a) witness-FREE exported Rotator-modifier — must be classified as
	// a violation.
	t.Run("(a)_witness_free_modifier", func(t *testing.T) {
		t.Parallel()
		const src = `package rotate

func UnsafeWrapRotator(r Rotator) Rotator {
	return r
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "regression_a.go", src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source: %v", err)
		}
		got := classifyRotatorSurface(file)
		p, ok := got["UnsafeWrapRotator"]
		if !ok {
			t.Fatal("NEGATIVE TEST FAIL: classifier did not detect the witness-free " +
				"Rotator-modifier — the guard would not fire on a real regression.")
		}
		if !p.isModifier {
			t.Fatal("NEGATIVE TEST FAIL: classifier did not flag UnsafeWrapRotator as a modifier.")
		}
		if p.witnessGated {
			t.Fatal("NEGATIVE TEST FAIL: classifier marked a witness-FREE modifier as " +
				"witness-gated — a regression would pass silently.")
		}
		t.Log("(a) guard fires: witness-free Rotator-modifier detected.")
	})

	// (b) a SECOND Rotator producer alongside NewRotator under default
	// tag set — must be classified as a producer.
	t.Run("(b)_second_producer", func(t *testing.T) {
		t.Parallel()
		const src = `package rotate

func NewSneakyRotator() Rotator {
	return nil
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "regression_b.go", src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source: %v", err)
		}
		got := classifyRotatorSurface(file)
		p, ok := got["NewSneakyRotator"]
		if !ok {
			t.Fatal("NEGATIVE TEST FAIL: classifier did not detect the second producer.")
		}
		if !p.isProducer {
			t.Fatal("NEGATIVE TEST FAIL: classifier did not flag NewSneakyRotator as a producer.")
		}
		t.Log("(b) guard fires: second Rotator producer detected as a producer.")
	})

	// Control: NewRotator alone classifies as a producer, not a modifier.
	t.Run("control_new_rotator_alone", func(t *testing.T) {
		t.Parallel()
		const src = `package rotate

func NewRotator(d RotatorDeps) (Rotator, error) {
	return nil, nil
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "control.go", src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source: %v", err)
		}
		got := classifyRotatorSurface(file)
		p, ok := got["NewRotator"]
		if !ok || !p.isProducer || p.isModifier {
			t.Fatalf("control: classifier failed to recognise NewRotator as a producer "+
				"(ok=%v producer=%v modifier=%v)", ok, p.isProducer, p.isModifier)
		}
		t.Log("control: NewRotator alone classifies as a producer.")
	})

	// Control: a witness-gated Rotator-modifier classifies safely.
	t.Run("control_witness_gated_modifier", func(t *testing.T) {
		t.Parallel()
		const src = `package rotate

func GatedWrap(w *rotationTestHookWitness, r Rotator) Rotator {
	return r
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "control_b.go", src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source: %v", err)
		}
		got := classifyRotatorSurface(file)
		p, ok := got["GatedWrap"]
		if !ok || !p.isModifier || !p.witnessGated {
			t.Fatalf("control: GatedWrap must classify as a witness-gated modifier "+
				"(ok=%v modifier=%v gated=%v)", ok, p.isModifier, p.witnessGated)
		}
		t.Log("control: witness-gated Rotator-modifier classifies safely.")
	})
}

// rotateSurfaceEntry describes one exported package-level func that touches
// the Rotator type.
type rotateSurfaceEntry struct {
	name            string
	isProducer      bool // returns Rotator AND has no Rotator parameter
	isModifier      bool // returns Rotator AND has at least one Rotator parameter
	witnessGated    bool // at least one parameter type is an unexported package-local identifier
	unexportedParam string
}

func tagLabelRotate(tags string) string {
	if tags == "" {
		return "default"
	}
	return tags
}

// exportedRotatorSurface lists this package's Go files for the given tag set
// via `go list -tags`, parses them, and returns every exported package-level
// func whose result type includes Rotator. A failure to enumerate is fatal:
// a gate that cannot run must fail loudly, never pass as a no-op.
func exportedRotatorSurface(t *testing.T, tags string) []rotateSurfaceEntry {
	t.Helper()
	args := []string{"list", "-json"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, rotateOwnPkgGuard)
	cmd := exec.CommandContext(t.Context(), "go", args...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("SHIPPED-SURFACE GATE FAIL: `go list %s` failed: %v\n"+
			"A gate that cannot run is a failure, never a silent pass.",
			strings.Join(args, " "), err)
	}
	var meta struct {
		Dir     string   `json:"Dir"`
		GoFiles []string `json:"GoFiles"`
	}
	if err := json.Unmarshal(out, &meta); err != nil {
		t.Fatalf("SHIPPED-SURFACE GATE FAIL: cannot decode `go list -json` output: %v", err)
	}
	if len(meta.GoFiles) == 0 {
		t.Fatalf("SHIPPED-SURFACE GATE FAIL: go list reported no Go files for %s (tags %q)",
			rotateOwnPkgGuard, tagLabelRotate(tags))
	}
	merged := map[string]rotateSurfaceEntry{}
	fset := token.NewFileSet()
	for _, gf := range meta.GoFiles {
		path := filepath.Join(meta.Dir, gf)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("SHIPPED-SURFACE GATE FAIL: cannot parse %s: %v", path, err)
		}
		for name, p := range classifyRotatorSurface(file) {
			merged[name] = p
		}
	}
	out2 := make([]rotateSurfaceEntry, 0, len(merged))
	for _, p := range merged {
		out2 = append(out2, p)
	}
	return out2
}

// classifyRotatorSurface walks a parsed file and returns every exported
// package-level func whose result type includes Rotator. It classifies as
// producer (no Rotator param) vs modifier (at least one Rotator param). It
// marks witnessGated when at least one parameter type is a package-local
// unexported identifier.
func classifyRotatorSurface(file *ast.File) map[string]rotateSurfaceEntry {
	out := map[string]rotateSurfaceEntry{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Recv != nil { // method, skip
			continue
		}
		if !fn.Name.IsExported() {
			continue
		}
		if fn.Type.Results == nil {
			continue
		}
		if !resultsIncludeRotator(fn.Type.Results) {
			continue
		}
		hasRotatorParam := paramsIncludeRotator(fn.Type.Params)
		gated, witness := paramsRequireUnexportedTypeRotate(fn.Type.Params)
		out[fn.Name.Name] = rotateSurfaceEntry{
			name:            fn.Name.Name,
			isProducer:      !hasRotatorParam,
			isModifier:      hasRotatorParam,
			witnessGated:    gated,
			unexportedParam: witness,
		}
	}
	return out
}

func resultsIncludeRotator(results *ast.FieldList) bool {
	for _, f := range results.List {
		if typeExprMentionsRotator(f.Type) {
			return true
		}
	}
	return false
}

func paramsIncludeRotator(params *ast.FieldList) bool {
	if params == nil {
		return false
	}
	for _, f := range params.List {
		if typeExprMentionsRotator(f.Type) {
			return true
		}
	}
	return false
}

func typeExprMentionsRotator(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "Rotator"
	case *ast.StarExpr:
		return typeExprMentionsRotator(t.X)
	case *ast.ArrayType:
		return typeExprMentionsRotator(t.Elt)
	case *ast.FuncType:
		if t.Results != nil {
			for _, r := range t.Results.List {
				if typeExprMentionsRotator(r.Type) {
					return true
				}
			}
		}
	}
	return false
}

func paramsRequireUnexportedTypeRotate(params *ast.FieldList) (bool, string) {
	if params == nil {
		return false, ""
	}
	for _, f := range params.List {
		if name, ok := unexportedLocalTypeNameRotate(f.Type); ok {
			return true, name
		}
	}
	return false, ""
}

func unexportedLocalTypeNameRotate(e ast.Expr) (string, bool) {
	switch t := e.(type) {
	case *ast.Ident:
		if t.Name != "" && !ast.IsExported(t.Name) && isTypeLikeIdentRotate(t.Name) {
			return t.Name, true
		}
	case *ast.StarExpr:
		return unexportedLocalTypeNameRotate(t.X)
	case *ast.ArrayType:
		return unexportedLocalTypeNameRotate(t.Elt)
	}
	return "", false
}

func isTypeLikeIdentRotate(name string) bool {
	switch name {
	case "bool", "byte", "rune", "string", "error", "any",
		"int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
		"float32", "float64", "complex64", "complex128":
		return false
	}
	return true
}
