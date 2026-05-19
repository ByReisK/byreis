// Package countertypes — shipped-surface mechanical guard.
//
// This file closes the testhook control gap that visibility_boundary_test.go
// alone could not: that test runs `go doc -all` under the DEFAULT tag set, and
// `go doc` does not honour `-tags` at all, so a Valid()-producing exported
// symbol added under a build tag (e.g. testhook) was invisible to it. The
// design (ADR-0006 / DESIGN §7.2-D1) requires a mechanical, in-CI, fail-closed
// gate — not grep/review and not "no build step sets the tag today".
//
// This test runs under the DEFAULT tag set (it has no //go:build constraint, so
// it executes in the normal `test` and `shipgate` CI jobs). It drives
// `go list -tags <set>` itself, so it can mechanically inspect the package's
// exported surface under EVERY tag set a shipped/release build could plausibly
// compile, including testhook. It is AST-based, not a string match.
//
// The invariant it enforces, fail-closed, for every shipped-candidate tag set:
//
//	No package-level exported func or var produces a CounterAuthority using
//	only types an outer package (verify/mode/usecase/cli) can name. A Valid()
//	-producer is permitted ONLY if its signature requires at least one
//	UNEXPORTED parameter type declared in this package — the established
//	witness/capmint pattern — because such a function is uncallable from any
//	package that cannot name the witness even if it is compiled in.
//
// If an exported, witness-free Valid()-producer ever appears under any
// shipped-candidate tag set, this test FAILS. A negative self-test
// (TestShippedSurface_GuardFires) proves the guard actually fires rather than
// silently passing.
package countertypes

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

// shippedCandidateTagSets enumerates the build-tag sets a shipped or release
// `go build`/`go install` could compile this package under. The default
// (no-tag) set is the real shipped configuration. `testhook` is included NOT
// because it ships — CI proves it does not — but because the gap was precisely
// that a tagged exported producer went unseen: the guard MUST inspect the tag
// it claims is excluded so the blind spot cannot recur silently.
var shippedCandidateTagSets = []struct {
	name string
	tags string // value for `go list -tags`, "" == default set
}{
	{name: "default (real shipped build)", tags: ""},
	{name: "testhook (must stay test-only and witness-gated)", tags: "testhook"},
}

const ctPkg = "github.com/ByReisK/byreis/internal/core/registry/countertypes"

// TestShippedSurface_NoUnwitnessedValidProducer is the mechanical, fail-closed
// gate. For each shipped-candidate tag set it lists the package's Go files via
// `go list -tags`, parses them, and asserts every exported package-level func
// returning CounterAuthority requires at least one unexported parameter type
// (the witness). The default set must additionally have ZERO such producers.
func TestShippedSurface_NoUnwitnessedValidProducer(t *testing.T) {
	t.Parallel()

	for _, ts := range shippedCandidateTagSets {
		t.Run(ts.name, func(t *testing.T) {
			producers := exportedCounterAuthorityProducers(t, ts.tags)

			if ts.tags == "" && len(producers) != 0 {
				for _, p := range producers {
					t.Errorf("FAIL: exported package-level %s %q produces CounterAuthority "+
						"under the DEFAULT (shipped) tag set.\n"+
						"  No exported Valid()-producer is permitted in the shipped surface — "+
						"the sole producer is the unexported newCounterAuthority via capmint.\n"+
						"  Remove or unexport it.", p.kind, p.name)
				}
				return
			}

			for _, p := range producers {
				if p.witnessGated {
					t.Logf("OK: exported %s %q returns CounterAuthority but is witness-gated "+
						"(requires unexported param %q) under tags %q — uncallable from "+
						"verify/mode/usecase/cli even if compiled.",
						p.kind, p.name, p.unexportedParam, tagLabel(ts.tags))
					continue
				}
				t.Errorf("FAIL: exported package-level %s %q produces CounterAuthority "+
					"under tags %q WITHOUT requiring an unexported witness parameter.\n"+
					"  Such a symbol is a production-grade Valid()-producer reachable as "+
					"module API: verify/mode/usecase/cli could call it if a shipped build "+
					"set this tag.\n"+
					"  Gate it behind an unexported witness type declared in this package "+
					"(mirror countertypes.testOnlyWitness / capmint), or remove it.",
					p.kind, p.name, tagLabel(ts.tags))
			}

			if !t.Failed() {
				t.Logf("tag set %q: %d CounterAuthority producer(s), all witness-gated "+
					"or absent — shipped-build-testhook-free is mechanically enforced.",
					tagLabel(ts.tags), len(producers))
			}
		})
	}
}

// TestShippedSurface_TesthookDeltaIsWitnessGated explicitly characterizes the
// testhook delta: the symbols that appear ONLY under -tags testhook and produce
// a CounterAuthority must all be witness-gated. This is the positive assertion
// that the test-scoped capability exists AND is structurally test-scoped, so a
// regression that adds a plain exported producer under testhook is caught even
// though the default-tag surface is unchanged.
func TestShippedSurface_TesthookDeltaIsWitnessGated(t *testing.T) {
	t.Parallel()

	defaultProducers := producerNameSet(exportedCounterAuthorityProducers(t, ""))
	hookProducers := exportedCounterAuthorityProducers(t, "testhook")

	var delta []ctProducer
	for _, p := range hookProducers {
		if !defaultProducers[p.name] {
			delta = append(delta, p)
		}
	}

	if len(delta) == 0 {
		t.Fatal("expected at least one CounterAuthority-producing symbol to appear " +
			"only under -tags testhook (the test hook). Found none — either the hook " +
			"was removed (verify_test can no longer build) or this guard is no longer " +
			"observing the testhook surface. Treat as a failure.")
	}

	for _, p := range delta {
		if !p.witnessGated {
			t.Errorf("FAIL: testhook-only exported %s %q produces CounterAuthority but is "+
				"NOT witness-gated. The testhook delta MUST be strictly test-scoped: gate "+
				"it behind an unexported witness param (testOnlyWitness).", p.kind, p.name)
			continue
		}
		t.Logf("OK: testhook delta %s %q is witness-gated (unexported param %q).",
			p.kind, p.name, p.unexportedParam)
	}
}

// TestShippedSurface_GuardFires is the negative self-test: it proves the AST
// classifier flags a plain exported Valid()-producer (mirrors the allowlist
// negative tests). It synthesizes the AST of a witness-free exported producer
// and asserts the classifier reports it as NOT witness-gated, so a real
// regression cannot pass silently.
func TestShippedSurface_GuardFires(t *testing.T) {
	t.Parallel()

	const src = `package countertypes

// Simulated REGRESSION: a plain exported Valid()-producer with only
// builtin/exported parameter types. verify/mode/usecase/cli could call this.
func ResurrectedNewForTest(lastAccepted uint64, pending *PendingBump) CounterAuthority {
	return newCounterAuthority(lastAccepted, pending)
}

// Control: a witness-gated producer (must be classified as safe).
func WitnessedProducer(w *testOnlyWitness, la uint64) CounterAuthority {
	return newCounterAuthority(la, nil)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "regression.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic regression source: %v", err)
	}
	got := classifyProducers(file)

	bad, ok := got["ResurrectedNewForTest"]
	if !ok {
		t.Fatal("NEGATIVE TEST FAIL: classifier did not detect the plain exported " +
			"Valid()-producer at all — the guard would not fire on a real regression.")
	}
	if bad.witnessGated {
		t.Fatal("NEGATIVE TEST FAIL: classifier marked a witness-FREE exported " +
			"Valid()-producer as witness-gated. A real regression would pass silently. " +
			"(A guard that silently passes a forbidden surface is itself a defect.)")
	}

	good, ok := got["WitnessedProducer"]
	if !ok || !good.witnessGated {
		t.Fatalf("NEGATIVE TEST FAIL: classifier failed to recognize the witness-gated "+
			"control as safe (ok=%v, gated=%v) — false positives would make the guard "+
			"unmaintainable.", ok, good.witnessGated)
	}
	t.Log("guard fires: a witness-free exported Valid()-producer is detected and " +
		"classified unsafe; the witness-gated control is classified safe.")
}

// ctProducer describes an exported package-level symbol that yields a
// CounterAuthority.
type ctProducer struct {
	name            string
	kind            string // "func" or "var"
	witnessGated    bool   // true if a parameter type is unexported (test-scoped)
	unexportedParam string // the witness type name, for diagnostics
}

func tagLabel(tags string) string {
	if tags == "" {
		return "default"
	}
	return tags
}

func producerNameSet(ps []ctProducer) map[string]bool {
	m := make(map[string]bool, len(ps))
	for _, p := range ps {
		m[p.name] = true
	}
	return m
}

// exportedCounterAuthorityProducers lists the package's Go files for the given
// tag set via `go list -tags`, parses them, and returns every exported
// package-level symbol that produces a CounterAuthority. Failure to enumerate
// is fatal (a gate that cannot run must fail loudly, never pass as a no-op).
func exportedCounterAuthorityProducers(t *testing.T, tags string) []ctProducer {
	t.Helper()

	args := []string{"list", "-json"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, ctPkg)

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
			ctPkg, tagLabel(tags))
	}

	merged := map[string]ctProducer{}
	fset := token.NewFileSet()
	for _, gf := range meta.GoFiles {
		path := filepath.Join(meta.Dir, gf)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("SHIPPED-SURFACE GATE FAIL: cannot parse %s: %v", path, err)
		}
		for name, p := range classifyProducers(file) {
			merged[name] = p
		}
	}

	producers := make([]ctProducer, 0, len(merged))
	for _, p := range merged {
		producers = append(producers, p)
	}
	return producers
}

// classifyProducers walks a parsed file and returns the exported package-level
// funcs/vars whose result type includes CounterAuthority. A func is
// "witnessGated" when at least one parameter's type names an UNEXPORTED type
// (the witness): such a function cannot be called by any package that cannot
// name that type, so it is not a production-grade Valid()-producer even if
// compiled. Methods (funcs with a receiver) are deliberately skipped: the
// CounterAuthority accessors (Valid/LastAccepted/Pending) are read-only and
// never return a new CounterAuthority.
func classifyProducers(file *ast.File) map[string]ctProducer {
	out := map[string]ctProducer{}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv != nil { // method, not a package-level constructor
				continue
			}
			if !d.Name.IsExported() {
				continue
			}
			if d.Type.Results == nil || !resultsIncludeCounterAuthority(d.Type.Results) {
				continue
			}
			gated, witness := paramsRequireUnexportedType(d.Type.Params)
			out[d.Name.Name] = ctProducer{
				name:            d.Name.Name,
				kind:            "func",
				witnessGated:    gated,
				unexportedParam: witness,
			}
		case *ast.GenDecl:
			if d.Tok != token.VAR {
				continue
			}
			// A package-level var of type CounterAuthority (or func returning
			// one) is a non-constructor producer surface; flag it as unsafe so
			// nobody smuggles a producer in as a var/func value. Vars cannot be
			// "witness-gated".
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || vs.Type == nil {
					continue
				}
				for _, n := range vs.Names {
					if !n.IsExported() {
						continue
					}
					if typeExprMentionsCounterAuthority(vs.Type) {
						out[n.Name] = ctProducer{name: n.Name, kind: "var"}
					}
				}
			}
		}
	}
	return out
}

func resultsIncludeCounterAuthority(results *ast.FieldList) bool {
	for _, f := range results.List {
		if typeExprMentionsCounterAuthority(f.Type) {
			return true
		}
	}
	return false
}

// typeExprMentionsCounterAuthority reports whether a type expression names the
// package-local CounterAuthority type (bare identifier, since these files are
// in package countertypes), including pointer/array forms.
func typeExprMentionsCounterAuthority(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "CounterAuthority"
	case *ast.StarExpr:
		return typeExprMentionsCounterAuthority(t.X)
	case *ast.ArrayType:
		return typeExprMentionsCounterAuthority(t.Elt)
	case *ast.FuncType:
		if t.Results != nil {
			for _, r := range t.Results.List {
				if typeExprMentionsCounterAuthority(r.Type) {
					return true
				}
			}
		}
	}
	return false
}

// paramsRequireUnexportedType reports whether any parameter's type names an
// unexported package-local identifier (the witness). It returns the first such
// type name for diagnostics.
func paramsRequireUnexportedType(params *ast.FieldList) (bool, string) {
	if params == nil {
		return false, ""
	}
	for _, f := range params.List {
		if name, ok := unexportedLocalTypeName(f.Type); ok {
			return true, name
		}
	}
	return false, ""
}

// unexportedLocalTypeName extracts an unexported, package-local type identifier
// from a parameter type expression (handling pointer/array wrappers). A
// qualified type (pkg.T) is never package-local and cannot be the witness.
func unexportedLocalTypeName(e ast.Expr) (string, bool) {
	switch t := e.(type) {
	case *ast.Ident:
		if t.Name != "" && !ast.IsExported(t.Name) && isTypeLikeIdent(t.Name) {
			return t.Name, true
		}
	case *ast.StarExpr:
		return unexportedLocalTypeName(t.X)
	case *ast.ArrayType:
		return unexportedLocalTypeName(t.Elt)
	}
	return "", false
}

// isTypeLikeIdent filters out the predeclared builtin types so e.g. a `uint64`
// parameter is never mistaken for an unexported witness. Any other lowercase
// identifier in this package's signatures is a package-local unexported type.
func isTypeLikeIdent(name string) bool {
	switch name {
	case "bool", "byte", "rune", "string", "error", "any",
		"int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
		"float32", "float64", "complex64", "complex128":
		return false
	}
	return true
}
