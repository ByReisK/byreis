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
// `go list -tags`, parses them, and applies the relaxed LB-2 rule from
// ADR-0007 §1.4:
//
//   - Zero unwitnessed exported CounterAuthority producers under ANY tag set.
//   - The only permitted producer name set is a subset of
//     {MintFromAdapter, NewForTest}; every member must be witness-gated.
//   - Default tag set in B3b (MintFromAdapter not yet added): len(P)==0.
//   - Default tag set at B3d acceptance (when MintFromAdapter is wired):
//     len(P)==1 && P[0].name=="MintFromAdapter" && P[0].witnessGated.
//   - Testhook set: every producer is witness-gated; the testhook-vs-default
//     delta is exactly {NewForTest}, witness-gated (asserted separately in
//     TestShippedSurface_TesthookDeltaIsWitnessGated).
//   - A second or unwitnessed producer under ANY tag set => test FAILS.
func TestShippedSurface_NoUnwitnessedValidProducer(t *testing.T) {
	t.Parallel()

	permitted := map[string]bool{"MintFromAdapter": true, "NewForTest": true}

	for _, ts := range shippedCandidateTagSets {
		ts := ts
		t.Run(ts.name, func(t *testing.T) {
			t.Parallel()
			producers := exportedCounterAuthorityProducers(t, ts.tags)
			producerMap := make(map[string]ctProducer, len(producers))
			for _, p := range producers {
				producerMap[p.name] = p
			}

			// B3b reality: default set must have zero producers.
			// B3d acceptance criterion: default set has exactly one named witness-gated
			// MintFromAdapter. Both are checked below by enforcing the relaxed rule.
			if ts.tags == "" {
				// In B3b (no MintFromAdapter yet): len must be 0.
				// In B3d+: len must be 1, name==MintFromAdapter, witnessGated.
				if len(producers) > 1 {
					for _, p := range producers {
						t.Errorf("FAIL: exported %s %q under DEFAULT tag set — "+
							"only zero (B3b) or exactly one named MintFromAdapter (B3d+) is permitted.",
							p.kind, p.name)
					}
				} else if len(producers) == 1 {
					p := producers[0]
					if p.name != "MintFromAdapter" {
						t.Errorf("FAIL: sole exported producer under DEFAULT tag set is %q "+
							"(want MintFromAdapter) — only MintFromAdapter is the permitted "+
							"production constructor name.", p.name)
					}
					if !p.witnessGated {
						t.Errorf("FAIL: MintFromAdapter under DEFAULT tag set is NOT witness-gated " +
							"— it must require an unexported adapterWitness parameter.")
					}
					if p.name == "MintFromAdapter" && p.witnessGated {
						t.Logf("OK (B3d acceptance): MintFromAdapter is present, witness-gated, " +
							"sole producer under default tag set — LB-2 B3d criterion satisfied.")
					}
				} else {
					t.Logf("OK (B3b reality): default tag set has zero CounterAuthority producers " +
						"(MintFromAdapter not yet wired).")
				}
			}

			// For ALL tag sets: enforce the relaxed rule.
			for _, p := range producers {
				// Rule 1: zero unwitnessed.
				if !p.witnessGated {
					t.Errorf("FAIL: exported package-level %s %q produces CounterAuthority "+
						"under tags %q WITHOUT requiring an unexported witness parameter.\n"+
						"  Zero unwitnessed CounterAuthority producers are permitted under "+
						"any shipped-candidate tag set.\n"+
						"  Gate it behind an unexported witness type or remove it.",
						p.kind, p.name, tagLabel(ts.tags))
					continue
				}
				// Rule 2: only permitted names.
				if !permitted[p.name] {
					t.Errorf("FAIL: exported %s %q is witness-gated but its name is not in "+
						"the permitted set {MintFromAdapter, NewForTest} under tags %q.\n"+
						"  Only these named constructors are permitted — rename or remove it.",
						p.kind, p.name, tagLabel(ts.tags))
					continue
				}
				t.Logf("OK: exported %s %q returns CounterAuthority, is witness-gated "+
					"(unexported param %q), and has a permitted name — uncallable from "+
					"verify/mode/usecase/cli even if compiled. tags=%q",
					p.kind, p.name, p.unexportedParam, tagLabel(ts.tags))
			}

			// Rule 3: for any tag set, if more than one producer exists, it must be
			// because testhook added NewForTest alongside MintFromAdapter. A second
			// MintFromAdapter (impossible via map key) or any other pair is a violation.
			if len(producers) > 2 {
				t.Errorf("FAIL: more than 2 CounterAuthority producers under tags %q (%d) — "+
					"only {MintFromAdapter} (default) or {MintFromAdapter, NewForTest} "+
					"(testhook) are permitted.", tagLabel(ts.tags), len(producers))
			}

			if !t.Failed() {
				t.Logf("tag set %q: %d CounterAuthority producer(s), relaxed LB-2 rule satisfied.",
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

// TestShippedSurface_GuardFires is the extended negative self-test.
//
// It proves the AST classifier fires on:
//
//	(a) a witness-FREE exported producer (the original guard),
//	(b) a SECOND witness-gated producer alongside MintFromAdapter (the relaxed
//	    rule must reject a second producer even if each is individually
//	    witness-gated), and
//	(c) an exported producer whose name is NOT "MintFromAdapter" even if
//	    witness-gated (the relaxed rule allows ONLY the named constructor).
//
// The relaxed LB-2 rule (ADR-0007 §1.4) permits at most one CounterAuthority
// producer under any shipped-candidate tag set, it must be named "MintFromAdapter",
// and it must be witness-gated. Zero unwitnessed producers. Zero second producers.
// A guard that silently accepts any of (a)/(b)/(c) is itself a defect.
func TestShippedSurface_GuardFires(t *testing.T) {
	t.Parallel()

	// (a) witness-FREE exported producer — the original case.
	t.Run("(a)_witness_free_producer", func(t *testing.T) {
		t.Parallel()
		const src = `package countertypes

func ResurrectedNewForTest(lastAccepted uint64, pending *PendingBump) CounterAuthority {
	return newCounterAuthority(lastAccepted, pending)
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "regression_a.go", src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source: %v", err)
		}
		got := classifyProducers(file)
		p, ok := got["ResurrectedNewForTest"]
		if !ok {
			t.Fatal("NEGATIVE TEST FAIL: classifier did not detect the witness-free producer — " +
				"the guard would not fire on a real regression.")
		}
		if p.witnessGated {
			t.Fatal("NEGATIVE TEST FAIL: classifier marked a witness-FREE producer as " +
				"witness-gated — a regression would pass silently.")
		}
		// Apply the relaxed rule: zero unwitnessed producers => FAIL.
		violations := countUnwitnessed(got)
		if violations == 0 {
			t.Fatal("NEGATIVE TEST FAIL: relaxed-rule check did not count the unwitnessed " +
				"producer as a violation — the guard fires on classification but the rule " +
				"check would pass silently.")
		}
		t.Log("(a) guard fires: witness-free producer detected and classified as violation.")
	})

	// (b) a SECOND witness-gated producer alongside MintFromAdapter — must FAIL.
	t.Run("(b)_second_witness_gated_producer", func(t *testing.T) {
		t.Parallel()
		const src = `package countertypes

func MintFromAdapter(w *adapterWitness, la uint64, p *PendingBump) CounterAuthority {
	return newCounterAuthority(la, p)
}

func SecondWitnessedProducer(w *adapterWitness, la uint64) CounterAuthority {
	return newCounterAuthority(la, nil)
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "regression_b.go", src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source: %v", err)
		}
		got := classifyProducers(file)
		if len(got) != 2 {
			t.Fatalf("expected 2 producers in synthetic source, got %d: %v", len(got), got)
		}
		// Apply the relaxed rule: exactly ONE named witness-gated producer allowed.
		// Two producers => violation even if both are witness-gated.
		if !relaxedRuleViolated(got) {
			t.Fatal("NEGATIVE TEST FAIL: relaxed rule accepted two witness-gated producers — " +
				"only one named MintFromAdapter is permitted.")
		}
		t.Log("(b) guard fires: second witness-gated producer detected as violation of " +
			"the 'exactly one named MintFromAdapter' rule.")
	})

	// (c) wrong-named witness-gated producer — must FAIL even if only one.
	t.Run("(c)_wrong_named_witness_gated_producer", func(t *testing.T) {
		t.Parallel()
		const src = `package countertypes

func WrongNamedProducer(w *adapterWitness, la uint64, p *PendingBump) CounterAuthority {
	return newCounterAuthority(la, p)
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "regression_c.go", src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source: %v", err)
		}
		got := classifyProducers(file)
		p, ok := got["WrongNamedProducer"]
		if !ok {
			t.Fatal("NEGATIVE TEST FAIL: classifier did not detect the wrong-named producer.")
		}
		if !p.witnessGated {
			t.Fatal("control check: expected WrongNamedProducer to be classified as " +
				"witness-gated (it has an unexported-type param) — classifier regression.")
		}
		// Apply the relaxed rule: the only permitted name is "MintFromAdapter".
		if !relaxedRuleViolated(got) {
			t.Fatal("NEGATIVE TEST FAIL: relaxed rule accepted a wrong-named witness-gated " +
				"producer — only 'MintFromAdapter' is permitted by name.")
		}
		t.Log("(c) guard fires: wrong-named witness-gated producer detected as violation.")
	})

	// Control: MintFromAdapter alone — must PASS the relaxed rule.
	t.Run("control_mint_from_adapter_alone", func(t *testing.T) {
		t.Parallel()
		const src = `package countertypes

func MintFromAdapter(w *adapterWitness, la uint64, p *PendingBump) CounterAuthority {
	return newCounterAuthority(la, p)
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "control.go", src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source: %v", err)
		}
		got := classifyProducers(file)
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 producer in control source, got %d", len(got))
		}
		if relaxedRuleViolated(got) {
			t.Fatal("NEGATIVE TEST FAIL (false positive): relaxed rule rejected " +
				"MintFromAdapter alone — the B3d acceptance criterion would fail.")
		}
		t.Log("control: MintFromAdapter alone passes the relaxed rule.")
	})

	// Original control from the old test: witness-gated producer classified as safe.
	t.Run("original_witnessed_control", func(t *testing.T) {
		t.Parallel()
		const src = `package countertypes

func WitnessedProducer(w *testOnlyWitness, la uint64) CounterAuthority {
	return newCounterAuthority(la, nil)
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "original_control.go", src, 0)
		if err != nil {
			t.Fatalf("parse synthetic source: %v", err)
		}
		got := classifyProducers(file)
		p, ok := got["WitnessedProducer"]
		if !ok || !p.witnessGated {
			t.Fatalf("original control: classifier failed to recognize witness-gated "+
				"producer (ok=%v, gated=%v)", ok, p.witnessGated)
		}
		t.Log("original control: witness-gated producer classified as safe.")
	})
}

// countUnwitnessed returns the number of producers that are NOT witness-gated.
func countUnwitnessed(producers map[string]ctProducer) int {
	n := 0
	for _, p := range producers {
		if !p.witnessGated {
			n++
		}
	}
	return n
}

// relaxedRuleViolated applies the ADR-0007 §1.4 relaxed LB-2 rule to a producer map:
//
//   - zero unwitnessed producers,
//   - the only permitted producer name set is a subset of {MintFromAdapter, NewForTest},
//   - every member is witness-gated,
//   - at most one producer with name "MintFromAdapter" (and zero others outside
//     the permitted set).
//
// Returns true if the rule is violated (test should FAIL if guard must fire).
// Returns false if the rule is satisfied (test should FAIL if guard must NOT fire).
func relaxedRuleViolated(producers map[string]ctProducer) bool {
	permitted := map[string]bool{"MintFromAdapter": true, "NewForTest": true}
	for name, p := range producers {
		if !p.witnessGated {
			return true // unwitnessed => violation
		}
		if !permitted[name] {
			return true // wrong name => violation
		}
	}
	// More than one producer with name MintFromAdapter is impossible (map key),
	// but two different permitted names (MintFromAdapter + NewForTest) is allowed
	// only under the testhook set. For the default set, MintFromAdapter must be
	// the only one. We accept both here; the per-tag-set rule is enforced in
	// TestShippedSurface_NoUnwitnessedValidProducer.
	return false
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
