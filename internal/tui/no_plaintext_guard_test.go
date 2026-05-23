package tui_test

// no_plaintext_guard_test.go — structural guard: no reference to a
// decrypted-value field of ReviewResult (or any other decrypted-value field)
// in non-test internal/tui source files.
//
// Why this guard exists:
//   The review detail is the no-plaintext security keystone. ReviewResult carries
//   a Plaintext field (map[string]string) that holds decrypted secret values.
//   The TUI must NEVER reference this field: the detail model (reviewDetail) has
//   NO Plaintext field, and the Review call site zeroizes the map immediately
//   after extracting the display-safe fields. If any TUI source file references
//   .Plaintext, a decrypted value could escape into the model or a view.
//
// Mechanism:
//   Walk every non-test .go file under internal/tui/ with go/ast, scanning for
//   *ast.SelectorExpr nodes whose Sel.Name is in a denylist of decrypted-value
//   field names. A match is a gate failure. The denylist is {"Plaintext"} today;
//   it is the extension point if a future decrypted-value field is added to
//   ReviewResult.
//
// Self-test (mandatory):
//   A sibling test (TestNoPlaIntextGuard_NegativeSelfTest_WalkerDetectsSelectors)
//   runs the same checker with an artificial denylist entry that DOES appear in
//   TUI source (e.g. "PerKey") and asserts the check fires. This proves the AST
//   walker actually detects selector expressions and would not silently pass a
//   broken scanner.
//
// Scope:
//   Only non-test files (NOT ending in _test.go) are scanned. Test files may
//   reference ReviewResult or its fields for test-harness purposes.
//
// This test runs under the DEFAULT build tag (no special tag) so it is included
// in both `go test ./internal/tui/` and `make test` and cannot be skipped.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// checkNoPlaIntextSelectors walks non-test .go files under tuiDir and reports
// any *ast.SelectorExpr whose Sel.Name is in the supplied denylist. It returns a
// slice of "file:line: selector" strings for every violation found.
//
// The denylist parameter makes the function reusable for both the production
// check (denylist = {"Plaintext"}) and the negative self-test (denylist = some
// name that definitely appears in TUI source).
func checkNoPlaIntextSelectors(t *testing.T, tuiDir string, denylist map[string]bool) []string {
	t.Helper()

	fset := token.NewFileSet()
	var violations []string

	entries, err := os.ReadDir(tuiDir)
	if err != nil {
		t.Fatalf("no-plaintext guard: cannot read directory %s: %v", tuiDir, err)
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Only scan non-test Go source files.
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		fullPath := filepath.Join(tuiDir, name)
		af, parseErr := parser.ParseFile(fset, fullPath, nil, 0)
		if parseErr != nil {
			t.Fatalf("no-plaintext guard: cannot parse %s: %v", fullPath, parseErr)
		}

		ast.Inspect(af, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if !denylist[sel.Sel.Name] {
				return true
			}
			pos := fset.Position(sel.Pos())
			violations = append(violations,
				pos.Filename+":"+itoa(pos.Line)+": ."+sel.Sel.Name)
			return true
		})
	}

	return violations
}

// TestNoPlaIntextGuard_NoDecryptedValueFieldInTUI fails if any non-test .go
// file in the internal/tui package tree contains a selector expression whose
// name is in the decrypted-value field denylist. Today the denylist is
// {"Plaintext"}.
//
// Failure means a decrypted value could escape into the TUI model or a view,
// defeating the no-plaintext security keystone.
func TestNoPlaIntextGuard_NoDecryptedValueFieldInTUI(t *testing.T) {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no-plaintext guard: cannot locate caller via runtime.Caller")
	}
	tuiDir := filepath.Dir(thisFile)

	// The production denylist: field names that must NEVER appear as selectors
	// in TUI source. "Plaintext" is the decrypted-value field on ReviewResult.
	// Add future decrypted-value fields here if ReviewResult gains new ones.
	denylist := map[string]bool{
		"Plaintext": true,
	}

	violations := checkNoPlaIntextSelectors(t, tuiDir, denylist)

	if len(violations) > 0 {
		t.Errorf(
			"NO-PLAINTEXT GUARD FAIL: %d decrypted-value field reference(s) found in "+
				"non-test internal/tui source file(s).\n\n"+
				"The TUI must never reference a decrypted-value field of ReviewResult "+
				"(e.g. .Plaintext). The detail model (reviewDetail) must bind key-names "+
				"only; the Review call site must zeroize ReviewResult.Plaintext immediately "+
				"after extracting display-safe fields. A selector reference here means a "+
				"decrypted value could escape into the model or a view, defeating the "+
				"asymmetric-access guarantee.\n\n"+
				"Violations:\n%s",
			len(violations),
			strings.Join(violations, "\n"),
		)
		return
	}

	t.Logf("PASS: no decrypted-value field selectors found in non-test internal/tui source files")
}

// TestNoPlaIntextGuard_NegativeSelfTest_WalkerDetectsSelectors proves that the
// AST walker actually detects selector expressions by running checkNoPlaIntextSelectors
// with an artificial denylist entry ("PerKey") that is known to appear in TUI
// source (review.go references PerKey in the viewDetail renderer). If the walker
// returned zero violations for such a denylist, the walker would be broken and
// would silently miss real violations.
func TestNoPlaIntextGuard_NegativeSelfTest_WalkerDetectsSelectors(t *testing.T) {
	t.Parallel()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no-plaintext guard (negative): cannot locate caller via runtime.Caller")
	}
	tuiDir := filepath.Dir(thisFile)

	// Artificial denylist: "PerKey" is used as a selector in review.go
	// (e.g. d.PerKey in viewDetail). The walker must fire on it.
	artificialDenylist := map[string]bool{
		"PerKey": true,
	}

	violations := checkNoPlaIntextSelectors(t, tuiDir, artificialDenylist)

	if len(violations) == 0 {
		t.Errorf(
			"NO-PLAINTEXT GUARD NEGATIVE SELF-TEST FAIL: the AST walker returned zero " +
				"violations for the artificial denylist {\"PerKey\"}, but \"PerKey\" is " +
				"used as a selector in internal/tui/review.go. The walker is broken and " +
				"would NOT catch a real decrypted-value field reference. Fix the walker " +
				"before relying on the production guard.")
		return
	}

	// Confirm at least one violation is from a file we own.
	foundReviewFile := false
	for _, v := range violations {
		if strings.Contains(v, "review.go") {
			foundReviewFile = true
			break
		}
	}
	if !foundReviewFile {
		t.Errorf(
			"NO-PLAINTEXT GUARD NEGATIVE SELF-TEST FAIL: violations were reported but none "+
				"from review.go; got: %v — the walker may be looking at the wrong directory",
			violations[:min(5, len(violations))])
		return
	}

	t.Logf("PASS: AST walker correctly detected %d selector(s) for the artificial denylist, "+
		"confirming the production guard is functional.", len(violations))
}
