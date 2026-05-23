package tui_test

// render_guard_test.go — structural guard: no render.New( call in non-test
// internal/tui source files.
//
// Why this guard exists:
//   The bubbletea program owns its output channel exclusively. Any call to
//   render.New() inside internal/tui/** would create a second Renderer bound
//   directly to bare os.Stdout, bypassing the bubbletea output model and
//   corrupting the terminal frame. The Renderer consumed by internal/tui code
//   must always be the one injected via tui.Deps.Renderer, which the
//   composition root (cmd/byreis/main.go) binds to the bubbletea output
//   channel.
//
// Mechanism:
//   The test walks every non-test .go file under internal/tui/ using go/ast,
//   looking for call expressions whose function name is "New" and whose
//   selector expression receiver resolves to the identifier "render". A match
//   is a gate failure.
//
// Scope:
//   Only non-test files (files NOT ending in _test.go) are scanned. Test
//   files may construct a render.Renderer via render.New for test harness
//   purposes without penalty.
//
// This test runs under the default build tag (no special tag required) so it
// is included in both `go test ./internal/tui/` and `make test`.

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

// TestRenderGuard_NoRenderNewInTUI fails if any non-test .go file in the
// internal/tui package tree contains a render.New( call expression.
func TestRenderGuard_NoRenderNewInTUI(t *testing.T) {
	t.Helper()

	// Locate internal/tui/ relative to this file.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("render guard: cannot locate caller via runtime.Caller")
	}
	tuiDir := filepath.Dir(thisFile)

	fset := token.NewFileSet()
	var violations []string

	entries, err := os.ReadDir(tuiDir)
	if err != nil {
		t.Fatalf("render guard: cannot read directory %s: %v", tuiDir, err)
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
			t.Fatalf("render guard: cannot parse %s: %v", fullPath, parseErr)
		}

		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name != "New" {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if recv.Name != "render" {
				return true
			}
			pos := fset.Position(call.Pos())
			violations = append(violations,
				pos.Filename+":"+itoa(pos.Line))
			return true
		})
	}

	if len(violations) > 0 {
		t.Errorf(
			"RENDER GUARD FAIL: render.New() called in %d non-test internal/tui source file(s).\n\n"+
				"The bubbletea program owns its output channel. A call to render.New() inside\n"+
				"internal/tui/** creates a second Renderer bound to bare os.Stdout, bypassing\n"+
				"the bubbletea output model and corrupting the terminal frame.\n\n"+
				"Use the injected tui.Deps.Renderer instead; it is bound to the bubbletea\n"+
				"output channel at the composition root (cmd/byreis/main.go).\n\n"+
				"Violations:\n%s",
			len(violations),
			strings.Join(violations, "\n"),
		)
		return
	}

	t.Logf("PASS: no render.New() calls found in %d non-test internal/tui source file(s)",
		len(entries))
}

// itoa converts an int to its decimal string representation without importing
// strconv (keeping this file dependency-free).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
