package github_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestPRReadClosedWorldNoWriteMethods asserts that pr_read.go does not directly
// reference any GitHub SDK write method by name. Write methods are a structural
// concern: the request-access PR reader is intentionally read-only; any call to
// a write method (Create*, Update*, Delete*, Push*, Add*, Patch*) in pr_read.go
// would be a security violation (BO-V6-CRYPTO-10).
//
// This is an AST-level check over the source file. It does not replace the
// runtime contract tests; it is a shift-left structural assertion.
func TestPRReadClosedWorldNoWriteMethods(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "pr_read.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing pr_read.go: %v", err)
	}

	// Write-method name fragments that must not appear as selector expressions
	// called in pr_read.go.
	writePrefixes := []string{
		"CreateFile", "UpdateFile", "DeleteFile", "CreateRef", "UpdateRef",
		"CreateCommit", "CreatePR", "MergeSubmission", "CreateBranch",
		"CreateContent", "UpdateContent", "DeleteContent",
	}

	var violations []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		for _, prefix := range writePrefixes {
			if name == prefix {
				pos := fset.Position(sel.Pos())
				violations = append(violations, pos.String()+": "+name)
			}
		}
		return true
	})

	if len(violations) > 0 {
		t.Errorf("pr_read.go contains write-method references (BO-V6-CRYPTO-10 violation):\n")
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}
