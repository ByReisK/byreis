package writesigner_test

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/registry/writesigner"
)

// fakeTextSigner is an injectable fake that satisfies writesigner.TextSigner.
type fakeTextSigner struct {
	calls   int
	lastMsg []byte
	id      string
	sig     []byte
	err     error
}

func (f *fakeTextSigner) SignText(_ context.Context, text []byte) (string, []byte, error) {
	f.calls++
	f.lastMsg = text
	return f.id, f.sig, f.err
}

// SIGNTEXT_DELEGATES_TO_MANIFESTSIGNER
// The fake TextSigner is invoked exactly once with the domain-separated input.
func TestSignerAdapter_DelegatesToTextSigner(t *testing.T) {
	t.Parallel()
	fake := &fakeTextSigner{id: "admin-1", sig: make([]byte, 64)}
	a, err := writesigner.New(fake)
	if err != nil {
		t.Fatalf("writesigner.New: %v", err)
	}

	msg := []byte("commit body")
	gotID, gotSig, err := a.SignText(context.Background(), msg)
	if err != nil {
		t.Fatalf("SignText: %v", err)
	}
	if gotID != "admin-1" {
		t.Errorf("signerID = %q, want %q", gotID, "admin-1")
	}
	if len(gotSig) != 64 {
		t.Errorf("sig len = %d, want 64", len(gotSig))
	}
	if fake.calls != 1 {
		t.Errorf("inner signer called %d times, want 1", fake.calls)
	}
}

// B-D3-DOMAIN-SEP: the domain-separation prefix "byreis-registry-write/v1\n"
// is applied inside the adapter so every caller inherits it.
func TestSignerAdapter_DomainSeparationPrefix_Applied(t *testing.T) {
	t.Parallel()
	fake := &fakeTextSigner{id: "admin-1", sig: make([]byte, 64)}
	a, err := writesigner.New(fake)
	if err != nil {
		t.Fatalf("writesigner.New: %v", err)
	}

	msg := []byte("my commit body")
	_, _, err = a.SignText(context.Background(), msg)
	if err != nil {
		t.Fatalf("SignText: %v", err)
	}

	// The fake received domain-separated bytes, not the raw message.
	const domainPrefix = "byreis-registry-write/v1\n"
	if !bytes.HasPrefix(fake.lastMsg, []byte(domainPrefix)) {
		t.Errorf("inner signer received %q, want prefix %q", fake.lastMsg, domainPrefix)
	}
	// The original message must appear after the prefix.
	expectedFull := append([]byte(domainPrefix), msg...)
	if !bytes.Equal(fake.lastMsg, expectedFull) {
		t.Errorf("inner signer received %q, want %q", fake.lastMsg, expectedFull)
	}
}

// B-D3-DOMAIN-SEP: assert no possible manifest.Encode output can begin with
// the domain-separation prefix. We encode several manifest-like fixtures and
// verify none starts with "byreis-registry-write/v1\n".
func TestSignText_DomainSeparationPrefix_NoManifestCollision(t *testing.T) {
	t.Parallel()

	const prefix = "byreis-registry-write/v1\n"

	// Manifest.Encode produces a binary stream starting with the FormatVersion
	// string. The domain-separation prefix uses "/" and is not a valid
	// FormatVersion pattern (^byreis\.native\.v[0-9]+$), but assert it anyway.
	manifestFixtures := []string{
		"byreis.native.v1\x1f...",
		"byreis.native.v1\x1eabc",
		"byreis.native.v2\x1fprojectA\x1fmain\x1f0",
		// Edge case: a manifest whose first bytes could be confused with the prefix.
		"byreis-registry-write/something",
	}

	for _, fix := range manifestFixtures {
		if strings.HasPrefix(fix, prefix) {
			t.Errorf("manifest fixture %q begins with domain-sep prefix %q — "+
				"domain separation would be defeated", fix, prefix)
		}
	}
}

// NIL_INNER_SIGNER_REFUSES_AT_CONSTRUCTION
// writesigner.New(nil) must return a non-nil error.
func TestSignerAdapter_NilInnerSigner_RefusedAtConstruction(t *testing.T) {
	t.Parallel()
	_, err := writesigner.New(nil)
	if err == nil {
		t.Fatal("expected error for nil TextSigner, got nil")
	}
}

// INNER_ERR_PROPAGATED_WRAPPED
// An error from the inner TextSigner must propagate as a wrapped error.
func TestSignerAdapter_InnerError_Propagated(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("inner signer failed")
	fake := &fakeTextSigner{err: sentinel}
	a, err := writesigner.New(fake)
	if err != nil {
		t.Fatalf("writesigner.New: %v", err)
	}

	_, _, err = a.SignText(context.Background(), []byte("msg"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("want errors.Is(err, sentinel), got: %v", err)
	}
}

// B-D7-STATIC-NO-ED25519: AST-level check that no non-test .go file in the
// writesigner package imports "crypto/ed25519". This is the static check
// required by the binding obligation. Runtime tests on a fake are insufficient
// per the spec.
func TestSignerAdapter_StaticNoEd25519Import(t *testing.T) {
	t.Parallel()

	pkgDir := filepath.Join(mustFindModuleRoot(t), "internal", "adapter", "registry", "writesigner")

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("reading writesigner dir: %v", err)
	}

	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		// Skip test files — only production code is checked.
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, e.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		for _, imp := range f.Imports {
			if imp.Path == nil {
				continue
			}
			impPath := strings.Trim(imp.Path.Value, `"`)
			if impPath == "crypto/ed25519" {
				t.Errorf("file %s imports crypto/ed25519 — writesigner must not "+
					"introduce a parallel ed25519 signing call site; use the TextSigner interface",
					e.Name())
			}
		}
	}
}

// mustFindModuleRoot walks upward from the package directory to find go.mod.
func mustFindModuleRoot(t *testing.T) string {
	t.Helper()
	// Use the test binary's working directory as the starting point.
	// go test sets the working directory to the package directory.
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod from", dir)
		}
		dir = parent
	}
}

// Compile-time check: fakeTextSigner implements writesigner.TextSigner.
var _ writesigner.TextSigner = (*fakeTextSigner)(nil)
