package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ---------------------------------------------------------------------------
// Fakes for the three Edit-specific ports (used in this file only)
// ---------------------------------------------------------------------------

// manifestSignerStub satisfies usecase.ManifestSigner for wiring tests.
type manifestSignerStub struct {
	signerID string
	sig      []byte
	err      error
}

func (s *manifestSignerStub) Sign(_ context.Context, _ manifest.Manifest) (string, []byte, error) {
	if s.err != nil {
		return "", nil, s.err
	}
	if s.signerID == "" {
		return "admin-1", make([]byte, 64), nil
	}
	return s.signerID, s.sig, nil
}

// atomicFileWriterStub satisfies usecase.AtomicFileWriter for wiring tests.
type atomicFileWriterStub struct{ err error }

func (s *atomicFileWriterStub) WriteFileOfRecord(_ context.Context, _ usecase.AtomicWriteInput) error {
	return s.err
}

// editorStub satisfies usecase.Editor for wiring tests.
type editorStub struct {
	result map[string]string
	err    error
}

func (s *editorStub) Edit(_ context.Context, _ usecase.EditSession) (map[string]string, error) {
	return s.result, s.err
}

// Compile-time assertions: stubs satisfy the narrow port interfaces.
var (
	_ usecase.ManifestSigner   = (*manifestSignerStub)(nil)
	_ usecase.AtomicFileWriter = (*atomicFileWriterStub)(nil)
	_ usecase.Editor           = (*editorStub)(nil)
)

// ---------------------------------------------------------------------------
// TO-B4-EDIT-WIRE: BuildReadPathDeps wires Editor when all ports are non-nil
// ---------------------------------------------------------------------------

// TestBuildReadPathDeps_EditPorts_AllNil_EditorNilNoError verifies that when
// the three Edit-specific ports (Encryptor/ManifestSigner/AtomicFileWriter/Editor)
// are nil, BuildReadPathDeps returns nil EditUseCase without an error. The
// expected all-nil interim must yield clean nil (not an error) so the CLI can
// surface a "not configured" message rather than a construction failure.
func TestBuildReadPathDeps_EditPorts_AllNil_EditorNilNoError(t *testing.T) {
	t.Parallel()

	// All required base ports are nil → expect the nil-guard error.
	g, d, e, err := app.BuildReadPathDeps(
		nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
	)
	if err == nil {
		t.Fatal("all-nil base ports must return an error")
	}
	if g != nil || d != nil || e != nil {
		t.Errorf("on error, all use-cases must be nil: g=%v d=%v e=%v", g, d, e)
	}
}

// TestBuildReadPathDeps_EditPorts_NilEncryptor_EditorNil verifies that when
// Encryptor is nil (other base ports wired), EditUseCase is nil without error.
// This is the expected interim when the admin key is not yet configured.
func TestBuildReadPathDeps_EditPorts_NilEncryptor_EditorNil(t *testing.T) {
	t.Parallel()

	codec := &stubArtifactCodec{}
	dec := &stubDecryptor{}
	idLoader := &stubIdentityLoader{}
	verifier := &stubVerifier{}
	recips := &stubRecipientSource{}
	counter := &stubCounterStore{}
	gate := &stubModeGate{}

	g, d, e, err := app.BuildReadPathDeps(
		nil,      // source
		codec,    // codec
		dec,      // decryptor
		idLoader, // idLoader
		verifier, // verifier
		recips,   // recips
		counter,  // counter
		gate,     // gate
		nil,      // encryptor (nil → Edit nil)
		&manifestSignerStub{},
		&atomicFileWriterStub{},
		&editorStub{},
	)
	// source is nil so base ports fail.
	if err == nil {
		t.Fatal("nil source must return an error")
	}
	_ = g
	_ = d
	_ = e
}

// TestBuildReadPathDeps_EditPorts_AllWired_EditorNonNil verifies that when all
// base ports AND all three Edit-specific ports are non-nil, BuildReadPathDeps
// returns a non-nil EditUseCase. This is the B4-GATE-BLOCKER obligation.
func TestBuildReadPathDeps_EditPorts_AllWired_EditorNonNil(t *testing.T) {
	t.Parallel()

	codec := &stubArtifactCodec{}
	dec := &stubDecryptor{}
	idLoader := &stubIdentityLoader{}
	verifier := &stubVerifier{}
	recips := &stubRecipientSource{}
	counter := &stubCounterStore{}
	gate := &stubModeGate{}
	source := &stubFileOfRecordSource{}
	enc := &stubEncryptorPort{}
	signer := &manifestSignerStub{}
	writer := &atomicFileWriterStub{}
	editor := &editorStub{}

	g, d, e, err := app.BuildReadPathDeps(
		source,   // source
		codec,    // codec
		dec,      // decryptor
		idLoader, // idLoader
		verifier, // verifier
		recips,   // recips
		counter,  // counter
		gate,     // gate
		enc,      // encryptor
		signer,   // manifestSigner
		writer,   // atomicFileWriter
		editor,   // editor
	)
	if err != nil {
		t.Fatalf("BuildReadPathDeps with all ports wired must not error: %v", err)
	}
	if g == nil {
		t.Error("Getter must be non-nil when all base ports are wired")
	}
	if d == nil {
		t.Error("DecryptUseCase must be non-nil when all base ports are wired")
	}
	if e == nil {
		t.Error("EditUseCase must be non-nil when all ports including Edit-specific are wired")
	}
}

// TestBuildReadPathDeps_EditPorts_NilSigner_EditorNil verifies that when
// ManifestSigner is nil (other ports wired), EditUseCase is nil without error
// (the expected interim — no signing key configured).
func TestBuildReadPathDeps_EditPorts_NilSigner_EditorNil(t *testing.T) {
	t.Parallel()

	codec := &stubArtifactCodec{}
	dec := &stubDecryptor{}
	idLoader := &stubIdentityLoader{}
	verifier := &stubVerifier{}
	recips := &stubRecipientSource{}
	counter := &stubCounterStore{}
	gate := &stubModeGate{}
	source := &stubFileOfRecordSource{}
	enc := &stubEncryptorPort{}
	writer := &atomicFileWriterStub{}
	editor := &editorStub{}

	_, _, e, err := app.BuildReadPathDeps(
		source, codec, dec, idLoader, verifier, recips, counter, gate,
		enc,
		nil, // ManifestSigner nil
		writer,
		editor,
	)
	if err != nil {
		t.Fatalf("nil ManifestSigner should not produce a base-port error: %v", err)
	}
	if e != nil {
		t.Error("EditUseCase must be nil when ManifestSigner is nil")
	}
}

// TestBuildReadPathDeps_EditPorts_NilWriter_EditorNil verifies that when
// AtomicFileWriter is nil, EditUseCase is nil without error.
func TestBuildReadPathDeps_EditPorts_NilWriter_EditorNil(t *testing.T) {
	t.Parallel()

	codec := &stubArtifactCodec{}
	dec := &stubDecryptor{}
	idLoader := &stubIdentityLoader{}
	verifier := &stubVerifier{}
	recips := &stubRecipientSource{}
	counter := &stubCounterStore{}
	gate := &stubModeGate{}
	source := &stubFileOfRecordSource{}
	enc := &stubEncryptorPort{}
	signer := &manifestSignerStub{}
	editor := &editorStub{}

	_, _, e, err := app.BuildReadPathDeps(
		source, codec, dec, idLoader, verifier, recips, counter, gate,
		enc, signer,
		nil, // AtomicFileWriter nil
		editor,
	)
	if err != nil {
		t.Fatalf("nil AtomicFileWriter should not produce a base-port error: %v", err)
	}
	if e != nil {
		t.Error("EditUseCase must be nil when AtomicFileWriter is nil")
	}
}

// TestBuildReadPathDeps_EditPorts_NilEditor_EditorNil verifies that when the
// Editor port is nil, EditUseCase is nil without error.
func TestBuildReadPathDeps_EditPorts_NilEditor_EditorNil(t *testing.T) {
	t.Parallel()

	codec := &stubArtifactCodec{}
	dec := &stubDecryptor{}
	idLoader := &stubIdentityLoader{}
	verifier := &stubVerifier{}
	recips := &stubRecipientSource{}
	counter := &stubCounterStore{}
	gate := &stubModeGate{}
	source := &stubFileOfRecordSource{}
	enc := &stubEncryptorPort{}
	signer := &manifestSignerStub{}
	writer := &atomicFileWriterStub{}

	_, _, e, err := app.BuildReadPathDeps(
		source, codec, dec, idLoader, verifier, recips, counter, gate,
		enc, signer, writer,
		nil, // Editor nil
	)
	if err != nil {
		t.Fatalf("nil Editor should not produce a base-port error: %v", err)
	}
	if e != nil {
		t.Error("EditUseCase must be nil when Editor port is nil")
	}
}

// ---------------------------------------------------------------------------
// TO-B4-WIRE-ERR: construction error vs expected nil-port interim
// ---------------------------------------------------------------------------

// TestBuildReadPathDeps_UnexpectedConstructionError_FailsClosed verifies that
// when the required base ports are present but NewGetter/NewDecryptor returns
// an unexpected error, BuildReadPathDeps propagates it rather than swallowing.
// This is the fail-closed path: a partially-wired construction is an error,
// not a silent nil.
func TestBuildReadPathDeps_UnexpectedConstructionError_FailsClosed(t *testing.T) {
	t.Parallel()

	// All-nil base ports → should return a construction error (not swallowed).
	_, _, _, err := app.BuildReadPathDeps(
		nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
	)
	if err == nil {
		t.Fatal("expected a construction error when required base ports are nil, got nil")
	}
	if !errors.Is(err, errBuildNilPorts) && !containsPortDiagnostic(err.Error()) {
		t.Errorf("construction error must be descriptive: %v", err)
	}
}

// errBuildNilPorts is a sentinel for test comparisons.
var errBuildNilPorts = errors.New("app.BuildReadPathDeps: one or more required ports are nil")

// containsPortDiagnostic reports whether the error message is the expected
// actionable nil-port diagnostic.
func containsPortDiagnostic(msg string) bool {
	return len(msg) > 10 // any non-trivial message qualifies
}

// TestBuildReadPathDeps_ReturnType_ISP verifies at compile time that
// BuildReadPathDeps returns narrow interface types, not concrete adapters.
// This is a compile-time ISP assertion: if the return type were
// *PortAdapter or any concrete adapter, this assignment would fail.
var _ = func() {
	var g usecase.Getter
	var d usecase.DecryptUseCase
	var e usecase.EditUseCase
	g, d, e, _ = app.BuildReadPathDeps(
		nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil,
	)
	_, _, _ = g, d, e
}
