//go:build windows

package atomicwrite_test

// TestWriteFileOfRecord_WindowsUnsupported asserts that on Windows,
// WriteFileOfRecord returns an error that chains ErrAtomicWriteWindowsUnsupported.
// Windows is not a supported release target for byreis write operations; the
// adapter fails closed immediately rather than attempting a write with a residual
// TOCTOU window.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/fs/atomicwrite"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

func TestWriteFileOfRecord_WindowsUnsupported(t *testing.T) {
	dir := t.TempDir()
	secretsDir := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	livePath := filepath.Join(secretsDir, "prod.enc.yaml")
	if err := os.WriteFile(livePath, []byte("original"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	w, err := atomicwrite.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	gotErr := w.WriteFileOfRecord(context.Background(), usecase.AtomicWriteInput{
		ProjectID:   "proj",
		FileName:    "prod",
		LiveRelPath: "secrets/prod.enc.yaml",
		SignedBytes: []byte("new content"),
	})

	if gotErr == nil {
		t.Fatal("expected error on Windows write path, got nil")
	}
	if !errors.Is(gotErr, atomicwrite.ErrAtomicWriteWindowsUnsupported) {
		t.Errorf("want errors.Is(err, ErrAtomicWriteWindowsUnsupported); got: %T %v", gotErr, gotErr)
	}

	// The live file must remain unchanged (fail-closed: no side effects before
	// the sentinel return).
	got, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatalf("ReadFile after failed write: %v", err)
	}
	if string(got) != "original" {
		t.Errorf("live file was modified on Windows unsupported path: got %q", got)
	}
}
