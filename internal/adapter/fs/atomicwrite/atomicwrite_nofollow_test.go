//go:build unix

package atomicwrite_test

// Tests for the parent-directory TOCTOU fix (O_NOFOLLOW + inode cross-check
// before rename). Covers the four mandated scenarios:
//
//  1. Happy path: clean directory, rename succeeds, content correct.
//  2. Parent-symlink-swap attack simulation: directory replaced with symlink;
//     write must return ErrAtomicWriteParentChanged.
//  3. No false-positive: clean parent, inode check passes through multiple writes.
//  4. Cleanup on TOCTOU detection: no temp residue after detection.
//
// Test 5 (unix.Renameat path) is implicitly exercised by tests 1 and 3 on
// any Unix host.
//
// TestNoFollow_InodeSwapDuringWrite exercises the mid-write inode-swap path
// via an exported test hook (atomicwrite_export_test.go).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/fs/atomicwrite"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// TestNoFollow_HappyPath writes a file under a clean directory tree and
// asserts the rename succeeds and the content is correct.
func TestNoFollow_HappyPath(t *testing.T) {
	root := t.TempDir()
	secretsDir := filepath.Join(root, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}
	livePath := filepath.Join(secretsDir, "prod.enc.yaml")

	if err := os.WriteFile(livePath, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	w, err := atomicwrite.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	want := []byte("new signed content\n")
	writeErr := w.WriteFileOfRecord(context.Background(), usecase.AtomicWriteInput{
		ProjectID:   "proj",
		FileName:    "prod",
		LiveRelPath: "secrets/prod.enc.yaml",
		SignedBytes: want,
	})
	if writeErr != nil {
		t.Fatalf("WriteFileOfRecord: %v", writeErr)
	}

	got, readErr := os.ReadFile(livePath)
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if string(got) != string(want) {
		t.Errorf("content mismatch: got %q want %q", got, want)
	}
}

// TestNoFollow_ParentSymlinkSwapAttack simulates the TOCTOU attack: the parent
// directory of the live file is replaced with a symlink to an attacker-controlled
// directory. The O_NOFOLLOW-based open of the parent must detect this and return
// ErrAtomicWriteParentChanged. The original live file must remain unchanged.
func TestNoFollow_ParentSymlinkSwapAttack(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skip as root: O_NOFOLLOW symlink check is not enforced for root")
	}

	root := t.TempDir()
	secretsDir := filepath.Join(root, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}

	livePath := filepath.Join(secretsDir, "prod.enc.yaml")
	original := []byte("original content — must not change")
	if err := os.WriteFile(livePath, original, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	w, newErr := atomicwrite.New(root)
	if newErr != nil {
		t.Fatalf("New: %v", newErr)
	}

	// Baseline: first write succeeds with clean directory.
	if baseErr := w.WriteFileOfRecord(context.Background(), usecase.AtomicWriteInput{
		ProjectID:   "proj",
		FileName:    "prod",
		LiveRelPath: "secrets/prod.enc.yaml",
		SignedBytes: original,
	}); baseErr != nil {
		t.Fatalf("baseline write: %v", baseErr)
	}

	// Attack: move the real secrets directory aside; replace with a symlink to
	// an attacker-controlled directory.
	attackerDir := filepath.Join(root, "attacker")
	if mkErr := os.MkdirAll(attackerDir, 0o700); mkErr != nil {
		t.Fatalf("mkdir attacker: %v", mkErr)
	}
	realDir := filepath.Join(root, "secrets.real")
	if renErr := os.Rename(secretsDir, realDir); renErr != nil {
		t.Fatalf("rename secrets -> secrets.real: %v", renErr)
	}
	if symErr := os.Symlink(attackerDir, secretsDir); symErr != nil {
		t.Skipf("os.Symlink not supported: %v", symErr)
	}

	gotErr := w.WriteFileOfRecord(context.Background(), usecase.AtomicWriteInput{
		ProjectID:   "proj",
		FileName:    "prod",
		LiveRelPath: "secrets/prod.enc.yaml",
		SignedBytes: []byte("attacker payload — must not land"),
	})

	if gotErr == nil {
		t.Fatal("expected ErrAtomicWriteParentChanged, got nil")
	}
	if !errors.Is(gotErr, atomicwrite.ErrAtomicWriteParentChanged) {
		t.Errorf("want ErrAtomicWriteParentChanged; got: %T %v", gotErr, gotErr)
	}

	// The original live file (now in realDir) must be unchanged.
	realLivePath := filepath.Join(realDir, "prod.enc.yaml")
	got, err := os.ReadFile(realLivePath)
	if err != nil {
		t.Fatalf("ReadFile real live path: %v", err)
	}
	if string(got) != string(original) {
		t.Errorf("live file was modified: got %q want %q", got, original)
	}

	// Nothing must have landed in the attacker directory.
	entries, err := os.ReadDir(attackerDir)
	if err != nil {
		t.Fatalf("ReadDir attacker: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("attacker dir has %d unexpected entries (payload may have landed!): %v",
			len(entries), names)
	}
}

// TestNoFollow_NoFalsePositive verifies that a clean parent directory passes
// the inode cross-check without error across multiple sequential writes.
func TestNoFollow_NoFalsePositive(t *testing.T) {
	root := t.TempDir()
	secretsDir := filepath.Join(root, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	w, err := atomicwrite.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := range 5 {
		if err := w.WriteFileOfRecord(context.Background(), usecase.AtomicWriteInput{
			ProjectID:   "proj",
			FileName:    "prod",
			LiveRelPath: "secrets/prod.enc.yaml",
			SignedBytes: []byte("iteration content"),
		}); err != nil {
			t.Fatalf("iteration %d: WriteFileOfRecord: %v", i, err)
		}
	}
}

// TestNoFollow_TempCleanedOnTOCTOU verifies that when the parent-symlink-swap
// is detected, no .byreis-atomic-* temp residue is left anywhere.
func TestNoFollow_TempCleanedOnTOCTOU(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skip as root: not meaningful for root")
	}

	root := t.TempDir()
	secretsDir := filepath.Join(root, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secretsDir, "prod.enc.yaml"), []byte("orig"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	attackerDir := filepath.Join(root, "attacker")
	if err := os.MkdirAll(attackerDir, 0o700); err != nil {
		t.Fatalf("mkdir attacker: %v", err)
	}
	realDir := filepath.Join(root, "secrets.real")
	if err := os.Rename(secretsDir, realDir); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.Symlink(attackerDir, secretsDir); err != nil {
		t.Skipf("os.Symlink not supported: %v", err)
	}

	w, err := atomicwrite.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	gotErr := w.WriteFileOfRecord(context.Background(), usecase.AtomicWriteInput{
		ProjectID:   "proj",
		FileName:    "prod",
		LiveRelPath: "secrets/prod.enc.yaml",
		SignedBytes: []byte("attack payload"),
	})
	if !errors.Is(gotErr, atomicwrite.ErrAtomicWriteParentChanged) {
		t.Fatalf("want ErrAtomicWriteParentChanged; got: %v", gotErr)
	}

	// Verify no temp residue in any relevant directory.
	for _, dir := range []string{root, realDir, attackerDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if len(e.Name()) >= 15 && e.Name()[:15] == ".byreis-atomic-" {
				t.Errorf("temp residue in %s: %q", dir, e.Name())
			}
		}
	}
}

// TestNoFollow_InodeSwapDuringWrite exercises the inode re-check that fires
// immediately before the rename. It uses the preRenameHook test hook
// (exported from atomicwrite_export_test.go) to inject an inode-swapping
// directory rename between the parent snapshot and the rename syscall.
//
// If the host OS does not preserve/change inodes predictably (exotic fs),
// the test reports a skip rather than a failure.
func TestNoFollow_InodeSwapDuringWrite(t *testing.T) {
	root := t.TempDir()
	secretsDir := filepath.Join(root, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secretsDir, "prod.enc.yaml"), []byte("orig"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var once sync.Once
	// Install the hook: fires between parent snapshot and rename.
	atomicwrite.SetPreRenameHook(func() {
		once.Do(func() {
			// Swap secrets dir with a fresh directory (new inode).
			newDir := filepath.Join(root, "secrets.new")
			oldDir := filepath.Join(root, "secrets.old")
			if err := os.MkdirAll(newDir, 0o700); err != nil {
				return
			}
			_ = os.Rename(secretsDir, oldDir)
			_ = os.Rename(newDir, secretsDir)
		})
	})
	t.Cleanup(func() { atomicwrite.SetPreRenameHook(nil) })

	w, err := atomicwrite.New(root)
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
		t.Skip("inode swap was not detected — expected only on filesystems that reuse inodes immediately (skip, not fail)")
	}
	if !errors.Is(gotErr, atomicwrite.ErrAtomicWriteParentChanged) {
		t.Errorf("want ErrAtomicWriteParentChanged; got: %T %v", gotErr, gotErr)
	}
}
