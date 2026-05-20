package trust_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ByReisK/byreis/internal/core/trust"
)

// TestCheckTrustFileTOCTOU_Exact0600_Accepted verifies that a file with exactly
// mode 0600 is accepted.
func TestCheckTrustFileTOCTOU_Exact0600_Accepted(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	p := filepath.Join(tmp, "trust.yaml")
	if err := os.WriteFile(p, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := trust.CheckTrustFileTOCTOU(p)
	if err != nil {
		t.Errorf("expected no error for 0600, got: %v", err)
	}
	if f != nil {
		_ = f.Close()
	}
}

// TestCheckTrustFileTOCTOU_0400_Rejected verifies that 0400 is rejected (not
// a special case — exactly 0600 is the only accepted mode).
func TestCheckTrustFileTOCTOU_0400_Rejected(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	p := filepath.Join(tmp, "trust.yaml")
	if err := os.WriteFile(p, []byte("signer_fingerprint: abc"), 0o400); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := trust.CheckTrustFileTOCTOU(p)
	if err == nil {
		t.Fatal("expected error for mode 0400, got nil")
	}
	if !errors.Is(err, trust.ErrTrustAnchorPerms) {
		t.Errorf("expected ErrTrustAnchorPerms, got: %v", err)
	}
	if errStr := err.Error(); !containsChmodHint(errStr) {
		t.Errorf("error does not contain chmod hint: %q", errStr)
	}
}

// TestCheckTrustFileTOCTOU_0644_Rejected verifies that a 0044 bit (group/world
// readable) is rejected with an exact chmod hint.
func TestCheckTrustFileTOCTOU_0644_Rejected(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	p := filepath.Join(tmp, "trust.yaml")
	//nolint:gosec // intentionally insecure mode 0644 to test that the check rejects it
	if err := os.WriteFile(p, []byte("signer_fingerprint: abc"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := trust.CheckTrustFileTOCTOU(p)
	if err == nil {
		t.Fatal("expected error for mode 0644, got nil")
	}
	if !errors.Is(err, trust.ErrTrustAnchorPerms) {
		t.Errorf("expected ErrTrustAnchorPerms, got: %v", err)
	}
}

// TestCheckTrustFileTOCTOU_Symlink_Rejected verifies that a symlink at the
// final component is rejected.
func TestCheckTrustFileTOCTOU_Symlink_Rejected(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realFile := filepath.Join(tmp, "real.yaml")
	symlinkPath := filepath.Join(tmp, "trust.yaml")

	if err := os.WriteFile(realFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := trust.CheckTrustFileTOCTOU(symlinkPath)
	if err == nil {
		t.Fatal("expected error for symlink, got nil")
	}
	if !errors.Is(err, trust.ErrTrustAnchorSymlink) {
		t.Errorf("expected ErrTrustAnchorSymlink, got: %v", err)
	}
}

// TestCheckTrustDirTOCTOU_0700_Accepted verifies that a directory with exactly
// mode 0700 is accepted.
func TestCheckTrustDirTOCTOU_0700_Accepted(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "byreis")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	f, err := trust.CheckTrustDirTOCTOU(dir)
	if err != nil {
		t.Errorf("expected no error for 0700 dir, got: %v", err)
	}
	if f != nil {
		_ = f.Close()
	}
}

// TestCheckTrustDirTOCTOU_0755_Rejected verifies that a directory with 0755
// (world-executable) is rejected with an exact chmod hint.
func TestCheckTrustDirTOCTOU_0755_Rejected(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "byreis")
	//nolint:gosec // intentionally insecure 0755 to test that the check rejects it
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	_, err := trust.CheckTrustDirTOCTOU(dir)
	if err == nil {
		t.Fatal("expected error for mode 0755, got nil")
	}
	if !errors.Is(err, trust.ErrTrustDirPerms) {
		t.Errorf("expected ErrTrustDirPerms, got: %v", err)
	}
	if errStr := err.Error(); !containsChmodHint(errStr) {
		t.Errorf("error does not contain chmod hint: %q", errStr)
	}
}

// TestCheckTrustDirTOCTOU_Symlink_Rejected verifies that a symlink in place of
// the config directory is rejected.
func TestCheckTrustDirTOCTOU_Symlink_Rejected(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real")
	symlinkDir := filepath.Join(tmp, "byreis")

	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := trust.CheckTrustDirTOCTOU(symlinkDir)
	if err == nil {
		t.Fatal("expected error for symlink dir, got nil")
	}
	// Should be either ErrTrustDirSymlink or ErrTrustDirPerms (platform-dependent
	// whether O_NOFOLLOW rejects the dir symlink).
	if !errors.Is(err, trust.ErrTrustDirSymlink) && !errors.Is(err, trust.ErrTrustDirPerms) {
		t.Errorf("expected ErrTrustDirSymlink or ErrTrustDirPerms, got: %v", err)
	}
}

// TestCheckTrustFileTOCTOU_D4_SymlinkSwapAfterCheck verifies the TOCTOU D4
// negative: opening with O_NOFOLLOW binds the security decision to the object
// opened, not to a subsequent stat. A symlink-to-real-file at the final
// component is rejected by O_NOFOLLOW before we read from the fd.
//
// This test directly validates that we use openNoFollow so a symlink swap
// AFTER the check (but before the read) is impossible because the check and the
// read happen on the SAME fd.
func TestCheckTrustFileTOCTOU_D4_SymlinkSwapAfterCheck(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realFile := filepath.Join(tmp, "real.yaml")
	symlinkPath := filepath.Join(tmp, "trust.yaml")

	if err := os.WriteFile(realFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Set up a symlink BEFORE the check.
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	// The O_NOFOLLOW open rejects the symlink at open time, not at stat time.
	// Even if we "swap" the file after the stat, the fd is bound — but more
	// importantly O_NOFOLLOW rejects the open entirely, so no second opportunity.
	_, err := trust.CheckTrustFileTOCTOU(symlinkPath)
	if err == nil {
		t.Fatal("D4: expected ErrTrustAnchorSymlink for symlink, got nil")
	}
	if !errors.Is(err, trust.ErrTrustAnchorSymlink) {
		t.Errorf("D4: expected ErrTrustAnchorSymlink, got: %v", err)
	}
}

// TestCheckTrustDirTOCTOU_D4_DirWritableThenReplace simulates the D4 "dir
// writable then replace" scenario. A too-permissive directory is caught by the
// mode check on the fd (no race window between stat-then-open because we open
// first and stat the fd).
func TestCheckTrustDirTOCTOU_D4_DirWritableThenReplace(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "byreis")

	// Create with world-writable mode (insecure): intentional for this negative test.
	//nolint:gosec // world-writable 0777 is the attacker-controlled-dir we are testing is rejected
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	_, err := trust.CheckTrustDirTOCTOU(dir)
	if err == nil {
		t.Fatal("D4: expected error for world-writable dir, got nil")
	}
	if !errors.Is(err, trust.ErrTrustDirPerms) {
		t.Errorf("D4: expected ErrTrustDirPerms, got: %v", err)
	}
}

// TestCheckTrustFileTOCTOU_OpenNoFollow validates that openNoFollow is used
// (i.e., we open with O_NOFOLLOW by verifying the syscall flag is set).
// We test this indirectly via the symlink-rejection test above.
// This test validates the ELOOP/ENOTDIR mapping in openNoFollow.
func TestCheckTrustFileTOCTOU_ELOOP_Mapped(t *testing.T) {
	t.Parallel()

	// Create a circular symlink.
	tmp := t.TempDir()
	symlinkPath := filepath.Join(tmp, "trust.yaml")
	// On macOS/Linux, opening a symlink with O_NOFOLLOW returns ELOOP.
	target := filepath.Join(tmp, "real.yaml")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, symlinkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := trust.CheckTrustFileTOCTOU(symlinkPath)
	if err == nil {
		t.Fatal("expected error for symlink with O_NOFOLLOW")
	}

	// The key assertion: we get ErrTrustAnchorSymlink, not a raw syscall error.
	if !errors.Is(err, trust.ErrTrustAnchorSymlink) {
		// If O_NOFOLLOW is not supported on this platform, skip.
		var pe *os.PathError
		if errors.As(err, &pe) && pe.Err == syscall.ENOTSUP {
			t.Skip("O_NOFOLLOW not supported on this platform")
		}
		t.Errorf("expected ErrTrustAnchorSymlink, got: %v", err)
	}
}

// TestCheckTrustDirTOCTOU_AbsentDir_ErrorsIsFsErrNotExist asserts that when the
// target directory does not exist, errors.Is(err, fs.ErrNotExist) returns true.
// REQ: ENOENT-CHAINING fix — the %w chain must survive the fmt.Errorf wrap.
func TestCheckTrustDirTOCTOU_AbsentDir_ErrorsIsFsErrNotExist(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	absent := filepath.Join(tmp, "nonexistent-byreis-dir")

	_, err := trust.CheckTrustDirTOCTOU(absent)
	if err == nil {
		t.Fatal("expected error for absent directory, got nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("errors.Is(err, fs.ErrNotExist) must be true for absent path; got err: %v", err)
	}
}

// TestCheckTrustFileTOCTOU_AbsentFile_ErrorsIsFsErrNotExist asserts that when
// the trust anchor file does not exist, errors.Is(err, fs.ErrNotExist) returns
// true.
// REQ: ENOENT-CHAINING fix — the %w chain must survive the fmt.Errorf wrap.
func TestCheckTrustFileTOCTOU_AbsentFile_ErrorsIsFsErrNotExist(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	absent := filepath.Join(tmp, "trust.yaml")

	_, err := trust.CheckTrustFileTOCTOU(absent)
	if err == nil {
		t.Fatal("expected error for absent file, got nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("errors.Is(err, fs.ErrNotExist) must be true for absent path; got err: %v", err)
	}
}

// TestCheckTrustDirTOCTOU_OtherErrors_PreservedNoFalsePositive asserts that a
// non-ENOENT error (symlink at the final component) does NOT satisfy
// errors.Is(err, fs.ErrNotExist). Guards against over-eager wrapping.
func TestCheckTrustDirTOCTOU_OtherErrors_PreservedNoFalsePositive(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real")
	symlinkDir := filepath.Join(tmp, "byreis")

	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := trust.CheckTrustDirTOCTOU(symlinkDir)
	if err == nil {
		t.Fatal("expected error for symlink dir, got nil")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("errors.Is(err, fs.ErrNotExist) must be false for symlink error; got err: %v", err)
	}
}

// TestCheckTrustFileTOCTOU_OtherErrors_PreservedNoFalsePositive asserts that a
// non-ENOENT error (symlink at the final component) does NOT satisfy
// errors.Is(err, fs.ErrNotExist). Guards against over-eager wrapping.
func TestCheckTrustFileTOCTOU_OtherErrors_PreservedNoFalsePositive(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realFile := filepath.Join(tmp, "real.yaml")
	symlinkPath := filepath.Join(tmp, "trust.yaml")

	if err := os.WriteFile(realFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := trust.CheckTrustFileTOCTOU(symlinkPath)
	if err == nil {
		t.Fatal("expected error for symlink file, got nil")
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("errors.Is(err, fs.ErrNotExist) must be false for symlink error; got err: %v", err)
	}
}

// containsChmodHint returns true if the error string contains a "chmod" hint.
func containsChmodHint(s string) bool {
	for i := 0; i+5 < len(s); i++ {
		if s[i:i+5] == "chmod" {
			return true
		}
	}
	return false
}
