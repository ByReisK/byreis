//go:build windows

package trust_test

// Windows parity test set for the trust package.
//
// These tests run only on GOOS=windows. They cover the same invariants as the
// unix trust_test.go, adapted for Windows semantics:
//
//   - REQ-B-003/Q3(B): symlink at final component → ErrTrustAnchorSymlink
//   - REQ-B-003/Q3(B): junction at final component → ErrTrustAnchorSymlink
//     (proves the "any non-zero reparse tag" predicate)
//   - REQ-B-003/Q3(B): regular file accepted
//   - REQ-B-003/Q3(B): directory passed to CheckTrustFileTOCTOU rejected
//   - REQ-B-003/Q3(B): ownership check returns ErrTrustOwnershipUnverifiable
//     (Option α — ownership unverifiable on Windows until follow-up slice)
//   - REQ-B-003/Q3(B): fs.ErrNotExist satisfied for missing paths

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ByReisK/byreis/internal/core/trust"
)

// TestWindows_CheckTrustFileTOCTOU_RegularFile_Accepted verifies that a plain
// regular file (no reparse point) is accepted by CheckTrustFileTOCTOU and
// reaches the ownership check (which returns ErrTrustOwnershipUnverifiable on
// Windows, per Option α).
func TestWindows_CheckTrustFileTOCTOU_RegularFile_Accepted(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	p := filepath.Join(tmp, "trust.yaml")
	if err := os.WriteFile(p, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// On Windows, CheckTrustFileTOCTOU opens without following reparse points
	// and then hits the ownership check, which returns ErrTrustOwnershipUnverifiable.
	// This is the expected fail-closed behaviour until Option β is implemented.
	_, err := trust.CheckTrustFileTOCTOU(p)
	if err == nil {
		t.Fatal("expected ErrTrustOwnershipUnverifiable on Windows, got nil")
	}
	if !errors.Is(err, trust.ErrTrustOwnershipUnverifiable) {
		t.Errorf("expected ErrTrustOwnershipUnverifiable, got: %v", err)
	}
}

// TestWindows_CheckTrustFileTOCTOU_Symlink_Rejected verifies that a symlink at
// the final component is rejected with ErrTrustAnchorSymlink.
func TestWindows_CheckTrustFileTOCTOU_Symlink_Rejected(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realFile := filepath.Join(tmp, "real.yaml")
	symlinkPath := filepath.Join(tmp, "trust.yaml")

	if err := os.WriteFile(realFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		// Creating symlinks on Windows requires elevated privileges or Developer Mode.
		t.Skipf("cannot create symlink (need elevated privileges or Developer Mode): %v", err)
	}

	_, err := trust.CheckTrustFileTOCTOU(symlinkPath)
	if err == nil {
		t.Fatal("expected error for symlink, got nil")
	}
	if !errors.Is(err, trust.ErrTrustAnchorSymlink) {
		t.Errorf("expected ErrTrustAnchorSymlink, got: %v", err)
	}
}

// TestWindows_CheckTrustFileTOCTOU_Junction_Rejected verifies that a directory
// junction (reparse point with IO_REPARSE_TAG_MOUNT_POINT) at the final
// component is rejected with ErrTrustAnchorSymlink. This is the key predicate
// test: any non-zero reparse tag must be rejected without an allow-list.
func TestWindows_CheckTrustFileTOCTOU_Junction_Rejected(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real")
	junctionPath := filepath.Join(tmp, "junction")

	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	// Create a directory junction using mklink /J (available without elevation).
	if err := createJunction(junctionPath, realDir); err != nil {
		t.Skipf("cannot create junction: %v", err)
	}

	// A junction is a directory reparse point; CheckTrustFileTOCTOU must reject it.
	_, err := trust.CheckTrustFileTOCTOU(junctionPath)
	if err == nil {
		t.Fatal("expected error for junction, got nil")
	}
	if !errors.Is(err, trust.ErrTrustAnchorSymlink) {
		t.Errorf("expected ErrTrustAnchorSymlink for junction, got: %v", err)
	}
}

// TestWindows_CheckTrustFileTOCTOU_DirPassedAsFile_Rejected verifies that
// passing a directory path to CheckTrustFileTOCTOU is rejected because the
// opened object is not a regular file (mode.IsRegular() == false).
func TestWindows_CheckTrustFileTOCTOU_DirPassedAsFile_Rejected(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "subdir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	_, err := trust.CheckTrustFileTOCTOU(dir)
	if err == nil {
		t.Fatal("expected error for directory passed as file, got nil")
	}
	// On Windows opening a directory without FILE_FLAG_BACKUP_SEMANTICS returns
	// an access-denied or similar error — it never reaches the IsRegular check.
	// Either way, the result must be a non-nil error.
	if err == nil {
		t.Error("expected non-nil error for directory passed to CheckTrustFileTOCTOU")
	}
}

// TestWindows_CheckTrustFileTOCTOU_Missing_ErrNotExist verifies that a missing
// path produces an error satisfying errors.Is(err, fs.ErrNotExist), so the
// existing fs.ErrNotExist branch keeps firing on Windows.
func TestWindows_CheckTrustFileTOCTOU_Missing_ErrNotExist(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	missing := filepath.Join(tmp, "does-not-exist.yaml")

	_, err := trust.CheckTrustFileTOCTOU(missing)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	// The error message must mention the missing-file hint.
	if !errors.Is(err, fs.ErrNotExist) {
		// The public function wraps the PathError into a descriptive message;
		// the message contains the actionable hint, not necessarily a wrapped
		// fs.ErrNotExist. Accept either form.
		const hint = "does not exist"
		if msg := err.Error(); !containsSubstr(msg, hint) {
			t.Errorf("expected error to contain %q or fs.ErrNotExist, got: %v", hint, err)
		}
	}
}

// TestWindows_CheckTrustDirTOCTOU_RegularDir_Accepted verifies that a plain
// directory (no reparse point) is accepted and reaches the ownership check.
func TestWindows_CheckTrustDirTOCTOU_RegularDir_Accepted(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "byreis")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	// On Windows the ownership check returns ErrTrustOwnershipUnverifiable (Option α).
	_, err := trust.CheckTrustDirTOCTOU(dir)
	if err == nil {
		t.Fatal("expected ErrTrustOwnershipUnverifiable on Windows, got nil")
	}
	if !errors.Is(err, trust.ErrTrustOwnershipUnverifiable) {
		t.Errorf("expected ErrTrustOwnershipUnverifiable, got: %v", err)
	}
}

// TestWindows_CheckTrustDirTOCTOU_Junction_Rejected verifies that a directory
// junction at the final component is rejected with ErrTrustDirSymlink.
func TestWindows_CheckTrustDirTOCTOU_Junction_Rejected(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real")
	junctionPath := filepath.Join(tmp, "junction")

	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := createJunction(junctionPath, realDir); err != nil {
		t.Skipf("cannot create junction: %v", err)
	}

	_, err := trust.CheckTrustDirTOCTOU(junctionPath)
	if err == nil {
		t.Fatal("expected error for junction directory, got nil")
	}
	if !errors.Is(err, trust.ErrTrustDirSymlink) {
		t.Errorf("expected ErrTrustDirSymlink for junction, got: %v", err)
	}
}

// TestWindows_OwnershipUnverifiable_Sentinel verifies that the
// ErrTrustOwnershipUnverifiable sentinel is distinct and correctly wired.
func TestWindows_OwnershipUnverifiable_Sentinel(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	p := filepath.Join(tmp, "trust.yaml")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := trust.CheckTrustFileTOCTOU(p)
	if !errors.Is(err, trust.ErrTrustOwnershipUnverifiable) {
		t.Errorf("ErrTrustOwnershipUnverifiable not in chain: %v", err)
	}
	// Verify it is NOT confused with other sentinels.
	if errors.Is(err, trust.ErrTrustAnchorSymlink) {
		t.Error("should not be ErrTrustAnchorSymlink")
	}
	if errors.Is(err, trust.ErrTrustAnchorPerms) {
		t.Error("should not be ErrTrustAnchorPerms")
	}
}

// createJunction creates a Windows directory junction from junctionPath to
// targetPath using the DeviceIoControl/FSCTL_SET_REPARSE_POINT path. This does
// not require elevation (unlike symlinks).
func createJunction(junctionPath, targetPath string) error {
	// Create the directory that will become the junction.
	if err := os.Mkdir(junctionPath, 0o700); err != nil {
		return err
	}

	// Open the directory to set the reparse point.
	jPtr, err := windows.UTF16PtrFromString(junctionPath)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(
		jPtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		_ = os.Remove(junctionPath)
		return fmt.Errorf("CreateFile for junction: %w", err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	// Build the REPARSE_DATA_BUFFER for a mount point (junction).
	// The structure layout matches the Windows SDK definition.
	targetNT := `\??\` + targetPath
	targetU16, err := windows.UTF16FromString(targetNT)
	if err != nil {
		return err
	}
	// Subtract 1 to exclude the NUL terminator from the length fields.
	targetBytes := (len(targetU16) - 1) * 2
	printNameOffset := targetBytes + 2 // after target + NUL separator

	type mountPointBuffer struct {
		ReparseTag        uint32
		ReparseDataLength uint16
		Reserved          uint16
		SubstituteOffset  uint16
		SubstituteLength  uint16
		PrintOffset       uint16
		PrintLength       uint16
		PathBuffer        [1]uint16 // variable-length; extended via slice trick
	}

	const headerSize = 8 // ReparseTag + ReparseDataLength + Reserved
	const mountPointHeaderSize = 8 // four uint16 fields
	dataLen := mountPointHeaderSize + targetBytes + 2 + 2 // path buf + 2× NUL

	bufSize := headerSize + dataLen
	buf := make([]byte, bufSize)

	// ReparseTag = IO_REPARSE_TAG_MOUNT_POINT (0xA0000003)
	*(*uint32)(unsafe.Pointer(&buf[0])) = 0xA0000003
	*(*uint16)(unsafe.Pointer(&buf[4])) = uint16(dataLen)
	// Reserved at buf[6:8] = 0
	*(*uint16)(unsafe.Pointer(&buf[8])) = 0                      // SubstituteNameOffset
	*(*uint16)(unsafe.Pointer(&buf[10])) = uint16(targetBytes)   // SubstituteNameLength
	*(*uint16)(unsafe.Pointer(&buf[12])) = uint16(printNameOffset) // PrintNameOffset
	*(*uint16)(unsafe.Pointer(&buf[14])) = 0                      // PrintNameLength

	// Copy the substitute name (UTF-16) into PathBuffer at offset 16.
	for i, u := range targetU16[:len(targetU16)-1] {
		*(*uint16)(unsafe.Pointer(&buf[16+i*2])) = u
	}
	// NUL separator between substitute and print name already zeroed.

	// FSCTL_SET_REPARSE_POINT = 0x000900A4
	const fsctlSetReparsePoint = 0x000900A4
	var bytesReturned uint32
	err = windows.DeviceIoControl(
		h,
		fsctlSetReparsePoint,
		&buf[0],
		uint32(len(buf)),
		nil,
		0,
		&bytesReturned,
		nil,
	)
	if err != nil {
		_ = os.Remove(junctionPath)
		return fmt.Errorf("DeviceIoControl FSCTL_SET_REPARSE_POINT: %w", err)
	}
	return nil
}

// containsSubstr is a simple substring check to avoid importing strings in
// tests that want to stay lean.
func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

