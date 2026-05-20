//go:build windows

package trust

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// Windows-specific open flags used for the no-follow open.
// FILE_FLAG_OPEN_REPARSE_POINT causes CreateFileW to open the link object
// itself rather than its target, equivalent to O_NOFOLLOW on Unix. This is
// combined with FILE_FLAG_BACKUP_SEMANTICS to allow opening directories.
const (
	fileFlagOpenReparsePoint = windows.FILE_FLAG_OPEN_REPARSE_POINT
	fileFlagBackupSemantics  = windows.FILE_FLAG_BACKUP_SEMANTICS
)

// openNoFollowDir opens a directory path refusing to follow a reparse point
// (symlink or junction) at the final component. On Windows this uses
// CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS.
// After opening, we verify via GetFileInformationByHandle that no reparse tag
// is set; any non-zero reparse tag is rejected.
func openNoFollowDir(path string) (*os.File, error) {
	return openNoFollowWithFlags(path, fileFlagOpenReparsePoint|fileFlagBackupSemantics)
}

// openNoFollow opens a file path refusing to follow a reparse point (symlink
// or junction) at the final component. On Windows this uses CreateFileW with
// FILE_FLAG_OPEN_REPARSE_POINT. After opening, GetFileInformationByHandle
// verifies that no reparse tag is set; any non-zero reparse tag is rejected.
func openNoFollow(path string) (*os.File, error) {
	return openNoFollowWithFlags(path, fileFlagOpenReparsePoint)
}

// openNoFollowWithFlags is the shared implementation for openNoFollow and
// openNoFollowDir. It opens path with CreateFileW using the provided flags
// (always combined with FILE_FLAG_OPEN_REPARSE_POINT to prevent symlink
// following), then inspects the handle with GetFileInformationByHandle to
// reject any reparse point.
func openNoFollowWithFlags(path string, extraFlags uint32) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	// Always include FILE_FLAG_OPEN_REPARSE_POINT: without it CreateFileW
	// resolves symlinks/junctions before we can inspect them.
	flags := extraFlags | fileFlagOpenReparsePoint

	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		// Map Windows not-found errors so errors.Is(err, fs.ErrNotExist) fires.
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
			errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_FILE_NOT_FOUND}
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	// GetFileInformationByHandle on the open handle — the security decision is
	// bound to the opened object, never to the path.
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		_ = windows.CloseHandle(h)
		return nil, &os.PathError{Op: "stat ... fd for", Path: path, Err: err}
	}

	// Reject any reparse point (symlink, junction, OneDrive placeholder, WSL
	// symlink, AppExecLink, etc.). No allow-list: any non-zero reparse tag or
	// the FILE_ATTRIBUTE_REPARSE_POINT attribute indicates the object is not a
	// plain file/directory.
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		// Internal-only discriminator; the public ErrTrustAnchorSymlink wraps this in CheckTrust{File,Dir}TOCTOU.
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_REPARSE_TAG_MISMATCH}
	}

	// Wrap the Windows handle in an os.File so callers get a standard *os.File.
	// os.NewFile takes ownership of the handle (it will CloseHandle on Close).
	f := os.NewFile(uintptr(h), path)
	return f, nil
}

// isSymlinkError reports whether an open error is due to a reparse point
// (symlink/junction) being encountered. On Windows we use
// ERROR_REPARSE_TAG_MISMATCH as the sentinel injected by openNoFollowWithFlags.
func isSymlinkError(err error) bool {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return errors.Is(pe.Err, windows.ERROR_REPARSE_TAG_MISMATCH)
	}
	return false
}

// checkOwner returns ErrTrustOwnershipUnverifiable on Windows. SID-level
// ownership checking is deferred to a follow-up slice. The binary fails closed:
// a Windows operator cannot use the trust anchor until ownership verification
// is implemented. See the package-level doc comment for operator guidance.
func checkOwner(_ fs.FileInfo, path string) error {
	return fmt.Errorf("%w: %s", ErrTrustOwnershipUnverifiable, path)
}

// checkDirMode is a no-op on Windows: POSIX permission bits are not applicable.
// Windows ACL enforcement is deferred to a follow-up slice.
func checkDirMode(_ fs.FileInfo, _ string) error {
	return nil
}

// checkFileMode is a no-op on Windows: POSIX permission bits are not
// applicable. Windows ACL enforcement is deferred to a follow-up slice.
func checkFileMode(_ fs.FileInfo, _ string) error {
	return nil
}

