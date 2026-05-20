//go:build windows

package atomicwrite

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// preRenameHook is called once, immediately before the rename, if non-nil.
// It is set exclusively by test code via SetPreRenameHook to inject a
// directory swap between the inode snapshot and the rename. Nil in production.
var preRenameHook func()

// parentInodeWindows captures the Windows file identity of the parent
// directory: VolumeSerialNumber + FileIndexHigh/Low together uniquely identify
// the object on a volume.
type parentInodeWindows struct {
	volumeSerial uint32
	fileIndexHi  uint32
	fileIndexLo  uint32
}

// Reserved for the future Windows-write-path implementation; not currently invoked by performAtomicRename.
//
// openParentNoFollow opens the parent directory at path with
// FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS (the Windows
// equivalent of O_NOFOLLOW for directories). It rejects any reparse point
// (symlink, junction, etc.) at the final path component and returns the
// file identity for inode-equivalent tracking.
//
// Platform limitation: Windows does not expose renameat(2), so the subsequent
// rename uses os.Rename. The pre/post inode verification provides equivalent
// protection against a concurrent directory swap. This limitation is documented
// in the package doc comment.
func openParentNoFollow(path string) (windows.Handle, parentInodeWindows, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, parentInodeWindows{},
			&os.PathError{Op: "open", Path: path, Err: err}
	}

	const flags = windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS

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
		return windows.InvalidHandle, parentInodeWindows{},
			fmt.Errorf("open parent dir %q: %w", path, err)
	}

	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, parentInodeWindows{},
			fmt.Errorf("GetFileInformationByHandle for parent dir %q: %w", path, err)
	}

	// Reject reparse points (symlinks, junctions, OneDrive placeholders, etc.).
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, parentInodeWindows{},
			fmt.Errorf("%w: parent directory %q is a reparse point (symlink or junction) — "+
				"the write path is unsafe", ErrAtomicWriteParentChanged, path)
	}

	snap := parentInodeWindows{
		volumeSerial: fi.VolumeSerialNumber,
		fileIndexHi:  fi.FileIndexHigh,
		fileIndexLo:  fi.FileIndexLow,
	}
	return h, snap, nil
}

// Reserved for the future Windows-write-path implementation; not currently invoked by performAtomicRename.
//
// verifyParentInodeByHandle re-checks the directory at h against a previously
// captured snapshot. A mismatch indicates a concurrent directory swap and
// returns ErrAtomicWriteParentChanged.
func verifyParentInodeByHandle(path string, h windows.Handle, snap parentInodeWindows) error {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return fmt.Errorf("GetFileInformationByHandle re-verify for %q: %w", path, err)
	}
	if fi.VolumeSerialNumber != snap.volumeSerial ||
		fi.FileIndexHigh != snap.fileIndexHi ||
		fi.FileIndexLow != snap.fileIndexLo {
		return fmt.Errorf(
			"%w: file identity changed for %q — verify the secrets directory tree and retry",
			ErrAtomicWriteParentChanged, path)
	}
	return nil
}

// performAtomicRename is the Windows implementation of the TOCTOU-hardened
// rename. Windows is not a supported release target for byreis write
// operations; this function fails closed immediately with
// ErrAtomicWriteWindowsUnsupported before performing any side-effecting work.
//
// The openParentNoFollow / verifyParentInodeByHandle infrastructure above is
// retained as the starting point for the future Windows-write-path slice.
func performAtomicRename(_, _, _ string) error {
	return fmt.Errorf("%w: Windows is not currently a supported release target "+
		"for byreis write operations; use the Linux or macOS build, or pin to a "+
		"follow-up release that supports the Windows write path",
		ErrAtomicWriteWindowsUnsupported)
}
