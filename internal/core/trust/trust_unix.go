//go:build unix

package trust

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// openNoFollowDir opens a directory path refusing to follow a symlink at the
// final component. On Unix this uses O_NOFOLLOW|O_RDONLY.
func openNoFollowDir(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if err == syscall.ENOENT {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ENOENT}
		}
		if err == syscall.ELOOP || err == syscall.ENOTDIR {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ELOOP}
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openNoFollow opens a file path with O_NOFOLLOW semantics. On Darwin/Linux
// this uses syscall.O_NOFOLLOW to reject symlinks at the final path component.
func openNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		// On macOS, ELOOP is returned when a symlink is followed and O_NOFOLLOW
		// is set; on Linux it is ELOOP or the open fails with ENOTDIR for trailing
		// symlinks that resolve to a non-dir. Treat both as the symlink case.
		if err == syscall.ELOOP || err == syscall.ENOTDIR {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ELOOP}
		}
		if err == syscall.ENOENT {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.ENOENT}
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// isSymlinkError reports whether an open error is due to a symlink being
// encountered when O_NOFOLLOW was set.
func isSymlinkError(err error) bool {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err == syscall.ELOOP || pe.Err == syscall.ENOTDIR
	}
	return false
}

// checkOwner checks that a file described by info is owned by the current
// process's effective user. On Unix this compares the inode's UID against
// os.Geteuid().
func checkOwner(info fs.FileInfo, path string) error {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Non-Unix platform: cannot enforce ownership. Return nil (best-effort).
		return nil
	}
	euid := uint32(os.Geteuid()) //nolint:gosec // Geteuid is always non-negative; uint32 is safe on all supported platforms
	if sys.Uid != euid {
		return fmt.Errorf("path %q is owned by uid %d, but current user is uid %d",
			path, sys.Uid, euid)
	}
	return nil
}

// checkDirMode enforces that a directory has no bits in 0077 (no group/world
// access).
func checkDirMode(info fs.FileInfo, dirPath string) error {
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf(
			"%w: %s has mode %#o; run: chmod 700 %s",
			ErrTrustDirPerms, dirPath, mode, dirPath)
	}
	return nil
}

// checkFileMode enforces that a file has exactly mode 0600.
func checkFileMode(info fs.FileInfo, filePath string) error {
	perm := info.Mode().Perm()
	if perm != 0o600 {
		return fmt.Errorf(
			"%w: %s has mode %#o; run: chmod 600 %s",
			ErrTrustAnchorPerms, filePath, perm, filePath)
	}
	return nil
}
