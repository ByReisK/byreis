//go:build unix

package atomicwrite

import (
	"fmt"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// preRenameHook is called once, immediately before the rename syscall, if
// non-nil. It is set exclusively by test code via SetPreRenameHook
// (atomicwrite_export_test.go) to inject a directory swap between the inode
// snapshot and the rename. It is nil in production.
var preRenameHook func()

// parentInodeUnix captures the inode and device number of an open directory
// file descriptor. It is used to detect concurrent directory swaps.
type parentInodeUnix struct {
	ino uint64
	dev uint64
}

// openParentNoFollow opens the directory at path with O_NOFOLLOW semantics so
// that a symlink at the final path component is rejected. Returns an open file
// descriptor and the inode snapshot of that directory, or an error.
//
// This is the Unix equivalent of the trust package's openNoFollowDir pattern.
// We duplicate the syscall rather than importing core/trust to preserve the
// adapter-does-not-import-core rule; the logic is identical.
func openParentNoFollow(path string) (fd int, snap parentInodeUnix, err error) {
	fd, err = syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if err == syscall.ELOOP || err == syscall.ENOTDIR {
			return -1, parentInodeUnix{}, fmt.Errorf("%w: parent directory %q is a symlink — "+
				"the write path is unsafe", ErrAtomicWriteParentChanged, path)
		}
		return -1, parentInodeUnix{}, fmt.Errorf("open parent dir %q: %w", path, err)
	}

	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return -1, parentInodeUnix{}, fmt.Errorf("fstat parent dir fd for %q: %w", path, err)
	}

	return fd, parentInodeUnix{ino: st.Ino, dev: uint64(st.Dev)}, nil //nolint:gosec // Dev is always non-negative on supported platforms
}

// verifyParentInode re-checks the directory at path against a previously
// captured inode snapshot. A mismatch indicates a concurrent directory swap
// and returns ErrAtomicWriteParentChanged.
func verifyParentInode(path string, snap parentInodeUnix) error {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return fmt.Errorf("lstat parent dir %q for re-verify: %w", path, err)
	}
	if uint64(st.Ino) != snap.ino || uint64(st.Dev) != snap.dev { //nolint:gosec // Ino/Dev are always non-negative
		return fmt.Errorf("%w: inode changed for %q (was dev=%d ino=%d, now dev=%d ino=%d) — "+
			"verify the secrets directory tree and retry",
			ErrAtomicWriteParentChanged, path, snap.dev, snap.ino, uint64(st.Dev), uint64(st.Ino)) //nolint:gosec
	}
	return nil
}

// performAtomicRename implements the TOCTOU-hardened rename for Unix platforms.
//
// Steps:
//  1. Open the parent directory with O_NOFOLLOW — rejects a symlink at the
//     parent's final path component and captures an inode snapshot via fstat(2).
//  2. If the preRenameHook is set (tests only), call it here to allow injection
//     of a directory swap between the snapshot and the rename.
//  3. Re-verify the parent directory inode via lstat(2) — detects any concurrent
//     directory swap that occurred after step 1.
//  4. Execute unix.Renameat(2) from the open parent fd so the rename target is
//     relative to the verified descriptor rather than the potentially-swapped path.
func performAtomicRename(tmpPath, livePath, parentDir string) error {
	dirfd, snap, err := openParentNoFollow(parentDir)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(dirfd) }()

	// Test hook: fires between snapshot and rename.
	if preRenameHook != nil {
		preRenameHook()
	}

	// Re-verify the parent inode immediately before rename.
	if err := verifyParentInode(parentDir, snap); err != nil {
		return err
	}

	// Use renameat(2) relative to the verified parent fd. The filenames passed
	// to unix.Renameat are the base names of tmpPath and livePath; they are
	// resolved relative to dirfd, which points to the directory we verified.
	tmpBase := filepath.Base(tmpPath)
	liveBase := filepath.Base(livePath)

	if err := unix.Renameat(dirfd, tmpBase, dirfd, liveBase); err != nil {
		return fmt.Errorf("renameat %q -> %q: %w", tmpPath, livePath, err)
	}

	return nil
}
