//go:build unix

package atomicwrite

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// preRenameHook is called once, immediately before the rename syscall, if
// non-nil. It is set exclusively by test code via SetPreRenameHook
// (atomicwrite_export_test.go) to inject a directory swap between the inode
// snapshot and the rename. It is nil in production.
var preRenameHook func()

// postRenameHook is called once, immediately after a successful unix.Renameat
// and before performAtomicRename returns the parent fd. It models the dirSync
// window for tests. It is nil in production.
var postRenameHook func()

// nextTempSuffixHook is called with the randomly generated temp-file name
// immediately before openExclTempFile calls os.OpenFile. Tests use it to
// observe or intercept the suffix to exercise EEXIST/ELOOP paths.
// It is nil in production.
var nextTempSuffixHook func(name string)

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

// newAtomicTempFile creates a new temp file in dir with the given prefix using
// the O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW hardened helper. This is the Unix
// implementation; the Windows stub bails early with ErrAtomicWriteWindowsUnsupported.
func newAtomicTempFile(dir, prefix string) (*os.File, error) {
	return openExclTempFile(dir, prefix)
}

// openExclTempFile creates a fresh O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW temp file
// in dir with a crypto/rand-derived suffix (≥8 bytes = 64 bits of entropy).
//
// Retry policy:
//   - On EEXIST: retry with a fresh random suffix, up to 8 times.
//   - On ELOOP: fail closed immediately with NO retry — a symlink at the temp
//     path indicates a potential injection attack; retrying would let an
//     attacker exhaust the retry budget.
//   - On any other error: surface as-is.
func openExclTempFile(dir, prefix string) (*os.File, error) {
	const maxRetries = 8
	const randBytes = 8 // 64 bits of entropy
	flags := os.O_CREATE | os.O_EXCL | os.O_WRONLY

	for attempt := range maxRetries {
		var buf [randBytes]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, fmt.Errorf("openExclTempFile: generating random suffix: %w", err)
		}
		name := filepath.Join(dir, prefix+hex.EncodeToString(buf[:]))

		// Notify the test hook (nil in production) before the open call.
		if nextTempSuffixHook != nil {
			nextTempSuffixHook(filepath.Base(name))
		}

		// O_NOFOLLOW is retained as defense-in-depth; under the current O_EXCL
		// flag, EEXIST fires first on a symlink at the temp path (the kernel's
		// path-exists check precedes link-resolution on both linux and darwin).
		// The ELOOP branch below remains for the case where O_EXCL is dropped
		// or a future libc/kernel variant surfaces ELOOP in this combination.
		f, err := os.OpenFile(name, flags|syscall.O_NOFOLLOW, 0o600)
		if err == nil {
			return f, nil
		}

		// ELOOP: defense-in-depth fail-closed branch (see comment above).
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf(
				"symlink injection at temp-file path: %s: %w",
				name, err)
		}

		// EEXIST: collision — retry with a fresh random suffix.
		if errors.Is(err, syscall.EEXIST) || os.IsExist(err) {
			if attempt < maxRetries-1 {
				continue
			}
			return nil, fmt.Errorf(
				"openExclTempFile: exhausted %d retries on EEXIST in %q — "+
					"another process may be occupying the temp namespace: %w",
				maxRetries, dir, err)
		}

		// Any other error: surface as-is.
		return nil, fmt.Errorf("openExclTempFile: creating temp file in %q: %w", dir, err)
	}
	// Unreachable, but satisfies the compiler.
	return nil, fmt.Errorf("openExclTempFile: exhausted retries in %q", dir)
}

// performAtomicRename implements the TOCTOU-hardened rename for Unix platforms.
// On success it returns the open, verified parent directory fd (caller owns
// close via defer syscall.Close). On any error it closes the fd internally and
// returns -1 so the caller never double-closes.
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
//  5. Fire postRenameHook (tests only) immediately after a successful rename and
//     before returning the fd. This models the dirSync window for tests.
//  6. Return (dirfd, nil) — the fd is still open; the caller fsyncs via
//     dirSyncFd and then closes it.
func performAtomicRename(tmpPath, livePath, parentDir string) (int, error) {
	dirfd, snap, err := openParentNoFollow(parentDir)
	if err != nil {
		// openParentNoFollow already returned -1 on error; nothing to close.
		return -1, err
	}
	// NOTE: NO blanket defer close here. Each error path closes
	// explicitly; the success path returns the open fd to the caller.

	// Test hook: fires between snapshot and rename.
	if preRenameHook != nil {
		preRenameHook()
	}

	// Re-verify the parent inode immediately before rename.
	if err := verifyParentInode(parentDir, snap); err != nil {
		_ = syscall.Close(dirfd)
		return -1, err
	}

	// Use renameat(2) relative to the verified parent fd. The filenames passed
	// to unix.Renameat are the base names of tmpPath and livePath; they are
	// resolved relative to dirfd, which points to the directory we verified.
	tmpBase := filepath.Base(tmpPath)
	liveBase := filepath.Base(livePath)

	if err := unix.Renameat(dirfd, tmpBase, dirfd, liveBase); err != nil {
		_ = syscall.Close(dirfd)
		return -1, fmt.Errorf("renameat %q -> %q: %w", tmpPath, livePath, err)
	}

	// Test hook: fires after successful rename, before returning the fd.
	// This models the dirSync window (the period between rename and fsync).
	if postRenameHook != nil {
		postRenameHook()
	}

	// Return the still-open fd; the caller owns close.
	return dirfd, nil
}

// dirSyncFd fsyncs a directory via its already-open file descriptor. This
// avoids a new path-based os.Open(dir) call after the rename, which would be
// subject to a symlink-swap attack (the swap target could be a FIFO or
// blocking device, causing a hang). Using the verified fd closes that window.
//
// Do NOT use os.NewFile here: the *os.File finalizer would call close(2) on
// the same fd when GC runs, racing with the caller's defer syscall.Close.
func dirSyncFd(fd int) error {
	if err := syscall.Fsync(fd); err != nil {
		return fmt.Errorf("dirSyncFd: fsync directory fd %d: %w", fd, err)
	}
	return nil
}
