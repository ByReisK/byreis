//go:build unix

package countercache

// Security helpers below (openNoFollowDir, openNoFollow, isSymlinkError,
// checkOwner, checkDirMode, checkFileMode) are a verbatim transplant of
// internal/core/trust/trust_unix.go lines 14-96. Any future change to this
// section MUST be applied to the canonical source first, then ported here
// byte-for-byte. Paraphrase is a security violation.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"

	"github.com/ByReisK/byreis/internal/adapter/fs/atomicwrite"
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
			ErrCounterCacheUnsafePerms, dirPath, mode, dirPath)
	}
	return nil
}

// checkFileMode enforces that a file has exactly mode 0600.
func checkFileMode(info fs.FileInfo, filePath string) error {
	perm := info.Mode().Perm()
	if perm != 0o600 {
		return fmt.Errorf(
			"%w: %s has mode %#o; run: chmod 600 %s",
			ErrCounterCacheUnsafePerms, filePath, perm, filePath)
	}
	return nil
}

// platformState holds Unix-build platform-specific state. On Unix, the
// Windows log-once fields are not needed; this is an empty struct.
type platformState struct{} //nolint:unused // used via embedding on all platforms; Windows build adds fields

// readSecureFile opens the file at path applying the full D3 security pattern:
//  1. openNoFollow — rejects symlinks via O_NOFOLLOW.
//  2. f.Stat() on the open fd — fstat-on-fd, not stat-the-path.
//  3. checkOwner — euid ownership.
//  4. checkFileMode — exact 0o600.
//  5. Parent directory checks (registry dir + cache root) on the chain.
//  6. Read content from the verified fd.
//
// Returns (nil, os.ErrNotExist) for a cold cache. Returns wrapped
// ErrCounterCacheUnsafePath or ErrCounterCacheUnsafePerms on security failures.
func (s *Store) readSecureFile(_ context.Context, filePath string) ([]byte, error) {
	// ---- Parent directory security checks (registry dir + cache root) ----
	if err := s.checkParentChain(filePath); err != nil {
		return nil, err
	}

	// ---- Step 1: O_NOFOLLOW open -------------------------------------------
	f, err := openNoFollow(filePath)
	if err != nil {
		if isSymlinkError(err) {
			return nil, fmt.Errorf("%w: %q is a symlink — remove ~/.cache/byreis/ and retry",
				ErrCounterCacheUnsafePath, filePath)
		}
		var pe *os.PathError
		if errors.As(err, &pe) && pe.Err == syscall.ENOENT {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("counter cache: opening %q: %w", filePath, err)
	}
	defer func() { _ = f.Close() }()

	// ---- Step 2: fstat on the open fd (NOT os.Stat on the path) -----------
	info, statErr := f.Stat()
	if statErr != nil {
		return nil, fmt.Errorf("counter cache: fstat on fd for %q: %w", filePath, statErr)
	}

	// ---- Step 3: ownership check -------------------------------------------
	if ownerErr := checkOwner(info, filePath); ownerErr != nil {
		return nil, fmt.Errorf("%w: %s", ErrCounterCacheUnsafePerms, ownerErr.Error())
	}

	// ---- Step 4: mode check (exact 0o600) ----------------------------------
	if modeErr := checkFileMode(info, filePath); modeErr != nil {
		return nil, modeErr
	}

	// ---- Step 6: read content from verified fd -----------------------------
	data, readErr := io.ReadAll(f)
	if readErr != nil {
		return nil, fmt.Errorf("counter cache: reading %q: %w", filePath, readErr)
	}

	return data, nil
}

// checkParentChain validates the parent directory chain for the given file.
// It checks the per-registry directory (one level up from filePath) and the
// cacheRoot directory using openNoFollowDir + fstat + checkOwner + checkDirMode.
func (s *Store) checkParentChain(filePath string) error {
	// Check the per-registry directory (immediate parent of the file).
	regDir := s.registryDir()
	if err := checkDir(regDir); err != nil {
		return err
	}

	// Check the cacheRoot directory (parent of the registry dir).
	if err := checkDir(s.cacheRoot); err != nil {
		return err
	}

	return nil
}

// checkDir validates a directory at path using openNoFollowDir + fstat-on-fd +
// checkOwner + checkDirMode. Returns wrapped ErrCounterCacheUnsafePath on
// symlink, wrapped ErrCounterCacheUnsafePerms on ownership/mode failures.
// ENOENT returns nil (directory not yet created is not a security failure).
func checkDir(path string) error {
	d, err := openNoFollowDir(path)
	if err != nil {
		if isSymlinkError(err) {
			return fmt.Errorf("%w: %q is a symlink — remove ~/.cache/byreis/ and retry",
				ErrCounterCacheUnsafePath, path)
		}
		var pe *os.PathError
		if errors.As(err, &pe) && pe.Err == syscall.ENOENT {
			return nil // directory does not yet exist — not a security failure
		}
		return fmt.Errorf("counter cache: opening dir %q: %w", path, err)
	}
	defer func() { _ = d.Close() }()

	info, infoErr := d.Stat()
	if infoErr != nil {
		return fmt.Errorf("counter cache: fstat on dir fd for %q: %w", path, infoErr)
	}
	if ownerErr := checkOwner(info, path); ownerErr != nil {
		return fmt.Errorf("%w: directory %s", ErrCounterCacheUnsafePerms, ownerErr.Error())
	}
	if modeErr := checkDirMode(info, path); modeErr != nil {
		return modeErr
	}
	return nil
}

// ensureRegistryDir creates the per-registry directory (and parents) with mode
// 0o700, then immediately verifies the created directory's owner and mode to
// catch non-zero umask environments.
func (s *Store) ensureRegistryDir(_ context.Context) error {
	dir := s.registryDir()

	// Ensure cacheRoot exists.
	if err := os.MkdirAll(s.cacheRoot, 0o700); err != nil {
		return fmt.Errorf("counter cache: creating cache root %q: %w", s.cacheRoot, err)
	}

	// Ensure per-registry dir exists.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("counter cache: creating registry dir %q: %w", dir, err)
	}

	// Immediately verify: MkdirAll does not guarantee the requested mode on
	// systems with non-zero umask. The verification catches that and refuses.
	if err := checkDir(dir); err != nil {
		return fmt.Errorf("counter cache: registry dir security check failed: %w", err)
	}

	return nil
}

// writeSecureFile atomically writes data to filePath via atomicwrite.WriteFile,
// which uses the TOCTOU-hardened rename semantics (O_NOFOLLOW parent +
// inode snapshot + Renameat(2)).
func (s *Store) writeSecureFile(ctx context.Context, filePath string, data []byte) error {
	if err := atomicwrite.WriteFile(ctx, filePath, data, 0o600); err != nil {
		return fmt.Errorf("counter cache: atomic write to %q: %w", filePath, err)
	}
	return nil
}
