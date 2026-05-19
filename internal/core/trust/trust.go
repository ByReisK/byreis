// Package trust provides TOCTOU-safe filesystem checks for security-critical
// config paths (config directory and trust anchor file). It is a core leaf
// shared primitive: it imports only stdlib packages and is used by both the
// Init use-case and the Doctor use-case.
//
// The O_NOFOLLOW open + fstat-on-the-returned-fd binding (the security decision
// is bound to the opened object, never stat-path-then-open-path) is the
// canonical implementation of the TOCTOU protection defined in the design. Any
// behavioural change to that binding is itself a security defect.
package trust

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// Sentinel errors owned by the trust package. Every call site references these
// directly (no alias vars anywhere in the codebase).
var (
	// ErrTrustAnchorPerms is returned when trust.yaml exists but its permissions
	// are not exactly 0600. byreis refuses to run any trust-consulting command
	// until the operator fixes the mode with the printed chmod hint.
	ErrTrustAnchorPerms = errors.New(
		"trust anchor file has insecure permissions: must be exactly 0600 — " +
			"run: chmod 600 <path>")

	// ErrTrustAnchorSymlink is returned when the trust anchor path resolves
	// via a symlink at the final component (O_NOFOLLOW protection).
	ErrTrustAnchorSymlink = errors.New(
		"trust anchor path is a symlink — symlinks are not allowed for security-critical config; " +
			"replace with a regular file")

	// ErrTrustDirPerms is returned when the config directory has bits in 0077
	// set (group/world readable/writable/executable), is a symlink, or is not
	// owned by the invoking user. byreis refuses to run.
	ErrTrustDirPerms = errors.New(
		"byreis config directory has insecure permissions: must be 0700 with no group/world bits — " +
			"run: chmod 700 <path>")

	// ErrTrustDirSymlink is returned when the config directory path is itself a
	// symlink rather than a real directory.
	ErrTrustDirSymlink = errors.New(
		"byreis config directory is a symlink — symlinks are not allowed for security-critical config; " +
			"replace with a real directory")

	// ErrTrustDirWrongOwner is returned when the config directory is not owned
	// by the invoking user.
	ErrTrustDirWrongOwner = errors.New(
		"byreis config directory is not owned by the current user — " +
			"run `byreis doctor` to diagnose")

	// ErrTrustAnchorWrongOwner is returned when trust.yaml is not owned by the
	// invoking user.
	ErrTrustAnchorWrongOwner = errors.New(
		"trust anchor file is not owned by the current user — " +
			"run `byreis doctor` to diagnose")
)

// CheckTrustDirTOCTOU performs the TOCTOU-safe parent-directory check using
// O_NOFOLLOW + fstat-on-fd. It opens the directory with O_NOFOLLOW|O_DIRECTORY,
// then fstats the resulting fd to verify:
//   - the path is a real directory (not a symlink at the final component)
//   - the mode has no bits in 0077 (no group/world access)
//   - the directory is owned by the invoking user
//
// The returned fd (if non-negative) is the open dir fd. The caller MUST close
// it. Errors are wrapped with actionable hints.
//
// This function is used by both the production TrustAnchorStore implementation
// and the doctor check. It is exported so the adapter can call it and unit tests
// can exercise it via the OS's real tmpdir (or a fake).
func CheckTrustDirTOCTOU(dirPath string) (*os.File, error) {
	// Open with O_NOFOLLOW to reject a symlink at the final component. We use
	// syscall.Open directly so we can pass O_NOFOLLOW, which os.OpenFile does
	// not expose. On both macOS and Linux, opening a symlink with O_NOFOLLOW
	// returns ELOOP (macOS) or ELOOP/ENOTDIR (Linux). O_DIRECTORY is not
	// available on all platforms, so we verify the directory type via fstat.
	fd, err := syscall.Open(dirPath, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if err == syscall.ENOENT {
			return nil, fmt.Errorf("config directory %q does not exist — "+
				"create it with: mkdir -m 700 %s", dirPath, dirPath)
		}
		if err == syscall.ELOOP || err == syscall.ENOTDIR {
			return nil, fmt.Errorf("%w: %s", ErrTrustDirSymlink, dirPath)
		}
		return nil, fmt.Errorf("opening config directory %q failed: %w", dirPath,
			&os.PathError{Op: "open", Path: dirPath, Err: err})
	}
	f := os.NewFile(uintptr(fd), dirPath)

	// fstat the fd to make the security decision on the open object, not the path.
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat config directory fd for %q failed: %w", dirPath, err)
	}

	// Verify it is actually a directory (not a file we raced onto).
	if !info.IsDir() {
		_ = f.Close()
		return nil, fmt.Errorf(
			"%w: %s is not a directory", ErrTrustDirSymlink, dirPath)
	}

	// Enforce ownership: must be owned by the invoking user.
	if err := checkOwner(info, dirPath); err != nil {
		_ = f.Close()
		return nil, err
	}

	// Enforce mode: no bits in 0077 (no group/world access).
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		_ = f.Close()
		return nil, fmt.Errorf(
			"%w: %s has mode %#o; run: chmod 700 %s",
			ErrTrustDirPerms, dirPath, mode, dirPath)
	}

	return f, nil
}

// CheckTrustFileTOCTOU performs the TOCTOU-safe trust.yaml check using
// O_NOFOLLOW + fstat-on-fd. It opens the file with O_NOFOLLOW (so a symlink at
// the final component is rejected), then fstats the resulting fd to verify:
//   - the path is a regular file
//   - the mode is exactly 0600 (0400 is also rejected per the canonical rule)
//   - the file is owned by the invoking user
//
// The returned fd (if non-nil) is the open file. The caller MUST close it.
// Errors are wrapped with actionable chmod hints.
func CheckTrustFileTOCTOU(filePath string) (*os.File, error) {
	// O_NOFOLLOW rejects a symlink at the final component.
	f, err := openNoFollow(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("trust anchor file %q does not exist — "+
				"run `byreis init` to initialise the project", filePath)
		}
		if isSymlinkError(err) {
			return nil, fmt.Errorf(
				"%w: %s", ErrTrustAnchorSymlink, filePath)
		}
		return nil, fmt.Errorf("opening trust anchor file %q failed: %w", filePath, err)
	}

	// fstat on the open fd: bind the security decision to this object.
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat trust anchor fd for %q failed: %w", filePath, err)
	}

	// Verify it is a regular file.
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf(
			"%w: %s is not a regular file (mode %s)",
			ErrTrustAnchorSymlink, filePath, info.Mode())
	}

	// Enforce ownership.
	if err := checkOwner(info, filePath); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: run `byreis doctor` to diagnose", ErrTrustAnchorWrongOwner)
	}

	// Enforce EXACTLY 0600 — 0400 and any 0077 bits are all rejected.
	perm := info.Mode().Perm()
	if perm != 0o600 {
		_ = f.Close()
		return nil, fmt.Errorf(
			"%w: %s has mode %#o; run: chmod 600 %s",
			ErrTrustAnchorPerms, filePath, perm, filePath)
	}

	return f, nil
}

// openNoFollow opens a file path with O_NOFOLLOW semantics. On Darwin/Linux this
// uses syscall.O_NOFOLLOW to reject symlinks at the final path component.
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
// process's effective user. On non-Unix platforms this is a no-op (returns nil).
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
