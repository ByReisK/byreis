// Package trust provides TOCTOU-safe filesystem checks for security-critical
// config paths (config directory and trust anchor file). It is a core leaf
// shared primitive: it imports only stdlib packages and is used by both the
// Init use-case and the Doctor use-case.
//
// The open-with-no-symlink-follow + fstat-on-the-returned-fd binding (the
// security decision is bound to the opened object, never stat-path-then-open-
// path) is the canonical implementation of the TOCTOU protection defined in the
// design. Any behavioural change to that binding is itself a security defect.
//
// Platform support:
//
//   - Unix (Linux, macOS): full enforcement — O_NOFOLLOW rejects symlinks;
//     ownership is verified against the invoking user's effective UID.
//
//   - Windows: symlink/reparse-point rejection is enforced via
//     FILE_FLAG_OPEN_REPARSE_POINT + GetFileInformationByHandle (any non-zero
//     reparse tag is rejected). Ownership verification is not yet implemented;
//     CheckTrustDirTOCTOU and CheckTrustFileTOCTOU will return
//     ErrTrustOwnershipUnverifiable on Windows until a follow-up slice adds
//     SID-level ownership checking. Windows operators should ensure the config
//     directory and trust anchor file are placed in a location not writable by
//     other local users.
package trust

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
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
	// via a symlink or reparse point at the final component.
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
	// symlink or reparse point rather than a real directory.
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

	// ErrTrustOwnershipUnverifiable is returned on platforms where ownership
	// verification is not yet implemented. The trust anchor open fails closed:
	// the binary builds and symlink protection is active, but ownership cannot
	// be confirmed. See the package-level doc comment for operator guidance.
	ErrTrustOwnershipUnverifiable = errors.New(
		"trust anchor ownership cannot be verified on this platform — " +
			"ensure the config path is not writable by other local users")
)

// CheckTrustDirTOCTOU performs the TOCTOU-safe parent-directory check using
// a no-follow open + fstat-on-fd. It opens the directory refusing to follow a
// symlink at the final component, then fstats the resulting fd to verify:
//   - the path is a real directory (not a symlink at the final component)
//   - the mode has no bits in 0077 (no group/world access) [Unix only]
//   - the directory is owned by the invoking user [Unix only]
//
// The returned fd (if non-negative) is the open dir fd. The caller MUST close
// it. Errors are wrapped with actionable hints.
//
// This function is used by both the production TrustAnchorStore implementation
// and the doctor check. It is exported so the adapter can call it and unit tests
// can exercise it via the OS's real tmpdir (or a fake).
func CheckTrustDirTOCTOU(dirPath string) (*os.File, error) {
	f, err := openNoFollowDir(dirPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config directory %q does not exist — "+
				"create it with: mkdir -m 700 %s", dirPath, dirPath)
		}
		if isSymlinkError(err) {
			return nil, fmt.Errorf("%w: %s", ErrTrustDirSymlink, dirPath)
		}
		return nil, fmt.Errorf("opening config directory %q failed: %w", dirPath, err)
	}

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

	// Enforce mode: no bits in 0077 (no group/world access). [Unix enforced by
	// the platform; Windows ACL enforcement is deferred to a follow-up slice.]
	if err := checkDirMode(info, dirPath); err != nil {
		_ = f.Close()
		return nil, err
	}

	return f, nil
}

// CheckTrustFileTOCTOU performs the TOCTOU-safe trust.yaml check using a
// no-follow open + fstat-on-fd. It opens the file refusing to follow a symlink
// or reparse point at the final component, then fstats the resulting fd to
// verify:
//   - the path is a regular file
//   - the mode is exactly 0600 (0400 is also rejected per the canonical rule)
//     [Unix only; Windows mode enforcement is not applicable]
//   - the file is owned by the invoking user [Unix only]
//
// The returned fd (if non-nil) is the open file. The caller MUST close it.
// Errors are wrapped with actionable chmod hints.
func CheckTrustFileTOCTOU(filePath string) (*os.File, error) {
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
	// [Unix only; Windows does not use POSIX permission bits.]
	if err := checkFileMode(info, filePath); err != nil {
		_ = f.Close()
		return nil, err
	}

	return f, nil
}
