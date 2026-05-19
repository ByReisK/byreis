// Package atomicwrite implements the usecase.AtomicFileWriter port for the
// real filesystem. It provides the no-clobber atomic write contract required
// by the Edit use-case for the live secrets file-of-record.
//
// Placement: OUTER adapter layer (internal/adapter/fs/atomicwrite). Core
// packages never import this adapter; it is injected at the composition root.
//
// Atomic write contract (binding):
//   - Resolve the target as AtomicWriteInput.LiveRelPath joined to the project
//     repo root; NEVER re-derive the path from artifact self-declared metadata.
//   - Create the temp file with O_EXCL, mode 0600, in the SAME directory as
//     the live file (ensures same filesystem, true atomic rename).
//   - Write SignedBytes verbatim (no re-encode, no normalization).
//   - fsync the temp file before rename.
//   - Atomic rename over the live path as the ONLY live-path mutation.
//   - fsync the parent directory after rename (best-effort durability).
//   - MUST NOT follow a symlink at the live path (O_NOFOLLOW on lstat check).
//   - MUST NOT widen a pre-existing mode/owner (preserve existing live-file
//     perms; if none, apply the secrets-file policy default: 0600).
//   - Any failure leaves the live file byte-identical and removes temp residue.
//   - Context cancellation is honoured at every I/O step; cancellation leaves
//     the live file untouched and removes the temp residue.
package atomicwrite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ByReisK/byreis/internal/core/usecase"
)

// secretsFileDefaultMode is the default mode applied to the live file when it
// does not pre-exist. 0600 (owner read/write only) is the secrets-file policy
// default: secrets must never be world-readable.
const secretsFileDefaultMode os.FileMode = 0o600

// ErrSymlinkAtLivePath is returned when the live path resolves to a symlink.
// The adapter refuses to follow symlinks to prevent a symlink-swap attack that
// could redirect the atomic rename to a different file.
var ErrSymlinkAtLivePath = errors.New(
	"live secrets file path resolves to a symlink — the atomic write refused " +
		"to follow it; resolve the symlink manually and retry")

// Writer implements usecase.AtomicFileWriter for the real filesystem. It is
// constructed via New and has no mutable state; all methods are safe for
// concurrent use.
type Writer struct {
	// repoRoot is the absolute path to the project repository root. LiveRelPath
	// is joined to this to derive the absolute live file path.
	repoRoot string
}

// New constructs a Writer rooted at repoRoot. repoRoot must be an absolute
// path to the project repository root (the directory containing the live
// secrets file). It is supplied by the composition root (resolved from the
// project config, never from the artifact itself).
func New(repoRoot string) (*Writer, error) {
	if repoRoot == "" {
		return nil, fmt.Errorf("atomicwrite.New: repoRoot is required")
	}
	if !filepath.IsAbs(repoRoot) {
		return nil, fmt.Errorf("atomicwrite.New: repoRoot must be an absolute path, got %q", repoRoot)
	}
	return &Writer{repoRoot: repoRoot}, nil
}

// Compile-time assertion: Writer implements usecase.AtomicFileWriter.
var _ usecase.AtomicFileWriter = (*Writer)(nil)

// WriteFileOfRecord implements usecase.AtomicFileWriter. It performs the
// no-clobber atomic write for Edit's live-file mutation.
//
// The sequence is strictly:
//  1. Resolve the absolute live path from in.LiveRelPath joined to repoRoot.
//  2. Lstat the live path (O_NOFOLLOW semantics): reject symlinks; record
//     existing perms if the file exists.
//  3. Create the temp file (O_EXCL, 0600) in the SAME directory as the live
//     file.
//  4. Write in.SignedBytes verbatim to the temp file.
//  5. fsync the temp file.
//  6. Chmod the temp file to match the existing live-file mode (or
//     secretsFileDefaultMode if it didn't exist) — MUST NOT widen perms.
//  7. Rename (atomic) the temp file over the live path.
//  8. fsync the parent directory (best-effort; non-fatal on failure).
//
// Any failure at any step leaves the live file byte-identical. Temp residue
// is removed on every failure path. Context cancellation is checked before
// each I/O step; a cancelled context leaves the live file untouched.
func (w *Writer) WriteFileOfRecord(ctx context.Context, in usecase.AtomicWriteInput) (retErr error) {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord cancelled before starting for project %q file %q: %w",
			in.ProjectID, in.FileName, err)
	}

	// (1) Resolve the absolute live path from the registry-supplied LiveRelPath.
	// The path comes from the VERIFIED registry config (cross-checked by the
	// merge/edit use-case) — never from the artifact's self-declared metadata.
	livePath, err := resolveLivePath(w.repoRoot, in.LiveRelPath)
	if err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord: resolving live path for project %q file %q: %w",
			in.ProjectID, in.FileName, err)
	}

	// (2) Lstat the live path. Reject symlinks (O_NOFOLLOW semantics).
	// Record existing perms for the chmod-to-match step.
	existingMode, liveExists, err := inspectLivePath(livePath)
	if err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord: inspecting live path %q: %w", livePath, err)
	}
	targetMode := existingMode
	if !liveExists {
		targetMode = secretsFileDefaultMode
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf(
			"WriteFileOfRecord cancelled after lstat for project %q file %q: %w",
			in.ProjectID, in.FileName, ctxErr)
	}

	// (3) Create the temp file in the SAME directory as the live file.
	// O_EXCL ensures we never silently overwrite an existing temp file.
	dir := filepath.Dir(livePath)
	tmp, err := os.CreateTemp(dir, ".byreis-atomic-*")
	if err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord: creating temp file in %q for project %q file %q: %w — "+
				"check directory write permissions",
			dir, in.ProjectID, in.FileName, err)
	}
	tmpPath := tmp.Name()

	// Ensure temp residue is removed on any failure after this point.
	defer func() {
		if retErr != nil {
			// Best-effort cleanup: close and remove the temp file.
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	// Immediately restrict the temp file to 0600 (O_EXCL guarantees it was
	// just created; we set mode before writing anything).
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord: chmod temp file %q to 0600: %w",
			tmpPath, err)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord cancelled after temp create for project %q file %q: %w",
			in.ProjectID, in.FileName, err)
	}

	// (4) Write SignedBytes verbatim — no re-encode, no normalization.
	if _, err := tmp.Write(in.SignedBytes); err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord: writing to temp file %q for project %q file %q: %w",
			tmpPath, in.ProjectID, in.FileName, err)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord cancelled after write for project %q file %q: %w",
			in.ProjectID, in.FileName, err)
	}

	// (5) fsync the temp file before rename.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord: fsync temp file %q for project %q file %q: %w",
			tmpPath, in.ProjectID, in.FileName, err)
	}

	// Close the temp file before rename to avoid cross-platform issues.
	if err := tmp.Close(); err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord: closing temp file %q for project %q file %q: %w",
			tmpPath, in.ProjectID, in.FileName, err)
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord cancelled before rename for project %q file %q: %w",
			in.ProjectID, in.FileName, err)
	}

	// (6) Apply the target mode to the temp file BEFORE the rename. This ensures
	// the live file's mode is not widened: if a file existed at 0600, we keep
	// it at 0600; if it didn't exist, we use the default 0600.
	if err := os.Chmod(tmpPath, targetMode); err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord: setting mode %04o on temp file %q: %w",
			targetMode, tmpPath, err)
	}

	// (7) Atomic rename: the ONLY live-path mutation. After this succeeds, the
	// live file is replaced atomically. The deferred cleanup will NOT run on
	// nil return (Go defer with named return retErr).
	if err := os.Rename(tmpPath, livePath); err != nil {
		return fmt.Errorf(
			"WriteFileOfRecord: atomic rename %q -> %q for project %q file %q: %w — "+
				"the live file is unchanged",
			tmpPath, livePath, in.ProjectID, in.FileName, err)
	}

	// Rename succeeded: clear retErr so the defer does not clean up the temp
	// (it's now the live file). The temp path no longer exists.
	retErr = nil

	// (8) fsync the parent directory after rename (best-effort durability;
	// a failure here is non-fatal because the rename already succeeded).
	dirSync(dir)

	return nil
}

// resolveLivePath joins repoRoot and livePath safely, rejecting any path that
// would escape the repo root. livePath must be a relative path (as supplied
// by the registry config); absolute paths are rejected.
func resolveLivePath(repoRoot, liveRelPath string) (string, error) {
	if filepath.IsAbs(liveRelPath) {
		return "", fmt.Errorf(
			"LiveRelPath must be a relative path, got absolute %q — "+
				"the path must come from the registry-configured project settings",
			liveRelPath)
	}
	if liveRelPath == "" {
		return "", fmt.Errorf("LiveRelPath must not be empty")
	}

	// Join and clean. filepath.Join + Abs handles ".." traversal.
	abs := filepath.Join(repoRoot, liveRelPath)
	abs = filepath.Clean(abs)

	// Path escape check: the cleaned path must be rooted at repoRoot.
	repoRootClean := filepath.Clean(repoRoot)
	rel, err := filepath.Rel(repoRootClean, abs)
	if err != nil || filepath.IsAbs(rel) || rel == ".." ||
		len(rel) >= 3 && rel[:3] == "../" {
		return "", fmt.Errorf(
			"LiveRelPath %q escapes the repository root %q — "+
				"the path must come from the registry-configured project settings",
			liveRelPath, repoRoot)
	}

	return abs, nil
}

// inspectLivePath performs a lstat on livePath:
//   - If the path does not exist, returns (0, false, nil).
//   - If the path is a symlink, returns (0, false, ErrSymlinkAtLivePath).
//   - If the path exists as a regular file, returns (mode, true, nil).
//   - Other stat errors are returned as-is.
func inspectLivePath(livePath string) (os.FileMode, bool, error) {
	fi, err := os.Lstat(livePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("lstat %q: %w", livePath, err)
	}

	// Reject symlinks.
	if fi.Mode()&os.ModeSymlink != 0 {
		return 0, false, fmt.Errorf("%w: %q", ErrSymlinkAtLivePath, livePath)
	}

	// Accept regular files only; reject directories, devices, etc.
	if !fi.Mode().IsRegular() {
		return 0, false, fmt.Errorf(
			"live path %q is not a regular file (mode %v) — "+
				"expected a regular secrets file",
			livePath, fi.Mode())
	}

	// Return the permission bits only (strip type bits).
	return fi.Mode().Perm(), true, nil
}

// dirSync best-effort fsyncs a directory. A failure is logged as a warning
// but does not fail the write (the rename already succeeded).
func dirSync(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
