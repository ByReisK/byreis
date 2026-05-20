// Package editor provides the production usecase.Editor adapter that runs
// $EDITOR (or $VISUAL, then a documented fallback) with the decrypted plaintext
// in a private temp file. The file is created in a process-private 0700
// MkdirTemp directory, opened O_CREATE|O_EXCL|O_WRONLY with O_NOFOLLOW
// semantics to prevent symlink attacks, and zeroized + removed on every exit
// path. No plaintext is ever placed in argv, env, logs, or error messages.
//
// The no-clobber invariant: this adapter only produces the edited
// map[string]string. The use-case (edit.go) + AtomicFileWriter are the
// sole mutators of the live secrets file; this adapter has no path to any
// live file and never touches it.
package editor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// tempDirPattern is the prefix used for the MkdirTemp call.
const tempDirPattern = "byreis-editor-"

// defaultFallback is the editor used when $EDITOR and $VISUAL are both unset.
// It is documented and will fail at exec time if the binary is absent.
const defaultFallback = "vi"

// editorAdapter is the concrete usecase.Editor.
type editorAdapter struct {
	// cmd overrides the binary lookup. Empty means use $EDITOR/$VISUAL/fallback.
	cmd string
	// extraArgs is inserted between cmd and the temp file path. Used by tests
	// to pass a directive to the helper binary.
	extraArgs []string
	// sidecarArg is inserted between extraArgs and the temp file path. Only
	// used by test constructors; empty in production.
	sidecarArg string
	// tmpParent is the parent directory for MkdirTemp. Empty means the OS default.
	// Tests inject t.TempDir() here to get an isolated parent they can inspect.
	tmpParent string
	// postWriteHook is called immediately after writeWithNoFollow succeeds and
	// before the editor binary is launched. It is nil in all production
	// constructors; only the testhook-tagged NewWithAfterWriteHook sets it.
	// The nil check in Edit is always cheap; the field costs nothing in production.
	postWriteHook func()
}

// New returns a production usecase.Editor that resolves the editor binary
// from $EDITOR, then $VISUAL, then the documented fallback (vi).
func New() usecase.Editor {
	return &editorAdapter{}
}

// NewWithCommand returns a usecase.Editor configured to run a specific binary
// with an additional argument (used by tests to inject the helper binary and
// its directive without touching $EDITOR).
func NewWithCommand(binPath, directive string) usecase.Editor {
	return &editorAdapter{cmd: binPath, extraArgs: []string{directive}}
}

// NewWithCommandInTmpParent returns a usecase.Editor that uses tmpParent as
// the parent directory for the private temp dir. Used by tests to provide
// an isolated, inspectable temp-parent scope.
func NewWithCommandInTmpParent(binPath, directive, tmpParent string) usecase.Editor {
	return &editorAdapter{cmd: binPath, extraArgs: []string{directive}, tmpParent: tmpParent}
}

// NewWithCommandAndSidecar returns a usecase.Editor configured to run a
// specific binary with a directive and a sidecar path argument (used by tests
// that need to receive inspection data from the helper binary).
func NewWithCommandAndSidecar(binPath, directive, sidecarPath string) usecase.Editor {
	return &editorAdapter{
		cmd:        binPath,
		extraArgs:  []string{directive},
		sidecarArg: sidecarPath,
	}
}

// NewWithCommandAndSidecarInTmpParent combines sidecar + tmpParent injection
// for tests that need both.
func NewWithCommandAndSidecarInTmpParent(binPath, directive, sidecarPath, tmpParent string) usecase.Editor {
	return &editorAdapter{
		cmd:        binPath,
		extraArgs:  []string{directive},
		sidecarArg: sidecarPath,
		tmpParent:  tmpParent,
	}
}

// Compile-time assertion.
var _ usecase.Editor = (*editorAdapter)(nil)

// Edit implements usecase.Editor.
//
// Sequence:
//  1. Resolve the editor binary.
//  2. Create a private MkdirTemp(0700) directory outside the repo tree.
//  3. Create the temp file inside it with O_CREATE|O_EXCL|O_WRONLY and
//     O_NOFOLLOW semantics (via syscall.Open) at mode 0600.
//  4. Serialise in.Plaintext as KEY=VALUE lines into the temp file.
//     No plaintext is placed in argv or the child environment.
//  5. Launch the editor with the temp file PATH as the only argument.
//     Monitor ctx; cancel kills the child.
//  6. On editor exit 0, re-open the file with O_NOFOLLOW and parse the
//     result back into a map[string]string.
//  7. On EVERY exit path (error, non-zero exit, ctx cancel, panic):
//     truncate + remove the temp file, remove the temp dir, and zeroize
//     all in-memory plaintext buffers.
func (e *editorAdapter) Edit(ctx context.Context, in usecase.EditSession) (result map[string]string, err error) {
	// Fail immediately if the context is already cancelled.
	if err = ctx.Err(); err != nil {
		return nil, fmt.Errorf("editor: context cancelled before starting: %w", err)
	}

	// Resolve the editor binary.
	editorBin, err := e.resolveEditor()
	if err != nil {
		return nil, err
	}

	// Create a process-private temp directory with mode 0700. os.MkdirTemp
	// creates the directory; we chmod it explicitly to guard against umask.
	// tmpParent is empty in production (uses OS temp dir); tests inject a
	// dedicated parent so residue assertions are scoped to that parent.
	tmpDir, err := os.MkdirTemp(e.tmpParent, tempDirPattern)
	if err != nil {
		return nil, fmt.Errorf("editor: creating private temp directory: %w — "+
			"check that the temp directory is writable", err)
	}
	// Enforce 0700 regardless of the process umask.
	if chmodErr := os.Chmod(tmpDir, 0o700); chmodErr != nil { //nolint:gosec // G302: 0700 is the required mode for a process-private temp dir; world-accessible mode is explicitly the attack we prevent
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("editor: setting temp directory permissions: %w", chmodErr)
	}

	// Build the temp file path — a fixed name inside the private dir.
	tmpFile := tmpDir + string(os.PathSeparator) + "plaintext.yaml"

	// plainBuf holds the serialised plaintext. We keep the backing slice so
	// we can zeroize it on every exit path including a panic.
	plainBuf := serializePlaintext(in.Plaintext)

	// cleanup is the single structural owner of plainBuf zeroization and temp
	// residue removal. The deferred call below runs on every exit path from
	// this point — including panics from injected dependencies or the runtime —
	// ensuring no plaintext temp file or in-memory buffer survives.
	cleanup := func() {
		identityadapter.ZeroizeBuffer(plainBuf)
		// Best-effort truncate before removal to reduce the observation window.
		_ = truncateFile(tmpFile)
		_ = os.Remove(tmpFile)
		_ = os.RemoveAll(tmpDir)
	}
	// Panic-safe single-owner defer: registered immediately so any panic after
	// this point (runtime, injected dependency, future refactor) still wipes
	// plainBuf and removes the temp file/dir before the stack unwinds.
	defer cleanup()

	// Write plaintext to temp file using O_NOFOLLOW + O_EXCL + O_WRONLY.
	if err = writeWithNoFollow(tmpFile, plainBuf); err != nil {
		return nil, fmt.Errorf("editor: writing plaintext to temp file: %w", err)
	}

	// postWriteHook is nil in all production constructors. Under the testhook
	// build tag, panic-injection tests set a panicking hook here to prove the
	// deferred cleanup still wipes the plaintext temp file on the panic path.
	if e.postWriteHook != nil {
		e.postWriteHook()
	}

	// Build the editor command. The temp file path is the ONLY extra argument
	// after any test-injected directive/sidecar args.
	argv := e.buildArgv(editorBin, tmpFile)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv is constructed from the resolved editor binary + temp path; no user input in argv
	// Attach stdout/stderr of the editor to the process's own stdout/stderr.
	// We do NOT capture them (which would risk echoing plaintext if the editor
	// writes to them). No custom Env: no plaintext in the child environment.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run the editor, watching ctx for cancellation.
	runErr := cmd.Run()

	// Check ctx error first: if context was cancelled we always return a ctx
	// error regardless of the process exit code.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("editor: context cancelled while running editor: %w", ctxErr)
	}

	if runErr != nil {
		return nil, fmt.Errorf("editor: editor exited with a non-zero status "+
			"(the live file was not modified): %w — re-run to retry the edit",
			runErr)
	}

	// Editor exited 0. Re-open the temp file with O_NOFOLLOW to read the
	// edited content. A symlink planted after our O_EXCL create is rejected.
	// Capture into outer-scope vars so the deferred cleanup runs AFTER this
	// read completes (same effective ordering as before, now structurally enforced).
	var edited []byte
	var readErr error
	edited, readErr = readWithNoFollow(tmpFile)

	if readErr != nil {
		return nil, fmt.Errorf("editor: reading edited temp file: %w — "+
			"the live file was not modified", readErr)
	}

	var parseErr error
	result, parseErr = parsePlaintext(edited)
	if parseErr != nil {
		return nil, fmt.Errorf("editor: parsing edited content: %w — "+
			"the live file was not modified", parseErr)
	}

	return result, nil
}

// resolveEditor returns the editor binary to use: cmd override (tests), then
// $EDITOR, then $VISUAL, then the documented fallback (vi).
func (e *editorAdapter) resolveEditor() (string, error) {
	if e.cmd != "" {
		return e.cmd, nil
	}
	if v := os.Getenv("EDITOR"); v != "" {
		return v, nil
	}
	if v := os.Getenv("VISUAL"); v != "" {
		return v, nil
	}
	return defaultFallback, nil
}

// buildArgv constructs the editor argv slice. The tmp file path is always
// the last element. Test-injected directives/sidecar args are interleaved.
func (e *editorAdapter) buildArgv(editorBin, tmpFile string) []string {
	argv := make([]string, 0, 1+len(e.extraArgs)+2)
	argv = append(argv, editorBin)
	argv = append(argv, e.extraArgs...)
	if e.sidecarArg != "" {
		argv = append(argv, e.sidecarArg)
	}
	argv = append(argv, tmpFile)
	return argv
}

// writeWithNoFollow creates the temp file at path with O_CREATE|O_EXCL|O_WRONLY
// and O_NOFOLLOW semantics at mode 0600, writes buf, and closes the file.
// O_NOFOLLOW prevents a symlink at the path from being followed; O_EXCL
// prevents creation if the path already exists (no clobber).
func writeWithNoFollow(path string, buf []byte) error {
	flags := syscall.O_CREAT | syscall.O_EXCL | syscall.O_WRONLY | noFollowFlag()
	fd, err := syscall.Open(path, flags, 0o600)
	if err != nil {
		if err == syscall.EEXIST {
			return fmt.Errorf("temp file %q already exists (O_EXCL): "+
				"refusing to overwrite — possible collision in temp directory", path)
		}
		if isSymlinkErrno(err) {
			return fmt.Errorf("temp file path %q is a symlink (O_NOFOLLOW): "+
				"refusing to follow symlink — possible symlink-swap attack", path)
		}
		return fmt.Errorf("opening temp file for write: %w", &os.PathError{
			Op: "open", Path: path, Err: err})
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()

	// Enforce mode 0600 after open to guard against umask.
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("setting temp file permissions: %w", err)
	}

	if _, err := f.Write(buf); err != nil {
		return fmt.Errorf("writing plaintext to temp file: %w", err)
	}
	return nil
}

// readWithNoFollow opens path with O_RDONLY and O_NOFOLLOW, reads its content,
// and returns it. A symlink at path is rejected.
func readWithNoFollow(path string) ([]byte, error) {
	flags := syscall.O_RDONLY | noFollowFlag()
	fd, err := syscall.Open(path, flags, 0)
	if err != nil {
		if isSymlinkErrno(err) {
			return nil, fmt.Errorf("temp file %q is a symlink (O_NOFOLLOW): "+
				"refusing to read — possible symlink-swap attack", path)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		return nil, fmt.Errorf("reading temp file: %w", err)
	}
	return buf.Bytes(), nil
}

// truncateFile opens the file for writing and truncates it to zero length,
// best-effort overwriting the plaintext before removal.
func truncateFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // path is the adapter-created temp file path, not user-controlled
	if err != nil {
		return err
	}
	return f.Close()
}

// serializePlaintext encodes the key→value map as KEY=VALUE lines. The
// returned []byte is a freshly allocated buffer owned by the caller; the
// caller must zeroize it after use via ZeroizeBuffer.
//
// Values containing newlines are not supported and will break round-trip
// parsing; the use-case is responsible for validating values before calling Edit.
func serializePlaintext(m map[string]string) []byte {
	var sb strings.Builder
	keys := sortedKeys(m)
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(m[k])
		sb.WriteByte('\n')
	}
	result := []byte(sb.String())
	sb.Reset()
	return result
}

// parsePlaintext decodes KEY=VALUE lines into a map. Blank lines and lines
// beginning with '#' are skipped. Lines without '=' are skipped. An empty
// input produces an empty map (not an error); the use-case (edit.go) rejects
// an empty map separately.
func parsePlaintext(b []byte) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := line[:idx]
		val := line[idx+1:]
		if key == "" {
			continue
		}
		result[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parsing edited plaintext: %w", err)
	}
	return result, nil
}

// sortedKeys returns the keys of m in ascending order for deterministic output.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// noFollowFlag returns the platform-specific O_NOFOLLOW flag.
func noFollowFlag() int {
	return openNoFollowFlag()
}

// isSymlinkErrno reports whether errno indicates a symlink was encountered
// when O_NOFOLLOW was set. ELOOP is the standard errno; ENOTDIR is also
// returned by some kernels.
func isSymlinkErrno(err error) bool {
	return err == syscall.ELOOP || (runtime.GOOS != "windows" && errors.Is(err, syscall.ENOTDIR))
}
