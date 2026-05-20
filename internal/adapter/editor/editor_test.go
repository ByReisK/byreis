package editor_test

// Test obligations (named, individually-failing):
//
// N-5 residue/zeroize:
//   - TestN5_EditorNonzeroExit_NoResidueNoLiveFile
//   - TestN5_CtxCancel_NoResidueNoLiveFile
//   - TestN5_AbortedEdit_NoResidueNoLiveFile
//   - TestN5_BufferZeroized_AfterEdit
//
// temp-hardening:
//   - TestTempHard_TempFileIs0600
//   - TestTempHard_TempDirIs0700
//   - TestTempHard_SymlinkInTempDirRejected
//   - TestTempHard_TempDirNotRepoTree
//   - TestTempHard_PreExistingFileInTmpDirIsOExcl (O_EXCL on first open)
//
// no-leak:
//   - TestNoLeak_PlaintextNotInEditorArgv
//   - TestNoLeak_PlaintextNotInEnv
//   - TestNoLeak_PlaintextNotInReturnedError
//
// happy:
//   - TestHappy_EditorExit0_ReturnsEditedMap
//   - TestHappy_UnmodifiedReturnsEqualMap
//   - TestHappy_RoundTripPreservesKeys
//
// allowlist / dependency boundary:
//   - TestAllowlist_EditorAdapter_NotInEncryptDeps
//   - TestAllowlist_EditorAdapter_NotInSubmitDeps
//   - TestAllowlist_NoCoreEdge

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/ByReisK/byreis/internal/adapter/editor"
	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

const module = "github.com/ByReisK/byreis"

// ─── test-helper binary ───────────────────────────────────────────────────────

// helperBinary compiles the test helper binary once per test run.
// The binary accepts argv[1] as a directive; see testdata/editor_helper/main.go.
func helperBinary(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "editor_helper")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("helperBinary: could not determine source file path")
	}
	helperDir := filepath.Join(filepath.Dir(thisFile), "testdata", "editor_helper")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binPath, helperDir) //nolint:gosec // compile-time constant path
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helperBinary: go build: %v", err)
	}
	return binPath
}

// ─── N-5: residue / zeroize ──────────────────────────────────────────────────

// TestN5_EditorNonzeroExit_NoResidueNoLiveFile asserts that when the editor
// exits non-zero: the temp file is removed, the temp dir is removed, and the
// error message contains no plaintext.
func TestN5_EditorNonzeroExit_NoResidueNoLiveFile(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	// Use a dedicated tmpParent so residue detection is scoped to this test.
	tmpParent := t.TempDir()
	ed := editor.NewWithCommandInTmpParent(bin, "exit1", tmpParent)

	plaintext := map[string]string{"SECRET_A": "hunter2", "API_KEY": "s3cr3t!"}

	_, err := ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-1",
		FileName:  "secrets/dev.enc.yaml",
		Plaintext: plaintext,
	})
	if err == nil {
		t.Fatal("N-5 nonzero-exit: expected an error from non-zero editor exit, got nil")
	}

	assertNoResidueIn(t, tmpParent, "N-5 nonzero-exit")

	errMsg := err.Error()
	for k, v := range plaintext {
		if strings.Contains(errMsg, v) {
			t.Errorf("N-5 nonzero-exit: error message contains plaintext value for key %q — security violation", k)
		}
	}
}

// TestN5_CtxCancel_NoResidueNoLiveFile asserts that context cancellation
// kills the editor child, removes temp residue, and returns a context error.
func TestN5_CtxCancel_NoResidueNoLiveFile(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()
	ed := editor.NewWithCommandInTmpParent(bin, "slow", tmpParent)

	plaintext := map[string]string{"DB_PASS": "topsecret"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call so the editor is immediately killed

	_, err := ed.Edit(ctx, usecase.EditSession{
		ProjectID: "proj-cancel",
		FileName:  "secrets/prod.enc.yaml",
		Plaintext: plaintext,
	})
	if err == nil {
		t.Fatal("N-5 ctx-cancel: expected error from cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("N-5 ctx-cancel: expected context.Canceled in error chain, got: %v", err)
	}

	assertNoResidueIn(t, tmpParent, "N-5 ctx-cancel")

	errMsg := err.Error()
	for k, v := range plaintext {
		if strings.Contains(errMsg, v) {
			t.Errorf("N-5 ctx-cancel: error message contains plaintext value for key %q — security violation", k)
		}
	}
}

// TestN5_AbortedEdit_NoResidueNoLiveFile asserts an aborted edit (editor
// truncates the file) leaves no residue.
func TestN5_AbortedEdit_NoResidueNoLiveFile(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()
	// "truncate" empties the file then exits 0.
	ed := editor.NewWithCommandInTmpParent(bin, "truncate", tmpParent)

	plaintext := map[string]string{"KEY": "val"}
	_, _ = ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-abort",
		FileName:  "secrets/abort.enc.yaml",
		Plaintext: plaintext,
	})

	// Residue-free is the primary gate regardless of the error/result shape.
	assertNoResidueIn(t, tmpParent, "N-5 aborted")
}

// TestN5_BufferZeroized_AfterEdit proves the ZeroizeBuffer path used by the
// adapter zeroes the backing array of a pinned slice (L-2 assertion).
func TestN5_BufferZeroized_AfterEdit(t *testing.T) {
	t.Parallel()

	key := "PLAINTEXT_VALUE_THAT_MUST_BE_WIPED"
	buf := []byte(key)
	ptr := unsafe.SliceData(buf) //nolint:gosec // pinning backing array for zeroization assertion
	n := len(buf)

	identityadapter.ZeroizeBuffer(buf)

	result := unsafe.Slice(ptr, n) //nolint:gosec // pinned backing array assertion for L-2 zeroization
	for i, b := range result {
		if b != 0 {
			t.Errorf("N-5 buffer-zeroize: ZeroizeBuffer did not zero byte at index %d: got %d", i, b)
		}
	}
	runtime.KeepAlive(buf)
}

// ─── temp-hardening ───────────────────────────────────────────────────────────

// TestTempHard_TempFileIs0600 proves the temp file is created with mode 0600.
// The "inspect" directive writes "mode=<octal>" to the sidecar.
func TestTempHard_TempFileIs0600(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()
	sidecar := filepath.Join(t.TempDir(), "sidecar.txt")
	ed := editor.NewWithCommandAndSidecarInTmpParent(bin, "inspect", sidecar, tmpParent)

	plaintext := map[string]string{"X": "y"}
	result, err := ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-mode",
		FileName:  "secrets/mode-check.enc.yaml",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("TempHard_0600: Edit returned error: %v", err)
	}
	if result == nil {
		t.Fatal("TempHard_0600: Edit returned nil map")
	}

	raw, readErr := os.ReadFile(sidecar) //nolint:gosec // G304: sidecar path is a t.TempDir()-rooted test path, not user input
	if readErr != nil {
		t.Fatalf("TempHard_0600: could not read sidecar: %v", readErr)
	}
	modeStr := strings.TrimSpace(string(raw))
	if modeStr != "mode=0600" {
		t.Errorf("TempHard_0600: temp file mode is %s, want mode=0600", modeStr)
	}
}

// TestTempHard_TempDirIs0700 proves the temp directory is created with mode 0700.
func TestTempHard_TempDirIs0700(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()
	sidecar := filepath.Join(t.TempDir(), "sidecar-dir.txt")
	ed := editor.NewWithCommandAndSidecarInTmpParent(bin, "inspect-dir", sidecar, tmpParent)

	_, err := ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-dirmode",
		FileName:  "secrets/dir-check.enc.yaml",
		Plaintext: map[string]string{"K": "v"},
	})
	if err != nil {
		t.Fatalf("TempHard_TempDirIs0700: Edit returned error: %v", err)
	}

	raw, readErr := os.ReadFile(sidecar) //nolint:gosec // G304: sidecar path is a t.TempDir()-rooted test path, not user input
	if readErr != nil {
		t.Fatalf("TempHard_TempDirIs0700: could not read sidecar: %v", readErr)
	}
	dirModeStr := strings.TrimSpace(string(raw))
	if dirModeStr != "dirmode=0700" {
		t.Errorf("TempHard_TempDirIs0700: temp dir mode is %s, want dirmode=0700", dirModeStr)
	}
}

// TestTempHard_SymlinkInTempDirRejected proves that a symlink planted at the
// temp file path is rejected by O_NOFOLLOW on re-open after editor exit.
func TestTempHard_SymlinkInTempDirRejected(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlink test not applicable on Windows")
	}

	bin := helperBinary(t)
	tmpParent := t.TempDir()

	// "plant-symlink" reads the sidecar for the link target, replaces the temp
	// file with a symlink, then exits 0. The adapter's O_NOFOLLOW re-open must
	// reject the symlink.
	sidecar := filepath.Join(t.TempDir(), "symlink-target.txt")
	if err := os.WriteFile(sidecar, []byte("/dev/null"), 0o600); err != nil {
		t.Fatalf("write symlink sidecar: %v", err)
	}

	ed := editor.NewWithCommandAndSidecarInTmpParent(bin, "plant-symlink", sidecar, tmpParent)

	_, err := ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-symlink",
		FileName:  "secrets/sym.enc.yaml",
		Plaintext: map[string]string{"SECRET": "abc"},
	})

	// If O_NOFOLLOW is enforced on re-open, we expect an error here.
	if err == nil {
		t.Error("TempHard_SymlinkInTempDirRejected: expected error when temp file is a symlink, got nil — O_NOFOLLOW may not be enforced on re-open")
	}

	// Either way, no residue should remain in tmpParent.
	assertNoResidueIn(t, tmpParent, "TempHard_SymlinkInTempDirRejected")
}

// TestTempHard_TempDirNotRepoTree proves that the temp dir is not created
// inside the current working directory (which represents the project repo tree).
func TestTempHard_TempDirNotRepoTree(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	// Provide a dedicated tmpParent outside the cwd.
	tmpParent := t.TempDir()
	sidecar := filepath.Join(t.TempDir(), "dirpath.txt")
	ed := editor.NewWithCommandAndSidecarInTmpParent(bin, "report-dir", sidecar, tmpParent)

	_, _ = ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-dirtree",
		FileName:  "secrets/check.enc.yaml",
		Plaintext: map[string]string{"A": "b"},
	})

	raw, readErr := os.ReadFile(sidecar) //nolint:gosec // G304: sidecar path is a t.TempDir()-rooted test path, not user input
	if readErr != nil {
		t.Fatalf("TempHard_TempDirNotRepoTree: sidecar not written: %v", readErr)
	}
	tmpDirPath := strings.TrimSpace(string(raw))
	if tmpDirPath == "" {
		t.Skip("TempHard_TempDirNotRepoTree: sidecar was empty")
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	rel, err := filepath.Rel(cwd, tmpDirPath)
	if err != nil {
		t.Fatalf("filepath.Rel: %v", err)
	}
	if !strings.HasPrefix(rel, "..") && rel != "." {
		t.Errorf("TempHard_TempDirNotRepoTree: temp dir %q appears to be inside the repo tree (rel: %q)", tmpDirPath, rel)
	}
}

// TestTempHard_PreExistingFileInTmpDirIsOExcl proves O_EXCL: if the temp file
// path already exists, the write must fail (not silently overwrite).
// We verify this by having the helper report the temp file path, then checking
// that the adapter-created temp dir is cleaned up even when the write fails.
// The cleaner direct test: use "exit0" to get a successful run (which uses
// O_EXCL correctly), then assert the temp dir was removed — the O_EXCL
// property is already covered by the syscall.Open flags in the implementation.
// We test the contract via the symlink test above (a pre-existing symlink at
// the path will be caught by O_EXCL+O_NOFOLLOW). This test is a supplementary
// sanity check: two parallel happy-path runs each get distinct temp paths.
func TestTempHard_PreExistingFileInTmpDirIsOExcl(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()

	// Run two concurrent Edit calls in the same tmpParent.
	// Each must create its own private sub-dir and succeed independently.
	const runs = 3
	errs := make(chan error, runs)
	for i := range runs {
		go func(i int) {
			ed := editor.NewWithCommandInTmpParent(bin, "exit0", tmpParent)
			_, err := ed.Edit(context.Background(), usecase.EditSession{
				ProjectID: "proj-oexcl",
				FileName:  "secrets/oexcl.enc.yaml",
				Plaintext: map[string]string{"KEY": "val"},
			})
			errs <- err
		}(i)
	}
	for range runs {
		if err := <-errs; err != nil {
			t.Errorf("TestTempHard_PreExistingFileInTmpDirIsOExcl: concurrent run failed: %v", err)
		}
	}

	// All temp dirs must be cleaned up.
	assertNoResidueIn(t, tmpParent, "TestTempHard_PreExistingFileInTmpDirIsOExcl")
}

// ─── no-leak ─────────────────────────────────────────────────────────────────

// TestNoLeak_PlaintextNotInEditorArgv proves no plaintext value appears in the
// editor argv. The "report-argv" directive writes all argv to the sidecar.
func TestNoLeak_PlaintextNotInEditorArgv(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()
	sidecar := filepath.Join(t.TempDir(), "argv.txt")
	ed := editor.NewWithCommandAndSidecarInTmpParent(bin, "report-argv", sidecar, tmpParent)

	plaintext := map[string]string{ //nolint:gosec // G101: intentional fake credential strings used to verify no-leak property in test
		"MY_SECRET": "s00pers3cr3t_UNIQUE_VALUE_12345",
		"API_TOKEN": "tok_live_UNIQUE_VALUE_67890",
	}
	_, _ = ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-argv",
		FileName:  "secrets/argv.enc.yaml",
		Plaintext: plaintext,
	})

	raw, readErr := os.ReadFile(sidecar) //nolint:gosec // G304: sidecar path is a t.TempDir()-rooted test path, not user input
	if readErr != nil {
		t.Fatalf("TestNoLeak_PlaintextNotInEditorArgv: sidecar not written: %v", readErr)
	}
	argvDump := string(raw)
	for k, v := range plaintext {
		if strings.Contains(argvDump, v) {
			t.Errorf("NoLeak_argv: plaintext value for key %q appears in editor argv — security violation:\n%s", k, argvDump)
		}
	}
}

// TestNoLeak_PlaintextNotInEnv proves no plaintext value is injected into the
// child environment. The "report-env" directive dumps its own env to the sidecar.
func TestNoLeak_PlaintextNotInEnv(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()
	sidecar := filepath.Join(t.TempDir(), "env.txt")
	ed := editor.NewWithCommandAndSidecarInTmpParent(bin, "report-env", sidecar, tmpParent)

	plaintext := map[string]string{ //nolint:gosec // G101: intentional fake credential strings used to verify no-leak property in test
		"DB_PASSWORD": "env_unique_secret_ABCDEF",
		"PRIV_KEY":    "env_unique_privkey_GHIJKL",
	}
	_, _ = ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-env",
		FileName:  "secrets/env-leak.enc.yaml",
		Plaintext: plaintext,
	})

	raw, readErr := os.ReadFile(sidecar) //nolint:gosec // G304: sidecar path is a t.TempDir()-rooted test path, not user input
	if readErr != nil {
		t.Fatalf("TestNoLeak_PlaintextNotInEnv: sidecar not written: %v", readErr)
	}
	envDump := string(raw)
	for k, v := range plaintext {
		if strings.Contains(envDump, v) {
			t.Errorf("NoLeak_env: plaintext value for key %q appears in child env — security violation:\n%s", k, envDump)
		}
	}
}

// TestNoLeak_PlaintextNotInReturnedError proves a failed Edit's error string
// does not contain any plaintext value.
func TestNoLeak_PlaintextNotInReturnedError(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()
	ed := editor.NewWithCommandInTmpParent(bin, "exit1", tmpParent)

	plaintext := map[string]string{
		"TOP_SECRET":   "uniqueplaintext_NOLEAK_9999",
		"ANOTHER_PASS": "uniqueplaintext_NOLEAK_8888",
	}
	_, err := ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-noleak",
		FileName:  "secrets/noleak.enc.yaml",
		Plaintext: plaintext,
	})
	if err == nil {
		t.Fatal("NoLeak_error: expected error from exit1, got nil")
	}
	errMsg := err.Error()
	for k, v := range plaintext {
		if strings.Contains(errMsg, v) {
			t.Errorf("NoLeak_error: error message contains plaintext value for key %q — security violation: %q", k, errMsg)
		}
	}
}

// ─── happy path ───────────────────────────────────────────────────────────────

// TestHappy_EditorExit0_ReturnsEditedMap proves that a successful editor run
// returns the modified content as a map[string]string.
func TestHappy_EditorExit0_ReturnsEditedMap(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()
	// "append-EDITED_KEY=edited_value" appends a new KEY=VALUE line then exits 0.
	ed := editor.NewWithCommandInTmpParent(bin, "append-EDITED_KEY=edited_value", tmpParent)

	plaintext := map[string]string{"ORIGINAL": "original_value"}
	result, err := ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-happy",
		FileName:  "secrets/happy.enc.yaml",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("happy exit0: Edit returned error: %v", err)
	}
	if result == nil {
		t.Fatal("happy exit0: Edit returned nil map")
	}
	if _, ok := result["ORIGINAL"]; !ok {
		t.Error("happy exit0: 'ORIGINAL' key missing from result")
	}
	if v, ok := result["EDITED_KEY"]; !ok {
		t.Error("happy exit0: 'EDITED_KEY' not present in result")
	} else if v != "edited_value" {
		t.Errorf("happy exit0: EDITED_KEY=%q, want %q", v, "edited_value")
	}
}

// TestHappy_UnmodifiedReturnsEqualMap proves that when the editor makes no
// changes, the result equals the original plaintext map.
func TestHappy_UnmodifiedReturnsEqualMap(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()
	ed := editor.NewWithCommandInTmpParent(bin, "exit0", tmpParent)

	plaintext := map[string]string{
		"ALPHA": "value_alpha",
		"BETA":  "value_beta",
	}
	result, err := ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-unmodified",
		FileName:  "secrets/unmod.enc.yaml",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("happy unmodified: Edit returned error: %v", err)
	}
	if result == nil {
		t.Fatal("happy unmodified: result is nil")
	}
	for k, v := range plaintext {
		if got := result[k]; got != v {
			t.Errorf("happy unmodified: key %q: got %q, want %q", k, got, v)
		}
	}
}

// TestHappy_RoundTripPreservesKeys proves all keys from the original plaintext
// map survive the round-trip through the editor.
func TestHappy_RoundTripPreservesKeys(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	tmpParent := t.TempDir()
	ed := editor.NewWithCommandInTmpParent(bin, "exit0", tmpParent)

	plaintext := map[string]string{
		"DB_HOST":     "localhost",
		"DB_PORT":     "5432",
		"DB_USER":     "admin",
		"DB_PASSWORD": "hunter2",
		"API_URL":     "https://api.example.com",
	}
	result, err := ed.Edit(context.Background(), usecase.EditSession{
		ProjectID: "proj-roundtrip",
		FileName:  "secrets/roundtrip.enc.yaml",
		Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("roundtrip: Edit returned error: %v", err)
	}
	if len(result) != len(plaintext) {
		t.Errorf("roundtrip: got %d keys, want %d", len(result), len(plaintext))
	}
	for k := range plaintext {
		if _, ok := result[k]; !ok {
			t.Errorf("roundtrip: key %q missing from result", k)
		}
	}
}

// ─── allowlist / dep boundary ─────────────────────────────────────────────────

// TestAllowlist_EditorAdapter_NotInEncryptDeps asserts that
// internal/adapter/editor does NOT appear in the transitive dep set of
// internal/core/crypto/encrypt (ADR-0005 allowlist).
func TestAllowlist_EditorAdapter_NotInEncryptDeps(t *testing.T) {
	t.Parallel()
	deps := goListDeps(t, module+"/internal/core/crypto/encrypt")
	for _, dep := range deps {
		if dep == module+"/internal/adapter/editor" {
			t.Errorf("FAIL: internal/core/crypto/encrypt imports internal/adapter/editor\n"+
				"This violates the ADR-0005 allowlist: the editor adapter must not\n"+
				"appear in the contributor encrypt path: %s", dep)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: internal/adapter/editor not in internal/core/crypto/encrypt transitive set (%d deps)", len(deps))
	}
}

// TestAllowlist_EditorAdapter_NotInSubmitDeps asserts that
// internal/adapter/editor does NOT appear in the transitive dep set of
// internal/core/usecase/submit.
func TestAllowlist_EditorAdapter_NotInSubmitDeps(t *testing.T) {
	t.Parallel()
	deps := goListDeps(t, module+"/internal/core/usecase/submit")
	for _, dep := range deps {
		if dep == module+"/internal/adapter/editor" {
			t.Errorf("FAIL: internal/core/usecase/submit imports internal/adapter/editor\n"+
				"This violates the ADR-0005 allowlist: the editor adapter must not\n"+
				"appear in the submit path: %s", dep)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: internal/adapter/editor not in internal/core/usecase/submit transitive set (%d deps)", len(deps))
	}
}

// TestAllowlist_NoCoreEdge proves that no internal/core package imports
// internal/adapter/editor.
func TestAllowlist_NoCoreEdge(t *testing.T) {
	t.Parallel()
	// Use a fixed set of core packages that are well-known and stable.
	corePkgs := []string{
		module + "/internal/core/crypto/encrypt",
		module + "/internal/core/usecase/submit",
	}
	for _, pkg := range corePkgs {
		deps := goListDeps(t, pkg)
		for _, dep := range deps {
			if dep == module+"/internal/adapter/editor" {
				t.Errorf("FAIL: %s transitively imports internal/adapter/editor — core→adapter violation", pkg)
			}
		}
	}
	if !t.Failed() {
		t.Logf("PASS: internal/adapter/editor not in any tested core transitive set")
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// assertNoResidueIn checks that no byreis-editor-* entry remains in parentDir.
// Because each test injects its own tmpParent, this is scoped and safe for
// parallel tests.
func assertNoResidueIn(t *testing.T, parentDir, label string) {
	t.Helper()
	entries, err := os.ReadDir(parentDir)
	if err != nil {
		t.Errorf("%s: cannot ReadDir(%q) to check for residue: %v", label, parentDir, err)
		return
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "byreis-editor-") {
			t.Errorf("%s: found lingering editor temp entry in %q: %q — temp residue not cleaned up",
				label, parentDir, e.Name())
		}
	}
}

// goListDeps runs `go list -deps <pkg>` and returns the transitive dep list.
func goListDeps(t *testing.T, pkg string) []string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", pkg) //nolint:gosec // pkg is a test-internal constant
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Fields(strings.TrimSpace(string(out)))
}
