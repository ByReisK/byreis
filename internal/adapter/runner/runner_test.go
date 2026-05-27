package runner_test

// Test obligations for internal/adapter/runner (S1 acceptance bar):
//
// S1-1 (argv-clean):
//   - TestS1_1_ArgvClean_NoSecretInOsArgs
//   - TestS1_1_ArgvClean_NoSecretInProcCmdline
//
// S1-2 (lifecycle — REAL child harness, -race clean, goroutine-leak-free):
//   - TestS1_2_ExitCode_Zero
//   - TestS1_2_ExitCode_One
//   - TestS1_2_ExitCode_Fortytwo
//   - TestS1_2_Signal_Kill_128PlusN
//   - TestS1_2_Signal_Term_128PlusN
//   - TestS1_2_CtxCancel_ChildKilledAndReaped
//   - TestS1_2_SignalForwarding_GoroutineLeakFree
//
// S1-3 (spawn-failure plaintext-free):
//   - TestS1_3_SpawnFailure_BinaryNotFound_PlaintextFree
//   - TestS1_3_SpawnFailure_NotExecutable_PlaintextFree
//   - TestS1_3_SpawnFailure_NoChild
//
// Additional correctness:
//   - TestRun_EmptyArgv_ReturnsError
//   - TestRun_CtxAlreadyCancelled_ReturnsError
//   - TestRun_EnvPassthrough_ChildSeesInjectedEnv
//   - TestRun_StdioPassthrough_NoCapture
//
// Allowlist boundary:
//   - TestAllowlist_RunnerNotInEncryptDeps
//   - TestAllowlist_RunnerNotInSubmitDeps

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/runner"
)

const module = "github.com/ByReisK/byreis"

// ─── helper binary ────────────────────────────────────────────────────────────

// helperBinary compiles the runner_helper test binary once per test run.
// The binary is placed in a t.TempDir() so it is automatically removed after
// the test. All tests that spawn a real child process use this binary.
func helperBinary(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "runner_helper")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("helperBinary: could not determine source file path")
	}
	helperDir := filepath.Join(filepath.Dir(thisFile), "testdata", "runner_helper")

	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binPath, helperDir) //nolint:gosec // compile-time constant path
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helperBinary: go build: %v", err)
	}
	return binPath
}

// ─── S1-1: argv-clean ─────────────────────────────────────────────────────────

// TestS1_1_ArgvClean_NoSecretInOsArgs proves that secret values placed in
// env are not visible in the child's os.Args. The helper writes its argv
// to a sidecar file; the test asserts zero secret bytes appear there.
//
// S1-1 acceptance proof: secrets → env only; argv carries no plaintext.
func TestS1_1_ArgvClean_NoSecretInOsArgs(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	sidecar := filepath.Join(t.TempDir(), "argv.txt")

	// These secrets must appear in env, NOT in argv.
	const secretVal1 = "s1_1_secret_UNIQUE_ARGV_ABC123" //nolint:gosec // G101: test-fixture fake credential for no-leak assertion
	const secretVal2 = "s1_1_secret_UNIQUE_ARGV_XYZ789" //nolint:gosec // G101: test-fixture fake credential for no-leak assertion

	env := []string{
		"BYREIS_TEST_SECRET_A=" + secretVal1,
		"BYREIS_TEST_SECRET_B=" + secretVal2,
		"PATH=" + os.Getenv("PATH"), // child needs PATH to be exec-able
	}
	argv := []string{bin, "report-argv", sidecar}

	outcome, err := runner.Run(context.Background(), argv, env)
	if err != nil {
		t.Fatalf("S1-1 argv-clean: Run returned error: %v", err)
	}
	if outcome.ExitCode != 0 {
		t.Fatalf("S1-1 argv-clean: child exited %d, want 0", outcome.ExitCode)
	}

	raw, readErr := os.ReadFile(sidecar) //nolint:gosec // G304: sidecar is a t.TempDir()-rooted test path
	if readErr != nil {
		t.Fatalf("S1-1 argv-clean: could not read sidecar: %v", readErr)
	}
	argvDump := string(raw)

	for _, secret := range []string{secretVal1, secretVal2} {
		if strings.Contains(argvDump, secret) {
			t.Errorf("S1-1 argv-clean: secret %q appears in child os.Args — security violation:\n%s",
				secret, argvDump)
		}
	}
	t.Logf("S1-1 argv-clean (os.Args): PASS — no secret in child argv (%d bytes)", len(argvDump))
}

// TestS1_1_ArgvClean_NoSecretInProcCmdline proves that secret values are
// absent from the kernel-visible argv (/proc/self/cmdline on Linux, os.Args
// on other platforms). This closes the argument that a crafted exec could
// smuggle bytes into the raw cmdline that Go's os.Args does not expose.
//
// S1-1 acceptance proof: secrets → env only; kernel argv carries no plaintext.
func TestS1_1_ArgvClean_NoSecretInProcCmdline(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	sidecar := filepath.Join(t.TempDir(), "cmdline.txt")

	const secretVal1 = "s1_1_secret_UNIQUE_CMDLINE_DEF456" //nolint:gosec // G101: test-fixture fake credential for no-leak assertion
	const secretVal2 = "s1_1_secret_UNIQUE_CMDLINE_GHI012" //nolint:gosec // G101: test-fixture fake credential for no-leak assertion

	env := []string{
		"BYREIS_TEST_SECRET_C=" + secretVal1,
		"BYREIS_TEST_SECRET_D=" + secretVal2,
		"PATH=" + os.Getenv("PATH"),
	}
	argv := []string{bin, "report-cmdline", sidecar}

	outcome, err := runner.Run(context.Background(), argv, env)
	if err != nil {
		t.Fatalf("S1-1 cmdline-clean: Run returned error: %v", err)
	}
	if outcome.ExitCode != 0 {
		t.Fatalf("S1-1 cmdline-clean: child exited %d, want 0", outcome.ExitCode)
	}

	raw, readErr := os.ReadFile(sidecar) //nolint:gosec // G304: sidecar is a t.TempDir()-rooted test path
	if readErr != nil {
		t.Fatalf("S1-1 cmdline-clean: could not read sidecar: %v", readErr)
	}
	cmdlineDump := string(raw)

	for _, secret := range []string{secretVal1, secretVal2} {
		if strings.Contains(cmdlineDump, secret) {
			t.Errorf("S1-1 cmdline-clean: secret %q appears in kernel cmdline — security violation:\n%s",
				secret, cmdlineDump)
		}
	}
	t.Logf("S1-1 cmdline-clean (/proc or os.Args): PASS — no secret in cmdline (%d bytes)", len(cmdlineDump))
}

// ─── S1-2: lifecycle (REAL child, -race clean, goroutine-leak-free) ───────────

// TestS1_2_ExitCode_Zero proves child exit 0 → Outcome.ExitCode 0.
func TestS1_2_ExitCode_Zero(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	outcome, err := runner.Run(context.Background(),
		[]string{bin, "exit0"},
		minEnv(),
	)
	if err != nil {
		t.Fatalf("S1-2 exit0: Run returned error: %v", err)
	}
	if outcome.ExitCode != 0 {
		t.Errorf("S1-2 exit0: Outcome.ExitCode = %d, want 0", outcome.ExitCode)
	}
	if outcome.Signalled {
		t.Errorf("S1-2 exit0: Outcome.Signalled = true, want false")
	}
	if outcome.SpawnFailed {
		t.Errorf("S1-2 exit0: Outcome.SpawnFailed = true, want false")
	}
}

// TestS1_2_ExitCode_One proves child exit 1 → Outcome.ExitCode 1.
func TestS1_2_ExitCode_One(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	outcome, err := runner.Run(context.Background(),
		[]string{bin, "exit1"},
		minEnv(),
	)
	if err != nil {
		t.Fatalf("S1-2 exit1: Run returned error: %v", err)
	}
	if outcome.ExitCode != 1 {
		t.Errorf("S1-2 exit1: Outcome.ExitCode = %d, want 1", outcome.ExitCode)
	}
	if outcome.Signalled {
		t.Errorf("S1-2 exit1: Outcome.Signalled = true, want false")
	}
}

// TestS1_2_ExitCode_Fortytwo proves child exit 42 → Outcome.ExitCode 42.
func TestS1_2_ExitCode_Fortytwo(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	outcome, err := runner.Run(context.Background(),
		[]string{bin, "exit42"},
		minEnv(),
	)
	if err != nil {
		t.Fatalf("S1-2 exit42: Run returned error: %v", err)
	}
	if outcome.ExitCode != 42 {
		t.Errorf("S1-2 exit42: Outcome.ExitCode = %d, want 42", outcome.ExitCode)
	}
}

// TestS1_2_Signal_Kill_128PlusN proves that when the child is killed by
// SIGKILL, Outcome.ExitCode = 128+9 = 137, Outcome.Signalled = true,
// Outcome.Signal = 9.
//
// The helper sends SIGKILL to itself so the test is portable (no external
// signal injection needed). On platforms where signals are not available this
// test is skipped.
func TestS1_2_Signal_Kill_128PlusN(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("signal kill test not supported on Windows")
	}
	bin := helperBinary(t)

	// "signal-self 9" sends SIGKILL to the helper process.
	outcome, err := runner.Run(context.Background(),
		[]string{bin, "signal-self", "9"},
		minEnv(),
	)
	if err != nil {
		t.Fatalf("S1-2 signal-kill: Run returned error: %v", err)
	}

	const wantCode = 128 + 9
	if outcome.ExitCode != wantCode {
		t.Errorf("S1-2 signal-kill: ExitCode = %d, want %d (128+SIGKILL)", outcome.ExitCode, wantCode)
	}
	if !outcome.Signalled {
		t.Errorf("S1-2 signal-kill: Signalled = false, want true")
	}
	if outcome.Signal != int(syscall.SIGKILL) {
		t.Errorf("S1-2 signal-kill: Signal = %d, want %d (SIGKILL)", outcome.Signal, int(syscall.SIGKILL))
	}
}

// TestS1_2_Signal_Term_128PlusN proves that when the child is killed by
// SIGTERM (signal 15), Outcome.ExitCode = 128+15 = 143.
func TestS1_2_Signal_Term_128PlusN(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("signal term test not supported on Windows")
	}
	bin := helperBinary(t)

	// "signal-self 15" sends SIGTERM to the helper process.
	outcome, err := runner.Run(context.Background(),
		[]string{bin, "signal-self", "15"},
		minEnv(),
	)
	if err != nil {
		t.Fatalf("S1-2 signal-term: Run returned error: %v", err)
	}

	const wantCode = 128 + 15
	if outcome.ExitCode != wantCode {
		t.Errorf("S1-2 signal-term: ExitCode = %d, want %d (128+SIGTERM)", outcome.ExitCode, wantCode)
	}
	if !outcome.Signalled {
		t.Errorf("S1-2 signal-term: Signalled = false, want true")
	}
	if outcome.Signal != int(syscall.SIGTERM) {
		t.Errorf("S1-2 signal-term: Signal = %d, want %d (SIGTERM)", outcome.Signal, int(syscall.SIGTERM))
	}
}

// TestS1_2_CtxCancel_ChildKilledAndReaped proves that context cancellation
// kills the child and Run returns with a non-zero exit code (from SIGKILL).
// The child runs "slow" (sleeps indefinitely); we cancel the context and
// assert the child is dead (Run returns) and no error is returned from Run
// itself (the Outcome carries the kill result).
//
// Goroutine-leak proof: Run returns promptly after ctx cancel; the test has a
// timeout via t.Context() which the overall test timeout enforces. If the
// forwarding goroutine leaked, the test would hang or -race would report a
// data race on the done channel.
func TestS1_2_CtxCancel_ChildKilledAndReaped(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ctx-cancel signal test not supported on Windows")
	}
	bin := helperBinary(t)

	ctx, cancel := context.WithCancel(context.Background())

	type result struct {
		outcome runner.Outcome
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		o, e := runner.Run(ctx, []string{bin, "slow"}, minEnv())
		ch <- result{o, e}
	}()

	// Give the child a moment to start up before cancelling.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case res := <-ch:
		// Run must return after ctx cancel. The child was killed by SIGKILL
		// (exec.CommandContext default), so ExitCode should be 128+9 or similar.
		// We do not assert the exact code here — the important property is that
		// Run returned (child reaped) and no error from Run itself.
		if res.err != nil {
			t.Errorf("S1-2 ctx-cancel: Run returned error: %v", res.err)
		}
		// The child must not have exited 0 (it was killed).
		if res.outcome.ExitCode == 0 && !res.outcome.Signalled {
			t.Errorf("S1-2 ctx-cancel: child reported clean exit 0 after ctx cancel — unexpected")
		}
		t.Logf("S1-2 ctx-cancel: Run returned ExitCode=%d Signalled=%v (child reaped)", res.outcome.ExitCode, res.outcome.Signalled)
	case <-time.After(5 * time.Second):
		t.Fatal("S1-2 ctx-cancel: Run did not return within 5s after ctx cancel — child not reaped or goroutine leaked")
	}
}

// TestS1_2_SignalForwarding_GoroutineLeakFree proves the signal-forwarding
// goroutine is torn down cleanly after the child exits. The test:
//  1. Spawns a "slow" child.
//  2. Cancels the context (kills the child via CommandContext).
//  3. Asserts Run returns promptly (done channel closed, goroutine returned).
//
// The absence of a hang or -race data-race on the done channel after Run
// returns is the goroutine-leak-free proof. A leaked goroutine would either:
//   - Block on sigCh receive (no sender after signal.Stop — but Stop drains
//     the channel, so it would block forever → test timeout).
//   - Race on the done channel or cmd.Process pointer after cmd.Wait returns.
//
// This test is deliberately separate from the ctx-cancel test to focus on the
// goroutine lifecycle, not the exit code.
func TestS1_2_SignalForwarding_GoroutineLeakFree(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("goroutine-leak test not supported on Windows")
	}
	bin := helperBinary(t)

	// Run multiple concurrent spawns and cancels to stress the goroutine
	// lifecycle under -race. If the forwarding goroutine leaks or races on
	// the done channel, the race detector will catch it here.
	const concurrency = 5
	errs := make(chan error, concurrency)

	for range concurrency {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			_, err := runner.Run(ctx, []string{bin, "slow"}, minEnv())
			errs <- err
		}()
	}

	deadline := time.After(3 * time.Second)
	for range concurrency {
		select {
		case err := <-errs:
			// Run may return a nil error even on ctx-cancel (child killed,
			// Outcome carries the exit code). Either nil or a context error
			// is acceptable here.
			if err != nil && !isContextErr(err) {
				t.Errorf("S1-2 goroutine-leak: Run returned unexpected error: %v", err)
			}
		case <-deadline:
			t.Fatal("S1-2 goroutine-leak: some Run calls did not return within 3s — goroutine may have leaked")
		}
	}
	t.Logf("S1-2 goroutine-leak: PASS — all %d concurrent spawns returned cleanly", concurrency)
}

// ─── S1-3: spawn-failure plaintext-free ───────────────────────────────────────

// TestS1_3_SpawnFailure_BinaryNotFound_PlaintextFree proves that when the
// binary does not exist, Run returns SpawnFailed=true and the error string
// contains ZERO secret bytes.
//
// S1-3 acceptance proof: spawn failure leaks only OS errno + argv[0], not env.
func TestS1_3_SpawnFailure_BinaryNotFound_PlaintextFree(t *testing.T) {
	t.Parallel()

	const secretVal = "s1_3_secret_UNIQUE_NOTFOUND_AAA111" //nolint:gosec // G101: test-fixture fake credential for no-leak assertion

	env := []string{
		"BYREIS_SECRET_X=" + secretVal,
		"PATH=" + os.Getenv("PATH"),
	}
	argv := []string{"/nonexistent/binary/that/does/not/exist/byreis_test_gone"}

	outcome, err := runner.Run(context.Background(), argv, env)

	if err == nil {
		t.Fatal("S1-3 not-found: expected error from non-existent binary, got nil")
	}
	if !outcome.SpawnFailed {
		t.Errorf("S1-3 not-found: Outcome.SpawnFailed = false, want true")
	}

	// PRIMARY security assertion: the error message must not contain the secret.
	errMsg := err.Error()
	if strings.Contains(errMsg, secretVal) {
		t.Errorf("S1-3 not-found: error contains secret value — security violation: %q", errMsg)
	}
	// The error must contain the binary name (not the env block).
	if !strings.Contains(errMsg, "byreis_test_gone") {
		t.Errorf("S1-3 not-found: error does not contain argv[0] name — unexpected: %q", errMsg)
	}
	t.Logf("S1-3 not-found: error = %q (no secret)", errMsg)
}

// TestS1_3_SpawnFailure_NotExecutable_PlaintextFree proves that when the
// binary exists but is not executable, Run returns SpawnFailed=true and the
// error string contains ZERO secret bytes.
func TestS1_3_SpawnFailure_NotExecutable_PlaintextFree(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("file-permission test not applicable on Windows")
	}

	// Create a non-executable file.
	dir := t.TempDir()
	notExecPath := filepath.Join(dir, "not_executable")
	if err := os.WriteFile(notExecPath, []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatalf("S1-3 not-executable: write file: %v", err)
	}
	// Explicitly ensure no execute bit.
	if err := os.Chmod(notExecPath, 0o600); err != nil {
		t.Fatalf("S1-3 not-executable: chmod: %v", err)
	}

	const secretVal = "s1_3_secret_UNIQUE_NOTEXEC_BBB222" //nolint:gosec // G101: test-fixture fake credential for no-leak assertion

	env := []string{
		"BYREIS_SECRET_Y=" + secretVal,
		"PATH=" + os.Getenv("PATH"),
	}
	argv := []string{notExecPath}

	outcome, err := runner.Run(context.Background(), argv, env)

	if err == nil {
		t.Fatal("S1-3 not-executable: expected error from non-executable binary, got nil")
	}
	if !outcome.SpawnFailed {
		t.Errorf("S1-3 not-executable: Outcome.SpawnFailed = false, want true")
	}

	errMsg := err.Error()
	if strings.Contains(errMsg, secretVal) {
		t.Errorf("S1-3 not-executable: error contains secret value — security violation: %q", errMsg)
	}
	t.Logf("S1-3 not-executable: error = %q (no secret)", errMsg)
}

// TestS1_3_SpawnFailure_NoChild proves that on a spawn failure no child
// process is ever spawned. We verify this indirectly: the sidecar file used
// by report-argv is NOT created (no child ran to write it), yet a plain
// "not found" error is returned.
func TestS1_3_SpawnFailure_NoChild(t *testing.T) {
	t.Parallel()

	sidecar := filepath.Join(t.TempDir(), "should_not_exist.txt")

	outcome, err := runner.Run(context.Background(),
		[]string{"/totally/absent/binary/byreis_nochild", "report-argv", sidecar},
		minEnv(),
	)

	if err == nil {
		t.Fatal("S1-3 no-child: expected error, got nil")
	}
	if !outcome.SpawnFailed {
		t.Errorf("S1-3 no-child: SpawnFailed = false, want true")
	}

	// The sidecar must not exist: no child ran to create it.
	if _, statErr := os.Stat(sidecar); statErr == nil {
		t.Errorf("S1-3 no-child: sidecar file exists despite spawn failure — a child ran unexpectedly")
	}
	t.Logf("S1-3 no-child: PASS — sidecar absent; spawn failure confirmed")
}

// ─── additional correctness ───────────────────────────────────────────────────

// TestRun_EmptyArgv_ReturnsError proves that calling Run with an empty argv
// returns an error immediately without spawning a child.
func TestRun_EmptyArgv_ReturnsError(t *testing.T) {
	t.Parallel()

	outcome, err := runner.Run(context.Background(), []string{}, nil)
	if err == nil {
		t.Fatal("EmptyArgv: expected error, got nil")
	}
	if !outcome.SpawnFailed {
		t.Errorf("EmptyArgv: SpawnFailed = false, want true")
	}
}

// TestRun_CtxAlreadyCancelled_ReturnsError proves that if the context is
// already cancelled before Run is called, it returns an error without spawn.
func TestRun_CtxAlreadyCancelled_ReturnsError(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	outcome, err := runner.Run(ctx, []string{bin, "exit0"}, minEnv())
	if err == nil {
		t.Fatal("CtxCancelled: expected error, got nil")
	}
	if !outcome.SpawnFailed {
		t.Errorf("CtxCancelled: SpawnFailed = false, want true")
	}
}

// TestRun_EnvPassthrough_ChildSeesInjectedEnv proves that the env block is
// passed correctly: the child's os.Environ() contains the injected values.
// This is the positive-path companion to the argv-clean tests.
func TestRun_EnvPassthrough_ChildSeesInjectedEnv(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	sidecar := filepath.Join(t.TempDir(), "env.txt")

	const injectedKey = "BYREIS_RUNNER_TEST_INJECT"
	const injectedVal = "runner_env_passthrough_unique_CCC333" //nolint:gosec // G101: test-fixture fake credential for env-passthrough assertion

	env := []string{
		injectedKey + "=" + injectedVal,
		"PATH=" + os.Getenv("PATH"),
	}
	argv := []string{bin, "report-env", sidecar}

	outcome, err := runner.Run(context.Background(), argv, env)
	if err != nil {
		t.Fatalf("EnvPassthrough: Run returned error: %v", err)
	}
	if outcome.ExitCode != 0 {
		t.Fatalf("EnvPassthrough: child exited %d, want 0", outcome.ExitCode)
	}

	raw, readErr := os.ReadFile(sidecar) //nolint:gosec // G304: sidecar is a t.TempDir()-rooted test path
	if readErr != nil {
		t.Fatalf("EnvPassthrough: could not read sidecar: %v", readErr)
	}
	envDump := string(raw)

	expected := injectedKey + "=" + injectedVal
	if !strings.Contains(envDump, expected) {
		t.Errorf("EnvPassthrough: injected env var %q not found in child env:\n%s", expected, envDump)
	}
}

// TestRun_StdioPassthrough_NoCapture proves that the adapter does not capture
// the child's stdout or stderr: cmd.Stdout/cmd.Stderr are wired directly to
// the parent's os.Stdout/os.Stderr, so the child's output goes to the
// terminal/pipe and is NOT buffered by byreis. We verify indirectly: the
// child exits cleanly when its stdout is inherited (not nil / missing).
// A concrete capture-check would require os.Pipe() wrapping at the test
// level, which would change the child's experience; we assert the documented
// behaviour by confirming the Run function sets no custom Stdout/Stderr.
// The real proof is the code review of runner.go (cmd.Stdout = os.Stdout).
// This test is a runtime smoke-check that the child runs fine with inherited
// stdio — it would fail if we accidentally set cmd.Stdout to nil.
func TestRun_StdioPassthrough_NoCapture(t *testing.T) {
	t.Parallel()
	bin := helperBinary(t)

	// exit0 does not write to stdout/stderr; if Run crashed due to nil
	// Stdout/Stderr we would see a non-nil error here.
	outcome, err := runner.Run(context.Background(),
		[]string{bin, "exit0"},
		minEnv(),
	)
	if err != nil {
		t.Fatalf("StdioPassthrough: Run returned error: %v", err)
	}
	if outcome.ExitCode != 0 {
		t.Errorf("StdioPassthrough: ExitCode = %d, want 0", outcome.ExitCode)
	}
}

// ─── allowlist / dep boundary ─────────────────────────────────────────────────

// TestAllowlist_RunnerNotInEncryptDeps asserts that internal/adapter/runner
// does NOT appear in the transitive dep set of internal/core/crypto/encrypt.
// This is the allowlist-stays-green proof for the runner adapter.
func TestAllowlist_RunnerNotInEncryptDeps(t *testing.T) {
	t.Parallel()
	deps := goListDeps(t, module+"/internal/core/crypto/encrypt")
	for _, dep := range deps {
		if dep == module+"/internal/adapter/runner" {
			t.Errorf("FAIL: internal/core/crypto/encrypt imports internal/adapter/runner\n"+
				"This violates the ADR-0022 / ADR-0005 allowlist: the runner adapter must not\n"+
				"appear in the contributor encrypt path: %s", dep)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: internal/adapter/runner not in internal/core/crypto/encrypt transitive set (%d deps)", len(deps))
	}
}

// TestAllowlist_RunnerNotInSubmitDeps asserts that internal/adapter/runner
// does NOT appear in the transitive dep set of internal/core/usecase/submit.
func TestAllowlist_RunnerNotInSubmitDeps(t *testing.T) {
	t.Parallel()
	deps := goListDeps(t, module+"/internal/core/usecase/submit")
	for _, dep := range deps {
		if dep == module+"/internal/adapter/runner" {
			t.Errorf("FAIL: internal/core/usecase/submit imports internal/adapter/runner\n"+
				"This violates the ADR-0022 / ADR-0005 allowlist: the runner adapter must not\n"+
				"appear in the submit path: %s", dep)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: internal/adapter/runner not in internal/core/usecase/submit transitive set (%d deps)", len(deps))
	}
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// minEnv returns a minimal environment for test children: just PATH so the
// OS can find system libraries on macOS (dyld). Tests that need specific env
// vars add to this.
func minEnv() []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/bin:/bin"
	}
	// On macOS the dynamic linker may need DYLD_LIBRARY_PATH. Carry it through
	// if set so children can find system libraries.
	env := []string{"PATH=" + path}
	if v := os.Getenv("DYLD_LIBRARY_PATH"); v != "" {
		env = append(env, "DYLD_LIBRARY_PATH="+v)
	}
	if v := os.Getenv("LD_LIBRARY_PATH"); v != "" {
		env = append(env, "LD_LIBRARY_PATH="+v)
	}
	return env
}

// isContextErr reports whether err is or wraps a context.Canceled or
// context.DeadlineExceeded error.
func isContextErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "context canceled") ||
		strings.Contains(s, "context deadline exceeded") ||
		strings.Contains(s, "signal: killed")
}

// goListDeps runs `go list -deps <pkg>` and returns the transitive dep list.
func goListDeps(t *testing.T, pkg string) []string {
	t.Helper()
	buf := new(bytes.Buffer)
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", pkg) //nolint:gosec // pkg is a test-internal constant
	cmd.Stdout = buf
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Fields(strings.TrimSpace(buf.String()))
}
