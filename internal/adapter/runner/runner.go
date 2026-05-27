// Package runner provides the production child-process spawner that implements
// the RunChild contract wired into cli.Deps at the composition root. It is the
// ONLY package in the codebase that imports os/exec and os/signal; those
// concerns must not appear in internal/core or internal/cli.
//
// Security properties this package is responsible for:
//   - Secrets never appear in the child argv (the caller builds argv from
//     non-secret user input; this package hands it to exec unchanged).
//   - The child receives secrets exclusively through its environment block
//     (the []string passed as env), which this package hands to os/exec
//     as cmd.Env — not appended to os.Environ().
//   - No child stdout/stderr is captured or buffered: Stdin/Stdout/Stderr are
//     wired directly to the parent's file descriptors (passthrough).
//   - The child is always reaped: Wait is called on every exit path (normal,
//     ctx-cancel, signal) so no zombie or orphan holding an env-block with
//     secret material can survive.
//   - Spawn failures carry only the OS error and argv[0] command name — never
//     any part of the env block.
package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// Outcome is the faithful result of a spawned child process. It is a plain
// value type; no os/exec or syscall type crosses into callers.
//
// Exit-code contract (mirrors POSIX shell conventions):
//   - Child exits N  → ExitCode N (0..255).
//   - Child killed by signal S → ExitCode 128+S, Signalled true, Signal S.
//   - Spawn failure (binary not found / not executable) → SpawnFailed true,
//     ExitCode 0 (meaningless), Signalled false.
type Outcome struct {
	// ExitCode is the child's exit code (0..255), or 128+signal if Signalled.
	ExitCode int
	// Signalled is true when the child was terminated by a signal.
	Signalled bool
	// Signal is the terminating signal number (valid only when Signalled is true).
	Signal int
	// SpawnFailed is true when the child process was never started (binary not
	// found, not executable, fork failure). When true, the returned error
	// describes the OS-level cause without exposing env-block content.
	SpawnFailed bool
}

// Run execs argv[0] with argv[1:] as a single child process, with env as the
// child's FULL environment block ([]string of "KEY=VALUE", already merged with
// injected-wins semantics by the caller). It inherits the parent's
// stdin/stdout/stderr without capture, forwards SIGINT and SIGTERM to the
// child, Wait-reaps on every exit path, and honors ctx cancellation by killing
// the child. It never builds a shell command string; argv is passed directly
// to execve.
//
// On a spawn failure the returned error contains only the OS errno and
// argv[0] — never any byte from env.
//
// The returned Outcome and error are mutually informative: a non-nil error
// with SpawnFailed=true means no child ran. A nil error means the child
// ran to completion (possibly with a non-zero exit code).
func Run(ctx context.Context, argv []string, env []string) (Outcome, error) {
	if len(argv) == 0 {
		return Outcome{SpawnFailed: true}, fmt.Errorf("runner: argv must not be empty")
	}

	// Fail immediately on an already-cancelled context so we never enter exec.
	if err := ctx.Err(); err != nil {
		return Outcome{SpawnFailed: true}, fmt.Errorf("runner: context already cancelled before spawn: %w", err)
	}

	// exec.CommandContext wires ctx-cancel → SIGKILL (or the cancel function
	// set below). We must not use a shell; argv[0] is the binary, argv[1:]
	// are arguments, and the OS receives them verbatim (no interpolation).
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv is caller-supplied; no shell; no interpolation
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// On ctx-cancel, exec.CommandContext sends SIGKILL by default on Go 1.20+.
	// We install a WaitDelay of zero (the default) — we do our own Wait below
	// so no second kill is needed. The default cancel func (os.Process.Kill) is
	// fine; we do not replace it.

	if err := cmd.Start(); err != nil {
		// Spawn failure: binary not found / permission denied / E2BIG.
		// Never format env into this error — only the OS error and argv[0].
		return Outcome{SpawnFailed: true}, fmt.Errorf("runner: failed to start %q: %w — "+
			"check that the command exists and is executable", argv[0], err)
	}

	// The child is running. Set up signal forwarding: SIGINT and SIGTERM
	// received by the byreis parent are forwarded to the child so that
	// interactive Ctrl-C propagates correctly and the child can clean up.
	//
	// The forwarding goroutine is torn down deterministically when the child
	// exits (done channel is closed). signal.Stop + channel drain guarantee
	// no goroutine leak regardless of exit path.
	// Buffer 2: absorbs one in-flight signal plus one that may arrive between
	// signal.Stop and the drain loop, preventing the forwarding goroutine from
	// blocking on the send and holding open after Wait returns.
	sigCh := make(chan os.Signal, 2) //nolint:mnd // 2 is the minimum safe buffer for stop+drain semantics
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		defer func() {
			// Stop delivering to sigCh and drain any pending signal so the
			// goroutine can return cleanly without blocking.
			signal.Stop(sigCh)
			for {
				select {
				case <-sigCh:
				default:
					return
				}
			}
		}()
		for {
			select {
			case sig := <-sigCh:
				// Forward the signal to the child. Ignore errors (child may
				// have just exited and the race is benign).
				if cmd.Process != nil {
					_ = cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	// Signal the forwarding goroutine to stop. The close + select in the
	// goroutine handles the race between a concurrent signal and Wait returning.
	close(done)

	return mapWaitError(waitErr), nil
}

// mapWaitError converts the error returned by cmd.Wait into an Outcome.
// A nil error means exit code 0. An *exec.ExitError means the child exited
// with a non-zero status or was killed by a signal.
func mapWaitError(err error) Outcome {
	if err == nil {
		return Outcome{ExitCode: 0}
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				sig := int(status.Signal())
				return Outcome{
					ExitCode:  128 + sig,
					Signalled: true,
					Signal:    sig,
				}
			}
			return Outcome{ExitCode: status.ExitStatus()}
		}
		// Fallback: use the ExitCode field directly (Windows / unknown platform).
		return Outcome{ExitCode: exitErr.ExitCode()}
	}

	// Some other Wait error (e.g. process was not started — should not happen
	// here since we checked Start). Treat as a non-zero exit.
	return Outcome{ExitCode: 1}
}
