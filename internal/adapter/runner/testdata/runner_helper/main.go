// runner_helper is a test-only binary that simulates various child-process
// behaviours for the runner adapter tests. It is compiled by the test suite
// at runtime and never shipped in production binaries.
//
// Usage: runner_helper <directive> [sidecar-path]
//
// Directives:
//
//	exit0             — exits 0 immediately.
//	exit1             — exits 1 immediately.
//	exit42            — exits 42 immediately.
//	slow              — sleeps until killed; used for ctx-cancel and signal tests.
//	report-argv       — writes os.Args (one per line) to sidecar, then exits 0.
//	report-cmdline    — writes raw argv bytes to sidecar: on Linux reads
//	                    /proc/self/cmdline (NUL-delimited); on other platforms
//	                    uses os.Args. Exits 0. Proves no secret appears in the
//	                    kernel-visible argv, not just in Go's os.Args.
//	signal-self <SIG> — sends signal SIG (SIGKILL=9, SIGTERM=15, etc.) to itself
//	                    and then sleeps; used to test 128+N exit-code mapping.
//	sigint-self       — sends SIGINT to itself, then sleeps.
//	report-env        — writes os.Environ() (one per line) to sidecar, exits 0.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() { //nolint:cyclop,gocognit // test helper intentionally has many directive branches
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "runner_helper: missing directive")
		os.Exit(2)
	}
	directive := os.Args[1]

	// sidecar is the optional second argument used by reporting directives.
	sidecar := ""
	if len(os.Args) >= 3 {
		sidecar = os.Args[2]
	}

	switch {
	case directive == "exit0":
		os.Exit(0)

	case directive == "exit1":
		os.Exit(1)

	case directive == "exit42":
		os.Exit(42)

	case directive == "slow":
		// Sleep until killed. ctx-cancel and signal-forwarding tests rely on
		// the adapter killing this process.
		time.Sleep(60 * time.Second)
		os.Exit(0)

	case directive == "report-argv":
		if sidecar == "" {
			fmt.Fprintln(os.Stderr, "runner_helper report-argv: missing sidecar path")
			os.Exit(2)
		}
		dump := strings.Join(os.Args, "\n")
		writeSidecar(sidecar, dump)
		os.Exit(0)

	case directive == "report-cmdline":
		// Read the raw kernel argv. On Linux, /proc/self/cmdline contains all
		// argument bytes NUL-delimited — this is what the kernel actually holds
		// and what tools like ps(1) inspect. On non-Linux platforms we fall back
		// to os.Args which is sufficient for the test assertion.
		if sidecar == "" {
			fmt.Fprintln(os.Stderr, "runner_helper report-cmdline: missing sidecar path")
			os.Exit(2)
		}
		dump := readCmdline()
		writeSidecar(sidecar, dump)
		os.Exit(0)

	case directive == "signal-self":
		// Send a specific signal to self so that the process terminates with a
		// signal-caused exit. The caller provides the signal number as argv[2],
		// and the sidecar path (if any) as argv[3]. We remap the positional args
		// here: sidecar variable above may hold the signal number if it was
		// provided without a sidecar — use explicit indexing.
		//
		// Invocation shape: runner_helper signal-self <signum>
		// (no sidecar needed — the test inspects the Outcome.ExitCode)
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "runner_helper signal-self: missing signal number")
			os.Exit(2)
		}
		signumStr := os.Args[2]
		signum, err := strconv.Atoi(signumStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "runner_helper signal-self: bad signal number %q: %v\n", signumStr, err)
			os.Exit(2)
		}
		// Send the signal to self. On Linux/macOS this kills the process with
		// the signal, producing the 128+N exit code in the parent Wait.
		proc, err := os.FindProcess(os.Getpid())
		if err != nil {
			fmt.Fprintf(os.Stderr, "runner_helper signal-self: FindProcess: %v\n", err)
			os.Exit(2)
		}
		if err := proc.Signal(syscall.Signal(signum)); err != nil {
			fmt.Fprintf(os.Stderr, "runner_helper signal-self: Signal: %v\n", err)
			os.Exit(2)
		}
		// Sleep so the signal has time to land before we could fall through.
		time.Sleep(10 * time.Second)
		os.Exit(0)

	case directive == "sigint-self":
		// Convenience alias: sends SIGINT to self. Useful for the
		// signal-forwarding test where the test sends SIGINT to byreis and the
		// adapter must forward it to the child.
		proc, err := os.FindProcess(os.Getpid())
		if err != nil {
			fmt.Fprintf(os.Stderr, "runner_helper sigint-self: FindProcess: %v\n", err)
			os.Exit(2)
		}
		if err := proc.Signal(syscall.SIGINT); err != nil {
			fmt.Fprintf(os.Stderr, "runner_helper sigint-self: Signal: %v\n", err)
			os.Exit(2)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)

	case directive == "report-env":
		if sidecar == "" {
			fmt.Fprintln(os.Stderr, "runner_helper report-env: missing sidecar path")
			os.Exit(2)
		}
		dump := strings.Join(os.Environ(), "\n")
		writeSidecar(sidecar, dump)
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "runner_helper: unknown directive %q\n", directive)
		os.Exit(2)
	}
}

// writeSidecar writes content to path and exits 1 on failure.
func writeSidecar(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec // test helper writes to sidecar path provided by the test
		fmt.Fprintf(os.Stderr, "runner_helper: write sidecar %q: %v\n", path, err)
		os.Exit(1)
	}
}
