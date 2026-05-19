// Package render implements TTY/JSON/pipe output, secret masking, and exit-code
// mapping. No business logic — pure presentation.
//
// Smart TTY detection: mask secrets in a terminal, plain output when piped;
// --json for machine output; meaningful exit codes; error messages must include
// actionable fix hints.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// ExitCode maps error categories to process exit codes so callers and scripts
// can branch on the failure kind.
type ExitCode int

// Exit code constants map error categories to process exit codes.
const (
	ExitOK               ExitCode = 0
	ExitGeneralError     ExitCode = 1
	ExitPermissionDenied ExitCode = 2
	ExitAuthError        ExitCode = 3
	ExitNotFound         ExitCode = 4
	ExitReplay           ExitCode = 5
	ExitCounterReconcile ExitCode = 6 // distinct from ErrReplay — triggers reconcile runbook hint
	ExitTrustError       ExitCode = 7
)

// Renderer writes CLI output to configurable writers. It is constructed with
// injected writers so it is fully testable without real os.Stdout/os.Stderr.
type Renderer struct {
	Out    io.Writer
	Err    io.Writer
	IsJSON bool
	IsTTY  bool
}

// New creates a Renderer detecting TTY from os.Stdout.
func New(jsonMode bool) *Renderer {
	isTTY := false
	stat, err := os.Stdout.Stat()
	if err == nil {
		isTTY = (stat.Mode() & os.ModeCharDevice) != 0
	}
	return &Renderer{
		Out:    os.Stdout,
		Err:    os.Stderr,
		IsJSON: jsonMode,
		IsTTY:  isTTY,
	}
}

// PrintVersion prints version information.
func (r *Renderer) PrintVersion(version string) {
	if r.IsJSON {
		enc := json.NewEncoder(r.Out)
		_ = enc.Encode(map[string]string{"version": version})
		return
	}
	_, _ = fmt.Fprintf(r.Out, "byreis version %s\n", version)
}

// PrintError prints an error with an actionable hint to stderr.
func (r *Renderer) PrintError(msg string) {
	_, _ = fmt.Fprintf(r.Err, "error: %s\n", msg)
}

// EncodeJSON encodes v as JSON to w. Errors are silently discarded to keep
// command RunE signatures clean; a write error to stdout is not actionable
// from the command layer.
func EncodeJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}
