// Package render implements TTY/JSON/pipe output, secret masking, and exit-code
// mapping. No business logic — pure presentation.
//
// Smart TTY detection: mask secrets in a terminal, plain output when piped;
// --json for machine output; meaningful exit codes; error messages must include
// actionable fix hints.
//
// Exit-code taxonomy (process exit codes, single source of truth):
//
//	ExitOK               (0)  command completed successfully
//	ExitGeneralError     (1)  internal / unexpected failure
//	ExitPermissionDenied (2)  mode policy denied the command
//	ExitAuthError        (3)  no admin identity / key not found
//	ExitNotFound         (4)  file-of-record or key not found
//	ExitReplay           (5)  counter replay detected
//	ExitCounterReconcile (6)  counter reconcile required
//	ExitTrustError       (7)  registry trust error
//	ExitDecodeMalformed  (8)  artifact decode failed
//	ExitVerifyFailure    (9)  VerifyOfRecord failed
//
// JSON error schema (--json on any failure channel):
//
//	{"error":{"code":"<exit-class-name>","message":"<actionable hint>","hint":"<suggested fix>"}}
//
// The error JSON object NEVER contains plaintext, ciphertext, or key material.
// The "code" field is the stable machine-readable string from ExitClass.String().
// The "hint" field is optional and is always safe to display or log.
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
// This is the single source of truth for all read-path exit codes.
const (
	ExitOK               ExitCode = 0
	ExitGeneralError     ExitCode = 1
	ExitPermissionDenied ExitCode = 2
	ExitAuthError        ExitCode = 3 // no admin identity / key not found
	ExitNotFound         ExitCode = 4
	ExitReplay           ExitCode = 5
	ExitCounterReconcile ExitCode = 6 // distinct from ErrReplay — triggers reconcile runbook hint
	ExitTrustError       ExitCode = 7
	ExitDecodeMalformed  ExitCode = 8 // artifact decode failed (malformed/typed-mismatch)
	ExitVerifyFailure    ExitCode = 9 // VerifyOfRecord failed (unsigned/untrusted/replay/rollback)
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
// In --json mode, it emits the stable JSON error schema to stderr.
// The message must never contain plaintext, ciphertext, or key material.
func (r *Renderer) PrintError(msg string) {
	if r.IsJSON {
		enc := json.NewEncoder(r.Err)
		_ = enc.Encode(jsonErrorEnvelope("general-error", msg, "run `byreis doctor` for diagnostics"))
		return
	}
	_, _ = fmt.Fprintf(r.Err, "error: %s\n", msg)
}

// PrintErrorClass prints a classified read-path error to stderr.
// In --json mode it emits the stable JSON error schema with the exit-class code.
// The message must never contain plaintext, ciphertext, or key material.
func (r *Renderer) PrintErrorClass(code string, msg string, hint string) {
	if r.IsJSON {
		enc := json.NewEncoder(r.Err)
		_ = enc.Encode(jsonErrorEnvelope(code, msg, hint))
		return
	}
	_, _ = fmt.Fprintf(r.Err, "error: %s\n", msg)
}

// PrintSecret prints a single secret value. On a TTY the value is masked
// (replaced with "***") to prevent shoulder-surfing; in piped or --json mode
// the plain value is emitted. The caller is responsible for zeroizing the
// value after this call.
//
// TTY masking: IsTTY=true masks the value (interactive terminal).
// Piped / --ci / --json: emits the real value (decrypt success is
// plaintext-by-design; the caller is responsible for protecting the output).
// FAILURE channels (errors) NEVER carry plaintext or key material.
func (r *Renderer) PrintSecret(key, value string) {
	if r.IsJSON {
		enc := json.NewEncoder(r.Out)
		_ = enc.Encode(map[string]string{"key": key, "value": value})
		return
	}
	if r.IsTTY {
		_, _ = fmt.Fprintf(r.Out, "%s=***\n", key)
		return
	}
	_, _ = fmt.Fprintf(r.Out, "%s=%s\n", key, value)
}

// PrintDecryptResult prints the full decrypted value set. On a TTY, values are
// masked; in piped/--json mode they are emitted plaintext (by design — this is
// the command's job). The caller must zeroize all values after this call.
//
// TTY masking: IsTTY=true masks every value; IsTTY=false (piped/--ci/--json)
// emits plaintext. The --ci flag sets IsTTY=false explicitly so CI pipelines
// receive the real value even if they have a pseudo-TTY attached.
func (r *Renderer) PrintDecryptResult(plaintext map[string]string, keyNames []string) {
	if r.IsJSON {
		enc := json.NewEncoder(r.Out)
		_ = enc.Encode(map[string]any{"values": plaintext, "keys": keyNames})
		return
	}
	for _, k := range keyNames {
		v := plaintext[k]
		if r.IsTTY {
			_, _ = fmt.Fprintf(r.Out, "%s=***\n", k)
		} else {
			_, _ = fmt.Fprintf(r.Out, "%s=%s\n", k, v)
		}
	}
}

// EncodeJSON encodes v as JSON to w. Errors are silently discarded to keep
// command RunE signatures clean; a write error to stdout is not actionable
// from the command layer.
func EncodeJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

// JSONErrorSchema is the stable machine-readable error envelope emitted on
// any failure channel when --json is active. It must not contain plaintext,
// ciphertext, or key material.
//
// The schema is: {"error":{"code":"<stable-code>","message":"<actionable-hint>","hint":"<fix>"}}.
type JSONErrorSchema struct {
	Error JSONErrorDetail `json:"error"`
}

// JSONErrorDetail carries the structured error fields.
type JSONErrorDetail struct {
	// Code is the stable machine-readable exit-class identifier.
	// Consumers may use this to branch on the failure kind without parsing text.
	Code string `json:"code"`
	// Message is the human-readable actionable error description.
	// It must not contain secret values, private key material, or ciphertext.
	Message string `json:"message"`
	// Hint is an optional suggested remediation action (e.g. "run byreis doctor").
	Hint string `json:"hint,omitempty"`
}

// jsonErrorEnvelope builds the JSON error envelope value for encoding.
func jsonErrorEnvelope(code, message, hint string) JSONErrorSchema {
	return JSONErrorSchema{
		Error: JSONErrorDetail{
			Code:    code,
			Message: message,
			Hint:    hint,
		},
	}
}
