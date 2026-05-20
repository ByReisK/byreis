package fetchtransport

import (
	"context"
	"time"
)

// IsValidSHA is the exported form of the internal isValidSHA validator.
// It returns true if s is a valid 40-char (SHA-1) or 64-char (SHA-256)
// lowercase or uppercase hex commit hash as returned by git rev-parse.
// Callers outside this package use this to validate SHA arguments before
// composing git argv or tree paths.
func IsValidSHA(s string) bool { return isValidSHA(s) }

// CleanGitEnv is the exported form of the internal cleanGitEnv helper.
// Returns a minimal, sanitised environment for git subprocess calls.
// PATH is preserved; LANG/LC_ALL=C ensures consistent ASCII output.
func CleanGitEnv() []string { return cleanGitEnv() }

// SanitizeOutput is the exported form of the internal sanitizeOutput helper.
// Trims and truncates subprocess stderr for use in error messages.
// Truncated at 256 bytes; must never include signature bytes, key material,
// or secret-adjacent content — for git diagnostics only.
func SanitizeOutput(b []byte) string { return sanitizeOutput(b) }

// WithBoundedDeadline is the exported form of the internal withBoundedDeadline
// helper. Derives a child context whose deadline is the earlier of the parent's
// deadline and (now + bound). The returned cancel function must always be called.
func WithBoundedDeadline(parent context.Context, bound time.Duration) (context.Context, context.CancelFunc) {
	return withBoundedDeadline(parent, bound)
}

// RunSubprocess invokes the HeadVerifier's injected CommandRunner directly.
// Used by production_transport.go for the git merge-base --is-ancestor leg,
// which must run against the retained clone from ReadCounter with the same
// hardened environment as ReadBlobAtSHA. The runner is not exposed as a field
// to keep the HeadVerifier struct opaque to callers outside this package.
//
// Returns (stdout, stderr, exitCode, runErr) with the same semantics as
// CommandRunner.Run: a non-zero exit code is NOT a runErr; it is returned as
// exitCode > 0 with runErr == nil.
func (v *HeadVerifier) RunSubprocess(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, int, error) {
	return v.runner.Run(ctx, dir, env, name, args...)
}
