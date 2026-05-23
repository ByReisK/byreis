// Package validator implements pre-commit value validation. Pure: no I/O, no
// SDK imports. Validation runs before any branch or commit is created so a bad
// value never reaches git.
//
// Error construction contract (binding): every rejection error is built from
// a fixed-reason string and, optionally, the key name or a line number. No
// rejected value, no prefix of a value, and no substring derived from a value
// may appear in any returned error string. The reason is always chosen from a
// fixed enum (empty, too-long, contains-NUL), never the value itself.
package validator

import (
	"errors"
	"fmt"
	"regexp"
)

// ErrInvalidKey is returned when a secret key name fails validation.
var ErrInvalidKey = errors.New(
	"invalid secret key name: must be non-empty, printable ASCII, no separator bytes (0x1e/0x1f)")

// ErrInvalidValue is returned when a secret value fails validation.
var ErrInvalidValue = errors.New(
	"invalid secret value: must be non-empty; validation refuses before any commit")

// maxValueBytes is the hard upper bound on secret value length. Values larger
// than this are rejected to prevent unbounded artifacts and memory consumption.
// 1 MiB is a generous ceiling; no realistic secret value approaches it.
const maxValueBytes = 1024 * 1024

// envKeyRE is the positive whitelist for environment-variable key names.
// Must match the envparse rule: ^[A-Za-z_][A-Za-z0-9_]*$.
var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// maxKeyLen is the maximum byte length for a key name. 256 bytes is well above
// any realistic env-var name and well below the manifest signed-field limit.
const maxKeyLen = 256

// ValidateKeyName reports whether the key name is acceptable for use in a
// byreis secret. Returns a wrapped ErrInvalidKey with a hint if not.
//
// Rules:
//   - Non-empty, at most 256 bytes.
//   - Matches ^[A-Za-z_][A-Za-z0-9_]*$ (env-var grammar, same as the envparse rule).
//   - Must not contain manifest separator bytes 0x1e or 0x1f.
func ValidateKeyName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("%w: key name must not be empty", ErrInvalidKey)
	}
	if len(name) > maxKeyLen {
		return fmt.Errorf("%w: key name exceeds maximum length of %d bytes",
			ErrInvalidKey, maxKeyLen)
	}
	for _, b := range []byte(name) {
		if b == 0x1e || b == 0x1f {
			return fmt.Errorf("%w: key name contains a manifest separator byte (0x%02x) "+
				"which would shift field boundaries in the signed stream", ErrInvalidKey, b)
		}
	}
	if !envKeyRE.MatchString(name) {
		return fmt.Errorf("%w: key name %q does not match the required pattern "+
			"^[A-Za-z_][A-Za-z0-9_]*$ — use letters, digits, and underscores only, "+
			"starting with a letter or underscore", ErrInvalidKey, name)
	}
	return nil
}

// ValidateValue reports whether a secret value is acceptable. Returns a wrapped
// ErrInvalidValue if not.
//
// Rules:
//   - Non-empty.
//   - At most 1 MiB (1,048,576 bytes).
//   - Must not contain NUL bytes (0x00) — NUL terminates C strings and can
//     confuse downstream git attribute processing.
//
// Error construction contract: the rejected value itself is NEVER embedded in
// the returned error. Only a fixed reason string (empty, too-long, contains-NUL)
// and, when relevant, the maximum length are included. This prevents secret
// material from appearing in logs, error messages, or the terminal.
func ValidateValue(v string) error {
	if len(v) == 0 {
		return fmt.Errorf("%w: value must not be empty", ErrInvalidValue)
	}
	if len(v) > maxValueBytes {
		return fmt.Errorf("%w: value exceeds maximum length of %d bytes",
			ErrInvalidValue, maxValueBytes)
	}
	for _, b := range []byte(v) {
		if b == 0x00 {
			return fmt.Errorf("%w: value contains a NUL byte (0x00) which is not "+
				"permitted in secrets managed by byreis", ErrInvalidValue)
		}
	}
	return nil
}
