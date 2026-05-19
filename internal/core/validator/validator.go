// Package validator implements pre-commit value validation. Pure: no I/O, no
// SDK imports. Validation runs before any branch or commit is created so a bad
// value never reaches git.
package validator

import "errors"

// ErrInvalidKey is returned when a secret key name fails validation.
var ErrInvalidKey = errors.New(
	"invalid secret key name: must be non-empty, printable ASCII, no separator bytes (0x1e/0x1f)")

// ErrInvalidValue is returned when a secret value fails validation.
var ErrInvalidValue = errors.New(
	"invalid secret value: must be non-empty; validation refuses before any commit")

// ValidateKeyName reports whether the key name is acceptable for use in a
// byreis secret. Returns ErrInvalidKey with a hint if not.
// Key names must be non-empty, printable ASCII, and must not contain the
// manifest separator bytes 0x1e or 0x1f (those would let an attacker shift
// field boundaries in the signed manifest stream).
func ValidateKeyName(name string) error {
	panic("not implemented") // stub: real implementation pending
}

// ValidateValue reports whether a secret value is acceptable (non-empty).
// Returns ErrInvalidValue if not. Validation runs before any branch or commit
// is created.
func ValidateValue(v string) error {
	panic("not implemented") // stub: real implementation pending
}
