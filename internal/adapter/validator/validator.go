// Package validator is the adapter that binds the pure core validation rules to
// the consumer-defined submit.ValueValidator and usecase.ValueValidator ports.
//
// Placement: OUTER adapter layer (internal/adapter/validator). Core packages
// never import this adapter; it is wired only at the composition root. This
// keeps the core free of adapter dependencies and upholds the Clean
// Architecture dependency rule.
//
// Error construction contract: every value-rejection
// error returned by this adapter is built from a fixed reason string and,
// optionally, the key name or line number ONLY. The rejected secret value is
// NEVER embedded in any error string — no %q, %v, %s, or %#v of the value, no
// derived prefix or substring of the value. This is a security requirement:
// errors may appear in logs, error messages, or the terminal; a value in an
// error is a plaintext disclosure.
package validator

import (
	"github.com/ByReisK/byreis/internal/core/validator"
)

// Adapter binds the core validator rules to the two consumer-defined ports:
//   - submit.ValueValidator (ValidateKeyName + ValidateValue)
//   - usecase.ValueValidator (ValidateValue only)
//
// Both ports are satisfied by this single type; the composition root passes
// one Adapter instance to both submit.New and usecase.NewReviewer.
//
// The type is an empty struct: the core rules are pure functions with no state.
// All methods are safe for concurrent use.
type Adapter struct{}

// New returns a ready-to-use Adapter. No I/O occurs at construction time.
func New() *Adapter { return &Adapter{} }

// ValidateKeyName delegates to the core pure key-name rules.
//
// Returns a non-nil error wrapping validator.ErrInvalidKey when the key name
// is empty, exceeds 256 bytes, contains manifest separator bytes (0x1e/0x1f),
// or does not match ^[A-Za-z_][A-Za-z0-9_]*$.
//
// The key name itself MAY appear in the error message (it is non-secret).
// The secret value is never available to this method.
func (a *Adapter) ValidateKeyName(name string) error {
	return validator.ValidateKeyName(name)
}

// ValidateValue delegates to the core pure value rules.
//
// Returns a non-nil error wrapping validator.ErrInvalidValue when the value is
// empty, exceeds 1 MiB, or contains a NUL byte.
//
// Security contract: the secret value is NEVER embedded in the returned error.
// Only a fixed reason (empty / too-long / contains-NUL) and, when relevant,
// the maximum length appear in the message. This prevents secret material from
// appearing in logs or terminal output.
func (a *Adapter) ValidateValue(value string) error {
	return validator.ValidateValue(value)
}
