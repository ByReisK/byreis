package pluginidentity

// This file contains internal (white-box) tests for pluginidentity. External
// tests for the full subprocess lifecycle live in pluginidentity_test.go.

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"filippo.io/age"
)

// TestMapPluginErr_WrappedErrIncorrectIdentity verifies that mapPluginErr
// preserves the age.ErrIncorrectIdentity sentinel when the plugin returns it
// wrapped inside another error.
//
// age.Decrypt aggregates across identities by calling errors.Is on each
// Unwrap result; if mapPluginErr mangled a wrapped sentinel into a plain
// string error, age.Decrypt would mis-classify the result as a hard failure
// rather than "try the next identity".
func TestMapPluginErr_WrappedErrIncorrectIdentity(t *testing.T) {
	t.Parallel()

	// Simulate a plugin that returns a wrapped ErrIncorrectIdentity, e.g.:
	//   fmt.Errorf("plugin yubikey: stanza type mismatch: %w", age.ErrIncorrectIdentity)
	wrapped := fmt.Errorf("plugin internal detail: %w", age.ErrIncorrectIdentity)

	got := mapPluginErr("yubikey", wrapped)

	if got == nil {
		t.Fatal("mapPluginErr(wrapped ErrIncorrectIdentity): returned nil, want non-nil sentinel-preserving error")
	}
	if !errors.Is(got, age.ErrIncorrectIdentity) {
		t.Errorf("mapPluginErr(wrapped ErrIncorrectIdentity): errors.Is(result, age.ErrIncorrectIdentity) = false; got %v", got)
	}
}

// TestMapPluginErr_BareErrIncorrectIdentity verifies that mapPluginErr also
// preserves the sentinel when the plugin returns age.ErrIncorrectIdentity directly
// (the common case in a well-behaved plugin).
func TestMapPluginErr_BareErrIncorrectIdentity(t *testing.T) {
	t.Parallel()

	got := mapPluginErr("yubikey", age.ErrIncorrectIdentity)

	if got == nil {
		t.Fatal("mapPluginErr(bare ErrIncorrectIdentity): returned nil")
	}
	if !errors.Is(got, age.ErrIncorrectIdentity) {
		t.Errorf("mapPluginErr(bare ErrIncorrectIdentity): errors.Is(result, age.ErrIncorrectIdentity) = false; got %v", got)
	}
}

// TestMapPluginErr_NilIsNil verifies that nil input produces nil output.
func TestMapPluginErr_NilIsNil(t *testing.T) {
	t.Parallel()
	if got := mapPluginErr("yubikey", nil); got != nil {
		t.Errorf("mapPluginErr(nil): expected nil, got %v", got)
	}
}

// TestMapPluginErr_OtherError verifies that a non-sentinel error is sanitized
// to a byreis-authored string and does NOT satisfy errors.Is(err, age.ErrIncorrectIdentity).
func TestMapPluginErr_OtherError(t *testing.T) {
	t.Parallel()

	input := errors.New("some other plugin failure")
	got := mapPluginErr("yubikey", input)

	if got == nil {
		t.Fatal("mapPluginErr(other error): returned nil")
	}
	if errors.Is(got, age.ErrIncorrectIdentity) {
		t.Error("mapPluginErr(other error): errors.Is(result, age.ErrIncorrectIdentity) should be false")
	}
}

// TestDeadlineIdentity_WrappedErrIncorrectIdentity verifies the full
// deadlineIdentity.Unwrap path when the inner identity returns a wrapped
// age.ErrIncorrectIdentity. The sentinel must survive the goroutine boundary
// and the mapPluginErr call so age.Decrypt can aggregate across identities.
func TestDeadlineIdentity_WrappedErrIncorrectIdentity(t *testing.T) {
	t.Parallel()

	// Construct a stub age.Identity that always returns a wrapped sentinel.
	wrapped := fmt.Errorf("stub: stanza not for this identity: %w", age.ErrIncorrectIdentity)
	stub := &stubIdentity{err: wrapped}

	di := &deadlineIdentity{
		inner:   stub,
		timeout: 5 * time.Second,
		name:    "yubikey",
	}

	// Build a minimal stanza slice (content is irrelevant for a stub).
	stanzas := []*age.Stanza{{Type: "fakebyreis", Body: []byte{0x01}}}
	_, err := di.Unwrap(stanzas)

	if err == nil {
		t.Fatal("deadlineIdentity.Unwrap with wrapped sentinel: expected non-nil error")
	}
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Errorf("deadlineIdentity.Unwrap with wrapped sentinel: errors.Is(err, age.ErrIncorrectIdentity) = false; got %v", err)
	}
}

// stubIdentity is a minimal age.Identity that always returns the configured error.
type stubIdentity struct {
	err error
}

func (s *stubIdentity) Unwrap(_ []*age.Stanza) ([]byte, error) {
	return nil, s.err
}
