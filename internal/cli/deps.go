package cli

import (
	"os"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// Deps bundles all injected use-case dependencies for the CLI command tree.
// It is populated by cmd/byreis/main.go (or test code) and passed into
// NewRootCmdWithDeps. No CLI command constructs an adapter directly; that is
// strictly the wiring layer's responsibility.
type Deps struct {
	// Initializer is the Init use-case. May be nil when adapters are not yet
	// wired; the init command will return a "not configured" error.
	Initializer usecase.Initializer

	// Doctor is the Doctor use-case. May be nil when adapters are not yet wired.
	Doctor usecase.Doctor

	// Policy is the mode permission gate used for submit/review/merge/get/
	// decrypt/edit commands. When non-nil it is called with CurrentMode + the
	// command verb to decide whether to allow or deny.
	Policy *mode.Policy

	// CurrentMode is the cryptographically-derived mode resolved at startup.
	// It must be ModeContributor when no admin key is available. Used together
	// with Policy for command-level permission checks.
	CurrentMode mode.Mode

	// ConfigDir is ~/.config/byreis/ (or $BYREIS_CONFIG).
	ConfigDir string
}

// exitError is a typed error that carries a render.ExitCode. The CLI entry
// point in cmd/byreis/main.go reads the exit code via ExitCodeOf and calls
// os.Exit with it.
type exitError struct {
	code  render.ExitCode
	cause error
}

func (e *exitError) Error() string {
	if e.cause != nil {
		return e.cause.Error()
	}
	return "command failed"
}

func (e *exitError) Unwrap() error {
	return e.cause
}

// ExitCodeOf extracts the render.ExitCode from an error if it wraps an
// exitError. Returns 0 when err is nil; returns 1 for any other non-exitError.
func ExitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	curr := err
	for curr != nil {
		if e, ok := curr.(*exitError); ok {
			ee = e
			break
		}
		if u, ok := curr.(interface{ Unwrap() error }); ok {
			curr = u.Unwrap()
		} else {
			break
		}
	}
	if ee == nil {
		return 1
	}
	return int(ee.code)
}

// envBool returns true if the environment variable name is set to a truthy value
// ("1", "true", or "yes").
func envBool(name string) bool {
	v := os.Getenv(name)
	return v == "1" || v == "true" || v == "yes"
}
