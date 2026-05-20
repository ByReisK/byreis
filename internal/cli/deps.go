package cli

import (
	"errors"
	"os"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// Deps bundles all injected use-case dependencies for the CLI command tree.
// It is populated by cmd/byreis/main.go (or test code) and passed into
// NewRootCmdWithDeps. No CLI command constructs an adapter directly; that is
// strictly the wiring layer's responsibility.
//
// Each read-path use-case (Getter, Decryptor, Editor) is typed to the NARROW
// consumer-defined interface, never to a concrete adapter type. This preserves
// the ISP contract: use-cases see only the minimal port they need.
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

	// Getter is the admin Get use-case. Narrow interface: only usecase.Getter.
	// May be nil when adapters are not yet wired; the get command will return a
	// "not configured" error.
	Getter usecase.Getter

	// Decryptor is the admin Decrypt use-case. Narrow interface:
	// usecase.DecryptUseCase. Also used by the CI-decrypt entrypoint (decrypt
	// --ci). May be nil when adapters are not yet wired.
	Decryptor usecase.DecryptUseCase

	// Editor is the admin Edit use-case. Narrow interface: usecase.EditUseCase.
	// May be nil when adapters are not yet wired.
	Editor usecase.EditUseCase

	// Merger is the admin Merge use-case. Narrow interface: usecase.Merger.
	// May be nil when the registry-write path is not yet wired; the merge
	// command will return a "not configured" error in that case.
	Merger usecase.Merger

	// MergeExitCode maps an error from the Merger use-case to the appropriate
	// render.ExitCode. When nil, the merge verb falls back to ExitGeneralError.
	// This is a function-field so the CLI layer never imports internal/adapter.
	MergeExitCode func(err error) render.ExitCode
}

// ExitCodeFromReadPathError maps a usecase.ExitClass to the corresponding
// documented process exit code. The mapping is the single source of truth for
// the CLI/CI layer; it is exported so the test layer can verify it directly
// without driving through the full cobra dispatch.
func ExitCodeFromReadPathError(class usecase.ExitClass) int {
	switch class {
	case usecase.ExitPermissionDenied:
		return int(render.ExitPermissionDenied)
	case usecase.ExitNotFound:
		return int(render.ExitNotFound)
	case usecase.ExitDecodeMalformed:
		return int(render.ExitDecodeMalformed)
	case usecase.ExitVerifyFailure:
		return int(render.ExitVerifyFailure)
	case usecase.ExitDecryptNoIdentity:
		return int(render.ExitAuthError)
	case usecase.ExitInternal:
		return int(render.ExitGeneralError)
	default:
		return int(render.ExitGeneralError)
	}
}

// exitCodeForErr extracts the exit code from a use-case error by inspecting it
// for a *usecase.ReadPathError (read-path exit class) or mode.ErrPermissionDenied
// (CLI-layer policy denial). Returns ExitGeneralError for all other errors.
func exitCodeForErr(err error) render.ExitCode {
	if err == nil {
		return render.ExitOK
	}
	var rpe *usecase.ReadPathError
	if errors.As(err, &rpe) {
		return render.ExitCode(ExitCodeFromReadPathError(rpe.Class))
	}
	if errors.Is(err, mode.ErrPermissionDenied) {
		return render.ExitPermissionDenied
	}
	return render.ExitGeneralError
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
