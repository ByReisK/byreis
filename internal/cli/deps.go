package cli

import (
	"context"
	"errors"
	"os"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
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

	// Rotator is the admin Rotate use-case. Narrow interface: rotate.Rotator.
	// May be nil when the rotation path is not yet wired; the rotate command
	// will return a "not configured" error at command time.
	Rotator rotate.Rotator

	// Reconciler is the admin rotation reconcile use-case. Narrow interface:
	// rotate.RotationReconciler. May be nil when not yet wired.
	Reconciler rotate.RotationReconciler

	// RotateExitCode maps an error from the Rotator use-case to the appropriate
	// render.ExitCode. When nil, the rotate verb falls back to ExitGeneralError.
	// This is a function-field so the CLI layer never imports internal/adapter.
	RotateExitCode func(err error) render.ExitCode

	// RotatePreFlight is the narrow read-only port the rotate command uses to
	// perform the two pre-flight checks required before invoking Rotator.Rotate:
	//   (a) registry freshness/verification — SourceVerified + non-stale
	//   (b) admin decrypt-all-existing — the running admin can decrypt every
	//       current project secrets file
	//
	// When nil the rotate command falls back to the prior hard-coded stubs
	// (SourceVerified:true, AdminCanDecryptAll:true), which is safe only in
	// integration test setups where a real pre-flight is unnecessary. Production
	// wiring sets this to the real pre-flight adapter at BuildProductionDeps.
	RotatePreFlight RotatePreFlightReader
}

// RotatePreFlightReader is the narrow consumer-defined port the rotate command
// uses for the two mandatory pre-flight checks. It is defined in the CLI layer
// (the consumer) so that internal/core packages never need to import it.
//
// The implementation lives in internal/app (production wiring) or in test code;
// neither the CLI nor the core imports an adapter directly.
type RotatePreFlightReader interface {
	// FetchVerifiedAdminSet fetches the signature-verified, non-stale admin set
	// for the given project. Returns an error wrapping
	// rotate.ErrRotationRequiresFreshRegistry when the result is stale or
	// unverified. The returned value contains the pre-rotation recipients,
	// registered admins, configured files map, and the current max epoch across
	// all project files.
	FetchVerifiedAdminSet(ctx context.Context, projectID string) (RotatePreFlightAdminSet, error)

	// CanDecryptAllFiles attempts to decrypt each of the provided file snapshots
	// using the running admin's identity. Returns nil when every file decrypts
	// successfully. Returns an error wrapping
	// rotate.ErrRotationCannotDecryptExisting when ANY file cannot be decrypted.
	// The implementation MUST NOT leak plaintext in errors, logs, or return
	// values — only a boolean "all-or-nothing" result is surfaced.
	CanDecryptAllFiles(ctx context.Context, snapshots []RotatePreFlightFileSnap) error
}

// RotatePreFlightAdminSet carries the SourceVerified registry data needed to
// populate a rotate.RotationInput before invoking Rotator.Rotate.
type RotatePreFlightAdminSet struct {
	// PreRotationRecipients is R, sourced from the SourceVerified registry.
	PreRotationRecipients []string
	// RegisteredAdmins is the full admin set from the SourceVerified registry HEAD.
	RegisteredAdmins []string
	// ConfiguredFiles maps logical_file_name → registry-configured path.
	ConfiguredFiles map[string]string
	// CurrentMaxEpoch is the highest per-file rotation_epoch in the project.
	CurrentMaxEpoch uint64
	// FileSnapshots are the current project secrets files for the pre-flight
	// CanDecryptAllFiles check and RotationInput.PreRotationFiles population.
	FileSnapshots []RotatePreFlightFileSnap
}

// RotatePreFlightFileSnap carries the per-file snapshot data for the pre-flight
// decrypt check. It mirrors rotate.FileSnapshot but uses only string/uint64
// domain types so the CLI layer stays free of crypto artifact imports.
type RotatePreFlightFileSnap struct {
	// LogicalName is the registry-canonical logical file name.
	LogicalName string
	// CurrentCounter is the per-file last_accepted_counter at pre-rotation.
	CurrentCounter uint64
	// CurrentEpoch is the per-file rotation_epoch at pre-rotation.
	CurrentEpoch uint64
	// EncodedBytes is the raw on-disk bytes of the signed file-of-record.
	// The pre-flight adapter passes these to the Decryptor and MUST zeroize
	// any plaintext derived from them before returning.
	EncodedBytes []byte
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
