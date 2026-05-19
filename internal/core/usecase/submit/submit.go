// Package submit is the Submit compilation unit — the dedicated sub-package for
// the contributor Submit use-case.
//
// This sub-package, not the parent internal/core/usecase, is the closed-world
// import allowlist target for "Submit". The full transitive dependency set of
// this package must be a subset of that allowlist. In particular:
//
//   - internal/core/crypto/decrypt and internal/core/crypto/identity are not
//     on the allowlist, so this package cannot, by construction, reach decrypt
//     or identity material.
//   - The parent internal/core/registry is not on the allowlist (it
//     transitively reaches crypto/ed25519 via SignerKey/CounterStore). Only
//     the pure sub-package internal/core/registry/rectypes is permitted.
//   - internal/core/registry/countertypes is not on the Submit allowlist (it
//     carries the counter authority for verify/admin paths, not contributor
//     submit).
//
// Decrypt, Edit, Merge, Get, Init, Doctor, Review live in the parent package
// internal/core/usecase, outside this sub-package. They are therefore off the
// Submit allowlist by construction, using the same package-boundary isolation
// pattern as rectypes.
//
// The allowlist test (make check-allowlist / go test -run TestAllowlist
// ./internal/core/usecase/submit/) enforces this mechanically; any transitive
// dependency not on the allowlist fails the build and forces an explicit
// allowlist amendment under review.
//
// This is a stub until the real implementation lands.
package submit

import (
	"context"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// SubmitInput carries all inputs for Submitter.Submit. The encryption
// recipients must originate from a signature-verified registry fetch; this
// package enforces the type — rectypes.Recipient, not the parent registry type
// — via the import allowlist gate.
type SubmitInput struct {
	// ProjectID and LogicalFileName are bound into the manifest so an artifact
	// cannot be replayed under a different project or file identity.
	ProjectID       string
	LogicalFileName string

	// Counter is the claimed counter. The registry is the acceptance authority;
	// Submit does not validate it — the registry port and verify do.
	Counter uint64

	// Recipients is the set of age recipient public keys. Must be non-empty
	// (ErrNoRecipients) and must originate from a signature-verified registry
	// fetch. Uses the pure rectypes sub-package, never the parent registry
	// package (which is off this allowlist).
	Recipients []rectypes.Recipient

	// Values maps secret key names to plaintext values. Plaintext is encrypted
	// per value (one fresh age.Encrypt per value, for AEAD nonce freshness).
	Values map[string]string

	// Action is Add or Replace. Drives the branch name and PR-title template.
	Action SubmitAction

	// Key is the secret key name being submitted (for branch naming).
	Key string

	// Justification is the contributor-supplied justification, included in the PR.
	Justification string
}

// SubmitAction indicates whether the submission adds a new key or replaces an
// existing one. This drives branch naming and PR labelling.
type SubmitAction int

const (
	// ActionAdd submits a new key (branch: byreis/add-<key>-<ts>).
	ActionAdd SubmitAction = iota

	// ActionReplace submits a replacement for an existing key
	// (branch: byreis/replace-<key>-<ts>).
	ActionReplace
)

// SubmitResult is returned by a successful Submit call. It carries the open PR
// reference and the artifact content SHA pinned at push time.
type SubmitResult struct {
	// PRRef is the project + PR number opened for this submission.
	PRRef PRRef

	// PRURL is the human-readable URL of the opened PR.
	PRURL string

	// Branch is the branch name used for the submission.
	Branch string

	// ArtifactSHA is sha256 over the exact pushed artifact bytes, with zero
	// normalization. Used by review/merge to pin the artifact at the time it
	// was submitted.
	ArtifactSHA string
}

// PRRef is the composite PR reference (project + PR number).
type PRRef struct {
	Project string
	Number  int
}

// Submitter is the consumer-defined interface for the Submit use-case.
// It lives here, in the consumer sub-package, per the Clean Architecture
// consumer-defines-interface rule.
//
// Implementations receive:
//   - an Encryptor (encrypt.Encryptor — public-key only, never identity-bearing)
//   - a GitProvider port (for branch/PR creation)
//   - an AuditLog port (for append-only submission audit trail)
//   - a Config port (for project config)
//
// These are injected at construction time: no global state, no init() side
// effects.
type Submitter interface {
	// Submit encrypts the provided values to the admin recipients and opens a
	// contributor PR. It never decrypts and never touches identity material
	// (enforced by the import allowlist gate on this package's transitive set).
	//
	// Returns ErrNoRecipients if Recipients is empty. Returns a wrapped error
	// with an actionable hint on encryption or git failure.
	Submit(ctx context.Context, in SubmitInput) (SubmitResult, error)
}

// submitUseCase is the concrete Submitter implementation.
// The real body is filled in later; the stub panics for now.
type submitUseCase struct {
	enc encrypt.Encryptor
	// GitProvider, AuditLog, and Config ports will be added here.
}

// New returns a Submitter. The constructor parameters expand to inject all
// required ports (git, audit, config) once implemented. All dependencies are
// injected; no real fs/net/clock/keychain in unit tests.
func New(enc encrypt.Encryptor) Submitter {
	return &submitUseCase{enc: enc}
}

func (s *submitUseCase) Submit(_ context.Context, _ SubmitInput) (SubmitResult, error) {
	panic("not implemented") // stub: real implementation pending
}

// Compile-time assertions.
var _ Submitter = (*submitUseCase)(nil)

// artifactUnsigned is referenced so the compiler keeps the artifact import;
// artifact.Unsigned is the intermediate produced by the encryptor.
var _ artifact.Unsigned
