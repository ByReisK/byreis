// Package submit is the Submit compilation unit — the dedicated sub-package for
// the contributor Submit use-case (the keyless, write-only spine).
//
// This sub-package, not the parent internal/core/usecase, is the closed-world
// import allowlist target for "Submit". The full transitive dependency set of
// this package must be a subset of that allowlist. In particular:
//
//   - internal/core/crypto/decrypt and internal/core/crypto/identity are not
//     on the allowlist, so this package cannot, by construction, reach decrypt
//     or identity material. No decrypting identity is ever constructed here.
//   - The parent internal/core/registry is not on the allowlist (it
//     transitively reaches crypto/ed25519 via SignerKey/CounterStore). Only
//     the pure sub-package internal/core/registry/rectypes is permitted, and
//     the registry result is consumed through a narrow consumer-defined port
//     (RecipientSource), never the parent registry client interface.
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
// All collaborators are consumer-defined ports injected at construction time:
// no global state, no init() side effects, no real fs/net/clock/tty in unit
// tests. The use-case never touches a private key and never needs one — a
// missing admin key is never an error here because Submit never derives one.
package submit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/logging"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// SubmitAction indicates whether the submission adds a new key or replaces an
// existing one. It drives branch naming and the PR add-vs-replace label and is
// determined WITHOUT decrypting any existing value.
type SubmitAction int

const (
	// ActionAdd submits a new key (branch: byreis/add-<key>-<ts>).
	ActionAdd SubmitAction = iota
	// ActionReplace submits a replacement for an existing key
	// (branch: byreis/replace-<key>-<ts>). Detected from key NAMES only — never
	// by decrypting the live value.
	ActionReplace
)

func (a SubmitAction) String() string {
	switch a {
	case ActionAdd:
		return "add"
	case ActionReplace:
		return "replace"
	default:
		return "unknown"
	}
}

// Sentinel errors owned by this package. Each wraps with %w and carries an
// actionable hint for the CLI layer to surface.
var (
	// ErrNoRecipients is returned when the resolved admin recipient set is
	// empty. Encrypting to nobody is a hard error.
	ErrNoRecipients = errors.New(
		"refusing to submit: registry returned zero admin recipients — " +
			"run `byreis doctor` to check the admin registry")

	// ErrRecipientsNotVerified is returned when the recipient set did not come
	// from a signature-verified registry fetch (SourceVerified == false), or
	// was served stale from cache. Submit must NEVER encrypt to an unverified
	// or stale recipient set, and never falls back to artifact/repo recipients.
	ErrRecipientsNotVerified = errors.New(
		"refusing to submit: admin recipient set is not signature-verified " +
			"(stale or unsigned registry) — submitting would encrypt to a set " +
			"that may have been tampered with; run `byreis doctor` and retry " +
			"when the registry is reachable and verified")

	// ErrInvalidValue is returned when value validation fails. Validation runs
	// BEFORE any branch, commit, or PR is created — a bad value never reaches
	// git.
	ErrInvalidValue = errors.New(
		"refusing to submit: secret value failed validation; " +
			"no branch, commit, or PR was created")

	// ErrIrreversibleNotAcknowledged is returned when the contributor did not
	// explicitly acknowledge that a submitted secret cannot later be read back
	// by them. The acknowledgement is mandatory before anything is sent.
	ErrIrreversibleNotAcknowledged = errors.New(
		"refusing to submit: the irreversibility acknowledgement was declined — " +
			"a submitted secret cannot be read back by a contributor")

	// ErrValueMismatch is returned on a TTY when the double-entry confirmation
	// values differ. The secret is never sent.
	ErrValueMismatch = errors.New(
		"refusing to submit: the two entered values did not match — " +
			"re-run `byreis submit` and re-enter the value")

	// ErrBranchConflict is returned when the submission branch (or its PR)
	// already exists for a different in-flight submission. Submit REFUSES and
	// never silently overwrites or drops a secret. This is a submission-side
	// concurrency guard, distinct from the merge-side write-ahead resume.
	ErrBranchConflict = errors.New(
		"refusing to submit: a submission branch/PR for this key already " +
			"exists from another in-flight submission — resolve or close it, " +
			"then retry; byreis will not overwrite another submission's branch")
)

// Recipients is a resolved, trust-tagged admin recipient set. It is produced
// only by a RecipientSource backed by a signature-verified registry fetch.
//
// SourceVerified MUST be true and Stale MUST be false for Submit to proceed:
// the encrypt target is never sourced from an artifact, the project repo, or a
// stale/expired cache.
type Recipients struct {
	// Set is the age recipient public-key set (pure rectypes value type — no
	// identity material reachable, enforced by the allowlist gate).
	Set []rectypes.Recipient

	// SourceVerified is true only when the registry HEAD commit signature was
	// verified against the client-pinned trust anchor.
	SourceVerified bool

	// Stale is true when the set was served from cache after a network failure.
	// A stale set is a refuse for Submit, never a downgrade.
	Stale bool
}

// RecipientSource is the consumer-defined port that yields the admin recipient
// set for a project. The concrete implementation is a registry-adapter wrapper
// wired at the CLI layer; the parent internal/core/registry package is
// deliberately NOT imported here so it stays off the Submit allowlist.
type RecipientSource interface {
	// Recipients returns the trust-tagged admin recipient set for projectID.
	// Implementations MUST set SourceVerified only from a verified registry
	// HEAD and MUST NOT source recipients from an artifact or the project repo.
	Recipients(ctx context.Context, projectID string) (Recipients, error)
}

// ValueValidator is the consumer-defined key-name and value-validation port.
// Defined here so Submit does not depend on the validator package directly and
// the rule can be unit-mocked. Validation runs before any branch/commit.
type ValueValidator interface {
	// ValidateKeyName returns a non-nil error if the key name is unacceptable.
	ValidateKeyName(name string) error
	// ValidateValue returns a non-nil error if the value is unacceptable.
	ValidateValue(value string) error
}

// KeyExistenceProbe reports whether a key already exists in the live secrets
// file, by NAME only. It MUST NOT decrypt any value and MUST NOT touch
// identity material — REPLACE detection is name-only by construction (the
// allowlist gate proves this package cannot reach decrypt/identity code).
type KeyExistenceProbe interface {
	// KeyExists reports whether key is present in the live file for projectID's
	// logical file. The implementation reads key names only.
	KeyExists(ctx context.Context, projectID, logicalFile, key string) (bool, error)
}

// OpenPRInput is the request the use-case hands to the git port. It carries
// only the unsigned artifact, never plaintext and never a private key.
type OpenPRInput struct {
	ProjectID       string
	LogicalFileName string
	Key             string
	Action          SubmitAction
	Branch          string
	SecretsPath     string
	BaseFilePath    string
	Justification   string
	Artifact        artifact.Unsigned
}

// PRRef identifies the opened pull request.
type PRRef struct {
	Project string
	Number  int
}

// OpenedPR is the result of opening a submission PR.
type OpenedPR struct {
	Ref         PRRef
	URL         string
	Branch      string
	ArtifactSHA string
}

// GitPort is the narrow consumer-defined git port for the submit spine. The
// concrete GitHub adapter is wired at the CLI layer. It is kept minimal so the
// Submit transitive import set stays tight.
type GitPort interface {
	// BranchExists reports whether the submission branch already exists on the
	// remote. Used for the concurrent-submission conflict guard.
	BranchExists(ctx context.Context, projectID, branch string) (bool, error)

	// OpenSubmissionPR creates the branch + commit of the unsigned artifact and
	// opens the PR. It MUST fail (not overwrite) if the branch was created
	// concurrently after BranchExists returned false; the use-case treats that
	// as ErrBranchConflict.
	OpenSubmissionPR(ctx context.Context, in OpenPRInput) (OpenedPR, error)
}

// ErrBranchTaken is the sentinel a GitPort implementation returns when the
// branch already exists at push time (lost the concurrent-create race). The
// use-case maps it to ErrBranchConflict so a secret is never silently dropped.
var ErrBranchTaken = errors.New("submission branch already exists on remote")

// PendingSubmission is the encrypted-at-rest resume record. It holds ONLY the
// unsigned (already-encrypted) artifact and non-secret metadata. Plaintext is
// NEVER persisted.
type PendingSubmission struct {
	ProjectID       string
	LogicalFileName string
	Key             string
	Action          SubmitAction
	Branch          string
	SecretsPath     string
	BaseFilePath    string
	Justification   string
	// Artifact is the UNSIGNED, already-encrypted artifact. There is no
	// plaintext field on this type by construction.
	Artifact artifact.Unsigned
	SavedAt  time.Time
}

// ResumeStore persists an encrypted-at-rest pending submission so an
// interrupted submit can resume without re-entering the secret. It only ever
// stores the unsigned (encrypted) artifact — never plaintext.
type ResumeStore interface {
	// Save persists the pending submission. The implementation MUST reject any
	// attempt to persist plaintext; this type carries none.
	Save(ctx context.Context, p PendingSubmission) error
	// Load returns the pending submission for (projectID, key) if one exists,
	// ok==false otherwise.
	Load(ctx context.Context, projectID, key string) (p PendingSubmission, ok bool, err error)
	// Discard removes the pending submission after a successful PR open or an
	// explicit decline.
	Discard(ctx context.Context, projectID, key string) error
}

// ValueEntry is the result of collecting a secret value through the injected
// Prompter. Core never reads a real TTY/stdin: the CLI wires the Prompter and
// applies the double-entry-on-TTY vs single-entry-when-piped policy.
type ValueEntry struct {
	// Value is the entered secret value.
	Value string
	// Interactive is true when the value was entered on a TTY (double-entry +
	// explicit irreversibility ack apply); false for piped/--value/stdin.
	Interactive bool
	// Confirm is the second-entry value, only meaningful when Interactive.
	Confirm string
	// IrreversibleAcknowledged is true when the contributor explicitly
	// acknowledged the submission is irreversible (TTY only). For piped input
	// the operator controls the source, so this is treated as acknowledged.
	IrreversibleAcknowledged bool
}

// Prompter is the consumer-defined value-entry port. It abstracts the TTY: core
// has no real stdin/TTY. The CLI implementation enforces no-echo entry,
// double-entry on a TTY, single entry when piped, and the irreversibility ack.
type Prompter interface {
	// CollectValue returns the entered secret value and the interaction
	// metadata. It MUST NOT echo the secret and MUST NOT write it to logs or
	// shell history.
	CollectValue(ctx context.Context, key string, action SubmitAction) (ValueEntry, error)
}

// Clock is the injected time source — no real clock in unit tests. Used for
// the timestamped submission branch name and the resume record.
type Clock interface {
	Now() time.Time
}

// Input carries all inputs for Submitter.Submit. The encryption recipients are
// resolved internally from the RecipientSource (SourceVerified only); callers
// never pass recipients in, so an artifact/repo-sourced set cannot be injected.
type Input struct {
	// ProjectID and LogicalFileName are bound into the signed manifest so an
	// artifact cannot be replayed under a different project or file identity.
	ProjectID       string
	LogicalFileName string

	// Key is the secret key name being submitted.
	Key string

	// Counter is the claimed counter. The registry is the acceptance
	// authority; Submit does not validate it.
	Counter uint64

	// Justification is the contributor-supplied justification, included in the
	// PR body. Never a secret value.
	Justification string

	// SecretsPath is the repo-relative target path of the signed
	// file-of-record. BaseFilePath is the current live file (== SecretsPath
	// unless renaming, which is unsupported). Neither is a crypto input.
	SecretsPath  string
	BaseFilePath string
}

// Result is returned by a successful Submit call.
type Result struct {
	PRRef       PRRef
	PRURL       string
	Branch      string
	ArtifactSHA string
	Action      SubmitAction
}

// Submitter is the consumer-defined interface for the Submit use-case. It lives
// here, in the consumer sub-package, per the Clean Architecture
// consumer-defines-interface rule.
type Submitter interface {
	// Submit validates the value, resolves the SourceVerified admin recipient
	// set, encrypts to it with the public-key-only Encryptor, detects ADD vs
	// REPLACE without decrypting, and opens a contributor PR. It never decrypts
	// and never touches identity material (enforced by the import allowlist
	// gate on this package's transitive set).
	Submit(ctx context.Context, in Input) (Result, error)
}

// Deps bundles the injected ports. Constructor injection only — no globals.
type Deps struct {
	Recipients RecipientSource
	Encryptor  encrypt.Encryptor
	Validator  ValueValidator
	KeyProbe   KeyExistenceProbe
	Git        GitPort
	Resume     ResumeStore
	Prompter   Prompter
	Clock      Clock
	Audit      audit.Logger
	Log        logging.Logger
}

type submitUseCase struct {
	d Deps
}

// New returns a Submitter. All collaborators are injected. A nil audit or log
// sink is replaced with the no-op discard so core never panics on a missing
// optional sink.
func New(d Deps) (Submitter, error) {
	if d.Recipients == nil || d.Encryptor == nil || d.Validator == nil ||
		d.KeyProbe == nil || d.Git == nil || d.Resume == nil ||
		d.Prompter == nil || d.Clock == nil {
		return nil, errors.New(
			"submit.New: a required port is nil — wire RecipientSource, " +
				"Encryptor, ValueValidator, KeyExistenceProbe, GitPort, " +
				"ResumeStore, Prompter and Clock")
	}
	if d.Audit == nil {
		d.Audit = audit.Discard
	}
	if d.Log == nil {
		d.Log = logging.Discard
	}
	return &submitUseCase{d: d}, nil
}

// branchName builds the submission branch: byreis/<add|replace>-<key>-<unix>.
func branchName(action SubmitAction, key string, now time.Time) string {
	return fmt.Sprintf("byreis/%s-%s-%d", action.String(), key, now.UTC().Unix())
}

// Submit is the keyless contributor spine. Ordering is security-critical:
//
//  1. Validate the key name and value BEFORE any branch/commit/PR.
//  2. Collect the value through the injected Prompter; on a TTY enforce
//     double-entry + explicit irreversibility ack; piped input is single-entry.
//  3. Resolve the admin recipient set from a SourceVerified registry fetch
//     ONLY; a stale/unverified set REFUSES (never falls back).
//  4. Detect ADD vs REPLACE by key NAME only (no decrypt, no identity).
//  5. Encrypt to the verified set via the public-key-only Encryptor.
//  6. Persist the encrypted-at-rest resume record (never plaintext).
//  7. Conflict-guard the branch, then open the PR. A branch conflict REFUSES.
//
// No private key is ever touched or derived; a missing admin key is never an
// error here because Submit never needs one.
func (s *submitUseCase) Submit(ctx context.Context, in Input) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("submit cancelled: %w", err)
	}

	// (1) Validate key + value BEFORE any side effect: a bad value never
	// reaches git — no branch, commit, or PR is created.
	if err := s.d.Validator.ValidateKeyName(in.Key); err != nil {
		return Result{}, fmt.Errorf("%w: key name rejected: %v", ErrInvalidValue, err)
	}

	// (2) Collect the value through the injected port. Core never reads a real
	// TTY; the CLI applies double-entry vs single-entry by terminal detection.
	entry, entryErr := s.d.Prompter.CollectValue(ctx, in.Key, ActionAdd)
	if entryErr != nil {
		return Result{}, fmt.Errorf("collecting secret value failed: %w", entryErr)
	}
	if valErr := s.d.Validator.ValidateValue(entry.Value); valErr != nil {
		// Validation refuses BEFORE any branch/commit.
		return Result{}, fmt.Errorf("%w: %v", ErrInvalidValue, valErr)
	}
	if entry.Interactive {
		// TTY: double-entry confirmation + explicit irreversibility ack.
		if entry.Value != entry.Confirm {
			return Result{}, ErrValueMismatch
		}
		if !entry.IrreversibleAcknowledged {
			return Result{}, ErrIrreversibleNotAcknowledged
		}
	}
	// Piped/--value/stdin: single entry, operator controls the source — no
	// re-prompt; the acknowledgement is implied by the explicit invocation.

	// (3) Resolve recipients ONLY from a SourceVerified registry fetch. A
	// stale/unsigned set is a REFUSE, never a downgrade, and we never fall back
	// to artifact/repo recipients (there is no such code path).
	recips, err := s.d.Recipients.Recipients(ctx, in.ProjectID)
	if err != nil {
		return Result{}, fmt.Errorf("resolving admin recipients failed: %w", err)
	}
	if len(recips.Set) == 0 {
		return Result{}, ErrNoRecipients
	}
	if !recips.SourceVerified || recips.Stale {
		return Result{}, ErrRecipientsNotVerified
	}

	// (4) ADD vs REPLACE — by key NAME only. KeyExists reads names, never
	// decrypts; this package cannot reach decrypt/identity (allowlist gate).
	exists, err := s.d.KeyProbe.KeyExists(ctx, in.ProjectID, in.LogicalFileName, in.Key)
	if err != nil {
		return Result{}, fmt.Errorf("checking whether key %q already exists failed: %w", in.Key, err)
	}
	action := ActionAdd
	if exists {
		action = ActionReplace
	}

	// (5) Encrypt to the verified recipient set with the public-key-only
	// Encryptor. No private key is touched anywhere on this path.
	art, err := s.d.Encryptor.Encrypt(ctx, encrypt.EncryptInput{
		ProjectID:       in.ProjectID,
		LogicalFileName: in.LogicalFileName,
		Counter:         in.Counter,
		Recipients:      recips.Set,
		Values:          map[string]string{in.Key: entry.Value},
	})
	if err != nil {
		return Result{}, fmt.Errorf("encrypting submission failed: %w", err)
	}

	branch := branchName(action, in.Key, s.d.Clock.Now())

	// (6) Persist the encrypted-at-rest resume record. ONLY the unsigned
	// (encrypted) artifact is stored; PendingSubmission carries no plaintext
	// field by construction.
	pending := PendingSubmission{
		ProjectID:       in.ProjectID,
		LogicalFileName: in.LogicalFileName,
		Key:             in.Key,
		Action:          action,
		Branch:          branch,
		SecretsPath:     in.SecretsPath,
		BaseFilePath:    in.BaseFilePath,
		Justification:   in.Justification,
		Artifact:        art,
		SavedAt:         s.d.Clock.Now(),
	}
	if saveErr := s.d.Resume.Save(ctx, pending); saveErr != nil {
		return Result{}, fmt.Errorf("persisting resumable submission failed: %w", saveErr)
	}

	// (7) Concurrent-submission guard: refuse if the branch already exists, and
	// also map the adapter's lost-race sentinel to a refusal. A secret is never
	// silently dropped or overwritten.
	taken, err := s.d.Git.BranchExists(ctx, in.ProjectID, branch)
	if err != nil {
		return Result{}, fmt.Errorf("checking submission branch failed: %w", err)
	}
	if taken {
		return Result{}, ErrBranchConflict
	}

	opened, err := s.d.Git.OpenSubmissionPR(ctx, OpenPRInput{
		ProjectID:       in.ProjectID,
		LogicalFileName: in.LogicalFileName,
		Key:             in.Key,
		Action:          action,
		Branch:          branch,
		SecretsPath:     in.SecretsPath,
		BaseFilePath:    in.BaseFilePath,
		Justification:   in.Justification,
		Artifact:        art,
	})
	if err != nil {
		if errors.Is(err, ErrBranchTaken) {
			// Lost the concurrent-create race after the pre-check: REFUSE,
			// never overwrite the other submission's branch.
			return Result{}, ErrBranchConflict
		}
		return Result{}, fmt.Errorf("opening submission PR failed: %w", err)
	}

	// Success: the encrypted resume record is no longer needed.
	if err := s.d.Resume.Discard(ctx, in.ProjectID, in.Key); err != nil {
		// Non-fatal: the PR is open. Log (no secret material) and continue.
		s.d.Log.Log(ctx, logging.LevelWarn,
			"submission PR opened but resume record discard failed",
			"project", in.ProjectID, "key", in.Key, "error", err.Error())
	}

	// The PR is already open: a failed audit append cannot unwind it, so this
	// is non-fatal, but it must be surfaced (never silently dropped). No secret
	// material is ever placed in the event or the log.
	auditErr := s.d.Audit.Append(ctx, audit.Event{
		Kind:       audit.EventKindSubmit,
		OccurredAt: s.d.Clock.Now(),
		ProjectID:  in.ProjectID,
		FileName:   in.LogicalFileName,
		KeyName:    in.Key,
		PRRef:      fmt.Sprintf("%s#%d", opened.Ref.Project, opened.Ref.Number),
		Outcome:    "ok",
		Details:    map[string]string{"action": action.String(), "branch": branch},
	})
	if auditErr != nil {
		s.d.Log.Log(ctx, logging.LevelWarn,
			"submission PR opened but audit append failed",
			"project", in.ProjectID, "key", in.Key, "error", auditErr.Error())
	}

	return Result{
		PRRef:       opened.Ref,
		PRURL:       opened.URL,
		Branch:      opened.Branch,
		ArtifactSHA: opened.ArtifactSHA,
		Action:      action,
	}, nil
}

// Compile-time assertion.
var _ Submitter = (*submitUseCase)(nil)
