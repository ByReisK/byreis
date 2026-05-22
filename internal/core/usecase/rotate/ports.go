package rotate

import (
	"context"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// ReplacePair carries the --replace old=new intent for one recipient.
type ReplacePair struct {
	Old rectypes.Recipient
	New rectypes.Recipient
}

// FileSnapshot is one existing project secrets file the planner needs to know
// about. Snapshots are computed at Phase-1 step 2 from the pre-rotation tree;
// the planner never reads from disk.
type FileSnapshot struct {
	// LogicalName is the registry-canonical logical file name.
	LogicalName string
	// SignedArtifact is the current signed file-of-record. The planner reads
	// the manifest's display-only recipients block to compute the per-file
	// pre-rotation recipient set view; it never trusts these bytes for any
	// security decision (the trusted set is sourced separately by the
	// caller from a SourceVerified registry fetch).
	SignedArtifact artifact.Signed
	// CurrentCounter is the per-file last_accepted_counter at the start of
	// the rotation; sourced from the SourceVerified counter store.
	CurrentCounter uint64
	// CurrentEpoch is the per-file rotation_epoch at the start of the
	// rotation; sourced from the SourceVerified counter store.
	CurrentEpoch uint64
}

// PlanInput carries every input the planner needs to compute a rotation plan.
// The planner is pure: zero write side effects, deterministic, idempotent.
type PlanInput struct {
	// ProjectID is the registry-canonical project identifier the rotation
	// targets. The planner does not validate it against the registry; the
	// caller is responsible for cross-checking against the SourceVerified
	// admin set.
	ProjectID string
	// PreRotationRecipients is the project's current recipient set R, sourced
	// ONLY from a SourceVerified registry fetch. The planner must NOT consult
	// artifact-declared recipients for any security decision; this field is
	// the canonical pre-rotation set.
	PreRotationRecipients []rectypes.Recipient
	// RegisteredAdmins is the set of admin pubkeys at the SourceVerified
	// registry HEAD. The planner cross-checks --add against this set so
	// rotation can never add a non-admin recipient.
	RegisteredAdmins []rectypes.Recipient
	// AddPubkeys is the --add intent (repeatable).
	AddPubkeys []rectypes.Recipient
	// RemovePubkeys is the --remove intent (repeatable).
	RemovePubkeys []rectypes.Recipient
	// ReplacePairs is the --replace old=new intent (repeatable).
	ReplacePairs []ReplacePair
	// PreRotationFiles is the snapshot of every existing project secrets
	// file at the pre-rotation tree.
	PreRotationFiles []FileSnapshot
	// CurrentMaxEpoch is the highest per-file rotation_epoch across the
	// project's pre-rotation files. The planner adds 1 to compute the new
	// epoch. Zero is valid (first rotation for a never-rotated project).
	CurrentMaxEpoch uint64
}

// RotationPlan is the materialised result of planning. It contains everything
// the caller needs to print a dry-run, prompt the operator, and (on confirm)
// hand to the Phase-1 executor — but the plan itself causes no write side
// effects.
type RotationPlan struct {
	// ProjectID is echoed from the input for downstream use.
	ProjectID string
	// NewRecipientSet is R', the post-rotation recipient set.
	NewRecipientSet []rectypes.Recipient
	// AddedRecipients is the subset of R' that was not in R.
	AddedRecipients []rectypes.Recipient
	// RemovedRecipients is the subset of R that is not in R'.
	RemovedRecipients []rectypes.Recipient
	// FilesToReencrypt is every project file that must be re-encrypted under
	// R'. Always equals the full pre-rotation file set (no --future-only).
	FilesToReencrypt []FileSnapshot
	// NewEpoch is the post-rotation epoch (CurrentMaxEpoch + 1).
	NewEpoch uint64
	// HasRemovals is true when RemovedRecipients is non-empty; the CLI uses
	// it to decide whether to print the forward-secrecy warning and whether
	// to require the typed-fingerprint confirm.
	HasRemovals bool
}

// RotationPlanner is the consumer-defined port for plan computation. Plan
// MUST NOT cause any write side effect; it is callable in --dry-run mode and
// in real-run mode with identical semantics, so the caller (the Rotator
// spine) decides whether to proceed.
type RotationPlanner interface {
	// Plan composes R' from R + flag intents, validates against registered
	// admins, and snapshots the files to re-encrypt. A flag-composition
	// violation returns a typed sentinel wrapped with %w (ErrRotationFlagConflict,
	// ErrRotationRemoveAbsentRecipient, ErrRotationAddNotAdmin,
	// ErrRotationEmptyRecipientSet). Plan never reads from disk, the network,
	// or the registry.
	Plan(ctx context.Context, in PlanInput) (RotationPlan, error)
}

// PerFileResult is the per-file outcome of Phase-1 step 5 (decrypt → fresh
// whole-file encrypt → sign → pending bump → write). It is the bridge into
// Phase-2.
type PerFileResult struct {
	LogicalName string
	// SignedBytes is the file-of-record byte sequence that landed on the
	// rotation branch tree at step 5e.
	SignedBytes []byte
	// ContentSHA is the canonical content SHA of SignedBytes; equals the
	// pending.target_artifact_sha recorded at step 5d.
	ContentSHA string
	// PendingCounter is the per-file pending_counter that was recorded; equals
	// the pre-rotation last_accepted_counter + 1.
	PendingCounter uint64
}

// Phase1Result is the durable Phase-1 outcome handed to Phase-2. The branch
// is pushed; the per-file pending bumps are durable on the registry side; the
// CAS-lease parent SHAs are captured at the appropriate steps.
type Phase1Result struct {
	// BranchRef identifies the rotation branch pushed at Phase-1 step 6.
	BranchRef git.PRRef
	// ProjectParentSHA is captured at Phase-1 step 4 (branch creation) and
	// used as the project-repo CAS lease at Phase-2 step 7.
	ProjectParentSHA string
	// RegistryParentSHA is captured at Phase-1 step 5d (first RecordPendingBump)
	// and used as the registry-repo CAS lease at Phase-2 step 8.
	RegistryParentSHA string
	// PerFileResults carries one entry per re-encrypted file, in plan order.
	PerFileResults []PerFileResult
	// PlannedEpoch is the post-rotation rotation_epoch CommitRotation will
	// land for every file.
	PlannedEpoch uint64
	// FromRequestPR is non-nil when this rotation originated from a
	// `--from-request <PR>` lift. Threaded from RotationInput by the Rotator
	// spine after Phase-1 returns and forwarded to Phase-2 so
	// BuildRotationAuditEvent can record PR provenance in the audit trail.
	// Nil on a plain `--add` invocation (no contributor PR).
	FromRequestPR *FromRequestPRMeta
}

// IntegrityCheck records the per-file post-merge verification result (Phase-2
// step 9).
type IntegrityCheck struct {
	LogicalName string
	// VerifyOK is true when the live file's signed manifest passes
	// VerifyOfRecord under the post-rotation recipient set and signer keys.
	VerifyOK bool
	// RoundTripOK is true when the running admin's identity can decrypt every
	// value in the live file. Round-trip scope: for the running admin only;
	// structural assertion for the remaining recipients of R' is covered by
	// VerifyOfRecord's recipient-set check, not by this field.
	RoundTripOK bool
}

// Phase2Result is the terminal-phase outcome: merged commit SHA, signed
// CommitRotation registry commit SHA, the new epoch, and the per-file
// integrity-check results.
type Phase2Result struct {
	MergedSHA         string
	CommitRotationSHA string
	NewEpoch          uint64
	IntegrityChecks   []IntegrityCheck
}

// Phase1Executor runs the REVERSIBLE phase of rotation: branch creation,
// per-file re-encrypt, per-file sign, per-file pending bump, per-file write
// to the rotation branch, and the final branch push. Any crash up to and
// including step 6 is reversible by RotationReconciler.
//
// The interface is intentionally narrow: the spine hands a fully validated
// RotationPlan and receives a Phase1Result. Real adapters wire the existing
// v0.1 ports (GitProvider, RegistryClient, usecase.ManifestSigner, etc.); the
// V1 tests exercise this port via fakes only.
type Phase1Executor interface {
	Execute(ctx context.Context, plan RotationPlan) (Phase1Result, error)
}

// Phase2Executor runs the TERMINAL phase of rotation: project-repo
// fast-forward merge with --force-with-lease CAS, the atomic-N-file
// CommitRotation registry commit (counter advances + pending clears + audit
// append in one signed commit), and the post-merge mandatory integrity check.
//
// A crash between steps 7 and 8 yields PHASE_2_MIDFLIGHT terminal state. There
// is no auto-rollback; the reconciler surfaces ErrRotationReconcile with a
// runbook hint.
type Phase2Executor interface {
	Execute(ctx context.Context, p1 Phase1Result) (Phase2Result, error)
}

// PartialStateClassification enumerates the four reconcile-classification
// outcomes the reconciler produces from a partial-state observation.
type PartialStateClassification int

const (
	// NoPartialState means the registry has no rotation-tagged pendings AND
	// the project repo has no rotation branch. Reconcile exits OK.
	NoPartialState PartialStateClassification = iota
	// Phase1Only means the registry has rotation-tagged pendings AND the
	// rotation branch exists unmerged. Reconcile deletes the branch and
	// clears the pendings; no last_accepted_counter advance has occurred and
	// none is introduced.
	Phase1Only
	// Phase2Midflight means the rotation branch was merged to project main
	// AND the registry has at least one rotation-tagged pending unconsumed
	// by a CommitRotation. Reconcile surfaces ErrRotationReconcile (terminal);
	// no auto-rollback.
	Phase2Midflight
	// InconsistentPartial covers shapes that should not occur under the
	// protocol (rotation branch present AND merged; or pendings absent
	// alongside a rotation branch). Reconcile surfaces ErrRotationReconcile
	// (terminal).
	InconsistentPartial
)

func (c PartialStateClassification) String() string {
	switch c {
	case NoPartialState:
		return "no-partial-state"
	case Phase1Only:
		return "phase-1-only"
	case Phase2Midflight:
		return "phase-2-midflight"
	case InconsistentPartial:
		return "inconsistent-partial"
	default:
		return "unknown"
	}
}

// ReconcileResult records what reconcile observed and acted on.
type ReconcileResult struct {
	Classification PartialStateClassification
	// BranchDeleted is true iff a Phase-1-only rotation branch was deleted by
	// this reconcile call.
	BranchDeleted bool
	// PendingsCleared is the count of per-file pendings cleared by this
	// reconcile call (Phase-1-only only).
	PendingsCleared int
	// Retries records the number of CAS-rejection retries this reconcile
	// performed (0..3).
	Retries int
}

// RotationStateProbe is the consumer-defined port the reconciler uses to
// observe the partial-state shape on the registry and project sides. The
// V1 tests inject a fake; the real adapter wiring lands in V5.
type RotationStateProbe interface {
	// FetchPartialState reads the per-(project,file) counter store entries
	// for the rotation-tagged pendings AND the project repo's rotation
	// branch state at the same SourceVerified registry HEAD. It returns the
	// raw observation the reconciler classifies. SourceVerified MUST be true
	// in the observation; a stale or unverified fetch is itself dangerous
	// for reconcile and the probe surfaces ErrRotationRequiresFreshRegistry.
	//
	// The probe reuses the registry write-token for read access; a distinct
	// read-token provider is planned. The write-token's load-site
	// CONTRIBUTOR-refusal is honored throughout this call chain.
	FetchPartialState(ctx context.Context, projectID string) (PartialStateObservation, error)
}

// PartialStateObservation is the registry+project shape input to the
// reconcile classification logic. All fields are sourced from a
// SourceVerified registry fetch and a project-repo refs/heads listing; the
// probe never trusts artifact or stale-cache data for these fields.
type PartialStateObservation struct {
	// PendingsTaggedRotation lists the per-file pendings whose target_pr
	// matches the byreis/rotate-* branch ref pattern, as recorded in the
	// SourceVerified counter store.
	PendingsTaggedRotation []PendingObservation
	// MatchingPendings is the subset of PendingsTaggedRotation whose
	// target_artifact_sha equals the content SHA of the file currently at
	// project main. Used as the matching-pending membership signal in the
	// reconcile classification logic.
	MatchingPendings []PendingObservation
	// RotationBranchExists is true when at least one byreis/rotate-* branch
	// exists on the project repo and is NOT merged into main.
	RotationBranchExists bool
	// RotationBranchMerged is true when a byreis/rotate-* branch's contents
	// are present in main's tree (the branch was fast-forwarded into main).
	RotationBranchMerged bool
	// RotationBranchRef identifies the observed rotation branch, when one
	// exists; used by reconcile to delete a Phase-1-only branch.
	RotationBranchRef git.PRRef
}

// PendingObservation is one per-file pending row from the SourceVerified
// counter store, as observed by the probe.
type PendingObservation struct {
	// LogicalName is a single path component (no path separator). Registry
	// adapter enforces via fetchtransport.ValidateFileName at the I/O boundary.
	// Path-separated logical names are a v0.3+ extension; v0.2 has none.
	LogicalName       string
	PendingCounter    uint64
	TargetArtifactSHA string
	TargetPR          git.PRRef
}

// RotationStateReverser is the consumer-defined port the reconciler invokes
// to act on a PHASE_1_ONLY classification: clear the pendings (signed
// registry commit) and delete the unmerged rotation branch. Real adapters
// wire RegistryWriteSigner + GitProvider; V1 tests inject a fake.
type RotationStateReverser interface {
	// ClearPendings clears every per-file rotation-tagged pending for the
	// project AND appends the supplied rotation-reversal audit event in a
	// SINGLE signed registry commit. Same-commit atomicity is load-bearing
	// here: the audit trail and the cleared-pendings state must land together
	// or not at all, so a reader of any post-reconcile registry snapshot
	// either sees both the cleared pendings AND the reversal audit row, or
	// neither. A CAS rejection on the push surfaces a non-nil error which
	// the reconciler treats as retryable up to a bounded budget.
	ClearPendings(ctx context.Context, projectID string, pendings []PendingObservation, auditEvent audit.Event) error
	// DeleteRotationBranch deletes the unmerged rotation branch on the
	// project repo. A CAS rejection (the branch was concurrently merged
	// between classification and now) surfaces a non-nil error which the
	// reconciler treats as a re-classification trigger.
	DeleteRotationBranch(ctx context.Context, ref git.PRRef) error
}

// RotationReconciler is the consumer-defined port the
// `byreis admin rotation reconcile` CLI verb wraps. The port itself does NOT
// check mode (separation of concerns — ADMIN gating is enforced at the verb
// wrapper level per V02_PORTS.md). Classify is read-only; Reconcile acts on
// the classification with bounded retries.
type RotationReconciler interface {
	// Classify inspects the partial state and returns the classification.
	// Pure read; no writes. A stale or unverified registry fetch surfaces
	// ErrRotationRequiresFreshRegistry.
	Classify(ctx context.Context, projectID string) (PartialStateClassification, error)
	// Reconcile classifies, then acts on the classification:
	//   PHASE_1_ONLY        → delete unmerged rotation branch + clear pendings.
	//   PHASE_2_MIDFLIGHT   → surface ErrRotationReconcile (terminal).
	//   NO_PARTIAL_STATE    → exit OK ("no partial rotation detected").
	//   INCONSISTENT_PARTIAL → terminal ErrRotationReconcile.
	// Bounded retries (max 3) under concurrent rotation: on CAS rejection
	// during pending-clear, re-classify; if classification flips to
	// PHASE_2_MIDFLIGHT, return that terminal error.
	Reconcile(ctx context.Context, projectID string) (ReconcileResult, error)
}

// Clock is the injected time source. Core never reads a real clock in tests.
type Clock interface {
	Now() time.Time
}

// RequestAccessFile is the parsed `requests/<handle>.yaml` payload. It is the
// only contributor-authored trust input to the admin-side `--from-request`
// absorption path; every field is strict-decoded and validated before any
// rotation orchestration consumes it.
//
// No PR title, body, description, or comment text appears as a field of this
// struct on purpose: those operator-visible texts are advisory only and never
// participate in any trust decision. Adding such a field is a structural
// regression of the read-only admin trust contract.
type RequestAccessFile struct {
	// SchemaVersion pins the YAML payload's version. Must match the regex
	// `^byreis\.request_access\.v[0-9]+$`; v0.2 accepts any version in that
	// family. Unknown / malformed values refuse with
	// ErrRequestAccessSchemaInvalid.
	SchemaVersion string
	// GitHubHandle is the canonical lowercase ASCII GitHub login of the
	// contributor requesting access. It is byte-compared (after lowercase
	// normalisation) against the PR opener's GitHub login during absorption.
	// Must match `^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$` and be
	// ASCII-only — Unicode confusables, bidi controls, and zero-width joiners
	// are rejected at schema time.
	GitHubHandle string
	// AgePubkey is the age recipient string the contributor wishes to add to
	// the admin recipient set. Parsed via age.ParseX25519Recipient; base64 /
	// raw bytes / non-X25519 encodings are rejected at schema time.
	AgePubkey string
	// Justification is the contributor's free-text rationale. Capped at 1000
	// BYTES (not runes) to prevent rune-counting bypass; must be valid UTF-8;
	// rendered through SanitizeForTerminal at any operator-facing display
	// site. Audit-log emission of this field is structurally denylisted to
	// keep contributor-controlled bytes out of permanent audit JSONL.
	Justification string
	// RequestedAt is the contributor-local timestamp in RFC3339 form. Used as
	// an advisory-only display field; no trust decision keys on its value.
	RequestedAt string
}

// PRMetadata is the typed projection of GitHub's PR resource the request-access
// validation consumes. The field set is deliberately minimal: only the canonical
// GitHub-controlled attributes that participate in a trust decision appear here,
// so the use-case has no API surface to mis-key against (e.g. PR body / title).
//
// The struct is populated by the adapter at the github seam. Every
// validation decision against PRMetadata is byte-equal or enumerated; no field
// is regex-parsed out of free text.
type PRMetadata struct {
	// AuthorLogin is `pull_request.user.login` — the GitHub-canonical PR
	// author identity. NEVER `pull_request.head.user.login`, NEVER
	// commit-author email, NEVER display name. Compared byte-equal
	// (lowercase-normalised) against the YAML's GitHubHandle.
	AuthorLogin string
	// State is `pull_request.state` ∈ {"open", "closed"}. The accepting shape
	// requires "open".
	State string
	// IsDraft is `pull_request.draft`. Draft PRs are refused as
	// structurally-not-finalised.
	IsDraft bool
	// IsMerged is `pull_request.merged`. Already-merged PRs are refused;
	// re-absorption is not the intended path.
	IsMerged bool
	// HeadSHA is `pull_request.head.sha` — the PR HEAD commit SHA at the moment
	// of read. The adapter pins this at the first read; the executor re-reads
	// at Phase-1 step 5b and asserts byte-equal to refuse force-push races.
	HeadSHA string
	// HeadRepoOwnerLogin is `pull_request.head.repo.owner.login` — the fork
	// owner. Pinned at the first read; the executor re-reads and asserts
	// byte-equal to refuse fork-ownership-transfer races.
	HeadRepoOwnerLogin string
	// AuthorType is `pull_request.user.type` ∈ {"User", "Bot", "Organization",
	// ...}. The accepting shape requires "User"; bot/org PR-author absorption
	// is not a v0.2 supported path.
	AuthorType string
	// Commits is the list of commits the PR carries with their author logins.
	// Every commit's author login must equal AuthorLogin; divergence triggers
	// a commit-author divergence refusal.
	Commits []CommitInfo
}

// CommitInfo is the per-commit projection consumed by the commit-author
// divergence check. The SHA is carried so the refusal message can name the
// divergent commit; the author login is the load-bearing field.
//
// Body carries the full, untruncated commit message body as reported by the
// upstream git host. It exists as defense-in-depth against operator-visible
// commit-body forge attempts: the request-access validator inspects every
// commit body for the reserved byreis-sig: footer token (case-insensitive)
// and refuses the PR on any match, on the rationale that contributor-authored
// commit messages must never contain bytes that resemble byreis's own
// signed-commit footer format. The adapter populates this field from the
// existing PR commits response so the trip-wire adds no extra HTTP call.
type CommitInfo struct {
	SHA         string
	AuthorLogin string
	Body        string
}

// FromRequestPRMeta carries the request-access PR provenance into the rotation
// audit event. Populated only when a rotation absorbs a `--from-request <PR>`
// payload; the existing rotation audit-event shape is unchanged when this
// pointer is nil.
type FromRequestPRMeta struct {
	// Project is the registry repo's canonical "<owner>/<repo>" identifier
	// (the PR's base repository).
	Project string
	// Number is the PR number on the registry repo.
	Number int
	// HeadSHA is the PR HEAD commit SHA captured at admin absorb time.
	HeadSHA string
	// YAMLHandle is the validated YAML `github_handle` (lowercase ASCII).
	YAMLHandle string
	// ValidatedAuthorLogin is the PR opener's GitHub login after the
	// PR-author-vs-YAML byte-equal check succeeded.
	ValidatedAuthorLogin string
}

// OpenRequestSummary is the read-only triage projection of one open
// request-access PR. Carries ONLY GitHub-canonical metadata; it is NOT a
// trust input and is NEVER fed to the request-access validation state machine.
type OpenRequestSummary struct {
	PRRef       git.PRRef // registry <owner>/<repo>#<number> — the ref `rotate --add --from-request` consumes
	AuthorLogin string    // pull_request.user.login, lowercase-normalised (advisory)
	Title       string    // pull_request.title — DISPLAY ONLY, sanitized at the render layer
	CreatedAt   string    // RFC3339 advisory age field
	HeadSHA     string    // PR HEAD at list time (advisory; absorb-time re-pins)
}

// AuditEntryView is the read-only display projection of one registry audit
// entry surfaced by `byreis admin audit show`. It is a closed allowlist: it
// carries ONLY the registry-canonical fields that are safe to surface to an
// operator. It deliberately omits the recipient pubkey-set, any per-file
// content SHA, and any secret or high-entropy value. The adapter maps an
// audit.Event to an AuditEntryView at the registry boundary (the pure
// ProjectAuditEvent helper applies the same partition); raw audit.Event JSON
// never crosses into the use-case or CLI.
//
// Every rendered string field is adversarial input — an actor with
// registry-write capability but no trusted-signer key can shape the
// unvalidated fields (Actor, Outcome, Project, OccurredAt, Kind). The render
// layer therefore passes every field through the terminal sanitiser before any
// write to a TTY; the narrowing here is defense-in-depth, not a substitute for
// that sanitiser.
type AuditEntryView struct {
	// Kind is the audit event kind string, constrained to the accepted
	// event-class set on read. An unrecognised kind sets Unknown=true and is
	// surfaced as a warning row, never dropped and never a crash.
	Kind string
	// OccurredAt is the event timestamp in RFC3339 (advisory display).
	OccurredAt string
	// Actor is the admin identity string that performed the action; may be
	// empty for system events. Never a key or pubkey.
	Actor string
	// Project is the canonical project identifier the entry belongs to.
	Project string
	// Outcome is the event outcome, one of "ok", "reverted", or "error: <hint>".
	Outcome string
	// SafeDetails is the positive-allowlisted subset of the event's Details map,
	// keyed by the same canonical key names the producer emits. Anything not on
	// the allowlist is dropped (fail-closed by omission). The per-index removed
	// recipient pubkeys are never copied here; their count is surfaced as the
	// synthetic key removed_recipients_count instead.
	SafeDetails map[string]string
	// Unknown is true when Kind fell outside the accepted set on read. The
	// render layer prints a forward-compat warning row rather than a typed
	// entry, so a newer client that wrote a future event class does not crash
	// an admin's audit display.
	Unknown bool
}

// RequestAccessReader is the consumer-defined port the admin-side `--from-request`
// orchestration uses to fetch the contributor's PR payload and the canonical
// GitHub metadata required for the PR-author-vs-YAML check. The github-SDK
// adapter implements this port; this port keeps the use-case spine
// independent of any SDK type.
//
// The adapter implementation MUST fail closed across the following failure
// modes; the validation use-case asserts the same matrix as a defense-in-depth
// boundary:
//
//  1. PR title spoof — author is read exclusively from the typed
//     pull_request.user.login field; title / body / description / comments are
//     NEVER parsed for any trust decision.
//  2. Base-ref swap — PR HEAD SHA is pinned at the first read and re-asserted
//     on every subsequent fetch. SHA drift returns
//     ErrRequestAccessPRForcePushed.
//  3. Force-push race — same defence as (2); also catches contributor pushes
//     between plan and execute.
//  4. Display-name vs login — github_handle is compared byte-equal (after
//     lowercase normalisation) against pr.User.Login; pr.User.Name (display
//     name) is NEVER consulted.
//  5. Deleted / renamed account — pr.User.Login = "ghost" or "" refuses with
//     ErrRequestAccessIdentityMismatch; renamed accounts naturally fail the
//     byte-equal compare.
//  6. Fork-PR vs branch-PR — YAML content is resolved from
//     pr.Head.Repo.FullName at the pinned HEAD SHA; existence in the base
//     repo is NOT a security signal. pr.Head.Repo.Owner.Login is pinned for
//     fork-ownership-change detection.
//  7. Draft PR — refused as structurally-not-finalised.
//  8. Closed / re-opened PR — refused on pr.state = "closed" regardless of
//     pr.merged_at; reopened PRs surface as state=open and re-enter checks
//     (1)–(7).
//  9. Bot identity — refused on pr.User.Type != "User".
type RequestAccessReader interface {
	// FetchRequestAccessYAML reads `requests/<handle>.yaml` from the PR's HEAD
	// ref at the SHA captured at the moment of the GitHub "get PR" call. It
	// returns the parsed YAML payload alongside the canonical PR metadata
	// projection. Implementations MUST refuse on HEAD-SHA drift between the
	// author-read and the YAML-read (TOCTOU defence); MUST refuse on path
	// scope violations (files-changed outside `requests/<handle>.yaml`); MUST
	// reject non-ASCII handles and any payload that fails strict-decoder
	// validation.
	FetchRequestAccessYAML(ctx context.Context, prRef git.PRRef) (RequestAccessFile, PRMetadata, error)
	// FetchPRHeadSHA returns the PR HEAD commit SHA and the fork-repo owner
	// login at the moment of call. Both values are sourced from the same
	// PullRequests.Get call; the executor re-asserts both against the values
	// pinned at FetchRequestAccessYAML call time. SHA drift means a force-push
	// race; ownerLogin drift means the fork was transferred between plan and
	// execute. Both conditions fail closed before Phase-1 starts.
	FetchPRHeadSHA(ctx context.Context, prRef git.PRRef) (sha string, ownerLogin string, err error)
	// ListOpenRequests returns the read-only triage projection of every OPEN
	// request-access PR in the registry repo. It performs no trust decision and
	// fetches no per-PR fork content: each summary carries only GitHub-canonical
	// metadata for operator display, never the contributor-authored age_pubkey
	// or justification. An empty result is a valid, non-error outcome ("nothing
	// to triage"); a backend failure returns a non-nil error so the caller never
	// mistakes a fetch failure for an empty queue.
	ListOpenRequests(ctx context.Context) ([]OpenRequestSummary, error)
}

// AuditReader is the consumer-defined port the `byreis admin audit show`
// orchestration uses to fetch the registry audit log for one project. It is
// read-only: it acquires no signer, no registry-write credential, and no
// trust-path capability.
type AuditReader interface {
	// FetchAuditLog returns the audit entries recorded for projectID, read from
	// the registry audit/<projectID>.jsonl file at a signature-verified
	// registry HEAD. Implementations MUST fail closed:
	//   - read ONLY from a HEAD verified at the same fetch that pinned it;
	//   - return the unsigned-registry sentinel when the HEAD is not
	//     signature-verified;
	//   - return the registry-offline sentinel when the registry is unreachable
	//     and no integrity-checked cache is available;
	//   - NEVER return entries sourced from an unverified HEAD or an unverified
	//     cache (no best-effort display path).
	// The result is bounded (per-project scope, count cap, and size cap). An
	// empty slice with a nil error is the valid "no audit entries yet" outcome.
	FetchAuditLog(ctx context.Context, projectID string) ([]AuditEntryView, error)
}

// RegistryReadTokenProvider is a NEW consumer-defined port introduced at V6
// for the read-only registry surfaces the admin side opens (the
// request-access PR fetch path, principally). It is structurally distinct
// from auth.RegistryWriteTokenStore so a read-only caller cannot accidentally
// acquire the write capability via port-reuse.
//
// The pre-existing RotationStateProbe.FetchPartialState read site remains on
// the write-token reuse path; broader migration of that read site to this
// new read-only provider is deferred to a later release.
type RegistryReadTokenProvider interface {
	// RegistryReadToken returns a registry-scoped read token. Implementations
	// MUST NOT return a token that also carries write capability — read /
	// write separation at the credential layer is load-bearing on the
	// asymmetric-access invariant for this new admin-mode read path.
	RegistryReadToken(ctx context.Context) (string, error)
}
