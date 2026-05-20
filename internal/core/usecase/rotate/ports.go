package rotate

import (
	"context"
	"time"

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
	// project in one signed registry commit (or N commits — atomicity is not
	// load-bearing for Phase-1-only state — no file has been committed to
	// project main yet). A CAS rejection on the
	// pending-clear push surfaces a non-nil error which the reconciler treats
	// as retryable up to a bounded budget.
	ClearPendings(ctx context.Context, projectID string, pendings []PendingObservation) error
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
