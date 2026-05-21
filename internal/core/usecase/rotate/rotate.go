package rotate

import (
	"context"
	"errors"
	"fmt"

	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// RotationInput is the full set of inputs the spine needs to execute one
// rotation invocation. Every input is value-typed or interface-typed; the
// caller (CLI verb layer) constructs the SourceVerified-registry-sourced
// fields from a fresh fetch and threads the operator-supplied flags here.
type RotationInput struct {
	// ProjectID is the registry-canonical project identifier. The spine does
	// not derive this from disk or env — the CLI layer resolves it.
	ProjectID string
	// Mode is the cryptographically-resolved current mode for this process.
	// The spine gates ADMIN-only at entry; CONTRIBUTOR is denied-not-attempted
	// before any registry fetch.
	Mode mode.Mode
	// SourceVerified is true only when PreRotationRecipients and
	// RegisteredAdmins were sourced from a signature-verified, non-stale
	// registry fetch within TTL. False causes the spine to fail closed with
	// ErrRotationRequiresFreshRegistry.
	SourceVerified bool
	// RegistryStale is true when the recipient set came from cache after a
	// network failure; the spine refuses to rotate against a stale set.
	RegistryStale bool
	// PreRotationRecipients is R, sourced from the SourceVerified registry.
	PreRotationRecipients []rectypes.Recipient
	// RegisteredAdmins is the full admin set at the SourceVerified registry
	// HEAD. The planner cross-checks --add against this set.
	RegisteredAdmins []rectypes.Recipient
	// AddPubkeys / RemovePubkeys / ReplacePairs carry the operator-supplied
	// recipient-set delta intents (repeatable flags).
	AddPubkeys    []rectypes.Recipient
	RemovePubkeys []rectypes.Recipient
	ReplacePairs  []ReplacePair
	// PreRotationFiles is the snapshot of every existing project secrets
	// file at the pre-rotation tree, with the running admin's identity
	// already used to decrypt the plaintext map at the caller side.
	// AdminCanDecryptAll signals whether that decrypt succeeded for every
	// file; a false value fails closed with ErrRotationCannotDecryptExisting
	// before any branch creation.
	PreRotationFiles   []FileSnapshot
	AdminCanDecryptAll bool
	CurrentMaxEpoch    uint64
	// FromRequestPR is non-nil when the rotation was invoked via
	// `byreis rotate --add --from-request <PR>`. The CLI layer populates it
	// after a successful ValidateRequestAccess call; the Phase-2 executor
	// threads it into BuildRotationAuditEvent so the audit trail records the
	// PR provenance. Nil on a plain `--add` invocation (no contributor PR).
	FromRequestPR *FromRequestPRMeta
	// DryRun selects preview-only behaviour: plan is computed and returned in
	// the result, but no Phase-1 work occurs.
	DryRun bool
	// Yes is set by the --yes flag and skips the interactive confirm. Under
	// BYREIS_NON_INTERACTIVE=1, Yes is REQUIRED or the spine fails closed
	// with ErrNonInteractiveRequiresYes.
	Yes bool
	// NonInteractive is the BYREIS_NON_INTERACTIVE=1 signal; the CLI sets
	// this from the env var. With NonInteractive=true and Yes=false, the
	// spine fails closed before any plan-print.
	NonInteractive bool
}

// RotationResult is the spine's output on success or non-error completion
// (dry-run). It carries the materialised plan and, on a real run, the
// terminal-phase result.
type RotationResult struct {
	// Plan is always populated; it is the dry-run output as well as the
	// real-run executed plan.
	Plan RotationPlan
	// DryRun is true when the spine exited after planning without invoking
	// Phase-1 or Phase-2 executors.
	DryRun bool
	// Phase1 is the Phase-1 result, populated only when a real run reached
	// the end of Phase-1 successfully.
	Phase1 Phase1Result
	// Phase2 is the Phase-2 result, populated only when a real run reached
	// the end of Phase-2 successfully.
	Phase2 Phase2Result
	// Phase1Executed indicates whether Phase1Executor.Execute was invoked.
	Phase1Executed bool
	// Phase2Executed indicates whether Phase2Executor.Execute was invoked.
	Phase2Executed bool
}

// RotatorDeps carries the constructor-injected ports for the spine. All
// collaborators are consumer-defined ports here in the rotate package or in
// upstream core packages — no SDK/transport/keychain types appear.
type RotatorDeps struct {
	Planner RotationPlanner
	Phase1  Phase1Executor
	Phase2  Phase2Executor
	Clock   Clock
}

// Rotator is the consumer-defined interface for the rotation use-case. It
// orchestrates the Plan → Phase-1 → Phase-2 state machine under the ADMIN-mode
// + SourceVerified-registry gates required by the protocol.
//
// Round-trip-decrypt scope (Phase-2 step 9): the runner round-trip-decrypts
// every value in the live post-rotation file for the running admin; the
// VerifyOfRecord port covers the recipient-set structural assertion for the
// remaining recipients in R' (the runner does NOT need every R' admin's
// private key to certify the rotation — VerifyOfRecord proves the live file
// is wrapped to every current recipient by checking the manifest's
// recipient-fingerprint set against the SourceVerified admin set, while the
// running admin's own round-trip-decrypt proves the live envelope is
// decryptable under at least that one identity).
type Rotator interface {
	Rotate(ctx context.Context, in RotationInput) (RotationResult, error)
}

// NewRotator returns a Rotator with the given dependencies. All ports are
// required; a missing port returns an error (no silent downgrade — security
// paths fail closed at construction).
func NewRotator(d RotatorDeps) (Rotator, error) {
	if d.Planner == nil || d.Phase1 == nil || d.Phase2 == nil || d.Clock == nil {
		return nil, errors.New(
			"rotate.NewRotator: a required port is nil — " +
				"wire RotationPlanner, Phase1Executor, Phase2Executor, and Clock")
	}
	return &rotator{d: d}, nil
}

type rotator struct {
	d RotatorDeps
}

// Rotate runs the two-phase rotation. Ordering is security-critical:
//
//  1. ADMIN-mode gate at entry. CONTRIBUTOR is denied-not-attempted: no
//     registry fetch, no plan computation, no Phase-1 work.
//  2. SourceVerified-registry gate. A stale or unverified set fails closed
//     with ErrRotationRequiresFreshRegistry.
//  3. Non-interactive opt-in gate. BYREIS_NON_INTERACTIVE=1 without --yes
//     fails closed with ErrNonInteractiveRequiresYes before any plan-print.
//  4. Plan computation. Planner is pure: no writes occur during this step.
//  5. Re-encrypt-all-existing precondition. If the running admin cannot
//     decrypt every existing file, fail closed with
//     ErrRotationCannotDecryptExisting BEFORE any branch creation.
//  6. Dry-run short-circuit. With DryRun=true, return the plan and exit.
//  7. Phase-1 execution. Branch + per-file work + pending bumps + push.
//  8. Phase-2 execution. Merge + atomic CommitRotation + integrity check.
//
// On any error before Phase-1 step 6 (branch push), no Phase-1 state has
// landed and reconcile is not required. On any error during Phase-1 between
// step 5d and step 6, reconcile classifies PHASE_1_ONLY and reverses.
// On any error in Phase-2, reconcile classifies and either reverses
// (still PHASE_1_ONLY shape if step 7 has not landed) or surfaces terminal
// ErrRotationReconcile (PHASE_2_MIDFLIGHT).
func (r *rotator) Rotate(ctx context.Context, in RotationInput) (RotationResult, error) {
	if err := ctx.Err(); err != nil {
		return RotationResult{}, fmt.Errorf("rotation cancelled: %w", err)
	}

	// (1) ADMIN-mode gate. The denial is denied-not-attempted: surface
	// ErrPermissionDenied before any registry-side action so a CONTRIBUTOR
	// never reaches the recipient fetch or branch creation.
	if in.Mode != mode.ModeAdmin && in.Mode != mode.ModeSuper {
		return RotationResult{}, fmt.Errorf(
			"%w: rotation requires ADMIN mode (current mode: %s)",
			mode.ErrPermissionDenied, in.Mode)
	}

	// (2) SourceVerified gate. A stale or unverified set is itself dangerous
	// for rotation: there is no --offline flag, ever.
	if !in.SourceVerified || in.RegistryStale {
		return RotationResult{}, ErrRotationRequiresFreshRegistry
	}

	// (3) Non-interactive opt-in gate. BYREIS_NON_INTERACTIVE=1 without
	// --yes fails closed before any plan-print so a runbook that forgot the
	// flag never silently writes.
	if in.NonInteractive && !in.Yes {
		return RotationResult{}, ErrNonInteractiveRequiresYes
	}

	// (4) Plan computation. Pure; no writes.
	plan, err := r.d.Planner.Plan(ctx, PlanInput{
		ProjectID:             in.ProjectID,
		PreRotationRecipients: in.PreRotationRecipients,
		RegisteredAdmins:      in.RegisteredAdmins,
		AddPubkeys:            in.AddPubkeys,
		RemovePubkeys:         in.RemovePubkeys,
		ReplacePairs:          in.ReplacePairs,
		PreRotationFiles:      in.PreRotationFiles,
		CurrentMaxEpoch:       in.CurrentMaxEpoch,
	})
	if err != nil {
		return RotationResult{}, err
	}

	// (5) Re-encrypt-all-existing precondition. If the running admin cannot
	// decrypt every existing file, fail closed BEFORE any branch creation
	// so reconcile is not needed (no Phase-1 write has occurred).
	if !in.AdminCanDecryptAll && len(plan.FilesToReencrypt) > 0 {
		return RotationResult{}, ErrRotationCannotDecryptExisting
	}

	// (6) Dry-run short-circuit. Return the plan; no Phase-1 work.
	if in.DryRun {
		return RotationResult{Plan: plan, DryRun: true}, nil
	}

	// (7) Phase-1 execution.
	p1, err := r.d.Phase1.Execute(ctx, plan)
	if err != nil {
		return RotationResult{Plan: plan}, fmt.Errorf("rotation phase 1: %w", err)
	}

	// Carry the request-access PR provenance from the spine input into the
	// Phase-1 result so the Phase-2 executor can record it on the rotation
	// audit event. Plain (non-request-access) rotations leave this nil and the
	// downstream audit-event builder omits the provenance fields.
	p1.FromRequestPR = in.FromRequestPR

	// (8) Phase-2 execution.
	p2, err := r.d.Phase2.Execute(ctx, p1)
	if err != nil {
		return RotationResult{
			Plan:           plan,
			Phase1:         p1,
			Phase1Executed: true,
		}, fmt.Errorf("rotation phase 2: %w", err)
	}

	return RotationResult{
		Plan:           plan,
		Phase1:         p1,
		Phase2:         p2,
		Phase1Executed: true,
		Phase2Executed: true,
	}, nil
}

// Compile-time assertion.
var _ Rotator = (*rotator)(nil)
