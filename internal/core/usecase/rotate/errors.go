// Package rotate is the admin rotation domain core: the use-case spine that
// orchestrates the recipient-set delta, re-encrypts every existing project
// secrets file under a fresh whole-file age envelope, and lands the per-file
// counter advance through a strict two-phase commit.
//
// This sub-package is parallel to internal/core/usecase/submit (NOT inside it):
// rotation is admin-only by construction and necessarily touches identity,
// decrypt, and the registry counter store, so it lives outside the contributor
// Submit closed-world allowlist target. The rotate sub-package has its own
// allowlist test asserting its transitive set is disjoint from the Submit
// allowlist target, so a rotate-side import cannot leak into the contributor
// compilation unit.
//
// The spine is pure domain code. It defines consumer-side ports for every
// boundary (planner, phase-1 executor, phase-2 executor, reconciler) so that
// real adapter implementations land in later slices and unit tests exercise
// fakes only — no real fs, net, clock, randomness, keychain, or git.
//
// Access boundary: mode is gated at the use-case entry (ADMIN only). The
// rotation transaction is the v0.2 trust-path verb; it consumes the at-most-one
// new trust-path verb budget for v0.2.
package rotate

import "errors"

// Sentinel errors owned by this package. Each wraps with %w on return paths
// and carries an actionable hint the CLI layer can surface to the operator.
// The package-private isolation pattern (no junk-drawer errors package) is
// honoured per the existing sentinel-ownership conventions.
//
// Reused (not aliased): countertypes.ErrCounterReconcile is referenced
// directly from internal/core/registry/countertypes where the rotation
// flow needs to surface a counter-authority reconcile event.
var (
	// ErrRotationRequiresFreshRegistry is returned when the rotation use-case
	// (or the reconciler) cannot obtain a SourceVerified, non-stale registry
	// fetch. Rotation against a stale or unverified admin set is itself
	// dangerous — there is no --offline flag, ever.
	ErrRotationRequiresFreshRegistry = errors.New(
		"rotation requires a signature-verified, non-stale registry fetch — " +
			"run `byreis registry refresh` and retry; rotation is never run against " +
			"a stale or unverified admin set")

	// ErrRotationReconcile is the terminal error surfaced when partial rotation
	// state is unrecoverable: a Phase-2 mid-flight crash (rotation branch merged
	// to project main but CommitRotation never landed) or an INCONSISTENT_PARTIAL
	// shape (rotation branch present alongside a merged tree, or pendings absent
	// alongside a rotation branch). No auto-rollback is attempted; operator
	// coordination is required.
	ErrRotationReconcile = errors.New(
		"rotation is in a partial state that cannot be auto-reconciled — " +
			"see docs/rotation-runbook.md for the operator recovery procedure")

	// ErrRotationCannotDecryptExisting is returned at planning / Phase-1 entry
	// when the running admin's identity is not in the pre-rotation recipient
	// set for at least one existing project file. Re-encrypt-all-existing
	// cannot proceed without read access to every plaintext, so the rotation
	// fails closed before any branch creation, signed manifest, or pending
	// bump is written.
	ErrRotationCannotDecryptExisting = errors.New(
		"refusing to rotate: the running admin's identity cannot decrypt every " +
			"existing project secrets file — another admin who is in the pre-rotation " +
			"recipient set must run this rotation, or run `byreis rotate --add` first " +
			"for this admin and then run the broader rotation")

	// ErrRotationFlagConflict is returned by the planner when --add and --remove
	// (or --replace and --add/--remove) request mutually exclusive intents for
	// the same pubkey within a single invocation. There is no defined
	// precedence — the admin must choose intent explicitly.
	ErrRotationFlagConflict = errors.New(
		"refusing to rotate: conflicting flags request mutually exclusive " +
			"intents for the same recipient — re-run with a single intent " +
			"(--add OR --remove OR --replace) for each recipient")

	// ErrRotationRemoveAbsentRecipient is returned when --remove names a
	// recipient that is not in the pre-rotation set. The operator likely has
	// the wrong project or the wrong fingerprint; rotation fails closed
	// before any write.
	ErrRotationRemoveAbsentRecipient = errors.New(
		"refusing to rotate: --remove names a recipient that is not in the " +
			"current recipient set — verify the project and the fingerprint " +
			"(run `byreis doctor`)")

	// ErrRotationAddNotAdmin is returned when --add names a pubkey that is
	// not registered in admins.yaml at the SourceVerified registry HEAD. Only
	// registered admins can be recipients; rotation does not register new
	// admins.
	ErrRotationAddNotAdmin = errors.New(
		"refusing to rotate: --add names a pubkey that is not a registered " +
			"admin in the signature-verified registry — register the admin first " +
			"(out-of-band admin registration is the v0.3 path)")

	// ErrRotationEmptyRecipientSet is returned when the composed new recipient
	// set R' is empty. A project with zero recipients is unreadable; operator
	// footgun protection rejects the plan before any write.
	ErrRotationEmptyRecipientSet = errors.New(
		"refusing to rotate: the new recipient set is empty — " +
			"a project with zero recipients is unreadable; restore at least one " +
			"admin and retry")

	// ErrNonInteractiveRequiresYes is returned when BYREIS_NON_INTERACTIVE=1 is
	// set without --yes. The dry-run plan is still computed and printed, but
	// the verb fails closed before any Phase-1 write — the operator must
	// explicitly opt into non-interactive execution.
	ErrNonInteractiveRequiresYes = errors.New(
		"refusing to rotate: BYREIS_NON_INTERACTIVE=1 requires --yes to " +
			"proceed without an interactive confirm — pass --yes to opt into " +
			"non-interactive execution")

	// ErrRequestAccessRegistryRejected is surfaced when the registry repo
	// rejects the contributor's request-access PR (branch protection, missing
	// requests/ directory, or insufficient permission for the contributor's
	// GitHub identity). Rotation does not fall back to a direct registry write
	// under any flag.
	ErrRequestAccessRegistryRejected = errors.New(
		"the registry repo rejected the request-access PR — " +
			"see the registry's onboarding docs for the supported path; " +
			"byreis does not fall back to a direct registry write")

	// ErrRequestAccessIdentityMismatch is surfaced when the request-access PR
	// author does not match the github_handle field in the requests YAML. The
	// adapter verifies this against the PR author at open time.
	ErrRequestAccessIdentityMismatch = errors.New(
		"refusing to open request-access PR: PR author does not match the " +
			"github_handle in the request payload — re-authenticate as the " +
			"intended contributor identity")

	// ErrRequestAccessSchemaInvalid is surfaced when the requests YAML fails
	// schema validation (schema_version mismatch, required field absent,
	// unknown field).
	ErrRequestAccessSchemaInvalid = errors.New(
		"request-access YAML failed schema validation — " +
			"re-run `byreis request-access` to regenerate a valid payload")

	// ErrRequestAccessShapeInfeasible is surfaced when, at DESIGN/PRE-impl
	// time, the request-access shape is found infeasible for the canonical
	// adopter registry configuration. Surfacing it from production code
	// signals the v0.6 demote-to-v0.3 fallback path; v0.2 ships an out-of-band
	// onboarding doc + rotate --add as the documented path instead.
	ErrRequestAccessShapeInfeasible = errors.New(
		"request-access is not feasible against this registry configuration — " +
			"out-of-band onboarding + `byreis rotate --add` is the supported v0.2 path")

	// ErrRotationReversalNoBranchRef is surfaced by BuildRotationReversalAuditEvent
	// when the observation has an empty RotationBranchRef. The reversal audit
	// event must carry the rotation branch PR ref so the audit trail can be
	// joined back to the failed rotation; a missing ref is a probe defect, not
	// an absence of action — the producer fails closed rather than emitting a
	// partial event.
	ErrRotationReversalNoBranchRef = errors.New(
		"refusing to emit rotation reversal audit event: observation carries an " +
			"empty rotation branch ref — the probe must populate RotationBranchRef " +
			"for any PHASE_1_ONLY observation")

	// ErrRotationFingerprintMismatch is surfaced when the operator-typed
	// fingerprint confirm value does not match the recipient's full SHA-256
	// fingerprint. The CLI's --remove / --replace path requires a full-64-char
	// typed confirm to defeat shoulder-surfed visual-only attacks; a mismatch
	// is a deliberate operator-side decision to abort. The verb surfaces this
	// sentinel so the CLI render layer can emit a clear, non-leaky message.
	ErrRotationFingerprintMismatch = errors.New(
		"refusing to rotate: the typed fingerprint does not match the displayed " +
			"recipient — re-run and type the full 64-char SHA-256 fingerprint exactly " +
			"as displayed; rotation never proceeds on a partial-match")
)
