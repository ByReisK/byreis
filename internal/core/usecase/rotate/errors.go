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

	// ErrCommitBumpRejectedRotationInFlight is returned by the Submit/Merge
	// CommitBump use-case wrapper when the RotationStateProbe observes a
	// rotation-tagged pending for the (projectID, fileName) pair. Advancing a
	// single-file CommitBump while a rotation is in flight would corrupt the
	// rotation's N-file atomic commit (the rotation's RecordPendingBump would
	// then conflict with a now-stale last_accepted_counter). The contributor is
	// asked to retry once the rotation has completed.
	//
	// Defense-in-depth: the registry adapter's CAS lease is the ground-truth
	// rejection (ErrRegistryConcurrentWrite / countertypes.ErrCounterReconcile).
	// This sentinel provides a clean, actionable error class at the use-case
	// boundary so CLI callers can surface a specific "rotation in flight" message
	// rather than a generic "CAS rejected" hint.
	ErrCommitBumpRejectedRotationInFlight = errors.New(
		"refusing to commit counter bump: a rotation is in flight for this " +
			"(project, file) pair — retry after the rotation has completed or " +
			"run `byreis admin rotation reconcile` if the rotation appears stale")

	// ErrRequestAccessPRForcePushed is surfaced when the PR HEAD SHA drifts
	// between the planner's first read (the SHA that anchored the operator's
	// review of the dry-run plan) and the executor's second read at Phase-1
	// step 5b. A force-push race between plan and execute is treated as a
	// structural impersonation attempt; rotation fails closed BEFORE any branch
	// creation, signed manifest, or pending bump. The operator must re-run the
	// rotation to re-fetch and re-review the new YAML content.
	ErrRequestAccessPRForcePushed = errors.New(
		"refusing to absorb request-access PR: PR HEAD commit SHA drifted " +
			"between plan and execute (force-push race) — re-run " +
			"`byreis rotate --add --from-request <PR>` to refetch and review the " +
			"new content")

	// ErrRequestAccessPRStateInvalid is surfaced when the PR's state machine
	// is not exactly {state=open, draft=false, merged=false}. Draft PRs signal
	// the contributor has not finalised the request; closed PRs signal the
	// contributor revoked it (re-open is suspect); merged PRs were already
	// absorbed. Each refusal carries the observed state so the operator can
	// remediate.
	ErrRequestAccessPRStateInvalid = errors.New(
		"refusing to absorb request-access PR: PR is not in the {open, " +
			"non-draft, non-merged} state required for absorption — convert " +
			"from Draft / re-open / open a new request-access PR as appropriate")

	// ErrRequestAccessCommitAuthorDivergence is surfaced when any commit on
	// the request-access PR has an author login that differs from the PR
	// opener's login. Commit-author divergence is a structural impersonation
	// trip-wire: the operator visually reviews the PR opener but the commits
	// were authored by a different identity. Login-level only — commit
	// signature verification is out of scope at v0.2.
	ErrRequestAccessCommitAuthorDivergence = errors.New(
		"refusing to absorb request-access PR: the PR contains commits whose " +
			"author login differs from the PR opener — the contributor must close " +
			"and re-open the PR with a clean commit set authored by the PR opener")

	// ErrRequestAccessPRFilePathInvalid is surfaced when the PR's files-changed
	// list contains anything outside the `requests/<handle>.yaml` namespace,
	// any path-traversal segment, or more than one file. The contributor verb
	// constructs the path with no operator input; admin-side defence-in-depth
	// refuses any PR whose write surface escapes the requests/ tree.
	ErrRequestAccessPRFilePathInvalid = errors.New(
		"refusing to absorb request-access PR: PR file path is invalid — " +
			"PR must change exactly one file matching `requests/<handle>.yaml`; " +
			"no traversal, no other registry paths, no multi-file PRs")

	// ErrRequestAccessForkOwnershipChanged is surfaced when the fork-PR's
	// `head.repo.owner.login` drifts between the first read at plan time and
	// the second read at execute time. Fork ownership transfer between plan
	// and execute means the YAML content the admin reviewed is now under a
	// different attacker identity; rotation fails closed regardless of the
	// HEAD SHA being unchanged.
	ErrRequestAccessForkOwnershipChanged = errors.New(
		"refusing to absorb request-access PR: fork repo owner changed " +
			"between plan and execute — re-run `byreis rotate --add --from-request " +
			"<PR>` so the new ownership is re-evaluated")

	// ErrRequestAccessCommitBodyForgery indicates a request-access PR carries a
	// commit whose message body contains the byreis-sig: byte sequence, which is
	// a forgery indicator — contributor-authored commit bodies must never contain
	// bytes that resemble byreis's own signed-commit footer format.
	ErrRequestAccessCommitBodyForgery = errors.New(
		"refusing to absorb request-access PR: a PR commit message body contains the " +
			"byreis-sig: byte sequence, which is reserved for byreis-authored signed commits " +
			"and is a forgery indicator — the contributor must close and re-open the PR with " +
			"a clean commit set whose messages do not include that token",
	)

	// ErrRequestAccessQuotaExceeded is surfaced when the contributor's
	// `request-access` verb detects more than the configured ceiling of open
	// request-access PRs by the same GitHub identity against the registry
	// repo. A client-side advisory bound complementing GitHub's server-side
	// rate-limit and the registry's branch-protection enforcement.
	ErrRequestAccessQuotaExceeded = errors.New(
		"refusing to open request-access PR: the configured open-PR quota " +
			"for this GitHub identity is already exhausted — close stale PRs and " +
			"retry")

	// ErrRequestAccessEnumerationBounded is surfaced when the contributor-side
	// quota and idempotency checks exhaust the page-walk ceiling without
	// reaching a definitive answer (the registry has more open PRs than the
	// bounded scan can inspect). Because these are correctness checks — not
	// display-only aggregations — the opener refuses rather than risking a
	// duplicate PR or an under-counted quota. The operator hint names the
	// remediation: close stale request-access PRs so the scan stays within
	// bounds, or contact an admin to triage the queue directly.
	ErrRequestAccessEnumerationBounded = errors.New(
		"refusing to open request-access PR: too many open PRs on the registry " +
			"to verify your quota safely within the bounded scan — close stale " +
			"request-access PRs or contact an admin to triage the open queue")
)
