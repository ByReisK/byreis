package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// newRotateCmd constructs the `byreis rotate` command. The command orchestrates
// the recipient-set delta for a project, re-encrypts every existing secrets
// file under the fresh whole-file age envelope, and lands the per-file counter
// advance through a strict two-phase commit.
//
// Mode gate is ALWAYS the first statement in RunE — denied-not-attempted before
// any registry fetch, plan computation, or Phase-1 work.
//
// Flag semantics:
//   - --add <age1...>       add a recipient to the set (repeatable)
//   - --remove <age1...>    remove a recipient (requires typed-fingerprint confirm)
//   - --replace <old=new>   replace one recipient with another (single composed delta)
//   - --from-request <PR>   deferred to a later slice; returns error immediately
//   - --dry-run             compute and print plan; no Phase-1 side effects
//   - --yes                 skip the interactive typed-fingerprint confirm
//   - --non-interactive     equivalent to BYREIS_NON_INTERACTIVE=1 at flag level
//   - --json                emit machine-readable JSON output
func newRotateCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		addPubkeys     []string
		removePubkeys  []string
		replacePairs   []string
		fromRequest    string
		dryRun         bool
		yes            bool
		nonInteractive bool
		project        string
	)

	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the recipient set for a project (admin only)",
		Long: `Rotate the recipient set and re-encrypt all existing project secrets files.

Requires ADMIN mode: denied-by-policy before any registry fetch or plan
computation when running as CONTRIBUTOR.

The rotation is a strict two-phase commit:
  Phase 1 (reversible): branch creation, per-file re-encrypt, per-file sign,
    per-file pending bump, branch push.
  Phase 2 (terminal): fast-forward merge, atomic N-file CommitRotation registry
    commit, post-merge integrity check.

Use --dry-run to preview the plan without writing anything.
Use --yes to skip the interactive typed-fingerprint confirm for --remove, --replace,
or --from-request.
Set BYREIS_NON_INTERACTIVE=1 (or --non-interactive) to fail closed if --yes is absent.

--from-request <registry>#<number> absorbs a contributor's request-access PR:
fetches requests/<handle>.yaml from the PR HEAD, validates the 9-mode state
machine, prints the admin warning, then fires the typed-fingerprint confirm gate.
A force-push race between plan and execute is caught by re-checking the HEAD SHA
immediately before Phase-1 starts.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST — denied-not-attempted before any other work.
			if pErr := checkPolicy(deps, r, mode.CommandRotate, "rotate"); pErr != nil {
				return pErr
			}

			// --from-request: absorb a contributor's request-access PR.
			var fromRequestMeta *rotate.FromRequestPRMeta
			if fromRequest != "" {
				var frErr error
				fromRequestMeta, frErr = resolveFromRequest(
					cmd, deps, r, fromRequest,
					yes, nonInteractive,
					&addPubkeys,
				)
				if frErr != nil {
					return frErr
				}
			}

			// Resolve non-interactive from env OR flag.
			nonInteractiveMode := nonInteractive || envBool("BYREIS_NON_INTERACTIVE")

			// ErrNonInteractiveRequiresYes gate: detect early at CLI for cleaner UX.
			// The spine also enforces this at rotate.go:174-176; the CLI layer
			// detects it here so stdout is never tainted with plan content on
			// this path (the critical no-plan-leak requirement).
			if nonInteractiveMode && !yes && !dryRun {
				err := rotate.ErrNonInteractiveRequiresYes
				r.PrintErrorClass("general-error", err.Error(),
					"pass --yes to proceed in non-interactive mode")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Parse --add pubkeys into domain types.
			var addRecips []rectypes.Recipient
			for _, pk := range addPubkeys {
				pk = strings.TrimSpace(pk)
				if pk == "" {
					continue
				}
				addRecips = append(addRecips, rectypes.Recipient{AgePubKey: pk})
			}

			// Parse --remove pubkeys into domain types.
			var removeRecips []rectypes.Recipient
			for _, pk := range removePubkeys {
				pk = strings.TrimSpace(pk)
				if pk == "" {
					continue
				}
				removeRecips = append(removeRecips, rectypes.Recipient{AgePubKey: pk})
			}

			// Parse --replace old=new pairs into ReplacePair domain types.
			// Each --replace value is ONE composed delta (NOT decomposed into
			// separate --add + --remove intents).
			var pairs []rotate.ReplacePair
			for _, pairStr := range replacePairs {
				pairStr = strings.TrimSpace(pairStr)
				if pairStr == "" {
					continue
				}
				eqIdx := strings.Index(pairStr, "=")
				if eqIdx <= 0 || eqIdx >= len(pairStr)-1 {
					err := fmt.Errorf(
						"--replace value %q is not in old=new form — "+
							"use --replace age1old...=age1new... with two full age public keys",
						pairStr)
					r.PrintErrorClass("general-error", err.Error(),
						"use --replace <old-age1-key>=<new-age1-key>")
					return &exitError{code: render.ExitGeneralError, cause: err}
				}
				oldKey := strings.TrimSpace(pairStr[:eqIdx])
				newKey := strings.TrimSpace(pairStr[eqIdx+1:])
				pairs = append(pairs, rotate.ReplacePair{
					Old: rectypes.Recipient{AgePubKey: oldKey},
					New: rectypes.Recipient{AgePubKey: newKey},
				})
			}

			// Typed-fingerprint confirm: required when removing recipients AND
			// NOT --yes AND NOT non-interactive mode.
			// "Removing" covers both --remove pubkeys and --replace pairs
			// (which carry an Old recipient that gets removed).
			hasRemovals := len(removeRecips) > 0 || len(pairs) > 0

			if hasRemovals && !yes && !nonInteractiveMode {
				// Identify the first recipient being removed for the confirm prompt.
				var confirmRecip rectypes.Recipient
				if len(removeRecips) > 0 {
					confirmRecip = removeRecips[0]
				} else {
					confirmRecip = pairs[0].Old
				}

				fullFingerprint := rotate.RecipientFingerprintFull(confirmRecip)
				prefix16 := fullFingerprint[:16]

				_, _ = fmt.Fprintf(r.Out,
					"Removing recipient %s...\n"+
						"Fingerprint prefix (first 16 chars): %s\n"+
						"Type the FULL 64-char SHA-256 fingerprint to confirm removal: ",
					confirmRecip.AgePubKey, prefix16)

				scanner := bufio.NewScanner(cmd.InOrStdin())
				var typed string
				if scanner.Scan() {
					typed = strings.TrimSpace(scanner.Text())
				}

				if typed != fullFingerprint {
					err := rotate.ErrRotationFingerprintMismatch
					r.PrintErrorClass("general-error", err.Error(),
						"re-run and type the full 64-char SHA-256 fingerprint exactly as displayed")
					return &exitError{code: render.ExitGeneralError, cause: err}
				}
			}

			// Build the RotationInput via real pre-flight checks when
			// RotatePreFlight is wired. When nil (integration-test setups
			// without a live registry), fall back to the prior stubs.
			in, preflightErr := buildRotationInput(
				cmd.Context(), deps, project,
				addRecips, removeRecips, pairs,
				dryRun, yes, nonInteractiveMode,
			)
			if preflightErr != nil {
				code := rotateMappedExitCode(deps, preflightErr)
				hint := rotateHintFor(code, preflightErr)
				class := rotateExitClass(code)
				r.PrintErrorClass(class, preflightErr.Error(), hint)
				return &exitError{code: code, cause: preflightErr}
			}
			// Attach PR provenance so the audit event records which request-access
			// PR triggered this rotation.
			in.FromRequestPR = fromRequestMeta

			result, err := deps.Rotator.Rotate(cmd.Context(), in)
			if err != nil {
				code := rotateMappedExitCode(deps, err)
				hint := rotateHintFor(code, err)
				class := rotateExitClass(code)
				r.PrintErrorClass(class, err.Error(), hint)
				return &exitError{code: code, cause: err}
			}

			if dryRun || result.DryRun {
				printRotationPlan(r, result.Plan, *jsonFlag)
				return nil
			}

			printRotationResult(r, result, *jsonFlag)
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&addPubkeys, "add", nil,
		"add a recipient age public key to the rotation set (repeatable)")
	cmd.Flags().StringArrayVar(&removePubkeys, "remove", nil,
		"remove a recipient age public key from the rotation set (repeatable; requires typed-fingerprint confirm)")
	cmd.Flags().StringArrayVar(&replacePairs, "replace", nil,
		"replace one recipient with another in old=new form (repeatable; single composed delta)")
	cmd.Flags().StringVar(&fromRequest, "from-request", "",
		"absorb recipient key from a request-access PR (e.g. myorg/admins#42)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"compute and print the rotation plan without writing anything")
	cmd.Flags().BoolVar(&yes, "yes", false,
		"skip the interactive typed-fingerprint confirm for --remove and --replace")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive",
		envBool("BYREIS_NON_INTERACTIVE"),
		"fail closed if --yes is absent (also set by BYREIS_NON_INTERACTIVE=1)")
	cmd.Flags().StringVar(&project, "project", "",
		"project ID (required)")
	_ = cmd.MarkFlagRequired("project")

	return cmd
}

// resolveFromRequest handles the `--from-request <PR>` path for `byreis rotate`.
// It fetches the contributor's request-access YAML, validates the 9-mode state
// machine, prints RequestAccessAdminWarning, fires the typed-fingerprint confirm
// gate, and re-checks the PR HEAD SHA to detect force-push races.
//
// On success it adds the validated age pubkey to addPubkeys and returns a
// populated *rotate.FromRequestPRMeta. The caller threads this into
// RotationInput.FromRequestPR for audit-trail provenance.
//
// Pre-condition: deps.RequestAccessReader must be non-nil; callers check before
// invoking this function.
func resolveFromRequest(
	cmd *cobra.Command,
	deps *Deps,
	r *render.Renderer,
	fromRequest string,
	yes bool,
	nonInteractive bool,
	addPubkeys *[]string,
) (*rotate.FromRequestPRMeta, error) {
	if deps.RequestAccessReader == nil {
		err := fmt.Errorf(
			"--from-request requires a RequestAccessReader but none is wired — " +
				"check that BYREIS_GITHUB_TOKEN is set and `byreis init` has been run")
		r.PrintErrorClass("general-error", err.Error(),
			"set BYREIS_GITHUB_TOKEN and run `byreis init`")
		return nil, &exitError{code: render.ExitGeneralError, cause: err}
	}

	// Parse the PR ref (e.g. "myorg/byreis-admins#42").
	prRef, parseErr := parsePRRef(fromRequest)
	if parseErr != nil {
		r.PrintErrorClass("general-error", parseErr.Error(),
			"use the form <owner>/<repo>#<number> (e.g. myorg/byreis-admins#42)")
		return nil, &exitError{code: render.ExitGeneralError, cause: parseErr}
	}

	ctx := cmd.Context()

	// Fetch and validate the contributor's YAML + PR metadata.
	file, prMeta, fetchErr := deps.RequestAccessReader.FetchRequestAccessYAML(ctx, prRef)
	if fetchErr != nil {
		r.PrintErrorClass("general-error", fetchErr.Error(),
			"check that the PR exists, is accessible, and contains exactly one requests/<handle>.yaml file")
		return nil, &exitError{code: render.ExitGeneralError, cause: fetchErr}
	}

	if valErr := rotate.ValidateRequestAccess(ctx, file, prMeta); valErr != nil {
		code := fromRequestValidateExitCode(valErr)
		r.PrintErrorClass(rotateExitClass(code), valErr.Error(),
			fromRequestValidateHint(valErr))
		return nil, &exitError{code: code, cause: valErr}
	}

	// Print the admin warning before the typed-fingerprint confirm so the
	// operator sees the full risk summary before being asked to type the key
	// fingerprint. This is the sole legitimate emission site for this warning.
	_, _ = fmt.Fprint(r.Out, rotate.RequestAccessAdminWarning) //nolint:forbidigo // boundary: CLI from-request absorption — sole legitimate emission site

	// Build a display line for the confirm prompt.
	sanitizedJust := render.SanitizeForTerminal(file.Justification)
	ageRecip := rotate.RecipientFingerprintFull(
		rectypes.Recipient{AgePubKey: file.AgePubkey},
	)

	// Typed-fingerprint confirm gate: required even when there is no --remove,
	// because absorbing a contributor-submitted key carries the same risk as
	// adding an unverified key manually.
	if !yes && !nonInteractive {
		prefix16 := ageRecip
		if len(ageRecip) >= 16 {
			prefix16 = ageRecip[:16]
		}
		_, _ = fmt.Fprintf(r.Out,
			"Adding recipient %s from PR %s;\n"+
				"  PR author      = %s\n"+
				"  YAML handle    = %s\n"+
				"  Justification  = %s\n"+
				"  Fingerprint prefix: %s\n"+
				"Type the FULL 64-char SHA-256 fingerprint of the recipient to confirm: ",
			file.AgePubkey, fromRequest,
			prMeta.AuthorLogin, file.GitHubHandle,
			sanitizedJust, prefix16)

		scanner := bufio.NewScanner(cmd.InOrStdin())
		var typed string
		if scanner.Scan() {
			typed = strings.TrimSpace(scanner.Text())
		}

		if typed != ageRecip {
			err := rotate.ErrRotationFingerprintMismatch
			r.PrintErrorClass("general-error", err.Error(),
				"re-run and type the full 64-char SHA-256 fingerprint exactly as displayed")
			return nil, &exitError{code: render.ExitGeneralError, cause: err}
		}
	}

	// Re-fetch the PR HEAD SHA and fork-repo owner login immediately before
	// Phase-1 starts. Both values are pinned at the FetchRequestAccessYAML call
	// above; any drift between that read and this re-check means the contributor
	// pushed new content (force-push race) or the fork was transferred to a
	// different account (ownership-transfer race). Either condition fails closed:
	// the admin reviewed content under the original identity and the original
	// commit; mismatches make that review invalid.
	currentSHA, currentOwner, recheckErr := deps.RequestAccessReader.FetchPRHeadSHA(ctx, prRef)
	if recheckErr != nil {
		r.PrintErrorClass("general-error", recheckErr.Error(),
			"could not re-verify PR HEAD SHA — re-run `byreis rotate --add --from-request` to retry")
		return nil, &exitError{code: render.ExitGeneralError, cause: recheckErr}
	}
	if currentSHA != prMeta.HeadSHA {
		err := fmt.Errorf("%w: HEAD SHA drifted from %q to %q between plan and execute",
			rotate.ErrRequestAccessPRForcePushed, prMeta.HeadSHA, currentSHA)
		r.PrintErrorClass("general-error", err.Error(),
			"re-run `byreis rotate --add --from-request` to re-fetch and re-review the new content")
		return nil, &exitError{code: render.ExitGeneralError, cause: err}
	}
	// Fork-ownership re-check: a fork transferred to a new account after the
	// admin's plan review retains the same HEAD SHA but places the YAML content
	// under a different identity. The audit row's validated_author_login would
	// no longer match the human who now controls the source; refuse to proceed.
	if currentOwner != prMeta.HeadRepoOwnerLogin {
		err := fmt.Errorf("%w: fork repo owner changed from %q to %q between plan and execute",
			rotate.ErrRequestAccessForkOwnershipChanged, prMeta.HeadRepoOwnerLogin, currentOwner)
		r.PrintErrorClass("general-error", err.Error(),
			"re-run `byreis rotate --add --from-request` so the new ownership is re-evaluated")
		return nil, &exitError{code: render.ExitGeneralError, cause: err}
	}

	// Inject the validated pubkey into --add list.
	*addPubkeys = append(*addPubkeys, file.AgePubkey)

	return &rotate.FromRequestPRMeta{
		Project:              prRef.Project,
		Number:               prRef.Number,
		HeadSHA:              prMeta.HeadSHA,
		YAMLHandle:           file.GitHubHandle,
		ValidatedAuthorLogin: prMeta.AuthorLogin,
	}, nil
}

// fromRequestValidateExitCode maps a ValidateRequestAccess error to the
// appropriate render.ExitCode.
func fromRequestValidateExitCode(err error) render.ExitCode {
	if errors.Is(err, rotate.ErrRequestAccessPRStateInvalid) {
		return render.ExitGeneralError
	}
	if errors.Is(err, rotate.ErrRequestAccessIdentityMismatch) {
		return render.ExitPermissionDenied
	}
	if errors.Is(err, rotate.ErrRequestAccessCommitAuthorDivergence) {
		return render.ExitPermissionDenied
	}
	if errors.Is(err, rotate.ErrRequestAccessForkOwnershipChanged) {
		return render.ExitGeneralError
	}
	if errors.Is(err, rotate.ErrRequestAccessSchemaInvalid) {
		return render.ExitDecodeMalformed
	}
	return render.ExitGeneralError
}

// fromRequestValidateHint returns an actionable hint for a validate error.
func fromRequestValidateHint(err error) string {
	if errors.Is(err, rotate.ErrRequestAccessPRStateInvalid) {
		return "the PR must be open, non-draft, and not yet merged"
	}
	if errors.Is(err, rotate.ErrRequestAccessIdentityMismatch) {
		return "the YAML github_handle must match the PR opener's GitHub login exactly"
	}
	if errors.Is(err, rotate.ErrRequestAccessCommitAuthorDivergence) {
		return "all commits on the PR must be authored by the PR opener"
	}
	if errors.Is(err, rotate.ErrRequestAccessForkOwnershipChanged) {
		return "re-run after the fork ownership is stable"
	}
	if errors.Is(err, rotate.ErrRequestAccessSchemaInvalid) {
		return "check the YAML schema (schema_version, github_handle, age_pubkey, justification, requested_at)"
	}
	return "run `byreis doctor` for diagnostics"
}

// buildRotationInput runs the two mandatory pre-flight checks and assembles a
// rotate.RotationInput with real values sourced from the SourceVerified registry
// and the admin decrypt-all-existing verification.
//
// When deps.RotatePreFlight is nil (integration-test setups without a live
// registry), the function falls back to SourceVerified:true and
// AdminCanDecryptAll:true with empty PreRotationRecipients and
// RegisteredAdmins — matching the prior stub behaviour. This fallback is
// intentional for unit tests that inject a fakeRotator; end-to-end tests and
// production must always wire RotatePreFlight.
func buildRotationInput(
	ctx context.Context,
	deps *Deps,
	projectID string,
	addRecips, removeRecips []rectypes.Recipient,
	pairs []rotate.ReplacePair,
	dryRun, yes, nonInteractive bool,
) (rotate.RotationInput, error) {
	base := rotate.RotationInput{
		ProjectID:      projectID,
		Mode:           deps.CurrentMode,
		AddPubkeys:     addRecips,
		RemovePubkeys:  removeRecips,
		ReplacePairs:   pairs,
		DryRun:         dryRun,
		Yes:            yes,
		NonInteractive: nonInteractive,
	}

	if deps.RotatePreFlight == nil {
		// No pre-flight adapter wired; fall back to prior stub values.
		// Production wiring always provides RotatePreFlight; this path is
		// for unit tests that inject fakeRotator without a registry.
		base.SourceVerified = true
		base.AdminCanDecryptAll = true
		return base, nil
	}

	// Pre-flight (a): fetch the SourceVerified, non-stale admin set.
	adminSet, err := deps.RotatePreFlight.FetchVerifiedAdminSet(ctx, projectID)
	if err != nil {
		return rotate.RotationInput{}, err
	}

	// Populate from the verified admin set.
	preRecips := make([]rectypes.Recipient, 0, len(adminSet.PreRotationRecipients))
	for _, pk := range adminSet.PreRotationRecipients {
		preRecips = append(preRecips, rectypes.Recipient{AgePubKey: pk})
	}
	regAdmins := make([]rectypes.Recipient, 0, len(adminSet.RegisteredAdmins))
	for _, pk := range adminSet.RegisteredAdmins {
		regAdmins = append(regAdmins, rectypes.Recipient{AgePubKey: pk})
	}

	// Populate pre-rotation files from snapshots.
	preFiles := make([]rotate.FileSnapshot, 0, len(adminSet.FileSnapshots))
	for _, snap := range adminSet.FileSnapshots {
		preFiles = append(preFiles, rotate.FileSnapshot{
			LogicalName:    snap.LogicalName,
			CurrentCounter: snap.CurrentCounter,
			CurrentEpoch:   snap.CurrentEpoch,
		})
	}

	// Pre-flight (b): verify the admin can decrypt every existing file.
	// CanDecryptAllFiles returns a sentinel wrapping
	// rotate.ErrRotationCannotDecryptExisting on any failure; plaintext
	// is never surfaced.
	if decryptErr := deps.RotatePreFlight.CanDecryptAllFiles(ctx, adminSet.FileSnapshots); decryptErr != nil {
		return rotate.RotationInput{}, decryptErr
	}

	base.SourceVerified = true
	base.RegistryStale = false
	base.AdminCanDecryptAll = true
	base.PreRotationRecipients = preRecips
	base.RegisteredAdmins = regAdmins
	base.PreRotationFiles = preFiles
	base.CurrentMaxEpoch = adminSet.CurrentMaxEpoch
	return base, nil
}

// rotateMappedExitCode maps a rotate-path error to the appropriate
// render.ExitCode. It first checks the static sentinel table, then delegates
// to deps.RotateExitCode for adapter-layer sentinels (e.g.
// ErrRegistryConcurrentWrite, ErrRegistryWriteAuth) that the CLI package cannot
// import directly.
func rotateMappedExitCode(deps *Deps, err error) render.ExitCode {
	if err == nil {
		return render.ExitOK
	}
	if errors.Is(err, rotate.ErrRotationReconcile) {
		return render.ExitCounterReconcile
	}
	if errors.Is(err, rotate.ErrRotationRequiresFreshRegistry) {
		return render.ExitTrustError
	}
	if errors.Is(err, rotate.ErrRotationCannotDecryptExisting) {
		return render.ExitAuthError
	}
	if errors.Is(err, rotate.ErrNonInteractiveRequiresYes) {
		return render.ExitGeneralError
	}
	if errors.Is(err, rotate.ErrRotationFingerprintMismatch) {
		return render.ExitGeneralError
	}
	if errors.Is(err, rotate.ErrRotationFlagConflict) {
		return render.ExitGeneralError
	}
	if errors.Is(err, rotate.ErrRotationReversalNoBranchRef) {
		return render.ExitTrustError
	}
	if errors.Is(err, mode.ErrPermissionDenied) {
		return render.ExitPermissionDenied
	}
	// Delegate to injected adapter-layer resolver when available.
	if deps != nil && deps.RotateExitCode != nil {
		return deps.RotateExitCode(err)
	}
	return render.ExitGeneralError
}

// rotateHintFor returns an actionable hint string for the given exit code.
func rotateHintFor(code render.ExitCode, err error) string {
	switch code {
	case render.ExitCounterReconcile:
		return "run `byreis admin rotation reconcile` to classify and recover the partial state"
	case render.ExitTrustError:
		if errors.Is(err, rotate.ErrRotationRequiresFreshRegistry) {
			return "trust-error-stale: run `byreis registry refresh` and retry"
		}
		if errors.Is(err, rotate.ErrRotationReversalNoBranchRef) {
			return "probe defect: re-run `byreis admin rotation reconcile` to re-probe"
		}
		return "run `byreis doctor` and verify the registry trust configuration"
	case render.ExitAuthError:
		return "run `byreis auth login` or check your admin key; " +
			"another admin who is in the pre-rotation recipient set must run this rotation"
	case render.ExitPermissionDenied:
		return "run `byreis doctor` to verify your admin mode"
	case render.ExitOK,
		render.ExitGeneralError,
		render.ExitNotFound,
		render.ExitReplay,
		render.ExitDecodeMalformed,
		render.ExitVerifyFailure:
		return "run `byreis doctor` for diagnostics"
	}
	return "run `byreis doctor` for diagnostics"
}

// rotateExitClass returns the stable string exit class for --json output.
func rotateExitClass(code render.ExitCode) string {
	switch code {
	case render.ExitOK:
		return "ok"
	case render.ExitPermissionDenied:
		return "permission-denied"
	case render.ExitAuthError:
		return "auth-error"
	case render.ExitCounterReconcile:
		return "counter-reconcile"
	case render.ExitTrustError:
		return "trust-error"
	case render.ExitGeneralError:
		return "general-error"
	case render.ExitNotFound:
		return "not-found"
	case render.ExitReplay:
		return "replay"
	case render.ExitDecodeMalformed:
		return "decode-malformed"
	case render.ExitVerifyFailure:
		return "verify-failure"
	}
	return "general-error"
}

// printRotationPlan writes the dry-run plan to stdout. No secret values are
// printed in any field.
func printRotationPlan(r *render.Renderer, plan rotate.RotationPlan, jsonOut bool) {
	if jsonOut {
		added := make([]string, len(plan.AddedRecipients))
		for i, rec := range plan.AddedRecipients {
			added[i] = rec.AgePubKey
		}
		removed := make([]string, len(plan.RemovedRecipients))
		for i, rec := range plan.RemovedRecipients {
			removed[i] = rec.AgePubKey
		}
		newSet := make([]string, len(plan.NewRecipientSet))
		for i, rec := range plan.NewRecipientSet {
			newSet[i] = rec.AgePubKey
		}
		files := make([]string, len(plan.FilesToReencrypt))
		for i, f := range plan.FilesToReencrypt {
			files[i] = f.LogicalName
		}
		_ = render.EncodeJSON(r.Out, map[string]any{
			"dry_run":            true,
			"project_id":         plan.ProjectID,
			"added_recipients":   added,
			"removed_recipients": removed,
			"new_recipient_set":  newSet,
			"files_to_reencrypt": files,
			"new_epoch":          plan.NewEpoch,
			"has_removals":       plan.HasRemovals,
		})
		return
	}
	_, _ = fmt.Fprintf(r.Out, "rotation plan (dry-run) for project %q:\n", plan.ProjectID)
	_, _ = fmt.Fprintf(r.Out, "  new epoch:           %d\n", plan.NewEpoch)
	_, _ = fmt.Fprintf(r.Out, "  added recipients:    %d\n", len(plan.AddedRecipients))
	_, _ = fmt.Fprintf(r.Out, "  removed recipients:  %d\n", len(plan.RemovedRecipients))
	_, _ = fmt.Fprintf(r.Out, "  files to re-encrypt: %d\n", len(plan.FilesToReencrypt))
	if plan.HasRemovals {
		_, _ = fmt.Fprintln(r.Out)
		_, _ = fmt.Fprintln(r.Out, rotate.ForwardSecrecyWarning) //nolint:forbidigo // boundary: CLI R4a output — this is the sole legitimate non-test emission site; the docgate asserts it byte-for-byte
	}
}

// printRotationResult writes the completed rotation result to stdout.
// No secret bytes are written; only structural metadata.
func printRotationResult(r *render.Renderer, result rotate.RotationResult, jsonOut bool) {
	if jsonOut {
		checks := make([]map[string]any, len(result.Phase2.IntegrityChecks))
		for i, ic := range result.Phase2.IntegrityChecks {
			checks[i] = map[string]any{
				"logical_name":  ic.LogicalName,
				"verify_ok":     ic.VerifyOK,
				"round_trip_ok": ic.RoundTripOK,
			}
		}
		_ = render.EncodeJSON(r.Out, map[string]any{
			"project_id":          result.Plan.ProjectID,
			"merged_sha":          result.Phase2.MergedSHA,
			"commit_rotation_sha": result.Phase2.CommitRotationSHA,
			"new_epoch":           result.Phase2.NewEpoch,
			"integrity_checks":    checks,
		})
		return
	}
	_, _ = fmt.Fprintf(r.Out,
		"rotation complete for project %q (epoch=%d merged=%s registry=%s)\n",
		result.Plan.ProjectID,
		result.Phase2.NewEpoch,
		result.Phase2.MergedSHA,
		result.Phase2.CommitRotationSHA,
	)
	if result.Plan.HasRemovals {
		_, _ = fmt.Fprintln(r.Out)
		_, _ = fmt.Fprintln(r.Out, rotate.ForwardSecrecyWarning) //nolint:forbidigo // boundary: CLI R4a output — this is the sole legitimate non-test emission site; the docgate asserts it byte-for-byte
	}
}
