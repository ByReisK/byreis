package cli

import (
	"bufio"
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
Use --yes to skip the interactive typed-fingerprint confirm for --remove or --replace.
Set BYREIS_NON_INTERACTIVE=1 (or --non-interactive) to fail closed if --yes is absent.

The --from-request flag requires the request-access PR contract which lands at a
later slice; use --add directly with the recipient key the PR proposes.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST — denied-not-attempted before any other work.
			if pErr := checkPolicy(deps, r, mode.CommandRotate, "rotate"); pErr != nil {
				return pErr
			}

			// --from-request deferred: return immediately with actionable hint.
			if fromRequest != "" {
				err := fmt.Errorf(
					"--from-request requires the request-access PR contract which lands at a later slice; " +
						"until then, pass --add <age1...> directly with the recipient key the PR proposes")
				r.PrintErrorClass("general-error", err.Error(),
					"pass --add <age1...> directly with the recipient key the PR proposes")
				return &exitError{code: render.ExitGeneralError, cause: err}
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

			if deps.Rotator == nil {
				err := fmt.Errorf(
					"rotate not available: the rotation use-case is not wired — " +
						"run `byreis doctor` or check your installation")
				r.PrintErrorClass("general-error", err.Error(),
					"run `byreis doctor` or check your installation")
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

			// Build the RotationInput. Mode is ALWAYS from cryptographic reality;
			// it is sourced from deps.CurrentMode and never from a flag, env, or
			// config file.
			in := rotate.RotationInput{
				ProjectID:      project,
				Mode:           deps.CurrentMode,
				AddPubkeys:     addRecips,
				RemovePubkeys:  removeRecips,
				ReplacePairs:   pairs,
				DryRun:         dryRun,
				Yes:            yes,
				NonInteractive: nonInteractiveMode,
				// SourceVerified and AdminCanDecryptAll are enforced by the spine
				// against its own SourceVerified registry fetch at Rotate() entry.
				// Setting both true here defers the authoritative check to the
				// spine; the spine gates (2) and (5) in rotate.go enforce the real
				// values — the CLI does not construct or trust these fields.
				SourceVerified:     true,
				AdminCanDecryptAll: true,
			}

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
		"read recipient key from a request-access PR (deferred to a later slice)")
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
		_, _ = fmt.Fprintln(r.Out, "  WARNING: recipients are being removed; "+
			"forward secrecy requires re-encryption of all files.")
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
}
