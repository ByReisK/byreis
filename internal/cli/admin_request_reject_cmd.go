package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// newAdminRequestRejectCmd constructs the `admin request reject` sub-command.
//
// The strict evaluation order is:
//
//  1. Mode gate via checkPolicy — CONTRIBUTOR is denied-not-attempted:
//     no adapter, no network contact.
//  2. CLI validates and sanitises --reason via render.SanitizeForTerminal (primary
//     scrubber) and enforces the 2000-byte cap before constructing RejectInput.
//     Non-interactive empty reason fails closed before any network contact.
//  3. Parse --pr into a git.PRRef via the existing parsePRRef whitelist validator.
//  4. Dispatch to the injected RequestRejecter use-case.
//  5. The use-case re-asserts its own core structural constraint on the reason
//     (fail-closed backstop for non-CLI callers; defense in depth).
//
// The --reason text is posted to a PUBLIC pull-request comment. The help text
// warns operators accordingly. The reason is NEVER stored in the audit log —
// only its byte length is recorded.
func newAdminRequestRejectCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		prVal  string
		reason string
	)

	cmd := &cobra.Command{
		Use:   "reject",
		Short: "Reject an open request or submission PR (admin only)",
		Long: `Close an open request-access or submission pull request with a reason.

Requires ADMIN mode: denied-by-policy before any network contact.

The --reason text is posted as a PUBLIC pull-request comment visible to anyone
who can see the repository. Do not include secrets or sensitive details.

The PR is classified by the repository it belongs to and its head branch prefix.
A PR that does not match a recognised byreis branch namespace is refused —
nothing is closed. A merged PR is refused; an already-closed PR is idempotent.

Non-interactive mode (BYREIS_NON_INTERACTIVE=1): --reason must be non-empty;
an empty reason fails closed before any network contact.

Exit codes:
  0   PR closed (or was already closed — idempotent).
  1   General error (network, parse, use-case).
  3   Permission denied (CONTRIBUTOR mode).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// (1) Mode gate FIRST — denied-not-attempted before any adapter or
			// network contact. A CONTRIBUTOR invocation never reaches parsePRRef
			// or the use-case.
			if pErr := checkPolicy(deps, r, mode.CommandRequestReject, "admin request reject"); pErr != nil {
				return pErr
			}

			// (2a) Non-interactive empty-reason check. Fail closed before any
			// network contact so no partial state is created.
			nonInteractive := envBool("BYREIS_NON_INTERACTIVE")
			if nonInteractive && reason == "" {
				err := fmt.Errorf(
					"%w: --reason is required when running non-interactively "+
						"(BYREIS_NON_INTERACTIVE); provide a reason with --reason",
					usecase.ErrRejectReasonUnsafe)
				r.PrintErrorClass("general-error", err.Error(),
					"provide --reason when BYREIS_NON_INTERACTIVE is set")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// (2b) Sanitise the reason via the CLI-level terminal sanitiser
			// (primary scrubber: strips ANSI, control bytes, bidi overrides,
			// truncates to maxSanitizedLen). The use-case will additionally
			// assert its own core structural constraint as a backstop.
			sanitized := render.SanitizeForTerminal(reason)

			// (2c) Enforce the 2000-byte cap explicitly so the error is surfaced
			// at the CLI before submitting to the use-case. The sanitiser already
			// truncates to maxSanitizedLen (2000), but we surface this as a clear
			// error rather than silently truncating an operator-supplied reason.
			const maxReasonBytes = 2000
			if len(reason) > maxReasonBytes {
				err := fmt.Errorf(
					"--reason is %d bytes, maximum is %d: shorten the reason and retry",
					len(reason), maxReasonBytes)
				r.PrintErrorClass("general-error", err.Error(),
					fmt.Sprintf("shorten --reason to at most %d bytes", maxReasonBytes))
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// (3) Parse and validate the --pr flag against the path whitelist.
			ref, parseErr := parsePRRef(prVal)
			if parseErr != nil {
				r.PrintErrorClass("general-error", parseErr.Error(),
					"use the form project#number (e.g. myorg/my-app-secrets#42)")
				return &exitError{code: render.ExitGeneralError, cause: parseErr}
			}

			// (4) Dispatch to the RequestRejecter use-case.
			if deps.Rejecter == nil {
				err := fmt.Errorf(
					"admin request reject not available: the reject use-case is not wired — " +
						"set BYREIS_GITHUB_TOKEN and BYREIS_REGISTRY and run `byreis doctor`")
				r.PrintErrorClass("general-error", err.Error(),
					"set BYREIS_GITHUB_TOKEN and BYREIS_REGISTRY and run `byreis doctor`")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			result, err := deps.Rejecter.Reject(cmd.Context(), usecase.RejectInput{
				Ref:            ref,
				Reason:         sanitized,
				NonInteractive: nonInteractive,
			})
			if err != nil {
				code, class, hint := rejectExitCodeClassHint(err)
				r.PrintErrorClass(class, err.Error(), hint)
				return &exitError{code: code, cause: err}
			}

			// (5) Render the outcome.
			if *jsonFlag {
				_ = render.EncodeJSON(r.Out, map[string]any{
					"pr":     result.PR,
					"status": result.Status,
					"reason": render.SanitizeForTerminal(result.Reason),
					"url":    result.URL,
				})
				return nil
			}

			switch result.Status {
			case "already-closed":
				_, _ = fmt.Fprintf(r.Out,
					"PR %s is already closed (idempotent — no duplicate comment posted)\n",
					result.PR)
			default:
				url := result.URL
				if url == "" {
					url = result.PR
				}
				_, _ = fmt.Fprintf(r.Out, "PR %s closed: %s\n", result.PR, url)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&prVal, "pr", "",
		"PR reference in the form project#number (required)")
	cmd.Flags().StringVar(&reason, "reason", "",
		"Reason for rejection. This reason is posted as a PUBLIC PR comment visible "+
			"to anyone who can see the repository. Do not include secrets or sensitive details. "+
			"Maximum 2000 bytes.")
	_ = cmd.MarkFlagRequired("pr")

	return cmd
}

// rejectExitCodeClassHint maps a reject use-case error to the appropriate
// render.ExitCode, JSON class string, and actionable hint.
func rejectExitCodeClassHint(err error) (render.ExitCode, string, string) {
	if err == nil {
		return render.ExitOK, "ok", ""
	}
	if errors.Is(err, usecase.ErrRejectAlreadyMerged) {
		return render.ExitGeneralError, "general-error",
			"a merged PR cannot be rejected — reverse it through the admin reversal flow"
	}
	if errors.Is(err, usecase.ErrRejectWrongPRType) {
		return render.ExitGeneralError, "general-error",
			"verify you targeted a byreis submission or access-request PR; " +
				"check the PR number and project name"
	}
	if errors.Is(err, usecase.ErrRejectReasonUnsafe) {
		return render.ExitGeneralError, "general-error",
			"provide a plain single-paragraph reason without control characters; " +
				"maximum 2000 bytes"
	}
	if errors.Is(err, mode.ErrPermissionDenied) {
		return render.ExitPermissionDenied, "permission-denied",
			"admin request reject requires ADMIN mode — run `byreis doctor` to check your current mode"
	}
	return render.ExitGeneralError, "general-error",
		"run `byreis doctor` for diagnostics; check BYREIS_GITHUB_TOKEN"
}
