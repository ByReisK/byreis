package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
	"github.com/ByReisK/byreis/internal/core/usecase/submit/envparse"
)

// maxEnvFileBytes is the hard ceiling on the size of a contributor-supplied
// .env file read by --file. It is enforced before any allocation of the file
// contents, so an oversized file never causes an OOM read. The ceiling is set
// well above any realistic dotenv file (thousands of pairs at generous value
// lengths) and well below the point where a single read could threaten
// available memory. The core parser (envparse) applies its own independent
// byte ceiling as a second line of defense; this CLI-layer cap is the outer
// guard on the I/O path.
const maxEnvFileBytes = 4 * 1024 * 1024 // 4 MiB

// newSubmitCmd constructs the `byreis submit` command. The command supports
// two mutually exclusive input modes:
//
//   - --key <name>   single-key; the value is collected via the injected
//     Prompter (double-entry on TTY, single on pipe, irreversibility ack).
//   - --file <path>  bulk: reads a .env file at the CLI/adapter layer (I/O is
//     not core's job), parses it with envparse, and calls SubmitBulk. A file
//     with exactly one pair still takes the bulk path by design.
//
// --file and --key are mutually exclusive; supplying both is an actionable
// error returned before any network contact.
//
// Mode gate is ALWAYS the first statement in RunE — denied-not-attempted
// before any file I/O, network call, or use-case invocation.
func newSubmitCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		key            string
		filePath       string
		justification  string
		nonInteractive bool
	)

	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Submit an encrypted secret (contributor write-only path)",
		Long: `Encrypt and submit a secret (or a .env file of secrets) to the admin
review queue.

The secret(s) are encrypted to the admin public-key set sourced from the
verified registry. The contributor never holds the plaintext after submission;
this path provides no decrypt capability by construction.

Two input modes (mutually exclusive):
  --key <name>   single-key: the value is collected interactively (TTY
                 double-entry + irreversibility ack) or from stdin.
  --file <path>  bulk: reads a .env file, parses all KEY=VALUE pairs, and
                 opens one PR carrying all of them. One pair still uses the
                 bulk path (no single-key special-case when --file is used).

Contributor and admin modes are both permitted to submit.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST — denied-not-attempted before any I/O.
			if deps.Policy != nil {
				if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandSubmit); err != nil {
					r.PrintErrorClass(
						"permission-denied",
						err.Error(),
						"submit requires CONTRIBUTOR or ADMIN mode — "+
							"run `byreis doctor` to check your current mode",
					)
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			}

			// Mutual exclusion: --file and --key cannot be used together.
			if key != "" && filePath != "" {
				err := fmt.Errorf(
					"--file and --key are mutually exclusive — " +
						"use --file <path> for a bulk .env submission or " +
						"--key <name> for a single-key interactive submission, not both")
				r.PrintErrorClass(
					"general-error",
					err.Error(),
					"pass either --file or --key, not both",
				)
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// TUI fork: if ShouldLaunchTUI returns true and RunTUISubmit is wired,
			// delegate to the TUI submit screen instead of the headless CLI path.
			// The fork runs BEFORE the "at least one flag required" check because
			// bare `byreis submit` with no flags at a TTY is the canonical TUI
			// launch case.
			//
			// The --file bulk path and --key-with-piped-stdin path always stay
			// headless (FlagsFullySpecify returns true for them), so the bulk and
			// piped paths stay headless without an explicit --file guard here.
			//
			// The TUI fork is placed after the mode gate and the mutual-exclusion
			// check but before the "at least one input mode" check so that bare
			// `submit` reaches the TUI rather than the headless error path.
			if deps.RunTUISubmit != nil && ShouldLaunchTUI(
				"submit",
				*jsonFlag,
				EnvFromOS(),
				IsTTYFile(os.Stdin),
				IsTTYFile(os.Stdout),
				deps.Policy,
				deps.CurrentMode,
				key,
				filePath,
				"",
				nonInteractive,
			) {
				// Build the base submit.Input with the same metadata fields the
				// headless CLI path uses. The TUI model populates Key from its
				// form (or from the pre-supplied --key value).
				projectID := os.Getenv("BYREIS_PROJECT")
				logicalFile := os.Getenv("BYREIS_LOGICAL_FILE")
				secretsPath := os.Getenv("BYREIS_SECRETS_PATH")
				baseFilePath := os.Getenv("BYREIS_BASE_FILE_PATH")
				if projectID == "" || secretsPath == "" {
					err := fmt.Errorf(
						"project configuration not set — " +
							"set BYREIS_PROJECT and BYREIS_SECRETS_PATH, " +
							"or run `byreis init` to generate a project config")
					r.PrintErrorClass(
						"general-error",
						err.Error(),
						"run `byreis init` or set BYREIS_PROJECT + BYREIS_SECRETS_PATH",
					)
					return &exitError{code: render.ExitGeneralError, cause: err}
				}
				if baseFilePath == "" {
					baseFilePath = secretsPath
				}

				base := submit.Input{
					ProjectID:       projectID,
					LogicalFileName: logicalFile,
					Justification:   justification,
					SecretsPath:     secretsPath,
					BaseFilePath:    baseFilePath,
				}

				ctx := cmd.Context()
				tuiErr := deps.RunTUISubmit(ctx, cmd.OutOrStdout(), key, base)
				if tuiErr != nil {
					if deps.ErrTUISubmitAborted != nil && errors.Is(tuiErr, deps.ErrTUISubmitAborted) {
						// Abort is clean: non-zero exit, no error message (the TUI
						// already rendered the "cancelled" state).
						return &exitError{code: render.ExitGeneralError, cause: tuiErr}
					}
					return handleSubmitError(r, tuiErr)
				}
				return nil
			}

			// At least one input mode is required for the headless path.
			if key == "" && filePath == "" {
				err := fmt.Errorf(
					"one of --key or --file is required — " +
						"pass --key <name> for a single secret or " +
						"--file <path> for a bulk .env file submission")
				r.PrintErrorClass(
					"general-error",
					err.Error(),
					"pass --key <name> or --file <path.env>",
				)
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Submitter must be wired before any use-case call.
			if deps.Submitter == nil {
				err := fmt.Errorf(
					"submit adapters not configured — " +
						"run `byreis init` to configure your project, " +
						"or check your BYREIS_* environment variables")
				r.PrintErrorClass(
					"general-error",
					err.Error(),
					"run `byreis init` or check your configuration",
				)
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			ctx := cmd.Context()

			// Resolve project/file/path config from env. Production wiring populates
			// these from the project config file parsed at startup; during the
			// interim wiring period the operator sets them via BYREIS_* env vars.
			projectID := os.Getenv("BYREIS_PROJECT")
			logicalFile := os.Getenv("BYREIS_LOGICAL_FILE")
			secretsPath := os.Getenv("BYREIS_SECRETS_PATH")
			baseFilePath := os.Getenv("BYREIS_BASE_FILE_PATH")
			if projectID == "" || secretsPath == "" {
				err := fmt.Errorf(
					"project configuration not set — " +
						"set BYREIS_PROJECT and BYREIS_SECRETS_PATH, " +
						"or run `byreis init` to generate a project config")
				r.PrintErrorClass(
					"general-error",
					err.Error(),
					"run `byreis init` or set BYREIS_PROJECT + BYREIS_SECRETS_PATH",
				)
				return &exitError{code: render.ExitGeneralError, cause: err}
			}
			if baseFilePath == "" {
				baseFilePath = secretsPath
			}

			// --file path: read bytes at the CLI/adapter layer (I/O is not core's
			// job), parse with envparse, call SubmitBulk. A one-pair file still
			// takes this path — there is no single-key special-case for --file.
			if filePath != "" {
				raw, ioErr := readEnvFileBounded(filePath)
				if ioErr != nil {
					r.PrintErrorClass(
						"general-error",
						ioErr.Error(),
						fmt.Sprintf("verify that %q exists, is readable, and is under %d bytes", filePath, maxEnvFileBytes),
					)
					return &exitError{code: render.ExitGeneralError, cause: ioErr}
				}

				pairs, parseErr := envparse.Parse(raw)
				if parseErr != nil {
					wrappedErr := fmt.Errorf("parsing %q: %w", filePath, parseErr)
					r.PrintErrorClass("general-error", wrappedErr.Error(), envparseHint(parseErr))
					return &exitError{code: render.ExitGeneralError, cause: wrappedErr}
				}

				// Map envparse.Pair → submit.Pair (same shape, different package).
				submitPairs := make([]submit.Pair, len(pairs))
				for i, p := range pairs {
					submitPairs[i] = submit.Pair{Key: p.Key, Value: p.Value}
				}

				nonInteractiveMode := nonInteractive || envBool("BYREIS_NON_INTERACTIVE")
				_ = nonInteractiveMode

				bulkResult, bulkErr := deps.Submitter.SubmitBulk(ctx, submit.BulkInput{
					ProjectID:       projectID,
					LogicalFileName: logicalFile,
					Justification:   justification,
					SecretsPath:     secretsPath,
					BaseFilePath:    baseFilePath,
					Pairs:           submitPairs,
					// The operator explicitly supplied a --file, which is the
					// irreversibility acknowledgement for the bulk path.
					IrreversibleAcknowledged: true,
				})
				if bulkErr != nil {
					return handleSubmitBulkError(r, bulkErr)
				}

				return renderBulkResult(bulkResult, *jsonFlag, cmd)
			}

			// --key path: single-key interactive submit. The use-case's Submit
			// method drives the injected Prompter (double-entry on TTY, single on
			// pipe, irreversibility ack). This path is unchanged from the
			// single-key spine.
			result, submitErr := deps.Submitter.Submit(ctx, submit.Input{
				ProjectID:       projectID,
				LogicalFileName: logicalFile,
				Key:             key,
				Justification:   justification,
				SecretsPath:     secretsPath,
				BaseFilePath:    baseFilePath,
			})
			if submitErr != nil {
				return handleSubmitError(r, submitErr)
			}

			return renderSingleResult(result, *jsonFlag, cmd)
		},
	}

	cmd.Flags().StringVar(&key, "key", "", "secret key name (single-key mode; mutually exclusive with --file)")
	cmd.Flags().StringVar(&filePath, "file", "", "path to a .env file for bulk submission (mutually exclusive with --key)")
	cmd.Flags().StringVar(&justification, "justification", "",
		"justification for the submission (logged in PR)")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive",
		envBool("BYREIS_NON_INTERACTIVE"),
		"non-interactive mode (or set BYREIS_NON_INTERACTIVE=1)")

	// Neither --key nor --file is globally required by cobra: at-least-one and
	// mutual-exclusion enforcement are checked in RunE with actionable errors.

	return cmd
}

// envparseHint returns an actionable suggested fix based on which envparse
// sentinel was returned.
func envparseHint(err error) string {
	switch {
	case errors.Is(err, envparse.ErrDuplicateKey):
		return "remove the duplicate key from the .env file so each key appears exactly once"
	case errors.Is(err, envparse.ErrTooManyPairs):
		return "split the .env file into multiple submissions of at most 100 pairs each"
	case errors.Is(err, envparse.ErrMalformedLine):
		return "fix the malformed line: each non-comment line must be KEY=VALUE (or export KEY=VALUE)"
	case errors.Is(err, envparse.ErrInputTooLarge):
		return "reduce the .env file size below 4 MiB, or split into multiple smaller submissions"
	case errors.Is(err, envparse.ErrLineTooLong):
		return "shorten the offending line below 64 KiB, or split large values across multiple keys"
	default:
		return "check the .env file for syntax errors and retry"
	}
}

// handleSubmitBulkError maps a SubmitBulk error to the appropriate exit code
// and renders an actionable message. No secret value appears in any channel.
func handleSubmitBulkError(r *render.Renderer, err error) error {
	switch {
	case errors.Is(err, submit.ErrBranchConflict):
		r.PrintErrorClass("branch-conflict", err.Error(),
			"close or resolve the conflicting submission branch and retry")
		return &exitError{code: render.ExitGeneralError, cause: err}
	case errors.Is(err, submit.ErrNoRecipients):
		r.PrintErrorClass("trust-error", err.Error(),
			"run `byreis doctor` to check the admin registry")
		return &exitError{code: render.ExitTrustError, cause: err}
	case errors.Is(err, submit.ErrRecipientsNotVerified):
		r.PrintErrorClass("trust-error", err.Error(),
			"wait for the registry to be reachable and retry; run `byreis doctor` for diagnostics")
		return &exitError{code: render.ExitTrustError, cause: err}
	case errors.Is(err, submit.ErrInvalidValue):
		r.PrintErrorClass("validation-error", err.Error(),
			"fix the key name or value and retry")
		return &exitError{code: render.ExitGeneralError, cause: err}
	case errors.Is(err, submit.ErrDuplicateKey):
		r.PrintErrorClass("validation-error", err.Error(),
			"remove the duplicate key from the submission so each key appears exactly once")
		return &exitError{code: render.ExitGeneralError, cause: err}
	case errors.Is(err, submit.ErrTooManyPairs):
		r.PrintErrorClass("validation-error", err.Error(),
			"split the submission into multiple smaller submissions (at most 100 pairs each)")
		return &exitError{code: render.ExitGeneralError, cause: err}
	case errors.Is(err, submit.ErrNoPairs):
		r.PrintErrorClass("validation-error", err.Error(),
			"ensure the .env file contains at least one KEY=VALUE pair")
		return &exitError{code: render.ExitGeneralError, cause: err}
	case errors.Is(err, submit.ErrIrreversibleNotAcknowledged):
		r.PrintErrorClass("general-error", err.Error(),
			"acknowledge that the submission is irreversible before submitting")
		return &exitError{code: render.ExitGeneralError, cause: err}
	default:
		r.PrintErrorClass("general-error", err.Error(),
			"run `byreis doctor` for diagnostics")
		return &exitError{code: render.ExitGeneralError, cause: err}
	}
}

// handleSubmitError maps a single-key Submit error to the appropriate exit
// code. Mirrors handleSubmitBulkError for the sentinels that apply to the
// single-key path.
func handleSubmitError(r *render.Renderer, err error) error {
	switch {
	case errors.Is(err, submit.ErrBranchConflict):
		r.PrintErrorClass("branch-conflict", err.Error(),
			"close or resolve the conflicting submission branch and retry")
		return &exitError{code: render.ExitGeneralError, cause: err}
	case errors.Is(err, submit.ErrNoRecipients):
		r.PrintErrorClass("trust-error", err.Error(),
			"run `byreis doctor` to check the admin registry")
		return &exitError{code: render.ExitTrustError, cause: err}
	case errors.Is(err, submit.ErrRecipientsNotVerified):
		r.PrintErrorClass("trust-error", err.Error(),
			"wait for the registry to be reachable and retry")
		return &exitError{code: render.ExitTrustError, cause: err}
	case errors.Is(err, submit.ErrInvalidValue):
		r.PrintErrorClass("validation-error", err.Error(),
			"fix the key name or value and retry")
		return &exitError{code: render.ExitGeneralError, cause: err}
	case errors.Is(err, submit.ErrValueMismatch):
		r.PrintErrorClass("validation-error", err.Error(),
			"re-run `byreis submit --key` and re-enter the secret value")
		return &exitError{code: render.ExitGeneralError, cause: err}
	case errors.Is(err, submit.ErrIrreversibleNotAcknowledged):
		r.PrintErrorClass("general-error", err.Error(),
			"acknowledge that the submission is irreversible before submitting")
		return &exitError{code: render.ExitGeneralError, cause: err}
	default:
		r.PrintErrorClass("general-error", err.Error(),
			"run `byreis doctor` for diagnostics")
		return &exitError{code: render.ExitGeneralError, cause: err}
	}
}

// renderBulkResult writes the BulkResult to the configured output channel.
// Success JSON schema: one PR ref/URL/branch + the N keys with per-key action.
// No plaintext or key material appears in any channel.
func renderBulkResult(result submit.BulkResult, jsonMode bool, cmd *cobra.Command) error {
	if jsonMode {
		keys := make([]map[string]string, len(result.PerKey))
		for i, k := range result.PerKey {
			// Key names are contributor-influenced; sanitize before JSON to avoid
			// control-character injection in downstream consumers that parse text.
			keys[i] = map[string]string{
				"key":    render.SanitizeForTerminal(k.Key),
				"action": k.Action.String(),
			}
		}
		return render.EncodeJSON(cmd.OutOrStdout(), map[string]any{
			"pr_url":       result.PRURL,
			"pr_number":    result.PRRef.Number,
			"pr_project":   result.PRRef.Project,
			"branch":       result.Branch,
			"artifact_sha": result.ArtifactSHA,
			"keys":         keys,
		})
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "submitted %d key(s) — PR opened: %s\n",
		len(result.PerKey), result.PRURL)
	_, _ = fmt.Fprintf(out, "branch: %s\n", render.SanitizeForTerminal(result.Branch))
	for _, k := range result.PerKey {
		action := k.Action.String()
		suffix := ""
		if action == "replace" {
			suffix = "  [REPLACE]"
		}
		_, _ = fmt.Fprintf(out, "  %s  %s%s\n",
			action,
			render.SanitizeForTerminal(k.Key),
			suffix,
		)
	}
	return nil
}

// renderSingleResult writes the single-key Result to the configured output
// channel. No plaintext or key material appears in any channel.
func renderSingleResult(result submit.Result, jsonMode bool, cmd *cobra.Command) error {
	if jsonMode {
		return render.EncodeJSON(cmd.OutOrStdout(), map[string]any{
			"pr_url":       result.PRURL,
			"pr_number":    result.PRRef.Number,
			"pr_project":   result.PRRef.Project,
			"branch":       result.Branch,
			"artifact_sha": result.ArtifactSHA,
			"action":       result.Action.String(),
		})
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "%s — PR opened: %s\n", result.Action.String(), result.PRURL)
	_, _ = fmt.Fprintf(out, "branch: %s\n", render.SanitizeForTerminal(result.Branch))
	return nil
}

// newReviewCmd constructs the `byreis review` command. It is ADMIN-only:
// denied-by-policy in CONTRIBUTOR mode before any git fetch or decrypt.
//
// The review table renders ReviewResult.PerKey as a multi-row table: each of
// N pairs with its per-key ADD/REPLACE label and per-key validation result.
// REPLACE rows are labeled prominently. All contributor-influenced strings
// (key names, validation messages) are sanitized with SanitizeForTerminal
// before terminal display; --json emits values without terminal sanitization
// (callers on controlled channels receive the literal values).
//
// Plaintext values are NEVER emitted in any channel; they exist only in the
// use-case's ReviewResult.Plaintext and are zeroized after this function
// returns.
func newReviewCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var prRef string

	cmd := &cobra.Command{
		Use:   "review",
		Short: "Review a pending submission (admin only)",
		Long: `Fetch and verify a pending submission from the admin review queue.

Requires ADMIN mode: a usable private key that can decrypt the project file
and whose public key is in the verified registry.

The review table shows each submitted key with its add-vs-replace classification
and per-key validation result. REPLACE entries are labeled prominently.

The printed PinnedSHA is the content pin you must pass to --expect when merging:
  byreis merge --pr <ref> --expect <pinnedSHA>
A branch re-push between review and merge invalidates the pin and merge fails.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST — denied-not-attempted before any git fetch, decrypt,
			// or TUI launch. A contributor reaching `review` is denied here before
			// any other path is considered.
			if deps.Policy != nil {
				if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandReview); err != nil {
					r.PrintErrorClass(
						"permission-denied",
						err.Error(),
						"review requires ADMIN mode — "+
							"run `byreis doctor` to check your current mode",
					)
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			} else {
				// No policy wired: default-deny for admin-only commands.
				err := fmt.Errorf("%w: review requires ADMIN mode — "+
					"no admin key found or mode policy not configured; "+
					"see `byreis doctor` for your current mode",
					mode.ErrPermissionDenied)
				r.PrintErrorClass(
					"permission-denied",
					err.Error(),
					"run `byreis doctor` to check your current mode",
				)
				return &exitError{code: render.ExitPermissionDenied, cause: err}
			}

			ctx := cmd.Context()

			// TUI fork: if ShouldLaunchTUI returns true and RunTUIReview is wired,
			// delegate to the TUI review screen. This happens AFTER the mode gate
			// (contributor denied above) and BEFORE the headless --pr enforcement.
			// Bare `byreis review` at a TTY launches the TUI queue; the TUI's own
			// ref-entry screen collects the PR ref interactively.
			//
			// When --pr is supplied but we still launch the TUI (e.g. future
			// supply-and-review path), prRef is forwarded so the TUI can jump
			// directly to the detail screen.
			if deps.RunTUIReview != nil && ShouldLaunchTUI(
				"review",
				*jsonFlag,
				EnvFromOS(),
				IsTTYFile(os.Stdin),
				IsTTYFile(os.Stdout),
				deps.Policy,
				deps.CurrentMode,
				"",    // flagKey (not used by review)
				"",    // flagFile (not used by review)
				prRef, // flagPR
				false, // flagNonInteractive (review has no --non-interactive flag)
			) {
				tuiErr := deps.RunTUIReview(ctx, cmd.OutOrStdout(), prRef)
				if tuiErr != nil {
					// A deliberate quit without completing a review is a clean non-zero
					// exit. Any other error is surfaced as a review failure.
					return &exitError{code: render.ExitGeneralError, cause: tuiErr}
				}
				return nil
			}

			// Headless path: --pr is required when not going through the TUI.
			// This enforces the "use --pr" contract on the headless path only,
			// rather than as a global cobra MarkFlagRequired (which would prevent
			// the bare `review` TUI launch at a TTY).
			if prRef == "" {
				err := fmt.Errorf(
					"--pr is required in headless mode — " +
						"pass --pr <project#number> (e.g. myorg/my-app-secrets#42), " +
						"or run `byreis review` at a TTY to use the interactive review screen")
				r.PrintErrorClass("general-error", err.Error(),
					"use the form project#number (e.g. myorg/my-app-secrets#42)")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Reviewer must be wired before any use-case call.
			if deps.Reviewer == nil {
				err := fmt.Errorf(
					"review adapters not configured — " +
						"run `byreis init` or check your BYREIS_* environment variables")
				r.PrintErrorClass(
					"general-error",
					err.Error(),
					"run `byreis init` or check your configuration",
				)
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			ref, parseErr := parsePRRef(prRef)
			if parseErr != nil {
				r.PrintErrorClass("general-error", parseErr.Error(),
					"use the form project#number (e.g. myorg/my-app-secrets#42)")
				return &exitError{code: render.ExitGeneralError, cause: parseErr}
			}

			reviewResult, reviewErr := deps.Reviewer.Review(ctx, usecase.ReviewInput{
				Ref: git.PRRef{
					Project: ref.Project,
					Number:  ref.Number,
				},
			})
			if reviewErr != nil {
				r.PrintErrorClass(
					"general-error",
					reviewErr.Error(),
					"check your admin key and registry reachability; run `byreis doctor` for diagnostics",
				)
				return &exitError{code: render.ExitGeneralError, cause: reviewErr}
			}

			// Zeroize plaintext after rendering. Values in ReviewResult.Plaintext
			// are admin-side plaintext; they must not appear in any log or JSON
			// success channel. The per-key table renders only key names and
			// validation status, never plaintext values.
			defer zeroizePlaintext(reviewResult.Plaintext)

			return renderReviewResult(r, reviewResult, *jsonFlag, cmd)
		},
	}

	cmd.Flags().StringVar(&prRef, "pr", "", "PR reference in project#number form (e.g. myorg/my-app-secrets#42)")

	return cmd
}

// renderReviewResult renders ReviewResult to the configured output channel.
// PerKey is rendered as a multi-row table. REPLACE rows are labeled
// prominently. Contributor-influenced strings are sanitized. Plaintext is
// NEVER rendered.
func renderReviewResult(r *render.Renderer, result usecase.ReviewResult, jsonMode bool, cmd *cobra.Command) error {
	if jsonMode {
		// JSON output: structured per-key array. No plaintext.
		// Key names are contributor-authored; sanitize before JSON to strip
		// control characters and ANSI sequences that could inject into
		// downstream consumers that parse text, consistent with the submit path.
		perKey := make([]map[string]any, len(result.PerKey))
		for i, kl := range result.PerKey {
			perKey[i] = map[string]any{
				"key":            render.SanitizeForTerminal(kl.Key),
				"action":         kl.Action,
				"validation_ok":  kl.ValidationOK,
				"validation_msg": kl.ValidationMsg,
			}
		}
		return render.EncodeJSON(cmd.OutOrStdout(), map[string]any{
			"pr_number":     result.Ref.Number,
			"pr_project":    result.Ref.Project,
			"author":        result.Author,
			"justification": result.Justification,
			"secrets_path":  result.SecretsPath,
			"pinned_sha":    result.PinnedSHA,
			"per_key":       perKey,
		})
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "PR #%d by %s\n",
		result.Ref.Number,
		render.SanitizeForTerminal(result.Author))
	if result.Justification != "" {
		_, _ = fmt.Fprintf(out, "justification: %s\n",
			render.SanitizeForTerminal(collapseLineBreaks(result.Justification)))
	}
	_, _ = fmt.Fprintf(out, "secrets_path:  %s\n",
		render.SanitizeForTerminal(result.SecretsPath))
	_, _ = fmt.Fprintf(out, "\n")

	// Per-key table header.
	_, _ = fmt.Fprintf(out, "%-10s  %-40s  %s\n", "ACTION", "KEY", "VALIDATION")
	_, _ = fmt.Fprintf(out, "%s\n", strings.Repeat("-", 70))

	for _, kl := range result.PerKey {
		action := render.SanitizeForTerminal(kl.Action)
		keyName := render.SanitizeForTerminal(kl.Key)
		if len(keyName) > 40 {
			keyName = keyName[:37] + "..."
		}
		valStatus := "ok"
		if !kl.ValidationOK {
			valStatus = "FAIL: " + render.SanitizeForTerminal(kl.ValidationMsg)
		}
		actionLabel := action
		if action == "replace" {
			actionLabel = "REPLACE"
		}
		_, _ = fmt.Fprintf(out, "%-10s  %-40s  %s\n", actionLabel, keyName, valStatus)
	}

	_, _ = fmt.Fprintf(out, "\npinned_sha: %s\n", result.PinnedSHA)
	_, _ = fmt.Fprintf(out, "To merge:   byreis merge --pr %s#%d --expect %s\n",
		result.Ref.Project, result.Ref.Number, result.PinnedSHA)
	return nil
}

// newMergeCmd constructs the `byreis merge` command (admin-only, stubbed).
func newMergeCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var prNumber int

	cmd := &cobra.Command{
		Use:   "merge",
		Short: "Merge a verified submission (admin only)",
		Long: `Merge a reviewed and signed submission into the secrets file.

Requires ADMIN mode. The submission must have been reviewed and signed before
merge. The merge path enforces the anti-replay counter and the file-path
cross-check against the signed registry configuration.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			if deps.Policy != nil {
				if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandMerge); err != nil {
					r.PrintError(err.Error())
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			} else {
				// No policy wired: default-deny for admin-only commands.
				err := fmt.Errorf("%w: merge requires ADMIN mode — "+
					"no admin key found or mode policy not configured; "+
					"see `byreis doctor` for your current mode",
					mode.ErrPermissionDenied)
				r.PrintError(err.Error())
				return &exitError{code: render.ExitPermissionDenied, cause: err}
			}

			r.PrintError(fmt.Sprintf(
				"merge --pr %d: not yet implemented — adapters not yet wired", prNumber))
			return fmt.Errorf("merge not available: adapters not wired")
		},
	}

	cmd.Flags().IntVar(&prNumber, "pr", 0, "PR number to merge (required)")
	_ = cmd.MarkFlagRequired("pr")

	return cmd
}

// readEnvFileBounded opens filePath and reads at most maxEnvFileBytes bytes.
// If the file's reported size already exceeds the ceiling, the file is refused
// before any read is attempted (stat-then-refuse). If the file is within the
// reported size but the actual read produces more bytes than the ceiling (e.g.
// a special file that grows between stat and read), io.LimitReader caps the
// read and the resulting byte count check triggers the same error. The ceiling
// is named explicitly in the returned error so the operator can act on it.
func readEnvFileBounded(filePath string) ([]byte, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading .env file %q: %w — check the file exists and is readable", filePath, err)
	}
	if info.Size() > maxEnvFileBytes {
		return nil, fmt.Errorf(
			"reading .env file %q: file is %d bytes, which exceeds the %d-byte limit — "+
				"split into multiple submissions or remove unused entries",
			filePath, info.Size(), maxEnvFileBytes)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading .env file %q: %w — check the file exists and is readable", filePath, err)
	}
	defer f.Close() //nolint:errcheck

	// Read one byte beyond the ceiling so we can distinguish "exactly at the
	// limit" from "over the limit" for files that grew between stat and read.
	limited := io.LimitReader(f, maxEnvFileBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading .env file %q: %w — check the file is readable", filePath, err)
	}
	if int64(len(raw)) > maxEnvFileBytes {
		return nil, fmt.Errorf(
			"reading .env file %q: file exceeds the %d-byte limit — "+
				"split into multiple submissions or remove unused entries",
			filePath, maxEnvFileBytes)
	}
	return raw, nil
}
