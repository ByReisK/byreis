package cli

// Package cli — admin-only command implementations.
//
// The commands defined here (get, decrypt, edit, and admin merge) are gated by
// mode policy: they are ADMIN-only and are rejected before any crypto code is
// reached when in CONTRIBUTOR mode. The rejection is "denied-by-policy" (not
// "attempted-then-failed") at the CLI layer, producing ErrPermissionDenied.
//
// Mode gate is ALWAYS checked first. Only after passing the gate are the
// injected use-case interfaces called. Use-cases are injected as narrow port
// interfaces (usecase.Getter, usecase.DecryptUseCase, usecase.EditUseCase,
// usecase.Merger); no concrete adapter type crosses the CLI boundary.
//
// admin merge does NOT spawn $EDITOR at any point (interactive or
// non-interactive). The verb operates non-interactively by design: it reads
// all required parameters from flags and invokes the Merger use-case directly.

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// prRefAllowRE is the whitelist for the project portion of a --pr flag value.
// It accepts segments that are valid git refname components: alphanumerics,
// hyphens, underscores, dots (not at end), and forward-slashes (no consecutive
// slashes, no leading slash). Rejects control characters, NUL, CR, leading
// dash, ".lock" suffix, and ".." sequences. Maximum 200 characters total
// (project + "#" + number).
//
// The regex is anchored: the entire project string (before "#") must match.
var prRefAllowRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/\-]{0,197}[a-zA-Z0-9_/\-]$|^[a-zA-Z0-9]$`)

// parsePRRef parses a --pr flag value in the form "project#number" into a
// git.PRRef. Enforces the branch-name whitelist on the project segment.
//
// Validation rejects:
//   - Any control character (0x00-0x1F including NUL, CR, LF)
//   - Leading '-' on the project segment
//   - ".." sequences in the project segment
//   - ".lock" suffix on any path component in the project segment
//   - Project segments that do not match prRefAllowRE
//   - Total value longer than 200 characters
//   - Missing "#" separator or non-positive PR number
func parsePRRef(prVal string) (git.PRRef, error) {
	if len(prVal) > 200 {
		return git.PRRef{}, fmt.Errorf(
			"--pr %q is too long (max 200 characters) — "+
				"use the form project#number (e.g. myorg/my-app-secrets#42)",
			prVal)
	}
	// Reject any control character (including NUL, CR, LF).
	for _, b := range []byte(prVal) {
		if b < 0x20 || b == 0x7F {
			return git.PRRef{}, fmt.Errorf(
				"--pr value contains a control character (0x%02X) — "+
					"use plain printable ASCII: project#number",
				b)
		}
	}

	hashIdx := strings.LastIndex(prVal, "#")
	if hashIdx <= 0 {
		return git.PRRef{}, fmt.Errorf(
			"--pr %q is missing the '#N' PR number suffix — "+
				"use the form project#number (e.g. myorg/my-app-secrets#42)",
			prVal)
	}
	project := prVal[:hashIdx]
	numStr := prVal[hashIdx+1:]

	// Structural checks on the project segment.
	if strings.HasPrefix(project, "-") {
		return git.PRRef{}, fmt.Errorf(
			"--pr project segment %q must not start with '-' — "+
				"use a valid repository name (e.g. myorg/my-secrets#1)",
			project)
	}
	if strings.Contains(project, "..") {
		return git.PRRef{}, fmt.Errorf(
			"--pr project segment %q contains '..' — "+
				"paths must not escape the repository root",
			project)
	}
	for _, seg := range strings.Split(project, "/") {
		if strings.HasSuffix(seg, ".lock") {
			return git.PRRef{}, fmt.Errorf(
				"--pr project segment %q contains a '.lock' path component — "+
					"use a valid repository name",
				project)
		}
	}
	if !prRefAllowRE.MatchString(project) {
		return git.PRRef{}, fmt.Errorf(
			"--pr project segment %q contains invalid characters — "+
				"use only alphanumerics, hyphens, underscores, dots, and slashes "+
				"(e.g. myorg/my-app-secrets#42)",
			project)
	}

	num, err := strconv.Atoi(numStr)
	if err != nil || num <= 0 {
		return git.PRRef{}, fmt.Errorf(
			"--pr PR number %q is not a positive integer — "+
				"use the form project#number (e.g. myorg/my-app-secrets#42)",
			numStr)
	}

	return git.PRRef{Project: project, Number: num}, nil
}

// checkPolicy enforces the mode-policy gate for admin-only commands. It returns
// a ready-to-return exitError on denial (or when no policy is wired, the
// default-deny else branch fires). The caller returns immediately on non-nil.
func checkPolicy(deps *Deps, r *render.Renderer, cmd mode.Command, name string) error {
	if deps.Policy != nil {
		if err := deps.Policy.Allow(deps.CurrentMode, cmd); err != nil {
			r.PrintErrorClass(
				"permission-denied",
				err.Error(),
				fmt.Sprintf("%s requires ADMIN mode — run `byreis doctor` to check your current mode", name),
			)
			return &exitError{code: render.ExitPermissionDenied, cause: err}
		}
		return nil
	}
	// No policy wired: default-deny for admin-only commands (belt-and-suspenders).
	err := fmt.Errorf("%w: %s requires ADMIN mode — "+
		"no admin key found or mode policy not configured; "+
		"see `byreis doctor` for your current mode",
		mode.ErrPermissionDenied, name)
	r.PrintErrorClass(
		"permission-denied",
		err.Error(),
		"run `byreis doctor` to check your current mode",
	)
	return &exitError{code: render.ExitPermissionDenied, cause: err}
}

// handleReadPathError maps a use-case read-path error to an exitError with the
// correct documented exit code. It prints the actionable error message to
// stderr and never places plaintext or key material in the error text (the
// use-case guarantees the error itself is already secret-free).
func handleReadPathError(r *render.Renderer, err error) error {
	if err == nil {
		return nil
	}
	code := exitCodeForErr(err)
	exitClass := exitClassStringFor(err)
	r.PrintErrorClass(exitClass, err.Error(), actionableHintFor(code))
	return &exitError{code: code, cause: err}
}

// exitClassStringFor returns the stable string code for the given error,
// used in the --json error schema. It inspects for a *usecase.ReadPathError
// first, then for mode.ErrPermissionDenied.
func exitClassStringFor(err error) string {
	if err == nil {
		return "ok"
	}
	var rpe *usecase.ReadPathError
	if errors.As(err, &rpe) {
		return rpe.Class.String()
	}
	if errors.Is(err, mode.ErrPermissionDenied) {
		return "permission-denied"
	}
	return "general-error"
}

// actionableHintFor maps an exit code to the suggested remediation hint shown
// in the --json error envelope. The hint is always safe to display or log.
func actionableHintFor(code render.ExitCode) string {
	switch code {
	case render.ExitOK:
		return ""
	case render.ExitPermissionDenied:
		return "run `byreis doctor` to verify your admin mode"
	case render.ExitNotFound:
		return "check the file name and registry-configured path; run `byreis doctor`"
	case render.ExitDecodeMalformed:
		return "the file may be corrupt; run `byreis doctor` to inspect"
	case render.ExitVerifyFailure:
		return "run `byreis doctor` and verify the registry is reachable and signed"
	case render.ExitAuthError:
		return "run `byreis auth login` or check your admin key"
	case render.ExitReplay:
		return "counter replay detected; run `byreis doctor` to diagnose"
	case render.ExitCounterReconcile:
		return "run `byreis admin counter reconcile` to resolve the counter state"
	case render.ExitTrustError:
		return "run `byreis doctor` and verify the registry trust configuration"
	case render.ExitGeneralError:
		return "run `byreis doctor` for diagnostics"
	default:
		return "run `byreis doctor` for diagnostics"
	}
}

// newGetCmd constructs the `get` command.
func newGetCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		key     string
		project string
		file    string
	)

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a decrypted secret value (admin only)",
		Long: `Decrypt and print a single secret value from the live file-of-record.

Requires ADMIN mode: the command is denied-by-policy (not attempted-then-failed)
when running as CONTRIBUTOR. The denial sentinel is mode.ErrPermissionDenied.

The VerifyOfRecord check runs before any decrypt or identity-load.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST. Denied-by-policy before any use-case entry.
			if pErr := checkPolicy(deps, r, mode.CommandGet, "get"); pErr != nil {
				return pErr
			}

			if deps.Getter == nil {
				err := fmt.Errorf(
					"get not available: the read-path use-case is not wired — " +
						"run `byreis doctor` or check your installation")
				r.PrintErrorClass("general-error", err.Error(), "run `byreis doctor` or check your installation")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			result, err := deps.Getter.Get(cmd.Context(), usecase.GetInput{
				ProjectID: project,
				FileName:  file,
				Key:       key,
			})
			if err != nil {
				return handleReadPathError(r, err)
			}

			r.PrintSecret(result.Key, result.Value)
			return nil
		},
	}

	cmd.Flags().StringVar(&key, "key", "", "secret key name (required)")
	cmd.Flags().StringVar(&project, "project", "", "project ID (required)")
	cmd.Flags().StringVar(&file, "file", "", "logical file name (required)")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("project")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

// newDecryptCmd constructs the `decrypt` command. It supports both interactive
// and CI-headless (--ci) operation; both paths call the same
// usecase.DecryptUseCase with VerifyOfRecord-first guaranteed by the use-case.
func newDecryptCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		project string
		file    string
		keys    []string
		ci      bool
	)

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a secrets file (admin only)",
		Long: `Decrypt and print all values in a secrets file.

Requires ADMIN mode: the command is denied-by-policy when running as CONTRIBUTOR.
The VerifyOfRecord check runs before any decrypt or identity-load.

The --ci flag activates the CI-decrypt entrypoint: headless, no TTY assumed,
suited for use in CI pipelines. Combine with --json for machine-readable output.
In --ci mode, secrets are not masked (by design — this is the command's job;
ensure your CI logs are appropriately protected).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST. Denied-by-policy before any use-case entry.
			// This is the single gate for BOTH interactive and --ci paths.
			if pErr := checkPolicy(deps, r, mode.CommandDecrypt, "decrypt"); pErr != nil {
				return pErr
			}

			if deps.Decryptor == nil {
				err := fmt.Errorf(
					"decrypt not available: the read-path use-case is not wired — " +
						"run `byreis doctor` or check your installation")
				r.PrintErrorClass("general-error", err.Error(), "run `byreis doctor` or check your installation")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			result, err := deps.Decryptor.Decrypt(cmd.Context(), usecase.DecryptInput{
				ProjectID: project,
				FileName:  file,
				Keys:      keys,
			})
			if err != nil {
				return handleReadPathError(r, err)
			}

			// CI path: no TTY assumption; plaintext emitted as-is (by design —
			// the caller is responsible for protecting output). TTY masking is
			// handled by PrintDecryptResult for the interactive path.
			if ci {
				// Force non-TTY rendering even if the process has a TTY (CI
				// pipelines may have a pseudo-TTY; we respect --ci as the
				// operator's explicit intent).
				r.IsTTY = false
			}

			r.PrintDecryptResult(result.Plaintext, result.KeyNames)
			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project ID (required)")
	cmd.Flags().StringVar(&file, "file", "", "logical file name (required)")
	cmd.Flags().StringArrayVar(&keys, "key", nil, "restrict output to these keys (repeatable)")
	cmd.Flags().BoolVar(&ci, "ci", envBool("BYREIS_NON_INTERACTIVE"),
		"CI-decrypt mode: headless, no TTY assumed; "+
			"set BYREIS_NON_INTERACTIVE=1 to enable by environment variable")
	_ = cmd.MarkFlagRequired("project")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

// newEditCmd constructs the `edit` command.
func newEditCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		project string
		file    string
	)

	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit a secret value in-place (admin only)",
		Long: `Open a decrypted secret for editing and re-encrypt the result.

Requires ADMIN mode: the command is denied-by-policy when running as CONTRIBUTOR.
The VerifyOfRecord check runs before any decrypt or identity-load.

The edit sequence is: VerifyOfRecord → decrypt → $EDITOR → re-encrypt (fresh
whole-file) → re-sign → atomic write. Any failure before the atomic rename
leaves the live file byte-identical.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST. Denied-by-policy before any use-case entry.
			if pErr := checkPolicy(deps, r, mode.CommandEdit, "edit"); pErr != nil {
				return pErr
			}

			if deps.Editor == nil {
				err := fmt.Errorf(
					"edit not available: the admin key or repo configuration is " +
						"not yet wired — run `byreis doctor` or check your installation")
				r.PrintErrorClass("general-error", err.Error(), "run `byreis doctor` or check your installation")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			result, err := deps.Editor.Edit(cmd.Context(), usecase.EditInput{
				ProjectID: project,
				FileName:  file,
			})
			if err != nil {
				return handleReadPathError(r, err)
			}

			if *jsonFlag {
				r.Out = cmd.OutOrStdout()
				_ = render.EncodeJSON(r.Out, map[string]any{
					"re_encrypted": result.ReEncrypted,
					"content_sha":  result.ContentSHA,
					"keys":         result.KeyNames,
				})
				return nil
			}
			_, _ = fmt.Fprintf(r.Out, "edit saved (re-encrypted=%v content_sha=%s)\n",
				result.ReEncrypted, result.ContentSHA)
			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project ID (required)")
	cmd.Flags().StringVar(&file, "file", "", "logical file name (required)")
	_ = cmd.MarkFlagRequired("project")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

// newAdminCmd constructs the `admin` parent command and registers its
// sub-commands (currently: `admin merge`, `admin rotation reconcile`).
func newAdminCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	admin := &cobra.Command{
		Use:   "admin",
		Short: "Admin-only operations (merge, rotation reconcile, etc.)",
		Long: `Admin-only operations require ADMIN mode.

Commands under 'admin' are gated by mode policy and denied-by-policy
(not attempted-then-failed) when running as CONTRIBUTOR.`,
	}
	admin.AddCommand(newAdminMergeCmd(deps, jsonFlag))
	admin.AddCommand(newAdminRotationCmd(deps, jsonFlag))
	admin.AddCommand(newAdminRequestCmd(deps, jsonFlag))
	return admin
}

// newAdminRotationCmd constructs the `admin rotation` parent command.
func newAdminRotationCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	rotation := &cobra.Command{
		Use:   "rotation",
		Short: "Rotation lifecycle admin operations",
		Long:  `Admin-only rotation lifecycle operations (reconcile, etc.).`,
	}
	rotation.AddCommand(newAdminRotationReconcileCmd(deps, jsonFlag))
	return rotation
}

// newAdminRotationReconcileCmd constructs the `admin rotation reconcile` command.
//
// Classify-first composition: invoke Reconciler.Classify FIRST. If the
// classification is NoPartialState, Phase2Midflight, or InconsistentPartial,
// NO write-side work is performed and NO keychain load for write credentials
// is triggered. Only Phase1Only triggers write-side work via Reconciler.Reconcile.
// This narrows the credential lifetime vs unconditional load.
func newAdminRotationReconcileCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var project string

	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Classify and recover partial rotation state (admin only)",
		Long: `Classify the partial rotation state for a project and act on Phase-1-only partial state.

Requires ADMIN mode: denied-by-policy before any registry observation.

Classification outcomes:
  no-partial-state      No rotation branch or pending; exits OK with no action.
  phase-1-only          Rotation branch unmerged + pendings present; reversed (branch deleted +
                        pendings cleared in a single signed registry commit).
  phase-2-midflight     Rotation branch merged but CommitRotation did not land; surfaces
                        ErrRotationReconcile (terminal — requires operator coordination).
  inconsistent-partial  Unexpected shape; surfaces ErrRotationReconcile (terminal).

Classify-first: the write-side credential is only loaded when the classification is
phase-1-only. All other classifications exit without any keychain access.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST — denied-not-attempted before any registry observation.
			if pErr := checkPolicy(deps, r, mode.CommandRotationReconcile, "admin rotation reconcile"); pErr != nil {
				return pErr
			}

			if deps.Reconciler == nil {
				err := fmt.Errorf(
					"admin rotation reconcile not available: the reconciler is not wired — " +
						"run `byreis doctor` or check your installation")
				r.PrintErrorClass("general-error", err.Error(),
					"run `byreis doctor` or check your installation")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			ctx := cmd.Context()

			// Classify-first: read-only probe before any write-side work.
			classification, classErr := deps.Reconciler.Classify(ctx, project)
			if classErr != nil {
				code := reconcileExitCode(classErr)
				r.PrintErrorClass(reconcileExitClass(code), classErr.Error(),
					reconcileHintFor(code, classErr))
				return &exitError{code: code, cause: classErr}
			}

			// Short-circuit paths that do NOT require write-side composition:
			// NoPartialState, Phase2Midflight, InconsistentPartial.
			switch classification {
			case rotate.NoPartialState:
				if *jsonFlag {
					_ = render.EncodeJSON(r.Out, map[string]any{
						"classification": classification.String(),
						"action":         "none",
					})
					return nil
				}
				_, _ = fmt.Fprintf(r.Out, "no partial rotation state detected for project %q\n", project)
				return nil

			case rotate.Phase2Midflight:
				err := fmt.Errorf(
					"rotation is in phase-2-midflight state for project %q: "+
						"rotation branch merged but CommitRotation did not land — "+
						"see docs/rotation-runbook.md for the operator recovery procedure",
					project)
				r.PrintErrorClass("counter-reconcile", err.Error(),
					"run `byreis admin rotation reconcile` after operator coordination; "+
						"see docs/rotation-runbook.md")
				return &exitError{code: render.ExitCounterReconcile, cause: err}

			case rotate.InconsistentPartial:
				err := fmt.Errorf(
					"rotation is in inconsistent-partial state for project %q: "+
						"unexpected protocol shape — "+
						"see docs/rotation-runbook.md for the operator recovery procedure",
					project)
				r.PrintErrorClass("counter-reconcile", err.Error(),
					"see docs/rotation-runbook.md")
				return &exitError{code: render.ExitCounterReconcile, cause: err}

			case rotate.Phase1Only:
				// Phase1Only falls through to the Reconciler.Reconcile call below.
			}

			// Phase1Only: write-side work via Reconciler.Reconcile.
			result, err := deps.Reconciler.Reconcile(ctx, project)
			if err != nil {
				code := reconcileExitCode(err)
				r.PrintErrorClass(reconcileExitClass(code), err.Error(),
					reconcileHintFor(code, err))
				return &exitError{code: code, cause: err}
			}

			if *jsonFlag {
				_ = render.EncodeJSON(r.Out, map[string]any{
					"classification":   result.Classification.String(),
					"branch_deleted":   result.BranchDeleted,
					"pendings_cleared": result.PendingsCleared,
					"retries":          result.Retries,
				})
				return nil
			}
			_, _ = fmt.Fprintf(r.Out,
				"rotation reconcile complete for project %q "+
					"(classification=%s branch_deleted=%v pendings_cleared=%d retries=%d)\n",
				project,
				result.Classification,
				result.BranchDeleted,
				result.PendingsCleared,
				result.Retries,
			)
			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project ID (required)")
	_ = cmd.MarkFlagRequired("project")

	return cmd
}

// newAdminRequestCmd constructs the `admin request` parent command. Currently
// provides only the `list` subverb. There is deliberately no `approve`,
// `reject`, or `close` subverb here; request rejection must go through
// `gh pr close` on the registry repo, and request promotion goes through
// `byreis rotate --add --from-request <PR>`.
func newAdminRequestCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	req := &cobra.Command{
		Use:   "request",
		Short: "Admin request-access operations",
		Long: `Admin-only operations on contributor request-access pull requests.

Commands under 'admin request' are gated by mode policy and denied-by-policy
when running as CONTRIBUTOR.

To approve a request: byreis rotate --add --from-request <owner/repo#N>
To reject a request:  gh pr close <N> --repo <owner/repo>`,
	}
	req.AddCommand(newAdminRequestListCmd(deps, jsonFlag))
	return req
}

// newAdminRequestListCmd constructs the `admin request list` command. It lists
// every OPEN request-access pull request in the admin registry repo so an
// admin can triage and then act with `byreis rotate --add --from-request <PR>`.
//
// The command is read-only: it performs no trust decision, no YAML decode, and
// no ValidateRequestAccess call. It contacts GitHub once (paginated PR list)
// and renders a summary table or JSON.
//
// Mode gate is enforced first. A CONTRIBUTOR invocation is denied-not-attempted:
// the ListOpenRequests call is never reached.
func newAdminRequestListCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List open contributor request-access PRs (admin only)",
		Long: `List every OPEN request-access pull request in the admin registry repo.

Requires ADMIN mode: denied-by-policy before any network touch.

This command is read-only: it performs no trust decision, no ValidateRequestAccess
call, and no registry write. Each row shows the PR reference, the contributor's
GitHub login, the creation date, and the PR title.

To act on a listed request:
  Approve: byreis rotate --add --from-request <owner/repo#N>
  Reject:  gh pr close <N> --repo <owner/repo>

There is no 'approve' or 'reject' subverb here by design: all trust decisions
go through the rotate --from-request path or the registry branch-protection rules.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST — denied-not-attempted before any network touch.
			if pErr := checkPolicy(deps, r, mode.CommandRequestList, "admin request list"); pErr != nil {
				return pErr
			}

			if deps.RequestAccessReader == nil {
				err := fmt.Errorf(
					"admin request list not available: the RequestAccessReader is not wired — " +
						"set BYREIS_GITHUB_TOKEN and BYREIS_REGISTRY and run `byreis doctor`")
				r.PrintErrorClass("general-error", err.Error(),
					"set BYREIS_GITHUB_TOKEN and BYREIS_REGISTRY and run `byreis doctor`")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			ctx := cmd.Context()
			summaries, err := deps.RequestAccessReader.ListOpenRequests(ctx)
			if err != nil {
				r.PrintErrorClass("general-error", err.Error(),
					"check BYREIS_REGISTRY and BYREIS_GITHUB_TOKEN; "+
						"run `byreis auth login` if auth expired")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Deterministic sort: newest-first by CreatedAt (descending), with
			// ascending PR number as a tie-breaker for reproducible output.
			sorted := make([]rotate.OpenRequestSummary, len(summaries))
			copy(sorted, summaries)
			sort.Slice(sorted, func(i, j int) bool {
				if sorted[i].CreatedAt != sorted[j].CreatedAt {
					// Lexicographic reverse of RFC3339 timestamps is
					// chronologically correct because RFC3339 is ISO 8601
					// with the ordering property: a later timestamp is
					// lexicographically greater.
					return sorted[i].CreatedAt > sorted[j].CreatedAt
				}
				return sorted[i].PRRef.Number < sorted[j].PRRef.Number
			})

			if *jsonFlag {
				type jsonRow struct {
					PR        string `json:"pr"`
					Author    string `json:"author"`
					Title     string `json:"title"`
					CreatedAt string `json:"created_at"`
					HeadSHA   string `json:"head_sha"`
				}
				rows := make([]jsonRow, len(sorted))
				for i, s := range sorted {
					rows[i] = jsonRow{
						PR:        fmt.Sprintf("%s#%d", s.PRRef.Project, s.PRRef.Number),
						Author:    s.AuthorLogin,
						Title:     s.Title, // JSON carries raw title for machine output
						CreatedAt: s.CreatedAt,
						HeadSHA:   s.HeadSHA,
					}
				}
				_ = render.EncodeJSON(r.Out, map[string]any{"requests": rows})
				return nil
			}

			// Human table output.
			if len(sorted) == 0 {
				_, _ = fmt.Fprintln(r.Out, "no open access requests")
				return nil
			}

			// Header row.
			_, _ = fmt.Fprintf(r.Out, "%-40s  %-20s  %-25s  %s\n",
				"PR", "AUTHOR", "CREATED", "TITLE")
			_, _ = fmt.Fprintf(r.Out, "%-40s  %-20s  %-25s  %s\n",
				strings.Repeat("-", 40), strings.Repeat("-", 20),
				strings.Repeat("-", 25), strings.Repeat("-", 30))

			for _, s := range sorted {
				prStr := fmt.Sprintf("%s#%d", s.PRRef.Project, s.PRRef.Number)
				// Title passes through SanitizeForTerminal (strips ANSI, C0, bidi)
				// and then through collapseLineBreaks so that a contributor-controlled
				// newline or tab cannot inject a fake second row into the table.
				// collapseLineBreaks is applied only here (the single-line table sink);
				// the --json path carries the raw title through encoding/json untouched.
				safeTitle := collapseLineBreaks(render.SanitizeForTerminal(s.Title))
				_, _ = fmt.Fprintf(r.Out, "%-40s  %-20s  %-25s  %s\n",
					prStr, s.AuthorLogin, s.CreatedAt, safeTitle)
			}
			return nil
		},
	}
	return cmd
}

// newAdminMergeCmd constructs the `admin merge` sub-command.
//
// admin merge does NOT spawn $EDITOR at any point (interactive or
// non-interactive). All required inputs are read from flags; the Merger
// use-case is invoked directly. No exec.Command, no os.Getenv("EDITOR").
func newAdminMergeCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		project           string
		file              string
		prVal             string
		targetArtifactSHA string
		commitMsg         string
	)

	cmd := &cobra.Command{
		Use:   "merge",
		Short: "Merge a reviewed submission into the live secrets file (admin only)",
		Long: `Execute the write-ahead merge sequence for a reviewed submission.

Requires ADMIN mode: denied-by-policy before any use-case entry.

The --pr flag accepts the form project#number (e.g. myorg/my-app-secrets#42).
The project segment must be a valid git repository name: alphanumerics,
hyphens, underscores, dots, and slashes; max 200 characters total; no
control characters, no leading dash, no ".." sequences, no ".lock" suffix.

The --expect flag is the review pin (SHA of the artifact as seen at review
time). When omitted, the use-case enforces the no-pin refusal.

This command does not spawn $EDITOR and has no interactive fallback.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST — denied-by-policy before any use-case entry.
			if pErr := checkPolicy(deps, r, mode.CommandMerge, "admin merge"); pErr != nil {
				return pErr
			}

			// Validate and parse the --pr flag against the whitelist.
			// Rejects control characters, leading dash, ".." sequences,
			// ".lock" suffixes, and values exceeding 200 characters.
			ref, parseErr := parsePRRef(prVal)
			if parseErr != nil {
				r.PrintErrorClass("general-error", parseErr.Error(),
					"use the form project#number (e.g. myorg/my-app-secrets#42)")
				return &exitError{code: render.ExitGeneralError, cause: parseErr}
			}

			if deps.Merger == nil {
				err := fmt.Errorf(
					"admin merge not available: the registry-write path is not " +
						"yet wired — run `byreis doctor` or check your installation")
				r.PrintErrorClass("general-error", err.Error(),
					"run `byreis doctor` to verify your admin mode and registry-write credential")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			msg := commitMsg
			if msg == "" {
				msg = fmt.Sprintf("byreis: merge submission %s#%d", ref.Project, ref.Number)
			}

			result, err := deps.Merger.Merge(cmd.Context(), usecase.MergeInput{
				Ref:               ref,
				ExpectSHA:         targetArtifactSHA,
				ExpectedProjectID: project,
				ExpectedFileName:  file,
				CommitMessage:     msg,
			})
			if err != nil {
				code := render.ExitGeneralError
				if deps.MergeExitCode != nil {
					code = deps.MergeExitCode(err)
				}
				hint := actionableHintFor(code)
				if hint == "" {
					hint = "run `byreis doctor` to verify your admin mode and registry-write credential"
				}
				r.PrintErrorClass(exitClassStringForMerge(code), err.Error(), hint)
				return &exitError{code: code, cause: err}
			}

			if *jsonFlag {
				_ = render.EncodeJSON(r.Out, map[string]any{
					"re_encrypted":      result.ReEncrypted,
					"pending_counter":   result.FinalCounter,
					"committed_counter": result.FinalCounter,
					"content_sha":       result.LiveFileSHA,
				})
				return nil
			}
			_, _ = fmt.Fprintf(r.Out,
				"merge complete (re-encrypted=%v counter=%d content_sha=%s)\n",
				result.ReEncrypted, result.FinalCounter, result.LiveFileSHA)
			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project ID (required)")
	cmd.Flags().StringVar(&file, "file", "", "logical file name (required)")
	cmd.Flags().StringVar(&prVal, "pr", "", "PR reference in the form project#number (required)")
	cmd.Flags().StringVar(&targetArtifactSHA, "expect", "",
		"review pin: SHA of the artifact as seen at review time (use-case enforces absent-pin refusal)")
	cmd.Flags().StringVar(&commitMsg, "commit-message", "",
		"commit message for the signed file-of-record (default: byreis: merge submission project#N)")
	_ = cmd.MarkFlagRequired("project")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("pr")

	return cmd
}

// exitClassStringForMerge maps a merge-path render.ExitCode to the stable
// string class used in the --json error schema. It covers all defined exit
// codes, supplementing exitClassStringFor with the registry-write path codes.
func exitClassStringForMerge(code render.ExitCode) string {
	switch code {
	case render.ExitOK:
		return "ok"
	case render.ExitPermissionDenied:
		return "permission-denied"
	case render.ExitNotFound:
		return "not-found"
	case render.ExitDecodeMalformed:
		return "decode-malformed"
	case render.ExitVerifyFailure:
		return "verify-failure"
	case render.ExitAuthError:
		return "auth-error"
	case render.ExitReplay:
		return "replay"
	case render.ExitCounterReconcile:
		return "counter-reconcile"
	case render.ExitTrustError:
		return "trust-error"
	case render.ExitGeneralError:
		return "general-error"
	default:
		return "general-error"
	}
}

// reconcileExitCode maps a reconcile-path error to the appropriate
// render.ExitCode.
func reconcileExitCode(err error) render.ExitCode {
	if err == nil {
		return render.ExitOK
	}
	if errors.Is(err, rotate.ErrRotationReconcile) {
		return render.ExitCounterReconcile
	}
	if errors.Is(err, rotate.ErrRotationRequiresFreshRegistry) {
		return render.ExitTrustError
	}
	if errors.Is(err, mode.ErrPermissionDenied) {
		return render.ExitPermissionDenied
	}
	return render.ExitGeneralError
}

// reconcileExitClass returns the stable string exit class for --json output.
func reconcileExitClass(code render.ExitCode) string {
	switch code {
	case render.ExitOK:
		return "ok"
	case render.ExitPermissionDenied:
		return "permission-denied"
	case render.ExitCounterReconcile:
		return "counter-reconcile"
	case render.ExitTrustError:
		return "trust-error"
	case render.ExitAuthError:
		return "auth-error"
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

// reconcileHintFor returns an actionable hint string for the given exit code.
func reconcileHintFor(code render.ExitCode, err error) string {
	switch code {
	case render.ExitCounterReconcile:
		return "see docs/rotation-runbook.md for the operator recovery procedure"
	case render.ExitTrustError:
		if errors.Is(err, rotate.ErrRotationRequiresFreshRegistry) {
			return "run `byreis registry refresh` and retry"
		}
		return "run `byreis doctor` and verify the registry trust configuration"
	case render.ExitPermissionDenied:
		return "run `byreis doctor` to verify your admin mode"
	case render.ExitAuthError:
		return "run `byreis auth login` or check your admin key"
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

// collapseLineBreaks replaces newline (\n), carriage return (\r), and tab (\t)
// characters with a single space. It is applied to PR titles in the human/table
// render path only — after SanitizeForTerminal — so that a contributor-controlled
// multi-line title cannot inject a fake extra row into the single-line-per-row
// table. The --json path is unaffected: encoding/json escapes control bytes
// without this transform, preserving the raw value for machine consumers.
func collapseLineBreaks(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
}

// Ensure parsePRRef and related helpers are only used at the CLI boundary.
// Compile-time import check: errors and strconv must be used.
var _ = errors.New
var _ = strconv.Itoa
