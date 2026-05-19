package cli

// Package cli — admin-only command implementations.
//
// The commands defined here (get, decrypt, edit) are gated by mode policy:
// they are ADMIN-only and are rejected before any crypto code is reached when
// in CONTRIBUTOR mode. The rejection is "denied-by-policy" (not
// "attempted-then-failed") at the CLI layer, producing ErrPermissionDenied.
//
// Mode gate is ALWAYS checked first. Only after passing the gate are the
// injected use-case interfaces called. Use-cases are injected as narrow port
// interfaces (usecase.Getter, usecase.DecryptUseCase, usecase.EditUseCase);
// no concrete adapter type crosses the CLI boundary.

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

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
