package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
)

func newSubmitCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		key            string
		justification  string
		nonInteractive bool
	)

	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Submit an encrypted secret (contributor write-only path)",
		Long: `Encrypt and submit a secret to the admin review queue.

The secret is encrypted to the admin public-key set sourced from the verified
registry. The contributor never holds the plaintext after submission; this path
provides no decrypt capability by construction.

Contributor and admin modes are both permitted to submit.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			if deps.Policy != nil {
				if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandSubmit); err != nil {
					r.PrintError(err.Error())
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			}

			r.PrintError(fmt.Sprintf(
				"submit --key %q: not yet implemented — adapters not yet wired", key))
			return fmt.Errorf("submit not available: adapters not wired")
		},
	}

	cmd.Flags().StringVar(&key, "key", "", "secret key name (required)")
	cmd.Flags().StringVar(&justification, "justification", "",
		"justification for the submission (logged in PR)")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive",
		envBool("BYREIS_NON_INTERACTIVE"),
		"non-interactive mode: read secret from stdin (or set BYREIS_NON_INTERACTIVE=1)")

	_ = cmd.MarkFlagRequired("key")

	return cmd
}

func newReviewCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var prNumber int

	cmd := &cobra.Command{
		Use:   "review",
		Short: "Review a pending submission (admin only)",
		Long: `Fetch and verify a pending submission from the admin review queue.

Requires ADMIN mode: a usable private key that can decrypt the project file
and whose public key is in the verified registry.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			if deps.Policy != nil {
				if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandReview); err != nil {
					r.PrintError(err.Error())
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			} else {
				// No policy wired: default-deny for admin-only commands.
				err := fmt.Errorf("%w: review requires ADMIN mode — "+
					"no admin key found or mode policy not configured; "+
					"see `byreis doctor` for your current mode",
					mode.ErrPermissionDenied)
				r.PrintError(err.Error())
				return &exitError{code: render.ExitPermissionDenied, cause: err}
			}

			r.PrintError(fmt.Sprintf(
				"review --pr %d: not yet implemented — adapters not yet wired", prNumber))
			return fmt.Errorf("review not available: adapters not wired")
		},
	}

	cmd.Flags().IntVar(&prNumber, "pr", 0, "PR number to review (required)")
	_ = cmd.MarkFlagRequired("pr")

	return cmd
}

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
