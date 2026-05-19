package cli

// Package cli — admin-only command stubs.
//
// The commands defined here (get, decrypt, edit) are gated by mode policy:
// they are ADMIN-only and are rejected before any crypto code is reached when
// in CONTRIBUTOR mode. The rejection is not "attempted-then-failed" — it is
// "denied-by-policy" at the CLI layer, producing ErrPermissionDenied.
//
// This file does NOT import any crypto, decrypt, or identity package.
// The mode policy check is the gate; the commands are stubs until full
// adapter wiring is complete.

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
)

func newGetCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var key string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a decrypted secret value (admin only)",
		Long: `Decrypt and print a secret value.

Requires ADMIN mode: the command is denied-by-policy (not attempted-then-failed)
when running as CONTRIBUTOR. The denial sentinel is mode.ErrPermissionDenied.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Policy gate: denied-by-policy before any crypto is reached.
			if deps.Policy != nil {
				if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandGet); err != nil {
					r.PrintError(err.Error())
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			} else {
				// No policy wired: default-deny for admin-only commands.
				err := fmt.Errorf("%w: get requires ADMIN mode — "+
					"no admin key found or mode policy not configured; "+
					"see `byreis doctor` for your current mode",
					mode.ErrPermissionDenied)
				r.PrintError(err.Error())
				return &exitError{code: render.ExitPermissionDenied, cause: err}
			}

			r.PrintError(fmt.Sprintf("get --key %q: not yet implemented", key))
			return fmt.Errorf("get not available: adapters not wired")
		},
	}

	cmd.Flags().StringVar(&key, "key", "", "secret key name (required)")
	_ = cmd.MarkFlagRequired("key")

	return cmd
}

func newDecryptCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a secrets file (admin only)",
		Long: `Decrypt and print all values in a secrets file.

Requires ADMIN mode: the command is denied-by-policy when running as CONTRIBUTOR.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			if deps.Policy != nil {
				if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandDecrypt); err != nil {
					r.PrintError(err.Error())
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			} else {
				err := fmt.Errorf("%w: decrypt requires ADMIN mode — "+
					"no admin key found or mode policy not configured; "+
					"see `byreis doctor` for your current mode",
					mode.ErrPermissionDenied)
				r.PrintError(err.Error())
				return &exitError{code: render.ExitPermissionDenied, cause: err}
			}

			r.PrintError("decrypt: not yet implemented")
			return fmt.Errorf("decrypt not available: adapters not wired")
		},
	}

	return cmd
}

func newEditCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var key string

	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit a secret value in-place (admin only)",
		Long: `Open a decrypted secret for editing and re-encrypt the result.

Requires ADMIN mode: the command is denied-by-policy when running as CONTRIBUTOR.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			if deps.Policy != nil {
				if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandEdit); err != nil {
					r.PrintError(err.Error())
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			} else {
				err := fmt.Errorf("%w: edit requires ADMIN mode — "+
					"no admin key found or mode policy not configured; "+
					"see `byreis doctor` for your current mode",
					mode.ErrPermissionDenied)
				r.PrintError(err.Error())
				return &exitError{code: render.ExitPermissionDenied, cause: err}
			}

			r.PrintError(fmt.Sprintf("edit --key %q: not yet implemented", key))
			return fmt.Errorf("edit not available: adapters not wired")
		},
	}

	cmd.Flags().StringVar(&key, "key", "", "secret key name (required)")
	_ = cmd.MarkFlagRequired("key")

	return cmd
}
