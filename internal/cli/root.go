// Package cli defines the cobra command tree. Thin: parse flags, call core
// use-cases, render via internal/cli/render. NO crypto, NO git, NO policy logic.
// Imports core + adapter constructors only.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/pkg/byreis"
)

// NewRootCmd constructs the root cobra command with all subcommands wired.
// All adapter construction and injection is done in cmd/byreis/main.go, which
// passes a populated Deps into this function. Zero business logic lives here.
func NewRootCmd() *cobra.Command {
	return NewRootCmdWithDeps(&Deps{})
}

// NewRootCmdWithDeps constructs the root command with fully-injected use-case
// deps. This overload is used by cmd/byreis/main.go (production) and by tests
// that need to verify command behaviour with injected fakes.
func NewRootCmdWithDeps(deps *Deps) *cobra.Command {
	var jsonFlag bool

	root := &cobra.Command{
		Use:   "byreis",
		Short: "GitOps secrets management with asymmetric access",
		Long: `byreis — Send secrets. Not see them.

A zero-infra, plain-git tool where contributors can safely add or update secrets
without ever being able to read them. Admins hold private keys; contributors
hold only public keys.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().BoolVar(&jsonFlag, "json", false, "emit machine-readable JSON output")

	root.AddCommand(newVersionCmd(&jsonFlag))
	root.AddCommand(newInitCmd(deps, &jsonFlag))
	root.AddCommand(newDoctorCmd(deps, &jsonFlag))
	root.AddCommand(newSubmitCmd(deps, &jsonFlag))
	root.AddCommand(newReviewCmd(deps, &jsonFlag))
	root.AddCommand(newMergeCmd(deps, &jsonFlag))
	root.AddCommand(newGetCmd(deps, &jsonFlag))
	root.AddCommand(newDecryptCmd(deps, &jsonFlag))
	root.AddCommand(newEditCmd(deps, &jsonFlag))
	root.AddCommand(newAdminCmd(deps, &jsonFlag))
	root.AddCommand(newRotateCmd(deps, &jsonFlag))
	root.AddCommand(newRequestAccessCmd(deps, &jsonFlag))

	return root
}

func newVersionCmd(jsonFlag *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the byreis version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			// Use cobra's configured output writer so tests can capture output.
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()
			r.PrintVersion(byreis.Version)
			return nil
		},
	}
}
