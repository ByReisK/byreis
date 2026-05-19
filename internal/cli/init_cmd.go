package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/trust"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

func newInitCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		registryURL    string
		projectID      string
		acceptSigner   string
		nonInteractive bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a project and pin the registry trust anchor",
		Long: `Bootstrap a project: verify the registry signer, pin the trust anchor on first
use (with explicit confirmation), and write .byreis.yaml.

On first run, byreis displays the registry signer fingerprint and asks you to
confirm it matches the expected key. Pass --accept-signer <fp> to confirm
non-interactively. Use --non-interactive to require --accept-signer (fails
closed if omitted).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			if deps.Initializer == nil {
				r.PrintError("init use-case not configured — adapters not yet wired")
				return fmt.Errorf("init not available: adapters not wired")
			}

			res, err := deps.Initializer.Init(cmd.Context(), usecase.InitInput{
				RegistryURL:    registryURL,
				ProjectID:      projectID,
				AcceptSigner:   acceptSigner,
				NonInteractive: nonInteractive,
				ConfigDir:      deps.ConfigDir,
			})
			if err != nil {
				exitCode := exitCodeForInitErr(err)
				r.PrintError(err.Error())
				return &exitError{code: exitCode, cause: err}
			}

			if *jsonFlag {
				type initResult struct {
					PinWritten        bool   `json:"pin_written"`
					ProjectConfig     bool   `json:"project_config_written"`
					SignerFingerprint string `json:"signer_fingerprint"`
				}
				_ = render.EncodeJSON(r.Out, initResult{
					PinWritten:        res.PinWritten,
					ProjectConfig:     res.ProjectConfigWritten,
					SignerFingerprint: res.SignerFingerprint,
				})
				return nil
			}

			if res.PinWritten {
				_, _ = fmt.Fprintf(r.Out, "ok: trust anchor pinned (signer: %s)\n", res.SignerFingerprint)
			} else {
				_, _ = fmt.Fprintf(r.Out, "ok: trust anchor verified (signer: %s)\n", res.SignerFingerprint)
			}
			_, _ = fmt.Fprintln(r.Out, "ok: project config written")
			return nil
		},
	}

	cmd.Flags().StringVar(&registryURL, "registry", os.Getenv("BYREIS_REGISTRY"),
		"registry repo URL (or set BYREIS_REGISTRY)")
	cmd.Flags().StringVar(&projectID, "project", "", "project ID")
	cmd.Flags().StringVar(&acceptSigner, "accept-signer", "",
		"explicitly accept signer fingerprint (bypasses interactive prompt)")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", envBool("BYREIS_NON_INTERACTIVE"),
		"non-interactive mode: requires --accept-signer (or set BYREIS_NON_INTERACTIVE=1)")

	return cmd
}

// exitCodeForInitErr maps init sentinel errors to render.ExitCode values.
func exitCodeForInitErr(err error) render.ExitCode {
	switch {
	case errors.Is(err, trust.ErrTrustAnchorPerms),
		errors.Is(err, trust.ErrTrustAnchorSymlink),
		errors.Is(err, trust.ErrTrustDirPerms),
		errors.Is(err, trust.ErrTrustDirSymlink),
		errors.Is(err, trust.ErrTrustDirWrongOwner),
		errors.Is(err, trust.ErrTrustAnchorWrongOwner):
		return render.ExitTrustError
	case errors.Is(err, usecase.ErrSignerChanged),
		errors.Is(err, usecase.ErrSignerNotAccepted):
		return render.ExitTrustError
	case errors.Is(err, usecase.ErrRegistryVerifyFailed):
		return render.ExitTrustError
	default:
		return render.ExitGeneralError
	}
}
