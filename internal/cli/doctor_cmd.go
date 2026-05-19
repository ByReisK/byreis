package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

func newDoctorCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run health checks and report mode, trust anchor, and registry status",
		Long: `Diagnose your byreis configuration:

  - Config directory permissions (must be 0700, not a symlink)
  - Trust anchor permissions (must be 0600, not a symlink)
  - Cryptographically-derived mode (CONTRIBUTOR or ADMIN) and its reason
  - Registry connectivity: offline = cache age (INFO, not an error); signature
    verify failure = FAIL; branch protection = advisory WARN.

Exit code is non-zero if any check has a FAIL severity. An offline registry
alone does NOT cause a non-zero exit.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			if deps.Doctor == nil {
				r.PrintError("doctor use-case not configured — adapters not yet wired")
				return fmt.Errorf("doctor not available: adapters not wired")
			}

			result, err := deps.Doctor.Diagnose(cmd.Context())
			if err != nil {
				r.PrintError(err.Error())
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			if *jsonFlag {
				_ = render.EncodeJSON(r.Out, doctorResultJSON(result))
				if result.HasFail() {
					return &exitError{code: render.ExitGeneralError}
				}
				return nil
			}

			// Plain output: print mode + reason, then all findings.
			_, _ = fmt.Fprintf(r.Out, "mode: %s\nreason: %s\n\n", result.Mode, result.ModeReason)
			for _, f := range result.Findings {
				_, _ = fmt.Fprintf(r.Out, "[%s] %s: %s\n", f.Severity, f.Check, f.Detail)
			}
			if result.OfflineCacheAge > 0 {
				_, _ = fmt.Fprintf(r.Out, "\nregistry offline — cached data is %s old\n",
					result.OfflineCacheAge)
			}
			if result.HasFail() {
				return &exitError{code: render.ExitGeneralError}
			}
			return nil
		},
	}
}

type doctorFindingJSON struct {
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type doctorResultJSONOut struct {
	Mode            string              `json:"mode"`
	ModeReason      string              `json:"mode_reason"`
	Findings        []doctorFindingJSON `json:"findings"`
	OfflineCacheAge string              `json:"offline_cache_age,omitempty"`
	HasFail         bool                `json:"has_fail"`
}

func doctorResultJSON(r usecase.DoctorResult) doctorResultJSONOut {
	out := doctorResultJSONOut{
		Mode:       r.Mode.String(),
		ModeReason: r.ModeReason,
		HasFail:    r.HasFail(),
	}
	if r.OfflineCacheAge > 0 {
		out.OfflineCacheAge = r.OfflineCacheAge.String()
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, doctorFindingJSON{
			Check:    f.Check,
			Severity: f.Severity.String(),
			Detail:   f.Detail,
		})
	}
	return out
}
