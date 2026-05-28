package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

func newDoctorCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var rotationHistory bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run health checks and report mode, trust anchor, and registry status",
		Long: `Diagnose your byreis configuration:

  - Config directory permissions (must be 0700, not a symlink)
  - Trust anchor permissions (must be 0600, not a symlink)
  - Cryptographically-derived mode (CONTRIBUTOR or ADMIN) and its reason
  - Registry connectivity: offline = cache age (INFO, not an error); signature
    verify failure = FAIL; branch protection = advisory WARN.

Use --rotation-history to report the per-file rotation epoch for every project
file. When files disagree on epoch a partial-rotation-detected advisory is shown.
When any file has epoch >= 1 the forward-secrecy advisory is also printed.

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

			// Wire the rotation-history flag into the use-case deps if requested.
			// The deps.Doctor use-case was constructed with RotationHistoryRequested
			// set to false by default; we cannot mutate it after construction.
			// Instead, reconstruct the doctor use-case when the flag is set, or
			// delegate to the deps-layer doctor directly and set the flag via the
			// DoctorWithRotationHistory helper when the flag is set.
			//
			// Because Doctor is an interface (not a concrete struct), we set the
			// flag by calling the deps layer's RotationHistoryDoctor when present,
			// falling back to the base Doctor otherwise.
			doctor := deps.Doctor
			if rotationHistory && deps.RotationHistoryDoctor != nil {
				doctor = deps.RotationHistoryDoctor
			}

			result, err := doctor.Diagnose(cmd.Context())
			if err != nil {
				r.PrintError(err.Error())
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Warn if BYREIS_PROJECT looks like an owner/repo slug. Under the
			// two-var contract, BYREIS_PROJECT must be the slash-free logical
			// project id; the GitHub repo slug belongs in BYREIS_PROJECT_REPO.
			if bp := os.Getenv("BYREIS_PROJECT"); strings.Contains(bp, "/") {
				result.Findings = append([]usecase.DoctorFinding{{
					Check:    "env:BYREIS_PROJECT",
					Severity: usecase.SeverityWarn,
					Detail: fmt.Sprintf(
						"BYREIS_PROJECT=%q looks like an owner/repo slug — "+
							"BYREIS_PROJECT must be the slash-free logical project id "+
							"(e.g. \"myapp\"); set the GitHub secrets-repo location in "+
							"BYREIS_PROJECT_REPO instead (e.g. \"myorg/myapp\")",
						bp),
				}}, result.Findings...)
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

			// When doctor runs with probe suppression (the mode matrix permits doctor
			// in CONTRIBUTOR mode, so the decrypt probe is never run) AND a key is
			// configured, the CONTRIBUTOR result may be misleading to an admin. Emit
			// an informational note so they know how to get an authoritative reading.
			if !mode.NeedsDecryptProbe(mode.CommandDoctor) && doctorKeyConfigured() {
				_, _ = fmt.Fprintf(r.Out,
					"[INFO] mode: probe suppressed (doctor does not require admin); "+
						"to verify admin mode try a key-using command\n")
			}

			for _, f := range result.Findings {
				_, _ = fmt.Fprintf(r.Out, "[%s] %s: %s\n", f.Severity, f.Check, f.Detail)
			}
			if result.OfflineCacheAge > 0 {
				_, _ = fmt.Fprintf(r.Out, "\nregistry offline — cached data is %s old\n",
					result.OfflineCacheAge)
			}

			// Rotation history section.
			if rotationHistory && len(result.RotationHistory) > 0 {
				_, _ = fmt.Fprintf(r.Out, "\nrotation history:\n")
				for _, rh := range result.RotationHistory {
					_, _ = fmt.Fprintf(r.Out, "  %s: epoch=%d", rh.File, rh.Epoch)
					if rh.PartialRotationDetected {
						_, _ = fmt.Fprintf(r.Out, " [partial-rotation-detected]")
					}
					_, _ = fmt.Fprintln(r.Out)
				}
			}

			// Emit the verbatim forward-secrecy warning when rotation history
			// reveals that a rotation has occurred (epoch >= 1 for any file).
			// This warning is advisory only and does NOT set a non-zero exit code.
			// The //nolint:forbidigo comment marks this as the single permitted
			// boundary site for emitting the constant at the CLI render layer.
			if result.HasRotationHistory {
				//nolint:forbidigo // boundary: emitting rotate.ForwardSecrecyWarning at the CLI render layer
				_, _ = fmt.Fprintf(r.Out, "\n%s\n", rotate.ForwardSecrecyWarning)
			}

			if result.HasFail() {
				return &exitError{code: render.ExitGeneralError}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&rotationHistory, "rotation-history", false,
		"Report per-file rotation epochs and emit the forward-secrecy advisory when any file has epoch >= 1")

	return cmd
}

type doctorFindingJSON struct {
	Check    string `json:"check"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type doctorRotationHistoryJSON struct {
	File                    string `json:"file"`
	Epoch                   uint64 `json:"epoch"`
	PartialRotationDetected bool   `json:"partial_rotation_detected"`
}

type doctorResultJSONOut struct {
	Mode            string                      `json:"mode"`
	ModeReason      string                      `json:"mode_reason"`
	Findings        []doctorFindingJSON         `json:"findings"`
	OfflineCacheAge string                      `json:"offline_cache_age,omitempty"`
	HasFail         bool                        `json:"has_fail"`
	RotationHistory []doctorRotationHistoryJSON `json:"rotation_history,omitempty"`
}

// doctorKeyConfigured returns true when at least one key-source environment
// variable is set, indicating a key is configured even though the decrypt probe
// was suppressed for this command. The note is suppressed for bare contributors
// who have no key configured at all, where it would be confusing.
func doctorKeyConfigured() bool {
	return os.Getenv("BYREIS_KEY") != "" ||
		os.Getenv("BYREIS_KEY_FILE") != ""
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
	for _, rh := range r.RotationHistory {
		out.RotationHistory = append(out.RotationHistory, doctorRotationHistoryJSON{
			File:                    rh.File,
			Epoch:                   rh.Epoch,
			PartialRotationDetected: rh.PartialRotationDetected,
		})
	}
	return out
}
