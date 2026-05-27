package cli

// Package cli — contributor audit-verify command.
//
// This file implements `byreis audit verify --project <id>`, a top-level verb
// (sibling of `admin audit show`, NOT a child of `admin`) that runs the full
// per-line audit-binding walk and is permitted in every mode (Contributor,
// Admin, Super). The gate is CommandAuditVerify in the mode permission matrix.
//
// Security discipline:
//   - This verb calls ONLY deps.AuditVerifier.VerifyAuditLog. It NEVER calls
//     deps.AuditReader.FetchAuditLog or any plaintext/decode path.
//   - It acquires NO private key, NO write credential, and makes NO registry
//     write. The audit channel is public; the binding walk is read-only.
//   - The gate (CommandAuditVerify, all-modes ALLOW) is on this verb's RunE,
//     not on the top-level `audit` parent group. The parent group is
//     mode-neutral so adding this verb does NOT relax the admin-only
//     `audit show` gate.
//   - Rendering reuses renderAuditEntries(..., showBinding=true, ...) and the
//     exit-code contract reuses auditFetchExitCode verbatim from admin_cmds.go,
//     giving parity with `admin audit show --verify` for CI consumers.

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// newAuditCmd constructs the top-level `audit` parent command that hosts both
// the admin `show` sub-command (registered by admin_cmds.go → newAdminAuditCmd)
// and the all-modes `verify` sub-command.
//
// This parent is mode-neutral: it carries no RunE of its own and imposes no
// gate. Each child verb gates itself independently. In particular, adding
// `audit verify` here does NOT relax the gate on `audit show`.
func newAuditCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	audit := &cobra.Command{
		Use:   "audit",
		Short: "Audit log operations",
		Long: `Audit log operations.

'audit verify' is available in all modes (contributor, admin, super): it
performs the per-line binding walk over the public audit channel.

'admin audit show' is admin-only: it decodes and renders the full audit
entry detail; contributors are denied-by-policy before any network touch.`,
	}
	audit.AddCommand(newAuditVerifyCmd(deps, jsonFlag))
	return audit
}

// newAuditVerifyCmd constructs the `byreis audit verify --project <id>`
// command.
//
// Mode gate: CommandAuditVerify (all modes ALLOW). The gate is the FIRST
// statement in RunE so the policy is enforced before any network or port
// contact.
//
// Binding obligations:
//   - Calls ONLY AuditVerifier.VerifyAuditLog. Never calls AuditReader or
//     any decode/plaintext path.
//   - Renders per-line binding status via renderAuditEntries with showBinding=true.
//   - Returns exit errors via auditFetchExitCode (the same contract as
//     `admin audit show --verify`).
//
// Tamper outcome: entries are rendered FIRST; then the typed exit error is
// returned so CI consumers always receive per-line status alongside the
// non-zero exit (never a partial-verified-as-clean result).
func newAuditVerifyCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var project string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the per-line binding of the registry audit log (all modes)",
		Long: `Verify the per-line binding of the registry audit log for a project.

Available in CONTRIBUTOR, ADMIN, and SUPER mode. The capability is confined
to the public audit channel: no private key, no write credential, and no
decoded secret is accessed or returned.

Each JSONL line in the audit log is bound to the signed commit that
introduced it. Any line that was added, removed, reordered, or forged
outside the signed-commit discipline is reported as TAMPERED and the
command exits with a non-zero code.

The full per-line binding walk is bounded; the registry HEAD must be
signature-verified before the walk begins (an unverified HEAD returns an
error immediately).

Use --json to emit a machine-readable binding report suitable for CI:
  byreis audit verify --project <id> --json || exit 1

Contributors can also read the audit log directly via git:
  git show audit/<project>.jsonl
  git verify-commit <HEAD>`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST — the gate is on the verb, not the parent group.
			// CommandAuditVerify is all-modes ALLOW; ErrPermissionDenied is
			// returned only for a forged or unknown mode value (fail-closed floor).
			if deps.Policy != nil {
				if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandAuditVerify); err != nil {
					r.PrintErrorClass("permission-denied", err.Error(),
						"audit verify is available in all modes — "+
							"run `byreis doctor` to diagnose your current mode")
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			}

			// Guard: verifier must be wired. A nil verifier means the registry is
			// not configured; the error is surfaced at command time (fail-closed,
			// deferred from composition time).
			if deps.AuditVerifier == nil {
				err := fmt.Errorf(
					"audit verify not available: the AuditVerifier is not wired — " +
						"set BYREIS_REGISTRY and run `byreis doctor`")
				r.PrintErrorClass("general-error", err.Error(),
					"set BYREIS_REGISTRY and run `byreis doctor`")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			ctx := cmd.Context()

			// Full per-line binding walk. The result carries per-line status even
			// on a tamper outcome; render before returning the error so CI consumers
			// always receive the per-line projection alongside the non-zero exit.
			result, verifyErr := deps.AuditVerifier.VerifyAuditLog(ctx, project)
			renderAuditEntries(ctx, r, *jsonFlag, result.Entries, true, project, deps.ActorResolver)
			if verifyErr != nil {
				code := auditFetchExitCode(verifyErr)
				r.PrintErrorClass(auditExitClass(code), verifyErr.Error(),
					auditVerifyHint(code))
				return &exitError{code: code, cause: verifyErr}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project ID (required)")
	_ = cmd.MarkFlagRequired("project")

	return cmd
}

// auditVerifyHint returns an actionable hint for audit verify errors.
// It mirrors auditFetchHint but uses contributor-appropriate language and
// omits the "requires ADMIN mode" framing that applies only to audit show.
func auditVerifyHint(code render.ExitCode) string {
	switch code {
	case render.ExitPermissionDenied:
		return "run `byreis doctor` to verify your current mode"
	case render.ExitTrustError:
		return "registry HEAD is not signature-verified — " +
			"run `byreis doctor` and verify the registry trust configuration; " +
			"read the audit log directly with: git show audit/<project>.jsonl && git verify-commit <HEAD>"
	case render.ExitVerifyFailure:
		return "registry is unreachable — " +
			"read the audit log directly with: git show audit/<project>.jsonl && git verify-commit <HEAD>"
	default:
		return "run `byreis doctor` for diagnostics; " +
			"read the audit log directly with: git show audit/<project>.jsonl && git verify-commit <HEAD>"
	}
}
