package cli

// Package cli — the admin-only `run` verb.
//
// `run` decrypts a project's live file-of-record and injects every value into
// the environment of a single spawned child process:
//
//	byreis run --project P --file F -- <cmd> [args...]
//
// Everything after `--` is the child argv, exec'd VERBATIM: byreis performs no
// `$VAR`/shell interpretation of it. The verb is a thin shell over the shipped
// admin-read decrypt use-case — it carries the identical ADMIN/SUPER permission
// shape as `decrypt`/`get`/`export`, the same VerifyOfRecord-first fail-closed
// whole-file decrypt, and the same audit trace (recorded under op="run"). The
// env-block build (reusing the export key→var mapping), the injected-wins merge,
// and the child exec all live in the UI/adapter layers; core gains no new symbol
// for the verb beyond the mode.CommandRun matrix cell.
//
// RunE ordering is fail-closed and load-bearing (mirrors export_cmd.go):
//   1. mode gate FIRST (denied-by-policy before any identity-load / decrypt /
//      network contact / child spawn)
//   2. nil-guard the Decryptor AND the RunChild spawner
//   3. whole-file decrypt via the shipped use-case (no partial/best-effort path)
//   4. zeroize the recovered plaintext map on every return path
//   5. key→var mapping + collision check (fail-closed; no spawn on error)
//   6. build the merged child env-block (injected-wins; NUL-reject; no spawn on error)
//   7. spawn the child — only after every prior step has passed — and pass its
//      faithful exit code (including 128+signal) straight through as byreis's own

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// runEnvProvider returns the inherited parent environment in os.Environ()
// "KEY=VALUE" form. It is a package-level seam (defaulting to os.Environ) so
// unit tests can drive a deterministic parent env without depending on the real
// process environment.
var runEnvProvider = osEnviron

// newRunCmd constructs the `run` command. It is a sibling of `decrypt`, `get`,
// and `export` (top-level, not under `admin`) and rides the same admin-read
// Decrypt use-case for the decrypt half.
func newRunCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		project string
		file    string
	)

	cmd := &cobra.Command{
		Use:   "run --project P --file F -- <cmd> [args...]",
		Short: "Run a command with a secrets file decrypted into its environment (admin only)",
		Long: `Decrypt a secrets file and run a command with every value injected into its environment.

Requires ADMIN mode: the command is denied-by-policy (not attempted-then-failed)
when running as CONTRIBUTOR — no identity-load, decrypt, network contact, or child
spawn occurs in that case. The VerifyOfRecord check runs before any decrypt, and
the whole file is decrypted fail-closed — if any value cannot be decrypted, or any
key cannot be mapped to a legal environment variable name, nothing is spawned.

Everything after ` + "`--`" + ` is the child command and is exec'd verbatim — byreis does
NOT perform shell ` + "`$VAR`" + `/glob interpretation on it. The child inherits this
process's stdin/stdout/stderr directly (no capture). When an injected variable
name collides with an inherited environment variable, the injected (secret) value
wins. The child's exit code (including signal termination) is passed through as
byreis's own exit code.

Example:
  byreis run --project myapp --file prod -- printenv API_KEY
  byreis run --project myapp --file prod -- ./deploy.sh`,
		RunE: func(cmd *cobra.Command, args []string) error {
			r := newRenderer(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Capture the post-`--` child argv. cobra records the index of the
			// `--` token via ArgsLenAtDash(); everything from there on is the
			// child command and arguments, exec'd verbatim. A missing or empty
			// child argv is a usage error — fail before any decrypt.
			dash := cmd.ArgsLenAtDash()
			var childArgv []string
			if dash >= 0 && dash <= len(args) {
				childArgv = args[dash:]
			}
			if len(childArgv) == 0 {
				err := fmt.Errorf(
					"run requires a command after `--`, e.g. `byreis run --project P --file F -- printenv`")
				r.PrintErrorClass("general-error", err.Error(),
					"put the command to run after a `--` separator")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// 1. Mode gate FIRST. Denied-by-policy before any use-case entry,
			//    identity-load, decrypt, network contact, or child spawn.
			if pErr := checkPolicy(deps, r, mode.CommandRun, "run"); pErr != nil {
				return pErr
			}

			// 2. nil-guard the Decryptor AND the RunChild spawner. Either being
			//    unwired is a configuration problem, surfaced before any decrypt.
			if deps.Decryptor == nil {
				err := fmt.Errorf(
					"run not available: the read-path use-case is not wired — " +
						"run `byreis doctor` or check your installation")
				r.PrintErrorClass("general-error", err.Error(),
					"run `byreis doctor` or check your installation")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}
			if deps.RunChild == nil {
				err := fmt.Errorf(
					"run not available: the process spawner is not wired — " +
						"run `byreis doctor` or check your installation")
				r.PrintErrorClass("general-error", err.Error(),
					"run `byreis doctor` or check your installation")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// 3. Whole-file decrypt via the shipped admin-read use-case. Keys
			//    empty = every value. VerifyOfRecord-first and fail-closed
			//    decryptAll are guaranteed by the use-case: on any error the
			//    whole run fails and NO child is spawned (Op="run" flows to the
			//    audit trail — only the op literal, never the child argv/args).
			result, err := deps.Decryptor.Decrypt(cmd.Context(), usecase.DecryptInput{
				ProjectID: project,
				FileName:  file,
				Op:        "run",
			})
			if err != nil {
				return handleReadPathError(r, err)
			}

			// 4. Zeroize the recovered plaintext map on every return path once we
			//    hold it, so a decrypted value does not linger after the command.
			defer zeroizePlaintext(result.Plaintext)

			// 5. Key→var mapping + post-mapping collision/leading-digit check over
			//    the recovered key names. On ANY error fail closed: NO child is
			//    spawned, and the error names the offending key (never a value).
			pairs, mapErr := render.BuildEnvPairs(result.Plaintext, result.KeyNames)
			if mapErr != nil {
				r.PrintErrorClass("general-error", mapErr.Error(), runMappingHint(mapErr))
				return &exitError{code: render.ExitGeneralError, cause: mapErr}
			}

			// 6. Build the merged child env-block: inherited parent env +
			//    injected secrets, injected-wins on a name collision, NUL-reject.
			//    On error fail closed: NO child is spawned.
			envBlock, blockErr := render.BuildChildEnvBlock(runEnvProvider(), pairs)
			if blockErr != nil {
				r.PrintErrorClass("general-error", blockErr.Error(), runMappingHint(blockErr))
				return &exitError{code: render.ExitGeneralError, cause: blockErr}
			}

			// 7. Spawn the child — only after the gate, decrypt, mapping, and
			//    env-block build have all passed. The spawner inherits stdio
			//    directly (no capture). Its faithful exit code (including 128+S
			//    for a signal) is passed straight through as byreis's own exit
			//    code, bypassing the read-path exit-class machinery (a non-zero
			//    child exit is not a byreis read-path failure).
			childExit, runErr := deps.RunChild(cmd.Context(), childArgv, envBlock)
			if runErr != nil {
				r.PrintErrorClass("general-error", runErr.Error(),
					"check that the command exists and is executable")
				return &exitError{code: render.ExitGeneralError, cause: runErr}
			}
			if childExit.Code != 0 {
				return &exitError{code: render.ExitCode(childExit.Code)}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project ID (required)")
	cmd.Flags().StringVar(&file, "file", "", "logical file name (required)")
	_ = cmd.MarkFlagRequired("project")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

// runMappingHint returns an actionable remediation hint for an env-block error
// (leading-digit, collision, or NUL-in-value). The hint never contains a secret
// value; the emitter sentinels name the offending key by name only.
func runMappingHint(err error) string {
	return exportMappingHint(err)
}
