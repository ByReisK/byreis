package cli

// Package cli — the admin-only `export` verb.
//
// `export` decrypts a project's live file-of-record and serializes every value
// as an env (`export KEY="..."`) or dotenv (`KEY="..."`) stream to stdout. It
// is a thin shell over the shipped admin-read decrypt use-case: it carries the
// identical ADMIN/SUPER permission shape as `decrypt`/`get`, the same
// VerifyOfRecord-first + fail-closed whole-file decrypt, and the same audit
// trace (recorded under op="export" so a bulk export is distinguishable from a
// single-file decrypt). The env/dotenv emitter, key→var mapping, collision
// detection, quoting, and the no-leak TTY refusal all live in the UI layer
// (internal/cli + internal/cli/render); core gains no new symbol for the verb.
//
// RunE ordering is fail-closed and load-bearing:
//   1. mode gate (denied-by-policy before any identity-load / decrypt / network)
//   2. Decryptor nil-guard
//   3. TTY refusal (fail-fast: refuse before decrypting if stdout is interactive)
//   4. whole-file decrypt via the shipped use-case (no partial/best-effort path)
//   5. key→var mapping + collision check (fail-closed, before any plaintext byte)
//   6. emit the env/dotenv stream — only after every prior step has passed

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// newRenderer is the renderer constructor used by the export verb. It is a
// package-level seam (defaulting to render.New) so unit tests can drive the
// resolved IsTTY value directly instead of standing up a real terminal. The
// TTY probe itself is resolved once by render.New at production call sites;
// the verb never re-stats the terminal.
var newRenderer = render.New

// ttyRefusalHint names the escape from the no-leak TTY refusal. The default
// refuses plaintext to an interactive terminal so decrypted secrets never land
// in scrollback by accident; piping or redirecting makes stdout non-interactive
// and is the explicit "I want to see it" path.
const ttyRefusalHint = "export refuses to write plaintext to an interactive terminal — " +
	"pipe or redirect the output, e.g. `byreis export --format env | cat` or `> app.env`"

// newExportCmd constructs the `export` command. It is a sibling of `decrypt`
// and `get` (top-level, not under `admin`) and rides the same admin-read
// Decrypt use-case.
func newExportCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		project string
		file    string
		format  string
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Decrypt a secrets file to an env/dotenv stream (admin only)",
		Long: `Decrypt a secrets file and serialize it as an env or dotenv stream to stdout.

Requires ADMIN mode: the command is denied-by-policy (not attempted-then-failed)
when running as CONTRIBUTOR. The VerifyOfRecord check runs before any decrypt or
identity-load, and the whole file is decrypted fail-closed — if any value cannot
be decrypted, nothing is emitted.

--format selects the serialization shape:
  env     emits one ` + "`export KEY=\"...\"`" + ` line per value (shell sourcing: ` + "`set -a; .`" + `)
  dotenv  emits one ` + "`KEY=\"...\"`" + ` line per value (.env files, docker-compose, godotenv)

Every value is double-quoted and escaped so it round-trips exactly and cannot
inject a shell command when the output is sourced or eval'd. Target consumers
are quote-aware (shell source/eval, godotenv, docker-compose env_file); raw
` + "`docker --env-file`" + ` (which does not process quotes/escapes) is out of scope.

The decrypted output is the secret. By default export refuses to write to an
interactive terminal so it does not land in scrollback; pipe or redirect the
output to consume it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := newRenderer(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// 1. Mode gate FIRST. Denied-by-policy before any use-case entry,
			//    identity-load, decrypt, or network contact.
			if pErr := checkPolicy(deps, r, mode.CommandExport, "export"); pErr != nil {
				return pErr
			}

			// Validate the required --format flag. Reject any value other than
			// env|dotenv with an actionable error, before touching the decrypt
			// path.
			emitFormat, formatErr := parseEnvFormat(format)
			if formatErr != nil {
				r.PrintErrorClass("general-error", formatErr.Error(),
					"use --format env or --format dotenv")
				return &exitError{code: render.ExitGeneralError, cause: formatErr}
			}

			// 2. Decryptor nil-guard.
			if deps.Decryptor == nil {
				err := fmt.Errorf(
					"export not available: the read-path use-case is not wired — " +
						"run `byreis doctor` or check your installation")
				r.PrintErrorClass("general-error", err.Error(),
					"run `byreis doctor` or check your installation")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// 3. TTY refusal (fail-fast). If stdout is an interactive terminal we
			//    refuse BEFORE decrypting: no plaintext is produced, nothing is
			//    written to stdout, and a non-zero exit names the pipe/redirect
			//    escape on stderr.
			if r.IsTTY {
				err := fmt.Errorf("%s", ttyRefusalHint)
				r.PrintErrorClass("general-error", err.Error(), ttyRefusalHint)
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// 4. Whole-file decrypt via the shipped admin-read use-case. Keys
			//    empty = every value. VerifyOfRecord-first and fail-closed
			//    decryptAll are guaranteed by the use-case: on any error the
			//    whole export fails and NO plaintext is emitted.
			result, err := deps.Decryptor.Decrypt(cmd.Context(), usecase.DecryptInput{
				ProjectID: project,
				FileName:  file,
				Op:        "export",
			})
			if err != nil {
				return handleReadPathError(r, err)
			}

			// Zeroize the recovered plaintext map on every return path once we
			// hold it, so a decrypted value does not linger after the command.
			defer zeroizePlaintext(result.Plaintext)

			// 5. Key→var mapping + post-mapping collision/leading-digit check over
			//    the recovered key names. On ANY error fail closed: no plaintext
			//    byte has been written yet, and none will be.
			pairs, mapErr := render.BuildEnvPairs(result.Plaintext, result.KeyNames)
			if mapErr != nil {
				code := render.ExitGeneralError
				r.PrintErrorClass("general-error", mapErr.Error(),
					exportMappingHint(mapErr))
				return &exitError{code: code, cause: mapErr}
			}

			// 6. Emit the env/dotenv stream — only after the gate, decrypt, and
			//    mapping have all passed. EmitEnv rejects NUL fail-closed (no
			//    partial output) and double-quotes/escapes every value.
			if emitErr := render.EmitEnv(r.Out, pairs, emitFormat); emitErr != nil {
				code := render.ExitGeneralError
				r.PrintErrorClass("general-error", emitErr.Error(),
					exportMappingHint(emitErr))
				return &exitError{code: code, cause: emitErr}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "project ID (required)")
	cmd.Flags().StringVar(&file, "file", "", "logical file name (required)")
	cmd.Flags().StringVar(&format, "format", "",
		"output format: env (export KEY=\"...\") or dotenv (KEY=\"...\") (required)")
	_ = cmd.MarkFlagRequired("project")
	_ = cmd.MarkFlagRequired("file")
	_ = cmd.MarkFlagRequired("format")

	return cmd
}

// parseEnvFormat maps the --format flag value to a render.EnvFormat. It accepts
// exactly "env" and "dotenv"; any other value (including empty) is an error
// with an actionable hint. cobra enforces the flag is present via
// MarkFlagRequired, but the empty/unknown case is handled here defensively.
func parseEnvFormat(format string) (render.EnvFormat, error) {
	switch format {
	case "env":
		return render.FormatEnv, nil
	case "dotenv":
		return render.FormatDotenv, nil
	default:
		return 0, fmt.Errorf(
			"--format %q is not a valid export format — use 'env' or 'dotenv'",
			format)
	}
}

// exportMappingHint returns an actionable remediation hint for an emitter-layer
// error (leading-digit, collision, or NUL-in-value). The hint never contains a
// secret value; the emitter sentinels name the offending key by name only.
func exportMappingHint(err error) string {
	switch {
	case errors.Is(err, render.ErrLeadingDigit):
		return "rename the secret key so its variable name starts with a letter or underscore"
	case errors.Is(err, render.ErrVarCollision):
		return "rename one of the named secret keys so the mapping is unambiguous"
	case errors.Is(err, render.ErrNulInValue):
		return "the named value contains a NUL byte and cannot be exported as an env stream"
	default:
		return "run `byreis doctor` for diagnostics"
	}
}
