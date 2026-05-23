package cli

// Package cli — contributor-mode CLI commands.
//
// This file implements the `byreis request-access` verb, the contributor-side
// in-band promotion request path. The verb is contributor-only (denied for
// ADMIN/SUPER per the mode policy matrix); it opens a PR against the registry
// repo bearing a `requests/<handle>.yaml` payload describing the contributor's
// desired age public key and justification.
//
// Auth discipline: this verb does not consume the trust-path verb ceiling,
// does not acquire a registry-write credential, does not call any signing
// primitive, and uses only the contributor's own GitHub token (GH_TOKEN /
// BYREIS_GITHUB_TOKEN) — the same transport `submit` uses. The GitHub client
// is encapsulated inside the RequestAccessOpener adapter; this file does not
// import go-github directly.

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// newRequestAccessCmd constructs the `byreis request-access` command.
//
// Mode gate is ALWAYS the first statement in RunE — contributor-only;
// ADMIN/SUPER are denied before any GitHub auth or network contact.
//
// This verb does not consume the trust-path verb ceiling, does not acquire a
// registry-write credential, and does not call SignText. It uses only the
// contributor's own GitHub identity (GH_TOKEN / BYREIS_GITHUB_TOKEN) —
// the same auth source as `byreis submit`.
//
// Flag semantics:
//
//	--key <age1...>         the contributor's age public key (required)
//	--justification "..."   free-text rationale (required)
//	--registry <owner/repo> registry repo (defaults to BYREIS_REGISTRY env)
//	--handle <login>        GitHub login to embed in the YAML (defaults to
//	                        the authenticated user's login)
func newRequestAccessCmd(deps *Deps, jsonFlag *bool) *cobra.Command {
	var (
		agePubkey     string
		justification string
		registryRepo  string
		handle        string
	)

	cmd := &cobra.Command{
		Use:   "request-access",
		Short: "Open a request-access PR to the registry (contributor only)",
		Long: `Open a request-access PR against the registry repo.

Operator-honesty contract: ` + rotate.RequestAccessHonestyContract + `.

Requires CONTRIBUTOR mode: denied-by-policy for ADMIN/SUPER operators before
any GitHub auth or network contact. This verb does NOT consume the trust-path verb ceiling
and does NOT acquire a registry-write credential.

The PR deposits a ` + "`requests/<handle>.yaml`" + ` file containing your age public key
and justification. An admin reviews the PR and may absorb it via
` + "`byreis rotate --add --from-request <PR>`" + `.

Fork discipline: the PR is opened from your own fork of the registry. If you do
not have a fork, create one first (` + "`gh repo fork <registry>`" + `) and re-run.

Rate-limit: at most ` + fmt.Sprintf("%d", maxRequestAccessPRQuota) + ` open request-access PRs per contributor
identity are permitted against the registry. Close stale PRs before opening a new one.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := render.New(*jsonFlag)
			r.Out = cmd.OutOrStdout()
			r.Err = cmd.ErrOrStderr()

			// Mode gate FIRST — denied-not-attempted for ADMIN/SUPER before any
			// network or auth touch.
			if deps.Policy != nil {
				if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandRequestAccess); err != nil {
					r.PrintErrorClass(
						"permission-denied",
						err.Error(),
						"request-access is a contributor-only verb — "+
							"ADMIN/SUPER operators do not need to open access requests",
					)
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			} else {
				// Default-allow for contributor (no policy wired = no admin key = contributor).
				// Belt-and-suspenders: if mode somehow resolved to non-contributor and no
				// policy is wired, refuse conservatively.
				if deps.CurrentMode == mode.ModeAdmin || deps.CurrentMode == mode.ModeSuper {
					err := fmt.Errorf(
						"%w: request-access is contributor-only — "+
							"ADMIN/SUPER operators do not need to open access requests",
						mode.ErrPermissionDenied)
					r.PrintErrorClass("permission-denied", err.Error(),
						"request-access is a contributor-only verb")
					return &exitError{code: render.ExitPermissionDenied, cause: err}
				}
			}

			// Guard: opener must be wired.
			if deps.RequestAccessOpener == nil {
				err := fmt.Errorf(
					"request-access is not configured — set BYREIS_GITHUB_TOKEN or GH_TOKEN " +
						"(run `gh auth login` to authenticate)")
				r.PrintErrorClass("auth-error", err.Error(),
					"run `gh auth login` or set BYREIS_GITHUB_TOKEN")
				return &exitError{code: render.ExitAuthError, cause: err}
			}

			// Resolve the registry repo from flag or env.
			reg := registryRepo
			if reg == "" {
				reg = os.Getenv("BYREIS_REGISTRY")
			}
			if reg == "" {
				err := fmt.Errorf(
					"registry repo not set — pass --registry or set BYREIS_REGISTRY " +
						"(e.g. myorg/byreis-admins)")
				r.PrintErrorClass("general-error", err.Error(),
					"pass --registry <owner/repo> or set BYREIS_REGISTRY")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}
			// Normalise: strip https://github.com/ prefix if accidentally included.
			reg = normaliseRegistryArg(reg)

			ctx := cmd.Context()

			// Resolve the contributor handle via the port (derives from token when
			// --handle is not supplied).
			in := rotate.RequestAccessInput{
				Registry:      reg,
				Handle:        strings.ToLower(strings.TrimSpace(handle)),
				AgePubkey:     agePubkey,
				Justification: justification,
			}

			contributorHandle, handleErr := deps.RequestAccessOpener.ResolveHandle(ctx, in)
			if handleErr != nil {
				err := fmt.Errorf(
					"cannot derive GitHub login — pass --handle or fix auth: %w", handleErr)
				r.PrintErrorClass("auth-error", err.Error(),
					"pass --handle <your-github-login> explicitly")
				return &exitError{code: render.ExitAuthError, cause: err}
			}
			in.Handle = contributorHandle

			// Open the PR. The opener handles quota check, idempotency check,
			// YAML pre-push validation, fork resolution, and PR creation.
			result, openErr := deps.RequestAccessOpener.Open(ctx, in)
			if openErr != nil {
				if isQuotaOrBounded(openErr) {
					r.PrintErrorClass("general-error", openErr.Error(),
						"close stale request-access PRs for your GitHub identity and retry")
					return &exitError{code: render.ExitGeneralError, cause: openErr}
				}
				r.PrintErrorClass("general-error", openErr.Error(),
					"check registry access and retry; see `byreis doctor` for diagnostics")
				return &exitError{code: render.ExitGeneralError, cause: openErr}
			}

			if *jsonFlag {
				_ = render.EncodeJSON(r.Out, map[string]any{
					"pr_url":    result.URL,
					"pr_number": result.PRRef.Number,
					"handle":    contributorHandle,
					"registry":  reg,
				})
				return nil
			}
			_, _ = fmt.Fprintf(r.Out,
				"request-access PR opened: %s\n"+
					"An admin can absorb it with: byreis rotate --add --from-request %s#%d\n",
				result.URL, reg, result.PRRef.Number)
			return nil
		},
	}

	cmd.Flags().StringVar(&agePubkey, "key", "",
		"age public key to request access for (required; e.g. age1...)")
	cmd.Flags().StringVar(&justification, "justification", "",
		"free-text rationale for the access request (required; max 1000 bytes)")
	cmd.Flags().StringVar(&registryRepo, "registry", "",
		"registry repo in owner/repo form (defaults to BYREIS_REGISTRY)")
	cmd.Flags().StringVar(&handle, "handle", "",
		"GitHub login to embed in the YAML (default: authenticated user's login)")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("justification")

	return cmd
}

// maxRequestAccessPRQuota is the client-side open-PR quota per contributor identity,
// mirrored from the adapter constant for use in the help text.
const maxRequestAccessPRQuota = 5

// isQuotaOrBounded returns true when err wraps ErrRequestAccessQuotaExceeded or
// ErrRequestAccessEnumerationBounded. Used to route error messages at the CLI
// boundary without importing adapter types.
func isQuotaOrBounded(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, rotate.ErrRequestAccessQuotaExceeded) ||
		errors.Is(err, rotate.ErrRequestAccessEnumerationBounded)
}

// normaliseRegistryArg strips common GitHub URL prefixes so that both
// "https://github.com/org/repo" and "org/repo" resolve to "org/repo".
func normaliseRegistryArg(reg string) string {
	reg = strings.TrimSuffix(reg, ".git")
	reg = strings.TrimPrefix(reg, "https://github.com/")
	reg = strings.TrimPrefix(reg, "git@github.com:")
	return reg
}
