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
// BYREIS_GITHUB_TOKEN) — the same transport `submit` uses.
//
// This is verified structurally by the compilation unit's import set:
// internal/adapter/registry/writesigner is absent from the transitive closure.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	ghsdk "github.com/google/go-github/v72/github"
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
any GitHub auth or network contact. This verb does NOT consume the §7 trust-path
verb ceiling and does NOT acquire a registry-write credential.

The PR deposits a ` + "`requests/<handle>.yaml`" + ` file containing your age public key
and justification. An admin reviews the PR and may absorb it via
` + "`byreis rotate --add --from-request <PR>`" + `.

Fork discipline: the PR is opened from your own fork of the registry. If you do
not have a fork, create one first (` + "`gh repo fork <registry>`" + `) and re-run.

Rate-limit: at most ` + fmt.Sprintf("%d", maxOpenRequestAccessPRs) + ` open request-access PRs per contributor
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

			// Resolve contributor's GitHub token from env (same source as submit).
			token := githubTokenContrib()
			if token == "" {
				err := fmt.Errorf(
					"no GitHub token found — set BYREIS_GITHUB_TOKEN or GH_TOKEN " +
						"(run `gh auth login` to authenticate)")
				r.PrintErrorClass("auth-error", err.Error(),
					"run `gh auth login` or set BYREIS_GITHUB_TOKEN")
				return &exitError{code: render.ExitAuthError, cause: err}
			}

			ctx := cmd.Context()

			// Build the GitHub client for the registry repo.
			regClient := ghsdk.NewClient(nil).WithAuthToken(token)

			// Resolve the handle: use flag override or derive from authenticated user.
			contributorHandle := strings.ToLower(strings.TrimSpace(handle))
			if contributorHandle == "" {
				login, loginErr := resolveAuthenticatedGitHubLogin(ctx, regClient)
				if loginErr != nil {
					err := fmt.Errorf(
						"cannot derive GitHub login — pass --handle or fix auth: %w", loginErr)
					r.PrintErrorClass("auth-error", err.Error(),
						"pass --handle <your-github-login> explicitly")
					return &exitError{code: render.ExitAuthError, cause: err}
				}
				contributorHandle = strings.ToLower(login)
			}

			// Parse owner/repo from reg early: needed for the quota check below.
			parts := strings.SplitN(reg, "/", 2)
			if len(parts) != 2 {
				err := fmt.Errorf("registry %q is not in owner/repo form", reg)
				r.PrintErrorClass("general-error", err.Error(), "use owner/repo format")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}
			owner, repo := parts[0], parts[1]

			// Rate-limit check: refuse if the open-PR quota is already exhausted.
			// listOpenRequestAccessPRsForContributor uses the SDK client directly so
			// this file does not import an internal adapter (Clean Architecture boundary).
			openCount, quotaErr := listOpenRequestAccessPRsForContributor(ctx, regClient, owner, repo, contributorHandle)
			if quotaErr != nil {
				// Non-fatal: quota check failure should not block the open path.
				// Surface a warning and proceed.
				_, _ = fmt.Fprintf(r.Err,
					"warning: could not check open-PR quota: %v — proceeding\n", quotaErr)
			} else if openCount >= maxOpenRequestAccessPRs {
				err := fmt.Errorf("%w: %d open request-access PR(s) found for %q "+
					"(limit %d) — close stale PRs and retry",
					rotate.ErrRequestAccessQuotaExceeded, openCount, contributorHandle,
					maxOpenRequestAccessPRs)
				r.PrintErrorClass("general-error", err.Error(),
					"close stale request-access PRs for your GitHub identity and retry")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Build the requests/<handle>.yaml payload.
			now := time.Now().UTC().Format(time.RFC3339)
			yamlContent := buildRequestAccessYAML(contributorHandle, agePubkey, justification, now)

			// Verify the YAML is decodable before pushing (early validation).
			if _, decodeErr := rotate.DecodeRequestAccessYAML([]byte(yamlContent)); decodeErr != nil {
				r.PrintErrorClass("general-error", decodeErr.Error(),
					"check that --key is a valid age1 public key and --justification is valid UTF-8")
				return &exitError{code: render.ExitGeneralError, cause: decodeErr}
			}

			// Check for an existing open PR for this handle (idempotency).
			existingPRURL, existingErr := findExistingRequestAccessPR(ctx, regClient, owner, repo, contributorHandle)
			if existingErr != nil {
				_, _ = fmt.Fprintf(r.Err,
					"warning: could not check for existing PR: %v — proceeding\n", existingErr)
			} else if existingPRURL != "" {
				err := fmt.Errorf(
					"%w: an open request-access PR for %q already exists: %s — "+
						"close it before opening a new one",
					rotate.ErrRequestAccessQuotaExceeded, contributorHandle, existingPRURL)
				r.PrintErrorClass("general-error", err.Error(),
					"close the existing request-access PR before opening a new one")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Determine fork coordinates.
			forkOwner, forkErr := resolveForkOwner(ctx, regClient, owner, repo, contributorHandle)
			if forkErr != nil {
				err := fmt.Errorf(
					"cannot determine fork for %s/%s — "+
						"fork the registry first: gh repo fork %s/%s --clone=false: %w",
					owner, repo, owner, repo, forkErr)
				r.PrintErrorClass("general-error", err.Error(),
					"create a fork first: gh repo fork "+owner+"/"+repo+" --clone=false")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Resolve the fork's default branch (HEAD).
			baseSHA, baseBranchName, branchErr := resolveForkBaseBranch(ctx, regClient, forkOwner, repo)
			if branchErr != nil {
				err := fmt.Errorf("cannot resolve fork base branch: %w", branchErr)
				r.PrintErrorClass("general-error", err.Error(),
					"ensure your fork exists and is accessible")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Create a branch on the fork for the request.
			branchName := fmt.Sprintf("byreis/request-access-%s-%d", contributorHandle, time.Now().Unix())
			if createBranchErr := createForkBranch(ctx, regClient, forkOwner, repo, branchName, baseSHA); createBranchErr != nil {
				err := fmt.Errorf("creating request-access branch: %w", createBranchErr)
				r.PrintErrorClass("general-error", err.Error(),
					"check fork permissions and try again")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Commit the requests/<handle>.yaml file to the fork branch.
			filePath := "requests/" + contributorHandle + ".yaml"
			commitMsg := "request-access: open access request for " + contributorHandle
			if commitErr := commitFileToFork(ctx, regClient, forkOwner, repo,
				branchName, filePath, []byte(yamlContent), commitMsg); commitErr != nil {
				err := fmt.Errorf("committing request-access file: %w", commitErr)
				r.PrintErrorClass("general-error", err.Error(),
					"check fork permissions and try again")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			// Open the PR against the upstream registry repo.
			headRef := forkOwner + ":" + branchName
			prTitle := "request-access: open access request for " + contributorHandle
			prBody := buildRequestAccessPRBody(contributorHandle)

			pr, prErr := openRequestAccessPR(ctx, regClient, owner, repo,
				headRef, baseBranchName, prTitle, prBody)
			if prErr != nil {
				err := fmt.Errorf("opening request-access PR: %w", prErr)
				r.PrintErrorClass("general-error", err.Error(),
					"check registry access and retry; see `byreis doctor` for diagnostics")
				return &exitError{code: render.ExitGeneralError, cause: err}
			}

			if *jsonFlag {
				_ = render.EncodeJSON(r.Out, map[string]any{
					"pr_url":    pr.GetHTMLURL(),
					"pr_number": pr.GetNumber(),
					"handle":    contributorHandle,
					"registry":  reg,
				})
				return nil
			}
			_, _ = fmt.Fprintf(r.Out,
				"request-access PR opened: %s\n"+
					"An admin can absorb it with: byreis rotate --add --from-request %s#%d\n",
				pr.GetHTMLURL(), reg, pr.GetNumber())
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

// maxOpenRequestAccessPRs is the client-side open-PR quota per contributor identity.
const maxOpenRequestAccessPRs = 5

// buildRequestAccessYAML returns the canonical `requests/<handle>.yaml` payload.
// The commit-message template is fixed: no operator-controlled body.
func buildRequestAccessYAML(handle, agePubkey, justification, requestedAt string) string {
	var sb strings.Builder
	sb.WriteString("schema_version: byreis.request_access.v1\n")
	sb.WriteString("github_handle: ")
	sb.WriteString(handle)
	sb.WriteByte('\n')
	sb.WriteString("age_pubkey: ")
	sb.WriteString(agePubkey)
	sb.WriteByte('\n')
	// Justification: YAML-quote to handle special characters.
	sb.WriteString("justification: ")
	sb.WriteString(yamlQuoteScalar(justification))
	sb.WriteByte('\n')
	sb.WriteString("requested_at: ")
	sb.WriteString(requestedAt)
	sb.WriteByte('\n')
	return sb.String()
}

// buildRequestAccessPRBody returns a minimal PR body. Operator-controlled
// text is intentionally absent from the PR body; the YAML is the only
// structured trust input.
func buildRequestAccessPRBody(handle string) string {
	return fmt.Sprintf(
		"Access request from contributor `%s`.\n\n"+
			"An admin can absorb this PR with:\n"+
			"```\nbyreis rotate --add --from-request <registry>#<pr-number>\n```\n",
		handle)
}

// yamlQuoteScalar wraps s in YAML double-quote style, escaping only characters
// that YAML requires escaping inside double quotes.
func yamlQuoteScalar(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// normaliseRegistryArg strips common GitHub URL prefixes so that both
// "https://github.com/org/repo" and "org/repo" resolve to "org/repo".
func normaliseRegistryArg(reg string) string {
	reg = strings.TrimSuffix(reg, ".git")
	reg = strings.TrimPrefix(reg, "https://github.com/")
	reg = strings.TrimPrefix(reg, "git@github.com:")
	return reg
}

// githubTokenContrib reads the contributor's GitHub token from env, matching
// the v0.1-shipped auth source (same as submit). No new keychain credential.
func githubTokenContrib() string {
	if v := os.Getenv("BYREIS_GITHUB_TOKEN"); v != "" {
		return v
	}
	return os.Getenv("GH_TOKEN")
}

// resolveAuthenticatedGitHubLogin returns the GitHub login of the authenticated
// user (the bearer-token identity). Called when --handle is not supplied.
func resolveAuthenticatedGitHubLogin(ctx context.Context, client *ghsdk.Client) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("resolveAuthenticatedGitHubLogin cancelled: %w", err)
	}
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return "", fmt.Errorf(
			"fetching authenticated GitHub user: %w — "+
				"check your GH_TOKEN or BYREIS_GITHUB_TOKEN", err)
	}
	login := user.GetLogin()
	if login == "" {
		return "", fmt.Errorf(
			"GitHub API returned an empty login for the authenticated user — " +
				"check your token scope (needs at least read:user)")
	}
	return login, nil
}

// findExistingRequestAccessPR returns the HTML URL of an open request-access PR
// opened by contributorHandle, or "" when none exists. It paginates through all
// open PRs for the registry repo so that registries with many open PRs do not
// silently miss an existing request from the contributor.
func findExistingRequestAccessPR(
	ctx context.Context,
	client *ghsdk.Client,
	owner, repo, handle string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("findExistingRequestAccessPR cancelled: %w", err)
	}

	opts := &ghsdk.PullRequestListOptions{
		State:       "open",
		ListOptions: ghsdk.ListOptions{PerPage: 100},
	}
	for {
		prs, resp, err := client.PullRequests.List(ctx, owner, repo, opts)
		if err != nil {
			return "", fmt.Errorf("listing PRs for %s/%s: %w", owner, repo, err)
		}
		for _, pr := range prs {
			if pr.GetUser() == nil {
				continue
			}
			if strings.ToLower(pr.GetUser().GetLogin()) != handle {
				continue
			}
			// Check if the head branch indicates a request-access PR.
			if pr.GetHead() != nil &&
				strings.HasPrefix(pr.GetHead().GetRef(), "byreis/request-access-") {
				return pr.GetHTMLURL(), nil
			}
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return "", nil
}

// resolveForkOwner returns the login of the contributor's fork of owner/repo,
// or an error if no fork exists. It uses the GitHub forks endpoint to find the
// contributor's fork.
func resolveForkOwner(
	ctx context.Context,
	client *ghsdk.Client,
	owner, repo, handle string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("resolveForkOwner cancelled: %w", err)
	}

	opts := &ghsdk.RepositoryListForksOptions{
		ListOptions: ghsdk.ListOptions{PerPage: 100},
	}
	forks, _, err := client.Repositories.ListForks(ctx, owner, repo, opts)
	if err != nil {
		return "", fmt.Errorf("listing forks for %s/%s: %w", owner, repo, err)
	}
	for _, f := range forks {
		if f.GetOwner() == nil {
			continue
		}
		if strings.EqualFold(f.GetOwner().GetLogin(), handle) {
			return f.GetOwner().GetLogin(), nil
		}
	}
	return "", fmt.Errorf(
		"no fork of %s/%s found for contributor %q — "+
			"create a fork first: gh repo fork %s/%s --clone=false",
		owner, repo, handle, owner, repo)
}

// resolveForkBaseBranch returns the default branch name and its HEAD SHA for
// the contributor's fork. Used as the base for the request-access branch.
func resolveForkBaseBranch(
	ctx context.Context,
	client *ghsdk.Client,
	forkOwner, repo string,
) (sha, branch string, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", "", fmt.Errorf("resolveForkBaseBranch cancelled: %w", ctxErr)
	}

	forkRepo, _, err := client.Repositories.Get(ctx, forkOwner, repo)
	if err != nil {
		return "", "", fmt.Errorf(
			"fetching fork %s/%s metadata: %w", forkOwner, repo, err)
	}

	defaultBranch := forkRepo.GetDefaultBranch()
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	ref, _, err := client.Git.GetRef(ctx, forkOwner, repo, "refs/heads/"+defaultBranch)
	if err != nil {
		return "", "", fmt.Errorf(
			"resolving HEAD for %s/%s@%s: %w", forkOwner, repo, defaultBranch, err)
	}
	if ref.GetObject() == nil {
		return "", "", fmt.Errorf(
			"fork %s/%s ref %q has no object", forkOwner, repo, defaultBranch)
	}
	return ref.GetObject().GetSHA(), defaultBranch, nil
}

// createForkBranch creates a new branch on the contributor's fork.
func createForkBranch(
	ctx context.Context,
	client *ghsdk.Client,
	forkOwner, repo, branchName, baseSHA string,
) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("createForkBranch cancelled: %w", ctxErr)
	}

	fullRef := "refs/heads/" + branchName
	newRef := &ghsdk.Reference{
		Ref:    &fullRef,
		Object: &ghsdk.GitObject{SHA: &baseSHA},
	}
	_, _, err := client.Git.CreateRef(ctx, forkOwner, repo, newRef)
	if err != nil {
		return fmt.Errorf("creating branch %q on %s/%s: %w", branchName, forkOwner, repo, err)
	}
	return nil
}

// commitFileToFork commits content to path on the given fork branch.
func commitFileToFork(
	ctx context.Context,
	client *ghsdk.Client,
	forkOwner, repo, branchName, filePath string,
	content []byte,
	message string,
) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("commitFileToFork cancelled: %w", ctxErr)
	}

	opts := &ghsdk.RepositoryContentFileOptions{
		Message: &message,
		Content: content,
		Branch:  &branchName,
	}
	_, _, err := client.Repositories.CreateFile(ctx, forkOwner, repo, filePath, opts)
	if err != nil {
		return fmt.Errorf(
			"committing %q to %s/%s@%s: %w", filePath, forkOwner, repo, branchName, err)
	}
	return nil
}

// openRequestAccessPR opens a PR from headRef (fork:branch) against the registry base.
func openRequestAccessPR(
	ctx context.Context,
	client *ghsdk.Client,
	owner, repo, headRef, baseBranch, title, body string,
) (*ghsdk.PullRequest, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("openRequestAccessPR cancelled: %w", ctxErr)
	}

	newPR := &ghsdk.NewPullRequest{
		Title: &title,
		Head:  &headRef,
		Base:  &baseBranch,
		Body:  &body,
	}
	pr, _, err := client.PullRequests.Create(ctx, owner, repo, newPR)
	if err != nil {
		return nil, fmt.Errorf(
			"creating PR in %s/%s (head=%q base=%q): %w",
			owner, repo, headRef, baseBranch, err)
	}
	return pr, nil
}

// listOpenRequestAccessPRsForContributor counts open PRs authored by authorLogin
// that have a head branch named byreis/request-access-*. It uses the provided
// GitHub client directly rather than the internal adapter so that this file
// does not import an internal adapter package (Clean Architecture boundary).
func listOpenRequestAccessPRsForContributor(
	ctx context.Context,
	client *ghsdk.Client,
	owner, repo, authorLogin string,
) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("listOpenRequestAccessPRsForContributor cancelled: %w", err)
	}

	var count int
	opts := &ghsdk.PullRequestListOptions{
		State:       "open",
		ListOptions: ghsdk.ListOptions{PerPage: 100},
	}
	for {
		prs, resp, err := client.PullRequests.List(ctx, owner, repo, opts)
		if err != nil {
			return 0, fmt.Errorf("listing open PRs for %s/%s: %w", owner, repo, err)
		}
		for _, pr := range prs {
			if pr.GetUser() == nil {
				continue
			}
			if !strings.EqualFold(pr.GetUser().GetLogin(), authorLogin) {
				continue
			}
			if pr.GetHead() != nil &&
				strings.HasPrefix(pr.GetHead().GetRef(), "byreis/request-access-") {
				count++
			}
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return count, nil
}
