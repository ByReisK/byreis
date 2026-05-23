package github

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	ghsdk "github.com/google/go-github/v72/github"

	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// maxOpenRequestAccessPRs is the client-side open-PR quota per contributor identity.
// The contributor is refused if they have this many or more open request-access PRs
// against the registry repo.
const maxOpenRequestAccessPRs = 5

// maxRequestAccessPageWalk is the page-walk ceiling for the contributor-side
// correctness checks (quota count and existing-PR idempotency). These checks must
// be definitive: if the ceiling is reached without a clear answer the opener
// refuses rather than risking a duplicate PR or an under-counted quota.
const maxRequestAccessPageWalk = 5 // 5 pages × 100 per-page = up to 500 PRs scanned

// RequestAccessOpener implements rotate.RequestAccessOpener for the GitHub
// adapter. All methods require context.Context as their first parameter; every
// API call honours the supplied deadline and cancellation.
//
// The struct carries only a *github.Client and the registry repo coordinates
// (owner, repo). It uses exclusively the contributor's own GitHub token — it
// acquires no registry-write keychain credential and calls no signing primitive.
//
// Closed-world boundary: this file contains ONLY the contributor write path
// (fork → branch → commit → PR). It shares no constructor parameter with
// RegistryWriteSigner or RegistryWriteTokenStore; a code reviewer can confirm
// by inspecting NewRequestAccessOpener's parameter list.
type RequestAccessOpener struct {
	client *ghsdk.Client
	owner  string
	repo   string
}

// NewRequestAccessOpener constructs a RequestAccessOpener bound to the given
// registry repo. registryProject must be "owner/repo". The supplied *ghsdk.Client
// is used verbatim; callers are responsible for token injection (contributor's
// GH_TOKEN / BYREIS_GITHUB_TOKEN — the same source as the submit path).
//
// This constructor mirrors NewRequestAccessReader exactly: nil-client guard,
// owner/repo parse, fail-closed on malformed input.
func NewRequestAccessOpener(client *ghsdk.Client, registryProject string) (*RequestAccessOpener, error) {
	if client == nil {
		return nil, fmt.Errorf(
			"NewRequestAccessOpener: github client must not be nil")
	}
	parts := strings.SplitN(registryProject, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf(
			"%w: NewRequestAccessOpener: registry project %q is not in owner/repo form",
			coregit.ErrInvalidProject, registryProject)
	}
	if strings.Contains(parts[1], "/") {
		return nil, fmt.Errorf(
			"%w: NewRequestAccessOpener: registry project repo part %q must not contain '/'",
			coregit.ErrInvalidProject, registryProject)
	}
	return &RequestAccessOpener{
		client: client,
		owner:  parts[0],
		repo:   parts[1],
	}, nil
}

// Compile-time assertion: RequestAccessOpener satisfies the consumer-defined port.
var _ rotate.RequestAccessOpener = (*RequestAccessOpener)(nil)

// ResolveHandle returns the authenticated GitHub login for the token supplied to
// the client when in.Handle is empty. When in.Handle is already set the method
// returns it unchanged (lowercased). This lets the caller echo the handle to the
// user before beginning the write sequence.
func (o *RequestAccessOpener) ResolveHandle(
	ctx context.Context,
	in rotate.RequestAccessInput,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("ResolveHandle cancelled: %w", err)
	}

	handle := strings.ToLower(strings.TrimSpace(in.Handle))
	if handle != "" {
		return handle, nil
	}

	user, _, err := o.client.Users.Get(ctx, "")
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
	return strings.ToLower(login), nil
}

// Open opens a request-access PR on behalf of the contributor. The sequence is:
//
//  1. Resolve registry owner/repo from in.Registry.
//  2. Count open request-access PRs for the contributor (quota check); refuse
//     with ErrRequestAccessQuotaExceeded if exhausted.
//  3. Check for an existing open PR for this handle (idempotency check); refuse
//     with ErrRequestAccessQuotaExceeded if one exists.
//  4. Both checks use a bounded page-walk (maxRequestAccessPageWalk pages); if
//     the ceiling is reached without a definitive answer the method returns
//     ErrRequestAccessEnumerationBounded and refuses rather than risking a
//     duplicate or under-counted quota.
//  5. Build and validate the YAML payload (DecodeRequestAccessYAML pre-push check).
//  6. Resolve the contributor's fork, create a branch on it, commit the YAML.
//  7. Open the PR against the registry upstream.
//
// A transport or API error on any correctness-path step (quota check, idempotency
// check) causes a hard refusal — the warn-and-proceed pattern is deliberately
// absent from this implementation.
func (o *RequestAccessOpener) Open(
	ctx context.Context,
	in rotate.RequestAccessInput,
) (rotate.RequestAccessResult, error) {
	if err := ctx.Err(); err != nil {
		return rotate.RequestAccessResult{}, fmt.Errorf("Open cancelled: %w", err)
	}

	// Resolve registry owner/repo from in.Registry.
	owner, repo, err := o.parseRegistry(in.Registry)
	if err != nil {
		return rotate.RequestAccessResult{}, err
	}

	handle := strings.ToLower(strings.TrimSpace(in.Handle))
	if handle == "" {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"Open: Handle must be resolved before calling Open — call ResolveHandle first")
	}

	// Quota check: count open request-access PRs for this contributor.
	// A transport error here causes a hard refusal (fail closed).
	openCount, quotaErr := o.countOpenRequestAccessPRs(ctx, owner, repo, handle)
	if quotaErr != nil {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"quota check for %q against %s/%s failed — cannot verify open-PR count "+
				"before opening: %w", handle, owner, repo, quotaErr)
	}
	if openCount >= maxOpenRequestAccessPRs {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"%w: %d open request-access PR(s) found for %q (limit %d) — "+
				"close stale PRs and retry",
			rotate.ErrRequestAccessQuotaExceeded, openCount, handle, maxOpenRequestAccessPRs)
	}

	// Idempotency check: refuse if an open request-access PR for this handle
	// already exists. A transport error here also causes a hard refusal.
	existingURL, existingErr := o.findExistingRequestAccessPR(ctx, owner, repo, handle)
	if existingErr != nil {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"idempotency check for %q against %s/%s failed — cannot verify existing PRs "+
				"before opening: %w", handle, owner, repo, existingErr)
	}
	if existingURL != "" {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"%w: an open request-access PR for %q already exists: %s — "+
				"close it before opening a new one",
			rotate.ErrRequestAccessQuotaExceeded, handle, existingURL)
	}

	// Build and pre-validate the YAML payload.
	now := time.Now().UTC().Format(time.RFC3339)
	yamlContent := buildRequestAccessYAML(handle, in.AgePubkey, in.Justification, now)
	if _, decodeErr := rotate.DecodeRequestAccessYAML([]byte(yamlContent)); decodeErr != nil {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"request-access YAML pre-push validation failed: %w", decodeErr)
	}

	// Resolve the contributor's fork.
	forkOwner, forkErr := o.resolveForkOwner(ctx, owner, repo, handle)
	if forkErr != nil {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"cannot determine fork for %s/%s — "+
				"fork the registry first: gh repo fork %s/%s --clone=false: %w",
			owner, repo, owner, repo, forkErr)
	}

	// Resolve the fork's default branch HEAD SHA.
	baseSHA, baseBranchName, branchErr := o.resolveForkBaseBranch(ctx, forkOwner, repo)
	if branchErr != nil {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"cannot resolve fork base branch: %w", branchErr)
	}

	// Create the request-access branch on the fork.
	branchName := fmt.Sprintf("byreis/request-access-%s-%d", handle, time.Now().Unix())
	if createBranchErr := o.createForkBranch(ctx, forkOwner, repo, branchName, baseSHA); createBranchErr != nil {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"creating request-access branch: %w", createBranchErr)
	}

	// Commit the requests/<handle>.yaml file to the branch.
	filePath := "requests/" + handle + ".yaml"
	commitMsg := "request-access: open access request for " + handle
	if commitErr := o.commitFileToFork(ctx, forkOwner, repo, branchName, filePath,
		[]byte(yamlContent), commitMsg); commitErr != nil {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"committing request-access file: %w", commitErr)
	}

	// Open the PR against the upstream registry repo.
	headRef := forkOwner + ":" + branchName
	prTitle := "request-access: open access request for " + handle
	prBody := buildRequestAccessPRBody(handle)

	pr, prErr := o.openRequestAccessPR(ctx, owner, repo, headRef, baseBranchName, prTitle, prBody)
	if prErr != nil {
		return rotate.RequestAccessResult{}, fmt.Errorf(
			"opening request-access PR: %w", prErr)
	}

	return rotate.RequestAccessResult{
		PRRef: coregit.PRRef{
			Project: owner + "/" + repo,
			Number:  pr.GetNumber(),
		},
		URL: pr.GetHTMLURL(),
	}, nil
}

// ─── internal helpers ────────────────────────────────────────────────────────

// parseRegistry splits in.Registry (or falls back to o.owner/o.repo when in.Registry
// equals the struct's configured project) into owner and repo. When in.Registry is
// empty the struct's wired coordinates are used.
func (o *RequestAccessOpener) parseRegistry(registry string) (owner, repo string, err error) {
	r := registry
	if r == "" {
		return o.owner, o.repo, nil
	}
	parts := strings.SplitN(r, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf(
			"registry %q is not in owner/repo form — use owner/repo format", r)
	}
	return parts[0], parts[1], nil
}

// countOpenRequestAccessPRs counts open PRs authored by authorLogin that have a
// head branch matching "byreis/request-access-*". The scan is bounded by
// maxRequestAccessPageWalk; if the ceiling is reached without exhausting all pages
// the method returns ErrRequestAccessEnumerationBounded (wrapped) so the caller
// can fail closed.
func (o *RequestAccessOpener) countOpenRequestAccessPRs(
	ctx context.Context,
	owner, repo, authorLogin string,
) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("countOpenRequestAccessPRs cancelled: %w", err)
	}

	var count int
	opts := &ghsdk.PullRequestListOptions{
		State:       "open",
		ListOptions: ghsdk.ListOptions{PerPage: 100},
	}
	for page := 0; ; page++ {
		if page >= maxRequestAccessPageWalk {
			return 0, fmt.Errorf("%w: scanned %d page(s) of open PRs on %s/%s "+
				"without completing the quota count",
				rotate.ErrRequestAccessEnumerationBounded, page, owner, repo)
		}

		prs, resp, err := o.client.PullRequests.List(ctx, owner, repo, opts)
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

// findExistingRequestAccessPR returns the HTML URL of an open request-access PR
// opened by handle, or "" when none exists. Like countOpenRequestAccessPRs, the
// scan is bounded by maxRequestAccessPageWalk; hitting the ceiling returns
// ErrRequestAccessEnumerationBounded (fail closed).
func (o *RequestAccessOpener) findExistingRequestAccessPR(
	ctx context.Context,
	owner, repo, handle string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("findExistingRequestAccessPR cancelled: %w", err)
	}

	opts := &ghsdk.PullRequestListOptions{
		State:       "open",
		ListOptions: ghsdk.ListOptions{PerPage: 100},
	}
	for page := 0; ; page++ {
		if page >= maxRequestAccessPageWalk {
			return "", fmt.Errorf("%w: scanned %d page(s) of open PRs on %s/%s "+
				"without confirming absence of an existing request-access PR",
				rotate.ErrRequestAccessEnumerationBounded, page, owner, repo)
		}

		prs, resp, err := o.client.PullRequests.List(ctx, owner, repo, opts)
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
// or an error when no fork is found. The first page of forks is inspected; the
// contributor is expected to fork before running this command.
func (o *RequestAccessOpener) resolveForkOwner(
	ctx context.Context,
	owner, repo, handle string,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("resolveForkOwner cancelled: %w", err)
	}

	opts := &ghsdk.RepositoryListForksOptions{
		ListOptions: ghsdk.ListOptions{PerPage: 100},
	}
	forks, _, err := o.client.Repositories.ListForks(ctx, owner, repo, opts)
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
// the contributor's fork. Used as the base reference for the request-access branch.
func (o *RequestAccessOpener) resolveForkBaseBranch(
	ctx context.Context,
	forkOwner, repo string,
) (sha, branch string, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", "", fmt.Errorf("resolveForkBaseBranch cancelled: %w", ctxErr)
	}

	forkRepo, _, repoErr := o.client.Repositories.Get(ctx, forkOwner, repo)
	if repoErr != nil {
		return "", "", fmt.Errorf(
			"fetching fork %s/%s metadata: %w", forkOwner, repo, repoErr)
	}

	defaultBranch := forkRepo.GetDefaultBranch()
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	ref, _, refErr := o.client.Git.GetRef(ctx, forkOwner, repo, "refs/heads/"+defaultBranch)
	if refErr != nil {
		return "", "", fmt.Errorf(
			"resolving HEAD for %s/%s@%s: %w", forkOwner, repo, defaultBranch, refErr)
	}
	if ref.GetObject() == nil {
		return "", "", fmt.Errorf(
			"fork %s/%s ref %q has no object", forkOwner, repo, defaultBranch)
	}
	return ref.GetObject().GetSHA(), defaultBranch, nil
}

// createForkBranch creates a new branch on the contributor's fork, pointing at baseSHA.
func (o *RequestAccessOpener) createForkBranch(
	ctx context.Context,
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
	_, _, err := o.client.Git.CreateRef(ctx, forkOwner, repo, newRef)
	if err != nil {
		return fmt.Errorf("creating branch %q on %s/%s: %w", branchName, forkOwner, repo, err)
	}
	return nil
}

// commitFileToFork commits content to filePath on the given fork branch.
func (o *RequestAccessOpener) commitFileToFork(
	ctx context.Context,
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
	_, _, err := o.client.Repositories.CreateFile(ctx, forkOwner, repo, filePath, opts)
	if err != nil {
		return fmt.Errorf(
			"committing %q to %s/%s@%s: %w", filePath, forkOwner, repo, branchName, err)
	}
	return nil
}

// openRequestAccessPR opens a PR from headRef (fork:branch) against the registry base.
// The returned *ghsdk.PullRequest carries only the fields the caller needs (Number,
// HTMLURL); no SDK type leaks past the Open method boundary.
func (o *RequestAccessOpener) openRequestAccessPR(
	ctx context.Context,
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
	pr, _, err := o.client.PullRequests.Create(ctx, owner, repo, newPR)
	if err != nil {
		var ghErr *ghsdk.ErrorResponse
		if isErrorResponse(err, &ghErr) && ghErr.Response != nil {
			switch ghErr.Response.StatusCode {
			case http.StatusUnprocessableEntity:
				return nil, fmt.Errorf(
					"%w: creating PR in %s/%s (head=%q base=%q): "+
						"the registry rejected the PR (branch protection, missing requests/ "+
						"directory, or insufficient fork permission): %s",
					rotate.ErrRequestAccessRegistryRejected,
					owner, repo, headRef, baseBranch, ghErr.Message)
			case http.StatusUnauthorized:
				return nil, fmt.Errorf(
					"GitHub auth expired for %s/%s — run `byreis auth login`: %w",
					owner, repo, err)
			case http.StatusForbidden:
				return nil, fmt.Errorf(
					"GitHub access denied for %s/%s — check fork permissions: %w",
					owner, repo, err)
			}
		}
		return nil, fmt.Errorf(
			"creating PR in %s/%s (head=%q base=%q): %w",
			owner, repo, headRef, baseBranch, err)
	}
	return pr, nil
}

// ─── pure YAML/PR-body builders ─────────────────────────────────────────────

// buildRequestAccessYAML returns the canonical `requests/<handle>.yaml` payload.
// The schema is fixed; no operator-controlled field reaches the template except
// through the validated parameters.
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

// buildRequestAccessPRBody returns a minimal PR body. Operator-controlled text
// is intentionally absent; the YAML is the only structured trust input.
func buildRequestAccessPRBody(handle string) string {
	return fmt.Sprintf(
		"Access request from contributor `%s`.\n\n"+
			"An admin can absorb this PR with:\n"+
			"```\nbyreis rotate --add --from-request <registry>#<pr-number>\n```\n",
		handle)
}

// yamlQuoteScalar wraps s in YAML double-quote style, escaping only the
// characters that YAML requires escaping inside double quotes.
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
