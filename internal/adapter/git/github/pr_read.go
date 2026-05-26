package github

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	ghsdk "github.com/google/go-github/v72/github"

	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// requestAccessPathRE is the allowlist for the path of the `requests/<handle>.yaml`
// file inside the registry repo. The handle must start with an alphanumeric,
// consist of alphanumeric and hyphen characters (1–39 chars), and end with
// `.yaml`. The no-consecutive-hyphen and no-trailing-hyphen rules are enforced
// structurally in validateRequestAccessPath rather than via look-ahead (RE2
// does not support Perl look-ahead syntax).
//
// This regex is the structural path-scope gate for the requests/ directory.
// An adapter that passes a path outside this namespace provides no upload surface
// to the registry tree beyond the designated requests/ directory.
var requestAccessPathRE = regexp.MustCompile(
	`^requests/[A-Za-z0-9][A-Za-z0-9\-]{0,38}\.yaml$`,
)

// RequestAccessReader implements rotate.RequestAccessReader for the GitHub
// adapter. All methods require context.Context as their first parameter; every
// API call honours the supplied deadline and cancellation.
//
// The struct carries only a *github.Client and the registry repo coordinates
// (owner, repo). It is explicitly NOT the project-repo Provider — the registry
// repo has distinct owner/repo coordinates sourced from BYREIS_REGISTRY at
// composition time.
//
// Closed-world boundary: this file contains ONLY read methods. The write
// methods (CreateFile / UpdateFile / DeleteFile / CreateRef / etc.) are
// deliberately absent; a code reviewer can confirm by diffing the method set of
// this type against the write-capable Provider.
type RequestAccessReader struct {
	client *ghsdk.Client
	owner  string
	repo   string
}

// NewRequestAccessReader constructs a RequestAccessReader bound to the given
// registry repo. registryProject must be "owner/repo". The supplied *ghsdk.Client
// is used verbatim; callers are responsible for token injection (ADMIN-mode
// GitHub token from the same auth.GitHubAuth source as the submit path).
//
// This constructor returns (*RequestAccessReader, error) so the composition root
// can fail closed on a malformed project string without panicking.
func NewRequestAccessReader(client *ghsdk.Client, registryProject string) (*RequestAccessReader, error) {
	if client == nil {
		return nil, fmt.Errorf(
			"NewRequestAccessReader: github client must not be nil")
	}
	parts := strings.SplitN(registryProject, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf(
			"%w: NewRequestAccessReader: registry project %q is not in owner/repo form",
			coregit.ErrInvalidProject, registryProject)
	}
	if strings.Contains(parts[1], "/") {
		return nil, fmt.Errorf(
			"%w: NewRequestAccessReader: registry project repo part %q must not contain '/'",
			coregit.ErrInvalidProject, registryProject)
	}
	return &RequestAccessReader{
		client: client,
		owner:  parts[0],
		repo:   parts[1],
	}, nil
}

// Compile-time assertion: RequestAccessReader satisfies the consumer-defined port.
var _ rotate.RequestAccessReader = (*RequestAccessReader)(nil)

// FetchRequestAccessYAML reads `requests/<handle>.yaml` from the contributor's
// request-access PR. It returns the parsed YAML payload and the canonical PR
// metadata projection.
//
// Implementation enforces the following failure modes at the adapter boundary
// (defense-in-depth; the use-case ValidateRequestAccess layer also checks them):
//
//  1. PR title spoof — AuthorLogin is read exclusively from pull_request.user.login.
//  2. Base-ref / force-push race — HeadSHA is pinned at the GetPR call.
//  3. Force-push race — same as (2); the executor re-checks via FetchPRHeadSHA.
//  4. Display-name vs login — github_handle is compared byte-equal (lowercase)
//     against pr.User.Login by the validator; this adapter populates AuthorLogin
//     from pr.User.Login only.
//  5. Deleted / renamed account — pr.User.Login = "ghost" or "" is surfaced as-is;
//     the validator refuses.
//  6. Fork-PR vs branch-PR — YAML is fetched from pr.Head.Repo.FullName at the
//     pinned HeadSHA; HeadRepoOwnerLogin is populated for the validator.
//  7. Draft PR — IsDraft is populated from the typed field; the validator refuses.
//  8. Closed / re-opened PR — State is populated from the typed field; the
//     validator refuses on state != "open".
//  9. Bot identity — AuthorType is populated from pr.User.Type; the validator
//     refuses on AuthorType != "User".
func (r *RequestAccessReader) FetchRequestAccessYAML(
	ctx context.Context, prRef coregit.PRRef,
) (rotate.RequestAccessFile, rotate.PRMetadata, error) {
	if err := ctx.Err(); err != nil {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			fmt.Errorf("FetchRequestAccessYAML cancelled: %w", err)
	}

	// Step 1: fetch canonical PR metadata. pin HeadSHA at this call.
	pr, _, err := r.client.PullRequests.Get(ctx, r.owner, r.repo, prRef.Number)
	if err != nil {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			r.wrapReadErr("FetchRequestAccessYAML/GetPR", err)
	}

	// Map GitHub PR fields to domain types. No SDK type leaks past this boundary.
	meta := rotate.PRMetadata{
		AuthorLogin:        strings.ToLower(safeLogin(pr.GetUser())),
		State:              pr.GetState(),
		IsDraft:            pr.GetDraft(),
		IsMerged:           pr.GetMerged(),
		HeadSHA:            pr.GetHead().GetSHA(),
		HeadRepoOwnerLogin: strings.ToLower(headRepoOwnerLogin(pr)),
		AuthorType:         safeUserType(pr.GetUser()),
	}

	// Step 2: refuse non-User PR openers before fetching file contents (fail closed early).
	if meta.AuthorType != "" && meta.AuthorType != "User" {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			fmt.Errorf("%w: PR opener is of type %q (only human User accounts may be absorbed)",
				rotate.ErrRequestAccessIdentityMismatch, meta.AuthorType)
	}

	// Step 3: enumerate files changed in the PR and validate path scope.
	files, err := r.listPRFiles(ctx, prRef.Number)
	if err != nil {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			r.wrapReadErr("FetchRequestAccessYAML/ListFiles", err)
	}
	if len(files) == 0 {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			fmt.Errorf("%w: PR changes no files — expected exactly one requests/<handle>.yaml",
				rotate.ErrRequestAccessPRFilePathInvalid)
	}
	if len(files) > 1 {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			fmt.Errorf("%w: PR changes %d files — expected exactly one requests/<handle>.yaml",
				rotate.ErrRequestAccessPRFilePathInvalid, len(files))
	}

	filePath := files[0]
	if !requestAccessPathRE.MatchString(filePath) || !validateRequestAccessPath(filePath) {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			fmt.Errorf("%w: PR file path %q does not match requests/<handle>.yaml namespace",
				rotate.ErrRequestAccessPRFilePathInvalid, filePath)
	}

	// Step 4: fetch file contents at the pinned PR HEAD SHA. Sourced from the
	// fork's repo so that fork PRs are handled correctly.
	headRepo := headRepoFullName(pr)
	if headRepo == "" {
		headRepo = r.owner + "/" + r.repo
	}
	rawBytes, err := r.fetchFileAtRef(ctx, headRepo, filePath, meta.HeadSHA)
	if err != nil {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			fmt.Errorf("FetchRequestAccessYAML: fetching %q at PR HEAD %q: %w",
				filePath, meta.HeadSHA, err)
	}

	// Step 5: strict-decode the YAML via the domain decoder.
	file, decodeErr := rotate.DecodeRequestAccessYAML(rawBytes)
	if decodeErr != nil {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			fmt.Errorf("FetchRequestAccessYAML: %w", decodeErr)
	}

	// Step 6: enumerate commits on the PR and populate Commits slice.
	commits, err := r.listPRCommits(ctx, prRef.Number)
	if err != nil {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			r.wrapReadErr("FetchRequestAccessYAML/ListCommits", err)
	}
	meta.Commits = commits

	return file, meta, nil
}

// FetchPRHeadSHA returns the current HEAD commit SHA and the fork-repo owner
// login for the given PR. Both values are sourced from a single PullRequests.Get
// call and are used together at execute time to detect both force-push races
// (SHA drift) and fork-ownership transfers (ownerLogin drift) between the
// operator's plan review and Phase-1 start.
func (r *RequestAccessReader) FetchPRHeadSHA(
	ctx context.Context, prRef coregit.PRRef,
) (sha string, ownerLogin string, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", "", fmt.Errorf("FetchPRHeadSHA cancelled: %w", ctxErr)
	}

	pr, _, apiErr := r.client.PullRequests.Get(ctx, r.owner, r.repo, prRef.Number)
	if apiErr != nil {
		return "", "", r.wrapReadErr("FetchPRHeadSHA/GetPR", apiErr)
	}
	sha = pr.GetHead().GetSHA()
	if sha == "" {
		return "", "", fmt.Errorf(
			"FetchPRHeadSHA: GitHub returned empty head SHA for PR %s/%s#%d — "+
				"the PR may have been deleted or is in an inconsistent state",
			r.owner, r.repo, prRef.Number)
	}
	ownerLogin = strings.ToLower(headRepoOwnerLogin(pr))
	return sha, ownerLogin, nil
}

// maxOpenRequestSummaries is the result-cap for the admin-side display list.
// When the registry has more open PRs than this cap, ListOpenRequestsBounded
// returns exactly maxOpenRequestSummaries entries and sets truncated=true so
// the caller can render a visible "showing N of many" affordance.
const maxOpenRequestSummaries = 200

// maxOpenRequestPages is the page-walk ceiling for ListOpenRequestsBounded.
// At 100 items per page this caps the scan at 500 PRs inspected; truncation
// fires at whichever limit is reached first (result cap or page ceiling).
const maxOpenRequestPages = 5

// ListOpenRequestsBounded is the bounded variant of ListOpenRequests. It walks
// at most maxOpenRequestPages pages (capping the API scan) and returns at most
// maxOpenRequestSummaries summaries. When either bound is reached before all
// pages are consumed, truncated is set to true and the caller MUST surface a
// visible truncation affordance — silent drop is forbidden.
//
// An empty result with truncated=false is the valid "nothing to triage" outcome.
func (r *RequestAccessReader) ListOpenRequestsBounded(
	ctx context.Context,
) (summaries []rotate.OpenRequestSummary, truncated bool, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, false, fmt.Errorf("ListOpenRequestsBounded cancelled: %w", ctxErr)
	}

	var out []rotate.OpenRequestSummary
	opts := &ghsdk.PullRequestListOptions{
		State:       "open",
		ListOptions: ghsdk.ListOptions{PerPage: 100},
	}
	for page := 0; ; page++ {
		if page >= maxOpenRequestPages {
			// Page ceiling reached without exhausting all pages: signal truncation.
			return out, true, nil
		}

		prs, resp, listErr := r.client.PullRequests.List(ctx, r.owner, r.repo, opts)
		if listErr != nil {
			return nil, false, r.wrapReadErr("ListOpenRequestsBounded/List", listErr)
		}
		for _, pr := range prs {
			if len(out) >= maxOpenRequestSummaries {
				// Result cap reached: signal truncation.
				return out, true, nil
			}
			var authorLogin string
			if pr.GetUser() != nil {
				authorLogin = strings.ToLower(pr.GetUser().GetLogin())
			}
			out = append(out, rotate.OpenRequestSummary{
				PRRef: coregit.PRRef{
					Project: r.owner + "/" + r.repo,
					Number:  pr.GetNumber(),
				},
				AuthorLogin: authorLogin,
				Title:       pr.GetTitle(),
				CreatedAt:   pr.GetCreatedAt().Format(time.RFC3339),
				HeadSHA:     pr.GetHead().GetSHA(),
			})
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return out, false, nil
}

// ListOpenRequests returns the read-only triage projection of every open PR on
// the registry repo. It performs no trust decision and fetches no per-PR fork
// content: each summary carries only the GitHub-canonical metadata available on
// the list response (PR number, author login, title, created-at, head SHA). An
// empty registry yields an empty slice and a nil error.
//
// This method is a thin wrapper over ListOpenRequestsBounded; callers that need
// to surface truncation should call ListOpenRequestsBounded directly.
//
// The richer per-PR validation (path-scope, HEAD-SHA pinning, the PR-author
// state machine) is intentionally NOT performed here; that is the absorb-time
// concern of FetchRequestAccessYAML / FetchPRHeadSHA, which the `--from-request`
// lift re-runs against the chosen PR.
func (r *RequestAccessReader) ListOpenRequests(
	ctx context.Context,
) ([]rotate.OpenRequestSummary, error) {
	summaries, _, err := r.ListOpenRequestsBounded(ctx)
	return summaries, err
}

// ─── project-repo submission reader ─────────────────────────────────────────

// submissionBranchPrefixes is the set of head-branch prefixes that identify
// a PR as a byreis submission. These are the same prefixes used by the submit
// use-case when naming submission branches (byreis/add-*, byreis/replace-*,
// byreis/bulk-*). A PR whose head branch matches any of these prefixes is a
// submission PR; all other PRs (access-request branches, feature branches,
// etc.) are excluded.
var submissionBranchPrefixes = []string{
	"byreis/add-",
	"byreis/replace-",
	"byreis/bulk-",
}

// isSubmissionBranch returns true when the given branch name starts with one of
// the submission branch prefixes.
func isSubmissionBranch(branch string) bool {
	for _, prefix := range submissionBranchPrefixes {
		if strings.HasPrefix(branch, prefix) {
			return true
		}
	}
	return false
}

// ProjectSubmissionsReader lists open submission PRs on the project secrets
// repository. It is the project-repo counterpart of RequestAccessReader (which
// reads the registry repo). The two types are intentionally separate: they are
// bound to different repos, carry different scopes, and never share a client
// instance at the composition root.
//
// Closed-world boundary: this type exposes ONLY read methods. No write methods
// (CreateFile, CreateRef, CloseWithComment) are present.
type ProjectSubmissionsReader struct {
	client *ghsdk.Client
	owner  string
	repo   string
}

// NewProjectSubmissionsReader constructs a ProjectSubmissionsReader bound to
// the given project secrets repository. projectRepo must be "owner/repo".
// Returns an error when the client is nil or the project string is malformed.
func NewProjectSubmissionsReader(client *ghsdk.Client, projectRepo string) (*ProjectSubmissionsReader, error) {
	if client == nil {
		return nil, fmt.Errorf(
			"NewProjectSubmissionsReader: github client must not be nil")
	}
	parts := strings.SplitN(projectRepo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf(
			"%w: NewProjectSubmissionsReader: project repo %q is not in owner/repo form",
			coregit.ErrInvalidProject, projectRepo)
	}
	if strings.Contains(parts[1], "/") {
		return nil, fmt.Errorf(
			"%w: NewProjectSubmissionsReader: project repo part %q must not contain '/'",
			coregit.ErrInvalidProject, projectRepo)
	}
	return &ProjectSubmissionsReader{
		client: client,
		owner:  parts[0],
		repo:   parts[1],
	}, nil
}

// ListSubmissionsBounded lists open submission PRs on the project repo,
// filtering to head branches that match the byreis submission prefix set
// (byreis/add-*, byreis/replace-*, byreis/bulk-*). It mirrors
// ListOpenRequestsBounded in shape: at most maxOpenRequestPages pages are
// walked, at most maxOpenRequestSummaries summaries are returned, and when
// either bound is reached before all pages are consumed, truncated is set to
// true so the caller MUST surface a visible truncation affordance.
//
// An empty result with truncated=false is the valid "no pending submissions"
// outcome. All context cancellations and deadlines are honored.
//
// SDK types are mapped to the existing rotate.OpenRequestSummary domain type at
// the boundary; no SDK field leaks into the returned slice.
func (r *ProjectSubmissionsReader) ListSubmissionsBounded(
	ctx context.Context,
) (summaries []rotate.OpenRequestSummary, truncated bool, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, false, fmt.Errorf("ListSubmissionsBounded cancelled: %w", ctxErr)
	}

	var out []rotate.OpenRequestSummary
	opts := &ghsdk.PullRequestListOptions{
		State:       "open",
		ListOptions: ghsdk.ListOptions{PerPage: 100},
	}
	for page := 0; ; page++ {
		if page >= maxOpenRequestPages {
			return out, true, nil
		}

		prs, resp, listErr := r.client.PullRequests.List(ctx, r.owner, r.repo, opts)
		if listErr != nil {
			return nil, false, r.wrapReadErr("ListSubmissionsBounded/List", listErr)
		}
		for _, pr := range prs {
			branchName := pr.GetHead().GetRef()
			if !isSubmissionBranch(branchName) {
				continue
			}
			if len(out) >= maxOpenRequestSummaries {
				return out, true, nil
			}
			var authorLogin string
			if pr.GetUser() != nil {
				authorLogin = strings.ToLower(pr.GetUser().GetLogin())
			}
			out = append(out, rotate.OpenRequestSummary{
				PRRef: coregit.PRRef{
					Project: r.owner + "/" + r.repo,
					Number:  pr.GetNumber(),
				},
				AuthorLogin: authorLogin,
				Title:       pr.GetTitle(),
				CreatedAt:   pr.GetCreatedAt().Format(time.RFC3339),
				HeadSHA:     pr.GetHead().GetSHA(),
			})
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return out, false, nil
}

// wrapReadErr maps GitHub API errors to domain errors with actionable hints for
// the project-repo reader. This is the project-repo counterpart of
// RequestAccessReader.wrapReadErr; both use the same error-hint vocabulary.
func (r *ProjectSubmissionsReader) wrapReadErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var ghErr *ghsdk.ErrorResponse
	if isErrorResponse(err, &ghErr) {
		switch ghErr.Response.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf(
				"GitHub auth expired for %s/%s — run `byreis auth login` to re-authenticate: %w",
				r.owner, r.repo, err)
		case http.StatusForbidden:
			return fmt.Errorf(
				"GitHub access denied for %s/%s — check repo permissions and run `byreis auth login` if expired: %w",
				r.owner, r.repo, err)
		case http.StatusNotFound:
			return fmt.Errorf(
				"GitHub resource not found in %s/%s — check the PR number and project name: %w",
				r.owner, r.repo, err)
		}
	}
	return fmt.Errorf("GitHub API error in %q for %s/%s: %w", op, r.owner, r.repo, err)
}

// ─── internal helpers ────────────────────────────────────────────────────────

// listPRFiles returns the file paths changed in the given PR (filenames only,
// not diff hunks). At most 100 files are fetched (GitHub's page limit); the
// caller enforces the single-file constraint.
func (r *RequestAccessReader) listPRFiles(ctx context.Context, prNumber int) ([]string, error) {
	opts := &ghsdk.ListOptions{PerPage: 100}
	files, _, err := r.client.PullRequests.ListFiles(ctx, r.owner, r.repo, prNumber, opts)
	if err != nil {
		return nil, r.wrapReadErr("ListPRFiles", err)
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		if f.GetFilename() != "" {
			out = append(out, f.GetFilename())
		}
	}
	return out, nil
}

// listPRCommits returns a []rotate.CommitInfo for all commits in the given PR.
// The adapter maps GitHub's per-commit author login (commit.Author.Login) to
// CommitInfo.AuthorLogin and the full commit message (commit.Commit.Message) to
// CommitInfo.Body. Both fields come from the existing ListCommits response; no
// extra HTTP call is needed.
func (r *RequestAccessReader) listPRCommits(ctx context.Context, prNumber int) ([]rotate.CommitInfo, error) {
	opts := &ghsdk.ListOptions{PerPage: 100}
	ghCommits, _, err := r.client.PullRequests.ListCommits(ctx, r.owner, r.repo, prNumber, opts)
	if err != nil {
		return nil, r.wrapReadErr("ListPRCommits", err)
	}
	out := make([]rotate.CommitInfo, 0, len(ghCommits))
	for _, c := range ghCommits {
		sha := c.GetSHA()
		var authorLogin string
		if c.Author != nil {
			authorLogin = strings.ToLower(c.Author.GetLogin())
		}
		body := c.GetCommit().GetMessage()
		out = append(out, rotate.CommitInfo{
			SHA:         sha,
			AuthorLogin: authorLogin,
			Body:        body,
		})
	}
	return out, nil
}

// fetchFileAtRef fetches the raw bytes of path at ref from the given repo
// (owner/repo form). Used to read request-access YAML from the fork's tree.
func (r *RequestAccessReader) fetchFileAtRef(
	ctx context.Context, fullRepo, path, ref string,
) ([]byte, error) {
	parts := strings.SplitN(fullRepo, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("fetchFileAtRef: malformed repo %q — expected owner/repo", fullRepo)
	}
	owner, repo := parts[0], parts[1]

	fc, _, _, err := r.client.Repositories.GetContents(ctx, owner, repo, path,
		&ghsdk.RepositoryContentGetOptions{Ref: ref})
	if err != nil {
		var ghErr *ghsdk.ErrorResponse
		if isErrorResponse(err, &ghErr) && ghErr.Response != nil &&
			ghErr.Response.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf(
				"request-access file %q not found at ref %q in %q — "+
					"the contributor must push the file to the PR branch before admin absorption: %w",
				path, ref, fullRepo, rotate.ErrRequestAccessPRFilePathInvalid)
		}
		return nil, r.wrapReadErr("GetContents", err)
	}
	if fc == nil {
		return nil, fmt.Errorf("GitHub returned nil content for %q at %q", path, ref)
	}

	// GetContent decodes base64-encoded content from GitHub's Contents API.
	// The SDK's GetContent returns (string, error); the error covers unsupported
	// encoding types (e.g. the response is a directory, not a file).
	encoded, getErr := fc.GetContent()
	if getErr != nil {
		return nil, fmt.Errorf("decoding GitHub content for %q at %q: %w", path, ref, getErr)
	}
	if encoded == "" {
		return nil, fmt.Errorf("GitHub returned empty content for %q at %q", path, ref)
	}
	return []byte(encoded), nil
}

// validateRequestAccessPath returns true when the handle portion of
// `requests/<handle>.yaml` satisfies the GitHub login hyphen-position rules
// that RE2 cannot express via look-ahead: no trailing hyphen, no consecutive
// hyphens.
func validateRequestAccessPath(path string) bool {
	// Strip "requests/" prefix and ".yaml" suffix to get the handle.
	if len(path) < len("requests/x.yaml") {
		return false
	}
	handle := path[len("requests/") : len(path)-len(".yaml")]
	if len(handle) == 0 {
		return false
	}
	// No trailing hyphen.
	if handle[len(handle)-1] == '-' {
		return false
	}
	// No consecutive hyphens.
	for i := 0; i+1 < len(handle); i++ {
		if handle[i] == '-' && handle[i+1] == '-' {
			return false
		}
	}
	return true
}

// wrapReadErr maps GitHub API errors to domain errors with actionable hints.
// This is the read-only variant: it carries no write-operation sentinel.
func (r *RequestAccessReader) wrapReadErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var ghErr *ghsdk.ErrorResponse
	if isErrorResponse(err, &ghErr) {
		switch ghErr.Response.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf(
				"GitHub auth expired for %s/%s — run `byreis auth login` to re-authenticate: %w",
				r.owner, r.repo, err)
		case http.StatusForbidden:
			return fmt.Errorf(
				"GitHub access denied for %s/%s — check repo permissions and run `byreis auth login` if expired: %w",
				r.owner, r.repo, err)
		case http.StatusNotFound:
			return fmt.Errorf(
				"GitHub resource not found in %s/%s — check the PR number and project name: %w",
				r.owner, r.repo, err)
		}
	}
	return fmt.Errorf("GitHub API error in %q for %s/%s: %w", op, r.owner, r.repo, err)
}

// ─── nil-safe field accessors ────────────────────────────────────────────────

func safeLogin(u *ghsdk.User) string {
	if u == nil {
		return ""
	}
	return u.GetLogin()
}

func safeUserType(u *ghsdk.User) string {
	if u == nil {
		return ""
	}
	return u.GetType()
}

func headRepoOwnerLogin(pr *ghsdk.PullRequest) string {
	if pr == nil || pr.Head == nil || pr.Head.Repo == nil || pr.Head.Repo.Owner == nil {
		return ""
	}
	return pr.Head.Repo.Owner.GetLogin()
}

func headRepoFullName(pr *ghsdk.PullRequest) string {
	if pr == nil || pr.Head == nil || pr.Head.Repo == nil {
		return ""
	}
	return pr.Head.Repo.GetFullName()
}

func isErrorResponse(err error, target **ghsdk.ErrorResponse) bool {
	if err == nil {
		return false
	}
	var ghErr *ghsdk.ErrorResponse
	if ok := isGHErrorResponse(err, &ghErr); ok {
		*target = ghErr
		return true
	}
	return false
}

// isGHErrorResponse uses a type assertion to check for *ghsdk.ErrorResponse.
// We cannot use errors.As because go-github ErrorResponse does not implement
// the errors.As target pattern in older versions; use direct type assertion.
func isGHErrorResponse(err error, target **ghsdk.ErrorResponse) bool {
	if ghErr, ok := err.(*ghsdk.ErrorResponse); ok {
		*target = ghErr
		return true
	}
	return false
}
