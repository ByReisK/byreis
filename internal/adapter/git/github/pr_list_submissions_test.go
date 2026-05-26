package github_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ghsdk "github.com/google/go-github/v72/github"

	. "github.com/ByReisK/byreis/internal/adapter/git/github"
)

// submissionPREntry is the JSON shape that the fake GitHub server returns for
// the project-repo submissions list endpoint. It carries the head.ref so the
// adapter's branch-prefix filter can distinguish submission PRs from others.
type submissionPREntry struct {
	Number    int    `json:"number"`
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
	User      struct {
		Login string `json:"login"`
	} `json:"user"`
	Head struct {
		SHA string `json:"sha"`
		Ref string `json:"ref"`
	} `json:"head"`
}

// makeSubmissionEntry builds a submissionPREntry with a specific head branch.
func makeSubmissionEntry(number int, login, title, headRef, sha string) submissionPREntry {
	e := submissionPREntry{
		Number:    number,
		Title:     title,
		CreatedAt: fmt.Sprintf("2026-01-%02dT00:00:00Z", number%28+1),
	}
	e.User.Login = login
	e.Head.SHA = sha
	e.Head.Ref = headRef
	return e
}

// newProjectSubmissionsServer starts a fake GitHub server that serves the given
// pages of PRs on the project-repo endpoint (owner/project). It mirrors
// newListRequestsServer but uses a different path and the richer
// submissionPREntry shape that includes head.ref.
func newProjectSubmissionsServer(t *testing.T, pages [][]submissionPREntry) *ghsdk.Client {
	t.Helper()

	mux := http.NewServeMux()
	var pageCount int

	mux.HandleFunc("/api/v3/repos/owner/project/pulls",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			page := pageCount
			pageCount++
			if page >= len(pages) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, "[]")
				return
			}
			if page+1 < len(pages) {
				nextURL := fmt.Sprintf(
					"http://%s/api/v3/repos/owner/project/pulls?state=open&per_page=100&page=%d",
					r.Host, page+1)
				w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, nextURL))
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(pages[page]); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		})

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "{}")
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := ghsdk.NewClient(nil)
	client, _ = client.WithAuthToken("fake-token").WithEnterpriseURLs(
		srv.URL+"/", srv.URL+"/")
	return client
}

// newProjectSubmissionsErrorServer starts a fake GitHub server that always
// returns the given HTTP status for the project-repo pulls endpoint.
func newProjectSubmissionsErrorServer(t *testing.T, statusCode int) *ghsdk.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/owner/project/pulls",
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			_, _ = fmt.Fprintf(w, `{"message":"error","documentation_url":""}`)
		})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "{}")
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := ghsdk.NewClient(nil)
	client, _ = client.WithAuthToken("fake-token").WithEnterpriseURLs(
		srv.URL+"/", srv.URL+"/")
	return client
}

// TestListSubmissionsBounded_SubmissionBranchesIncluded verifies that PRs whose
// head branches match the submission prefix set (byreis/add-*, byreis/replace-*,
// byreis/bulk-*) are included, and non-submission branches are filtered out.
func TestListSubmissionsBounded_SubmissionBranchesIncluded(t *testing.T) {
	t.Parallel()

	pages := [][]submissionPREntry{{
		makeSubmissionEntry(1, "alice", "byreis: add DB_HOST",
			"byreis/add-DB_HOST-1748000000", "sha1"),
		makeSubmissionEntry(2, "bob", "byreis: replace API_KEY",
			"byreis/replace-API_KEY-1748000001", "sha2"),
		makeSubmissionEntry(3, "carol", "byreis: bulk 3 keys",
			"byreis/bulk-3keys-1748000002", "sha3"),
		// Access-request branch — must be filtered.
		makeSubmissionEntry(4, "dave", "add dave key",
			"requests/dave", "sha4"),
		// Arbitrary feature branch — must be filtered.
		makeSubmissionEntry(5, "eve", "feature branch",
			"feature/something", "sha5"),
	}}
	client := newProjectSubmissionsServer(t, pages)
	reader, err := NewProjectSubmissionsReader(client, "owner/project")
	if err != nil {
		t.Fatalf("NewProjectSubmissionsReader: %v", err)
	}

	summaries, truncated, err := reader.ListSubmissionsBounded(context.Background())
	if err != nil {
		t.Fatalf("ListSubmissionsBounded: %v", err)
	}
	if truncated {
		t.Error("truncated must be false for a small result set")
	}
	if len(summaries) != 3 {
		t.Fatalf("len(summaries) = %d, want 3 (only submission PRs)", len(summaries))
	}
	for i, want := range []string{
		"byreis: add DB_HOST",
		"byreis: replace API_KEY",
		"byreis: bulk 3 keys",
	} {
		if summaries[i].Title != want {
			t.Errorf("summaries[%d].Title = %q, want %q", i, summaries[i].Title, want)
		}
	}
}

// TestListSubmissionsBounded_NonSubmissionBranchesExcluded verifies that PRs
// whose head branches do not match any submission prefix are filtered out.
func TestListSubmissionsBounded_NonSubmissionBranchesExcluded(t *testing.T) {
	t.Parallel()

	pages := [][]submissionPREntry{{
		makeSubmissionEntry(1, "alice", "byreis: add KEY",
			"byreis/add-KEY-111", "s1"),
		makeSubmissionEntry(2, "bob", "request: bob",
			"requests/bob", "s2"),
		makeSubmissionEntry(3, "carol", "feature",
			"feature/something", "s3"),
		makeSubmissionEntry(4, "dave", "merge main",
			"main", "s4"),
	}}
	client := newProjectSubmissionsServer(t, pages)
	reader, _ := NewProjectSubmissionsReader(client, "owner/project")

	summaries, _, err := reader.ListSubmissionsBounded(context.Background())
	if err != nil {
		t.Fatalf("ListSubmissionsBounded: %v", err)
	}
	if len(summaries) != 1 {
		t.Errorf("len(summaries) = %d, want 1 (only byreis/add-* PR)", len(summaries))
	}
}

// TestListSubmissionsBounded_EmptyResult verifies that an empty project repo
// returns an empty (not nil) slice, truncated=false, and nil error.
func TestListSubmissionsBounded_EmptyResult(t *testing.T) {
	t.Parallel()

	client := newProjectSubmissionsServer(t, [][]submissionPREntry{{}})
	reader, _ := NewProjectSubmissionsReader(client, "owner/project")

	summaries, truncated, err := reader.ListSubmissionsBounded(context.Background())
	if err != nil {
		t.Fatalf("ListSubmissionsBounded: unexpected error: %v", err)
	}
	if truncated {
		t.Error("truncated must be false for empty result")
	}
	if len(summaries) != 0 {
		t.Errorf("len(summaries) = %d, want 0", len(summaries))
	}
}

// TestListSubmissionsBounded_BoundedAtMaxResults verifies that when the page
// walk produces more than 200 matching PRs the result is capped at 200 and
// truncated=true is set.
func TestListSubmissionsBounded_BoundedAtMaxResults(t *testing.T) {
	t.Parallel()

	// Build one page with 201 submission PRs — enough to exceed the 200 cap.
	page := make([]submissionPREntry, 201)
	for i := range page {
		page[i] = makeSubmissionEntry(i+1, "alice",
			fmt.Sprintf("byreis: add KEY%d", i+1),
			fmt.Sprintf("byreis/add-KEY%d-%d", i+1, 1748000000+i),
			fmt.Sprintf("sha%d", i+1))
	}

	client := newProjectSubmissionsServer(t, [][]submissionPREntry{page})
	reader, _ := NewProjectSubmissionsReader(client, "owner/project")

	summaries, truncated, err := reader.ListSubmissionsBounded(context.Background())
	if err != nil {
		t.Fatalf("ListSubmissionsBounded: %v", err)
	}
	if !truncated {
		t.Error("truncated must be true when result cap is reached")
	}
	if len(summaries) != 200 {
		t.Errorf("len(summaries) = %d, want exactly 200 (the cap)", len(summaries))
	}
}

// TestListSubmissionsBounded_BoundedAtMaxPages verifies that the adapter stops
// walking pages at the 5-page ceiling and sets truncated=true.
func TestListSubmissionsBounded_BoundedAtMaxPages(t *testing.T) {
	t.Parallel()

	// Build 6 pages of 10 submission PRs each; the adapter must stop at 5 pages.
	var pages [][]submissionPREntry
	prNum := 1
	for p := 0; p < 6; p++ {
		page := make([]submissionPREntry, 10)
		for i := range page {
			page[i] = makeSubmissionEntry(prNum, "alice",
				fmt.Sprintf("byreis: add K%d", prNum),
				fmt.Sprintf("byreis/add-K%d-%d", prNum, 1748000000+prNum),
				fmt.Sprintf("sha%d", prNum))
			prNum++
		}
		pages = append(pages, page)
	}

	client := newProjectSubmissionsServer(t, pages)
	reader, _ := NewProjectSubmissionsReader(client, "owner/project")

	summaries, truncated, err := reader.ListSubmissionsBounded(context.Background())
	if err != nil {
		t.Fatalf("ListSubmissionsBounded: %v", err)
	}
	if !truncated {
		t.Error("truncated must be true when page ceiling is reached")
	}
	// 5 pages × 10 PRs = 50 summaries (all match the submission prefix).
	if len(summaries) != 50 {
		t.Errorf("len(summaries) = %d, want 50 (5 pages × 10)", len(summaries))
	}
}

// TestListSubmissionsBounded_ContextCancelled verifies that a pre-cancelled
// context is detected immediately and the error wraps context.Canceled.
func TestListSubmissionsBounded_ContextCancelled(t *testing.T) {
	t.Parallel()

	client := ghsdk.NewClient(nil)
	reader, _ := NewProjectSubmissionsReader(client, "owner/project")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := reader.ListSubmissionsBounded(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled in error chain, got %v", err)
	}
}

// TestListSubmissionsBounded_AuthError verifies that a 401 from GitHub is
// wrapped with an actionable auth hint.
func TestListSubmissionsBounded_AuthError(t *testing.T) {
	t.Parallel()

	client := newProjectSubmissionsErrorServer(t, http.StatusUnauthorized)
	reader, _ := NewProjectSubmissionsReader(client, "owner/project")

	_, _, err := reader.ListSubmissionsBounded(context.Background())
	if err == nil {
		t.Fatal("expected non-nil error for 401")
	}
	if !strings.Contains(err.Error(), "byreis auth login") {
		t.Errorf("error %q should contain 'byreis auth login' hint", err.Error())
	}
}

// TestListSubmissionsBounded_NotFoundError verifies that a 404 from GitHub is
// wrapped with an actionable hint.
func TestListSubmissionsBounded_NotFoundError(t *testing.T) {
	t.Parallel()

	client := newProjectSubmissionsErrorServer(t, http.StatusNotFound)
	reader, _ := NewProjectSubmissionsReader(client, "owner/project")

	_, _, err := reader.ListSubmissionsBounded(context.Background())
	if err == nil {
		t.Fatal("expected non-nil error for 404")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q should contain 'not found' hint", err.Error())
	}
}

// TestListSubmissionsBounded_DomainTypeNoBoundaryLeak is a compile-time and
// runtime assertion: the returned summaries use rotate.OpenRequestSummary (a
// domain type) — no SDK types leak past the boundary.
func TestListSubmissionsBounded_DomainTypeNoBoundaryLeak(t *testing.T) {
	t.Parallel()

	pages := [][]submissionPREntry{{
		makeSubmissionEntry(1, "alice", "byreis: add KEY",
			"byreis/add-KEY-111", "sha1"),
	}}
	client := newProjectSubmissionsServer(t, pages)
	reader, _ := NewProjectSubmissionsReader(client, "owner/project")

	summaries, _, err := reader.ListSubmissionsBounded(context.Background())
	if err != nil {
		t.Fatalf("ListSubmissionsBounded: %v", err)
	}
	// Static compile-time assertion via field access on domain types.
	for _, s := range summaries {
		_ = s.PRRef.Project
		_ = s.PRRef.Number
		_ = s.AuthorLogin
		_ = s.Title
		_ = s.CreatedAt
		_ = s.HeadSHA
	}
}

// TestListSubmissionsBounded_PRRefProjectIsProjectRepo verifies that every
// returned summary's PRRef.Project is the project-repo "owner/repo" string.
func TestListSubmissionsBounded_PRRefProjectIsProjectRepo(t *testing.T) {
	t.Parallel()

	pages := [][]submissionPREntry{{
		makeSubmissionEntry(1, "alice", "byreis: add K1", "byreis/add-K1-111", "s1"),
		makeSubmissionEntry(2, "bob", "byreis: replace K2", "byreis/replace-K2-222", "s2"),
	}}
	client := newProjectSubmissionsServer(t, pages)
	reader, _ := NewProjectSubmissionsReader(client, "owner/project")

	summaries, _, err := reader.ListSubmissionsBounded(context.Background())
	if err != nil {
		t.Fatalf("ListSubmissionsBounded: %v", err)
	}
	for i, s := range summaries {
		if s.PRRef.Project != "owner/project" {
			t.Errorf("summaries[%d].PRRef.Project = %q, want owner/project", i, s.PRRef.Project)
		}
	}
}

// TestNewProjectSubmissionsReader_MalformedProject verifies that a malformed
// projectRepo string causes construction to return an error.
func TestNewProjectSubmissionsReader_MalformedProject(t *testing.T) {
	t.Parallel()

	client := ghsdk.NewClient(nil)
	for _, bad := range []string{"", "no-slash", "owner/"} {
		_, err := NewProjectSubmissionsReader(client, bad)
		if err == nil {
			t.Errorf("NewProjectSubmissionsReader(%q): expected error, got nil", bad)
		}
	}
}

// TestNewProjectSubmissionsReader_NilClient verifies that a nil client returns
// an error at construction time.
func TestNewProjectSubmissionsReader_NilClient(t *testing.T) {
	t.Parallel()

	_, err := NewProjectSubmissionsReader(nil, "owner/project")
	if err == nil {
		t.Error("NewProjectSubmissionsReader(nil client): expected error, got nil")
	}
}
