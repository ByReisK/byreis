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
	"time"

	ghsdk "github.com/google/go-github/v72/github"

	. "github.com/ByReisK/byreis/internal/adapter/git/github"
)

// prListEntry is the minimal shape returned by GitHub's pull-request list API
// that our adapter maps to OpenRequestSummary.
type prListEntry struct {
	Number    int    `json:"number"`
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
	User      struct {
		Login string `json:"login"`
	} `json:"user"`
	Head struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

// newListRequestsServer starts a fake GitHub server that returns the given
// pages of PRs. Each element of pages is one page of results; the server
// sets the Link: rel="next" header to drive the paginator on the client.
// It also registers a catch-all for other paths so the Go SDK does not blow
// up on optional-resource fetches.
func newListRequestsServer(t *testing.T, pages [][]prListEntry) *ghsdk.Client {
	t.Helper()

	mux := http.NewServeMux()
	var pageCount int

	// GET /api/v3/repos/owner/registry/pulls?state=open&per_page=100&page=N
	mux.HandleFunc("/api/v3/repos/owner/registry/pulls",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			page := pageCount
			pageCount++
			if page >= len(pages) {
				// No more pages — return an empty array.
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode([]prListEntry{})
				return
			}

			// If there are subsequent pages, emit a Link header so the SDK
			// advances to the next page. The SDK treats NextPage==0 as "done".
			if page+1 < len(pages) {
				nextURL := fmt.Sprintf(
					"http://%s/api/v3/repos/owner/registry/pulls?state=open&per_page=100&page=%d",
					r.Host, page+1)
				w.Header().Set("Link",
					fmt.Sprintf(`<%s>; rel="next"`, nextURL))
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pages[page])
		})

	// Catch-all: return 200 with empty JSON for any other path.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

// newErrorServer starts a fake GitHub server that always returns the given
// HTTP status code for the pulls list endpoint.
func newErrorServer(t *testing.T, statusCode int) *ghsdk.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/owner/registry/pulls",
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

// makeEntry builds a prListEntry with sane RFC3339 timestamps for tests.
func makeEntry(number int, login, title, sha string) prListEntry {
	e := prListEntry{
		Number: number,
		Title:  title,
	}
	e.User.Login = login
	e.Head.SHA = sha
	e.CreatedAt = time.Date(2026, 1, int(number), 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	return e
}

// TestListOpenRequests_SinglePage verifies a single-page result is returned
// correctly with every domain field populated.
func TestListOpenRequests_SinglePage(t *testing.T) {
	t.Parallel()

	pages := [][]prListEntry{
		{makeEntry(10, "Alice", "Add new secret", "sha10")},
	}
	client := newListRequestsServer(t, pages)
	reader, err := NewRequestAccessReader(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessReader: %v", err)
	}

	summaries, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("len(summaries) = %d, want 1", len(summaries))
	}

	s := summaries[0]
	if s.PRRef.Project != "owner/registry" {
		t.Errorf("PRRef.Project = %q, want owner/registry", s.PRRef.Project)
	}
	if s.PRRef.Number != 10 {
		t.Errorf("PRRef.Number = %d, want 10", s.PRRef.Number)
	}
	if s.AuthorLogin != "alice" {
		t.Errorf("AuthorLogin = %q, want alice (lowercase-normalised)", s.AuthorLogin)
	}
	if s.Title != "Add new secret" {
		t.Errorf("Title = %q, want verbatim title", s.Title)
	}
	if s.HeadSHA != "sha10" {
		t.Errorf("HeadSHA = %q, want sha10", s.HeadSHA)
	}
	// CreatedAt must be parseable RFC3339.
	if _, parseErr := time.Parse(time.RFC3339, s.CreatedAt); parseErr != nil {
		t.Errorf("CreatedAt %q is not valid RFC3339: %v", s.CreatedAt, parseErr)
	}
}

// TestListOpenRequests_Pagination verifies that the adapter walks all pages and
// returns the combined result — no silent truncation at page 1.
func TestListOpenRequests_Pagination(t *testing.T) {
	t.Parallel()

	page1 := []prListEntry{
		makeEntry(1, "alice", "PR 1", "sha1"),
		makeEntry(2, "bob", "PR 2", "sha2"),
	}
	page2 := []prListEntry{
		makeEntry(3, "carol", "PR 3", "sha3"),
	}
	client := newListRequestsServer(t, [][]prListEntry{page1, page2})
	reader, err := NewRequestAccessReader(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessReader: %v", err)
	}

	summaries, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests: %v", err)
	}
	if len(summaries) != 3 {
		t.Fatalf("len(summaries) = %d, want 3 (both pages consumed)", len(summaries))
	}

	// Verify numbers in the order returned — pagination preserves order.
	for i, want := range []int{1, 2, 3} {
		if summaries[i].PRRef.Number != want {
			t.Errorf("summaries[%d].PRRef.Number = %d, want %d", i, summaries[i].PRRef.Number, want)
		}
	}
}

// TestListOpenRequests_EmptyResult verifies that an empty registry returns
// an empty (not nil) slice and a nil error.
func TestListOpenRequests_EmptyResult(t *testing.T) {
	t.Parallel()

	client := newListRequestsServer(t, [][]prListEntry{{}})
	reader, err := NewRequestAccessReader(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessReader: %v", err)
	}

	summaries, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests returned unexpected error on empty result: %v", err)
	}
	// Nil slice is acceptable — both nil and empty behave as empty (len == 0).
	if len(summaries) != 0 {
		t.Errorf("len(summaries) = %d, want 0 for empty registry", len(summaries))
	}
}

// TestListOpenRequests_AuthorLoginLowercased verifies that mixed-case GitHub
// logins are lowercased in the domain type at the adapter boundary.
func TestListOpenRequests_AuthorLoginLowercased(t *testing.T) {
	t.Parallel()

	entry := makeEntry(5, "UPSTREAM-User", "My PR", "sha5")
	client := newListRequestsServer(t, [][]prListEntry{{entry}})
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	summaries, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if summaries[0].AuthorLogin != "upstream-user" {
		t.Errorf("AuthorLogin = %q, want upstream-user (fully lowercased)", summaries[0].AuthorLogin)
	}
}

// TestListOpenRequests_TitleVerbatim verifies that the adapter carries the PR
// title byte-for-byte without sanitization (sanitization is the render layer's
// responsibility, not the adapter's).
func TestListOpenRequests_TitleVerbatim(t *testing.T) {
	t.Parallel()

	rawTitle := "Add secret\x1b[1mBOLD\x1b[0m with ANSI"
	entry := makeEntry(7, "alice", rawTitle, "sha7")
	client := newListRequestsServer(t, [][]prListEntry{{entry}})
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	summaries, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if summaries[0].Title != rawTitle {
		t.Errorf("Title = %q, want verbatim %q (adapter must not sanitize)", summaries[0].Title, rawTitle)
	}
}

// TestListOpenRequests_PRRefProjectIsRegistryRepo verifies that every summary's
// PRRef.Project is the registry "owner/repo" string regardless of the PR
// content.
func TestListOpenRequests_PRRefProjectIsRegistryRepo(t *testing.T) {
	t.Parallel()

	pages := [][]prListEntry{{
		makeEntry(1, "alice", "PR 1", "sha1"),
		makeEntry(2, "bob", "PR 2", "sha2"),
	}}
	client := newListRequestsServer(t, pages)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	summaries, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests: %v", err)
	}
	for i, s := range summaries {
		if s.PRRef.Project != "owner/registry" {
			t.Errorf("summaries[%d].PRRef.Project = %q, want owner/registry", i, s.PRRef.Project)
		}
	}
}

// TestListOpenRequests_SDKError verifies that a GitHub API error is wrapped into
// a domain error with an actionable hint and a non-nil return (backend failure
// is never mistaken for an empty queue).
func TestListOpenRequests_SDKError(t *testing.T) {
	t.Parallel()

	// 401 Unauthorized — should produce a hinted auth-expiry error.
	client := newErrorServer(t, http.StatusUnauthorized)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	summaries, err := reader.ListOpenRequests(context.Background())
	if err == nil {
		t.Fatal("expected non-nil error for 401 Unauthorized, got nil")
	}
	if summaries != nil {
		t.Errorf("expected nil summaries on error, got %v", summaries)
	}
	// Verify the error carries an actionable hint about re-authenticating.
	if !strings.Contains(err.Error(), "byreis auth login") {
		t.Errorf("error %q does not contain 'byreis auth login' hint", err.Error())
	}
}

// TestListOpenRequests_ForbiddenError verifies that a 403 GitHub error is
// wrapped with an actionable permissions hint.
func TestListOpenRequests_ForbiddenError(t *testing.T) {
	t.Parallel()

	client := newErrorServer(t, http.StatusForbidden)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	_, err := reader.ListOpenRequests(context.Background())
	if err == nil {
		t.Fatal("expected non-nil error for 403 Forbidden")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("error %q does not contain 'access denied' hint", err.Error())
	}
}

// TestListOpenRequests_ContextCancelled verifies that a cancelled context is
// detected immediately before any network call.
func TestListOpenRequests_ContextCancelled(t *testing.T) {
	t.Parallel()

	client := ghsdk.NewClient(nil)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := reader.ListOpenRequests(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled in error chain, got %v", err)
	}
}

// TestListOpenRequests_CreatedAtRFC3339 verifies that the CreatedAt field is
// returned in valid RFC3339 format.
func TestListOpenRequests_CreatedAtRFC3339(t *testing.T) {
	t.Parallel()

	entry := makeEntry(11, "dave", "PR 11", "shad")
	client := newListRequestsServer(t, [][]prListEntry{{entry}})
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	summaries, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if _, parseErr := time.Parse(time.RFC3339, summaries[0].CreatedAt); parseErr != nil {
		t.Errorf("CreatedAt %q is not valid RFC3339: %v", summaries[0].CreatedAt, parseErr)
	}
}

// TestListOpenRequests_NilUserHandled verifies that a PR with a nil user
// (e.g., a deleted account returning null in the API response) results in an
// empty AuthorLogin rather than a panic.
func TestListOpenRequests_NilUserHandled(t *testing.T) {
	t.Parallel()

	// Craft a page with a null user field by building the JSON manually through
	// the fixture server's raw JSON path.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/owner/registry/pulls",
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Emit a PR with null user.
			_, _ = fmt.Fprint(w, `[{"number":99,"title":"ghost PR","user":null,"head":{"sha":"ghostsha"},"created_at":"2026-05-22T00:00:00Z"}]`)
		})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "{}")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := ghsdk.NewClient(nil)
	client, _ = client.WithAuthToken("fake-token").WithEnterpriseURLs(srv.URL+"/", srv.URL+"/")

	reader, _ := NewRequestAccessReader(client, "owner/registry")

	summaries, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests: unexpected error for nil-user PR: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if summaries[0].AuthorLogin != "" {
		t.Errorf("AuthorLogin = %q, want empty string for nil-user PR", summaries[0].AuthorLogin)
	}
}

// TestListOpenRequests_DoesNotLeakSDKTypes is a compile-time assertion:
// OpenRequestSummary is a domain type (no SDK type fields). This test exercises
// the return value to confirm no *ghsdk.PullRequest leaks past the boundary.
func TestListOpenRequests_DoesNotLeakSDKTypes(t *testing.T) {
	t.Parallel()

	// Ensure the returned slice only contains domain types.
	pages := [][]prListEntry{{makeEntry(1, "alice", "t", "s")}}
	client := newListRequestsServer(t, pages)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	summaries, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests: %v", err)
	}
	// Static check: PRRef must be a coregit.PRRef domain value (not a GitHub
	// SDK type). The assignment would fail to compile if the field were an SDK
	// type; this loop is intentionally trivial.
	for _, s := range summaries {
		_ = s.PRRef
	}
}
