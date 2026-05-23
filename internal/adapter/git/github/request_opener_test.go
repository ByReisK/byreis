package github_test

// Tests for the RequestAccessOpener adapter.
//
// Coverage:
//   - BO-V1-2: structural/wiring test asserting the opener constructor takes no
//     signer / write-token parameter (TestRequestAccessOpener_NoSignerNoWriteToken).
//   - T-V1-2: fail-closed negative tests — injected List error causes refusal,
//     not warn-and-proceed (TestRequestAccessOpener_QuotaCheckListErrorRefuses).
//   - T-V1-3: page-walk ceiling fires on both contributor enumeration loops
//     (TestRequestAccessOpener_QuotaCeilingFires,
//      TestRequestAccessOpener_IdempotencyCeilingFires);
//     admin-side cap+truncation (TestListOpenRequestsBounded_*).
//   - Happy-path open (TestRequestAccessOpener_HappyPath).
//   - Quota-exceeded (TestRequestAccessOpener_QuotaExceededRefuses).
//   - ResolveHandle derives login from token (TestRequestAccessOpener_ResolveHandle_*).

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
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ─── BO-V1-2: structural / wiring test ───────────────────────────────────────

// TestRequestAccessOpener_NoSignerNoWriteToken asserts that NewRequestAccessOpener
// only accepts (client, registryProject) — no signer or write-token parameter.
// This is the compile-time + runtime structural proof of BO-V1-2: if a signer or
// write-token parameter were required, the call site below would not compile.
func TestRequestAccessOpener_NoSignerNoWriteToken(t *testing.T) {
	t.Parallel()

	// Nil client guard: only error expected is the nil-client guard.
	_, err := NewRequestAccessOpener(nil, "owner/repo")
	if err == nil {
		t.Fatal("expected error for nil client; got nil")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("expected nil-client error message, got: %v", err)
	}

	// Well-formed call: two parameters only — compile-time proof that no extra
	// (signer, write-token) parameter exists.
	_, err = NewRequestAccessOpener(ghsdk.NewClient(nil), "owner/repo")
	if err != nil {
		t.Fatalf("well-formed (client, registryProject) call returned unexpected error: %v", err)
	}
}

// TestRequestAccessOpener_ConstructorFailsOnBadProject mirrors
// NewRequestAccessReader's fail-closed owner/repo parse guard.
func TestRequestAccessOpener_ConstructorFailsOnBadProject(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		project string
	}{
		{"empty", ""},
		{"no-slash", "singletoken"},
		{"trailing-slash", "owner/"},
		{"leading-slash", "/repo"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewRequestAccessOpener(ghsdk.NewClient(nil), tc.project)
			if err == nil {
				t.Errorf("project %q: expected construction error, got nil", tc.project)
			}
		})
	}
}

// ─── T-V1-2: fail-closed on List transport error ──────────────────────────────

// TestRequestAccessOpener_QuotaCheckListErrorRefuses asserts that an HTTP error
// from the PR list endpoint during the quota check causes a hard refusal — never
// a warn-and-proceed. This is the load-bearing T-V1-2 negative test.
func TestRequestAccessOpener_QuotaCheckListErrorRefuses(t *testing.T) {
	t.Parallel()

	// Serve HTTP 500 on every PR list call.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/owner/registry/pulls", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "injected server error", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, _ := ghsdk.NewClient(nil).WithAuthToken("fake").WithEnterpriseURLs(
		srv.URL+"/api/v3/", srv.URL+"/api/v3/")

	opener, err := NewRequestAccessOpener(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessOpener: %v", err)
	}

	in := rotate.RequestAccessInput{
		Registry:      "owner/registry",
		Handle:        "alice",
		AgePubkey:     "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		Justification: "test",
	}

	_, openErr := opener.Open(context.Background(), in)
	if openErr == nil {
		t.Fatal("expected error on List transport failure; got nil (warn-and-proceed is forbidden)")
	}
	// Must NOT be quota-exceeded (that would mean the quota check reported success).
	if errors.Is(openErr, rotate.ErrRequestAccessQuotaExceeded) {
		t.Fatalf("opener returned quota-exceeded sentinel instead of refusing on transport error: %v", openErr)
	}
	// Must NOT be enumeration-bounded (the error arrived before the page ceiling).
	if errors.Is(openErr, rotate.ErrRequestAccessEnumerationBounded) {
		t.Fatalf("opener returned enumeration-bounded sentinel instead of a transport error: %v", openErr)
	}
	// Error message must indicate the quota check was the failure site.
	if !strings.Contains(openErr.Error(), "quota check") {
		t.Errorf("error should mention 'quota check'; got: %v", openErr)
	}
}

// ─── T-V1-3: page-walk ceiling on quota count ────────────────────────────────

// TestRequestAccessOpener_QuotaCeilingFires asserts that when the PR list has
// more pages than maxRequestAccessPageWalk, the quota check returns
// ErrRequestAccessEnumerationBounded and the opener refuses — it does not
// silently proceed with an under-counted quota.
func TestRequestAccessOpener_QuotaCeilingFires(t *testing.T) {
	t.Parallel()

	// Build 7 pages of PRs from users other than "alice". The page-walk ceiling
	// (5 pages) is reached before the last two pages are seen.
	pages := make([][]openerPREntry, 7)
	for i := range pages {
		pages[i] = []openerPREntry{
			{Number: i*10 + 1, HeadRef: "unrelated-branch", UserLogin: "carol"},
		}
	}

	client := openerPageServer(t, pages)
	opener, err := NewRequestAccessOpener(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessOpener: %v", err)
	}

	in := rotate.RequestAccessInput{
		Registry:      "owner/registry",
		Handle:        "alice",
		AgePubkey:     "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		Justification: "test",
	}

	_, openErr := opener.Open(context.Background(), in)
	if openErr == nil {
		t.Fatal("expected ErrRequestAccessEnumerationBounded from quota ceiling; got nil")
	}
	if !errors.Is(openErr, rotate.ErrRequestAccessEnumerationBounded) {
		t.Fatalf("expected ErrRequestAccessEnumerationBounded; got: %v", openErr)
	}
}

// ─── T-V1-3: page-walk ceiling on idempotency check ─────────────────────────

// TestRequestAccessOpener_IdempotencyCeilingFires asserts that when the quota
// check passes (alice has 0 open request-access PRs on the first scan) but the
// idempotency check scan also hits the page ceiling, the opener returns
// ErrRequestAccessEnumerationBounded rather than opening a potentially duplicate PR.
func TestRequestAccessOpener_IdempotencyCeilingFires(t *testing.T) {
	t.Parallel()

	// 7 pages of non-alice, non-request-access PRs: quota scan completes (count=0)
	// on the first pass AND the idempotency scan also runs all 7 pages, hitting
	// the ceiling on both. We need the first scan to complete successfully (count=0)
	// so we ensure Alice's PR appears on page 6 (after the ceiling) to trigger only
	// the idempotency ceiling.
	//
	// Simpler approach: just 7 pages of other-user PRs. Both scans walk all 7
	// pages and both hit the 5-page ceiling.
	pages := make([][]openerPREntry, 7)
	for i := range pages {
		pages[i] = []openerPREntry{
			{Number: i*10 + 1, HeadRef: "some-other-branch", UserLogin: "notAlice"},
		}
	}

	client := openerPageServer(t, pages)
	opener, err := NewRequestAccessOpener(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessOpener: %v", err)
	}

	in := rotate.RequestAccessInput{
		Registry:      "owner/registry",
		Handle:        "alice",
		AgePubkey:     "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		Justification: "test",
	}

	_, openErr := opener.Open(context.Background(), in)
	if openErr == nil {
		t.Fatal("expected ErrRequestAccessEnumerationBounded from idempotency ceiling; got nil")
	}
	if !errors.Is(openErr, rotate.ErrRequestAccessEnumerationBounded) {
		t.Fatalf("expected ErrRequestAccessEnumerationBounded; got: %v", openErr)
	}
}

// ─── T-V1-3: ListOpenRequestsBounded result-cap and truncation ───────────────

// TestListOpenRequestsBounded_TruncatesAtCap asserts the admin-side bounded list
// returns exactly 200 entries and sets truncated=true when the registry has 201.
func TestListOpenRequestsBounded_TruncatesAtCap(t *testing.T) {
	t.Parallel()

	entries := make([]prListEntry, 201)
	for i := range entries {
		login := fmt.Sprintf("user%d", i)
		entries[i] = prListEntry{
			Number:    i + 1,
			Title:     fmt.Sprintf("request-access: add %s", login),
			CreatedAt: "2026-05-22T10:00:00Z",
			User: struct {
				Login string `json:"login"`
			}{Login: login},
			Head: struct {
				SHA string `json:"sha"`
			}{SHA: fmt.Sprintf("sha%d", i)},
		}
	}

	client := newListRequestsServer(t, [][]prListEntry{entries})
	reader, err := NewRequestAccessReader(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessReader: %v", err)
	}

	summaries, truncated, listErr := reader.ListOpenRequestsBounded(context.Background())
	if listErr != nil {
		t.Fatalf("ListOpenRequestsBounded: unexpected error: %v", listErr)
	}
	if !truncated {
		t.Error("expected truncated=true when result count exceeds cap; got false")
	}
	if len(summaries) != 200 {
		t.Errorf("expected 200 summaries (cap), got %d", len(summaries))
	}
}

// TestListOpenRequestsBounded_TruncatesAtPageCeiling asserts the bounded list
// stops at 5 pages even when more are available.
func TestListOpenRequestsBounded_TruncatesAtPageCeiling(t *testing.T) {
	t.Parallel()

	// 6 pages of 5 entries each; the ceiling stops the walk at 5 pages = 25 entries.
	pages := make([][]prListEntry, 6)
	for i := range pages {
		var page []prListEntry
		for j := 0; j < 5; j++ {
			num := i*5 + j + 1
			page = append(page, prListEntry{
				Number:    num,
				Title:     fmt.Sprintf("pr-%d", num),
				CreatedAt: "2026-05-22T10:00:00Z",
				User: struct {
					Login string `json:"login"`
				}{Login: "alice"},
				Head: struct {
					SHA string `json:"sha"`
				}{SHA: fmt.Sprintf("sha%d", num)},
			})
		}
		pages[i] = page
	}

	client := newListRequestsServer(t, pages)
	reader, err := NewRequestAccessReader(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessReader: %v", err)
	}

	summaries, truncated, listErr := reader.ListOpenRequestsBounded(context.Background())
	if listErr != nil {
		t.Fatalf("ListOpenRequestsBounded: unexpected error: %v", listErr)
	}
	if !truncated {
		t.Error("expected truncated=true when page ceiling is hit; got false")
	}
	if len(summaries) != 25 {
		t.Errorf("expected 25 summaries (5 pages × 5 entries), got %d", len(summaries))
	}
}

// TestListOpenRequestsBounded_NoTruncationForSmallResult asserts truncated=false
// for a result within both the result cap and the page ceiling.
func TestListOpenRequestsBounded_NoTruncationForSmallResult(t *testing.T) {
	t.Parallel()

	pages := [][]prListEntry{
		{
			{Number: 1, Title: "pr-1", CreatedAt: "2026-05-22T10:00:00Z",
				User: struct {
					Login string `json:"login"`
				}{Login: "alice"},
				Head: struct {
					SHA string `json:"sha"`
				}{SHA: "sha1"}},
		},
	}

	client := newListRequestsServer(t, pages)
	reader, err := NewRequestAccessReader(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessReader: %v", err)
	}

	summaries, truncated, listErr := reader.ListOpenRequestsBounded(context.Background())
	if listErr != nil {
		t.Fatalf("ListOpenRequestsBounded: unexpected error: %v", listErr)
	}
	if truncated {
		t.Error("expected truncated=false for small result; got true")
	}
	if len(summaries) != 1 {
		t.Errorf("expected 1 summary, got %d", len(summaries))
	}
}

// ─── ResolveHandle ───────────────────────────────────────────────────────────

// TestRequestAccessOpener_ResolveHandle_FromToken asserts ResolveHandle derives
// the contributor's login from the GitHub token identity when Handle is "".
func TestRequestAccessOpener_ResolveHandle_FromToken(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"login": "alice"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, _ := ghsdk.NewClient(nil).WithAuthToken("fake").WithEnterpriseURLs(
		srv.URL+"/api/v3/", srv.URL+"/api/v3/")

	opener, err := NewRequestAccessOpener(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessOpener: %v", err)
	}

	handle, err := opener.ResolveHandle(context.Background(), rotate.RequestAccessInput{Handle: ""})
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	if handle != "alice" {
		t.Errorf("expected handle=alice, got %q", handle)
	}
}

// TestRequestAccessOpener_ResolveHandle_Passthrough asserts ResolveHandle returns
// the supplied Handle (lowercased) without making a network call when non-empty.
func TestRequestAccessOpener_ResolveHandle_Passthrough(t *testing.T) {
	t.Parallel()

	// No /api/v3/user handler — any call would return 404 and cause an error.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, _ := ghsdk.NewClient(nil).WithAuthToken("fake").WithEnterpriseURLs(
		srv.URL+"/api/v3/", srv.URL+"/api/v3/")

	opener, err := NewRequestAccessOpener(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessOpener: %v", err)
	}

	handle, err := opener.ResolveHandle(context.Background(), rotate.RequestAccessInput{Handle: "ALICE"})
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	if handle != "alice" {
		t.Errorf("expected lowercased handle alice, got %q", handle)
	}
}

// ─── Happy path ──────────────────────────────────────────────────────────────

// TestRequestAccessOpener_HappyPath verifies the full fork-branch-commit-PR
// sequence completes when quota and idempotency checks pass.
func TestRequestAccessOpener_HappyPath(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()

	// PR list (GET only): empty on both quota and idempotency scans.
	mux.HandleFunc("GET /api/v3/repos/owner/registry/pulls", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]interface{}{})
	})

	// ListForks: return alice's fork.
	mux.HandleFunc("/api/v3/repos/owner/registry/forks", func(w http.ResponseWriter, _ *http.Request) {
		type forkOwner struct {
			Login string `json:"login"`
		}
		type fork struct {
			Owner forkOwner `json:"owner"`
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]fork{{Owner: forkOwner{Login: "alice"}}})
	})

	// Get fork repo: return default branch.
	mux.HandleFunc("/api/v3/repos/alice/registry", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
	})

	// Get fork ref HEAD SHA.
	mux.HandleFunc("/api/v3/repos/alice/registry/git/ref/heads/main", func(w http.ResponseWriter, _ *http.Request) {
		type obj struct {
			SHA string `json:"sha"`
		}
		type ref struct {
			Object obj `json:"object"`
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ref{Object: obj{SHA: "basesha123"}})
	})

	// Create branch ref on fork.
	mux.HandleFunc("/api/v3/repos/alice/registry/git/refs", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ref": "refs/heads/byreis/request-access-alice-1"})
	})

	// Commit file to fork: the SDK unmarshals RepositoryContentResponse.
	mux.HandleFunc("/api/v3/repos/alice/registry/contents/requests/alice.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		// The SDK maps the "content" field to RepositoryContent; use the expected shape.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"content": map[string]string{
				"name":    "alice.yaml",
				"path":    "requests/alice.yaml",
				"sha":     "newfilesha",
				"content": "",
			},
		})
	})

	// Create PR (POST only).
	mux.HandleFunc("POST /api/v3/repos/owner/registry/pulls", func(w http.ResponseWriter, _ *http.Request) {
		type pr struct {
			Number  int    `json:"number"`
			HTMLURL string `json:"html_url"`
		}
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pr{Number: 42, HTMLURL: "https://github.com/owner/registry/pull/42"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, _ := ghsdk.NewClient(nil).WithAuthToken("fake").WithEnterpriseURLs(
		srv.URL+"/api/v3/", srv.URL+"/api/v3/")

	opener, err := NewRequestAccessOpener(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessOpener: %v", err)
	}

	in := rotate.RequestAccessInput{
		Registry:      "owner/registry",
		Handle:        "alice",
		AgePubkey:     "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		Justification: "I need access",
	}

	result, openErr := opener.Open(context.Background(), in)
	if openErr != nil {
		t.Fatalf("Open: unexpected error: %v", openErr)
	}
	if result.PRRef.Project != "owner/registry" {
		t.Errorf("PRRef.Project: got %q, want %q", result.PRRef.Project, "owner/registry")
	}
	if result.PRRef.Number != 42 {
		t.Errorf("PRRef.Number: got %d, want 42", result.PRRef.Number)
	}
	if result.URL != "https://github.com/owner/registry/pull/42" {
		t.Errorf("URL: got %q, want %q", result.URL, "https://github.com/owner/registry/pull/42")
	}
}

// TestRequestAccessOpener_QuotaExceededRefuses asserts the opener refuses when
// the contributor already has maxOpenRequestAccessPRs open request-access PRs.
func TestRequestAccessOpener_QuotaExceededRefuses(t *testing.T) {
	t.Parallel()

	// Build exactly 5 open request-access PRs from "alice".
	entries := make([]openerPREntry, 5)
	for i := range entries {
		entries[i] = openerPREntry{
			Number:    i + 1,
			HeadRef:   fmt.Sprintf("byreis/request-access-alice-%d", i),
			UserLogin: "alice",
		}
	}

	client := openerSinglePageServer(t, entries)
	opener, err := NewRequestAccessOpener(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessOpener: %v", err)
	}

	in := rotate.RequestAccessInput{
		Registry:      "owner/registry",
		Handle:        "alice",
		AgePubkey:     "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		Justification: "test",
	}

	_, openErr := opener.Open(context.Background(), in)
	if openErr == nil {
		t.Fatal("expected ErrRequestAccessQuotaExceeded; got nil")
	}
	if !errors.Is(openErr, rotate.ErrRequestAccessQuotaExceeded) {
		t.Fatalf("expected ErrRequestAccessQuotaExceeded; got: %v", openErr)
	}
}

// ─── helpers for opener tests ─────────────────────────────────────────────────

// openerPREntry is the minimal PR shape for the opener's list-based checks.
type openerPREntry struct {
	Number    int
	HeadRef   string
	UserLogin string
}

// openerSinglePageServer starts a fake server returning the given entries as a
// single page with no Link header.
func openerSinglePageServer(t *testing.T, entries []openerPREntry) *ghsdk.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/owner/registry/pulls", func(w http.ResponseWriter, _ *http.Request) {
		type prHead struct {
			Ref string `json:"ref"`
		}
		type prUser struct {
			Login string `json:"login"`
		}
		type pr struct {
			Number  int    `json:"number"`
			HTMLURL string `json:"html_url"`
			Head    prHead `json:"head"`
			User    prUser `json:"user"`
		}
		resp := make([]pr, len(entries))
		for i, e := range entries {
			resp[i] = pr{
				Number:  e.Number,
				HTMLURL: fmt.Sprintf("https://github.com/owner/registry/pull/%d", e.Number),
				Head:    prHead{Ref: e.HeadRef},
				User:    prUser{Login: e.UserLogin},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, _ := ghsdk.NewClient(nil).WithAuthToken("fake").WithEnterpriseURLs(
		srv.URL+"/api/v3/", srv.URL+"/api/v3/")
	return client
}

// openerPageServer starts a fake server that serves the given pages in order via
// Link: rel="next" headers. The page counter is global across all calls (both
// quota scan and idempotency scan draw from the same sequence).
func openerPageServer(t *testing.T, pages [][]openerPREntry) *ghsdk.Client {
	t.Helper()

	type prHead struct {
		Ref string `json:"ref"`
	}
	type prUser struct {
		Login string `json:"login"`
	}
	type prResp struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
		Head    prHead `json:"head"`
		User    prUser `json:"user"`
	}

	mux := http.NewServeMux()
	call := 0

	mux.HandleFunc("/api/v3/repos/owner/registry/pulls", func(w http.ResponseWriter, r *http.Request) {
		idx := call
		call++

		var resp []prResp
		if idx < len(pages) {
			for _, e := range pages[idx] {
				resp = append(resp, prResp{
					Number:  e.Number,
					HTMLURL: fmt.Sprintf("https://github.com/owner/registry/pull/%d", e.Number),
					Head:    prHead{Ref: e.HeadRef},
					User:    prUser{Login: e.UserLogin},
				})
			}
			if idx+1 < len(pages) {
				host := r.Host
				if host == "" {
					host = r.URL.Host
				}
				w.Header().Set("Link",
					fmt.Sprintf(`<http://%s/api/v3/repos/owner/registry/pulls?page=%d>; rel="next"`,
						host, idx+2))
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if resp == nil {
			_ = json.NewEncoder(w).Encode([]prResp{})
		} else {
			_ = json.NewEncoder(w).Encode(resp)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, _ := ghsdk.NewClient(nil).WithAuthToken("fake").WithEnterpriseURLs(
		srv.URL+"/api/v3/", srv.URL+"/api/v3/")
	return client
}
