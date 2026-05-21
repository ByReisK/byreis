package github_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ghsdk "github.com/google/go-github/v72/github"

	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"

	. "github.com/ByReisK/byreis/internal/adapter/git/github"
)

// prReadFixture provides a minimal GitHub HTTP fixture for pr_read tests.
// It serves the PR metadata, the files-changed list, the commits list, and
// the file contents endpoint.
type prReadFixture struct {
	prState            string
	prDraft            bool
	prMerged           bool
	prAuthorLogin      string
	prAuthorType       string
	prHeadSHA          string
	prHeadRepoOwner    string
	prHeadRepoFullName string
	prFiles            []string
	prCommitAuthors    []string
	yamlContent        string
}

// newPRReadServer starts a fake GitHub server for the given fixture and returns
// the *github.Client wired to it.
func newPRReadServer(t *testing.T, fx *prReadFixture, prNumber int) *ghsdk.Client {
	t.Helper()

	mux := http.NewServeMux()

	// All paths are prefixed with /api/v3/ because WithEnterpriseURLs appends
	// that prefix to the base URL when it is not already present.

	// GET /api/v3/repos/:owner/:repo/pulls/:prNumber
	mux.HandleFunc(fmt.Sprintf("/api/v3/repos/owner/registry/pulls/%d", prNumber),
		func(w http.ResponseWriter, r *http.Request) {
			type headRepo struct {
				FullName string     `json:"full_name"`
				Owner    ghUserJSON `json:"owner"`
			}
			type head struct {
				SHA  string   `json:"sha"`
				Repo headRepo `json:"repo"`
			}
			type prUser struct {
				Login string `json:"login"`
				Type  string `json:"type"`
			}
			type prResponse struct {
				Number int    `json:"number"`
				State  string `json:"state"`
				Draft  bool   `json:"draft"`
				Merged bool   `json:"merged"`
				User   prUser `json:"user"`
				Head   head   `json:"head"`
			}
			resp := prResponse{
				Number: prNumber,
				State:  fx.prState,
				Draft:  fx.prDraft,
				Merged: fx.prMerged,
				User: prUser{
					Login: fx.prAuthorLogin,
					Type:  fx.prAuthorType,
				},
				Head: head{
					SHA: fx.prHeadSHA,
					Repo: headRepo{
						FullName: fx.prHeadRepoFullName,
						Owner:    ghUserJSON{Login: fx.prHeadRepoOwner},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		})

	// GET /api/v3/repos/:owner/:repo/pulls/:prNumber/files
	mux.HandleFunc(fmt.Sprintf("/api/v3/repos/owner/registry/pulls/%d/files", prNumber),
		func(w http.ResponseWriter, r *http.Request) {
			type prFile struct {
				Filename string `json:"filename"`
			}
			files := make([]prFile, len(fx.prFiles))
			for i, f := range fx.prFiles {
				files[i] = prFile{Filename: f}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(files)
		})

	// GET /api/v3/repos/:owner/:repo/pulls/:prNumber/commits
	mux.HandleFunc(fmt.Sprintf("/api/v3/repos/owner/registry/pulls/%d/commits", prNumber),
		func(w http.ResponseWriter, r *http.Request) {
			type commitUser struct {
				Login string `json:"login"`
			}
			type commitGitAuthor struct {
				Name string `json:"name"`
			}
			type commitInner struct {
				Message string          `json:"message"`
				Author  commitGitAuthor `json:"author"`
			}
			type commitEntry struct {
				SHA    string      `json:"sha"`
				Author commitUser  `json:"author"`
				Commit commitInner `json:"commit"`
			}
			commits := make([]commitEntry, len(fx.prCommitAuthors))
			for i, a := range fx.prCommitAuthors {
				commits[i] = commitEntry{
					SHA:    fmt.Sprintf("commit%02d", i),
					Author: commitUser{Login: a},
					Commit: commitInner{
						Message: fmt.Sprintf("commit message %02d", i),
					},
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(commits)
		})

	// GET /api/v3/repos/:owner/:repo/contents/:path — for the fork repo
	mux.HandleFunc("/api/v3/repos/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		// Serve any GetContents call with the fixture YAML content.
		if strings.Contains(r.URL.Path, "/contents/") {
			encoded := base64.StdEncoding.EncodeToString([]byte(fx.yamlContent))
			type contentsResp struct {
				Content  string `json:"content"`
				Encoding string `json:"encoding"`
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(contentsResp{
				Content:  encoded,
				Encoding: "base64",
			})
			return
		}
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := ghsdk.NewClient(nil)
	client, _ = client.WithAuthToken("fake-token").WithEnterpriseURLs(
		srv.URL+"/", srv.URL+"/")
	return client
}

// ghUserJSON is a minimal GitHub user JSON shape for the fixture server.
type ghUserJSON struct {
	Login string `json:"login"`
}

// minimalValidYAML returns a valid request-access YAML payload for the given handle.
func minimalValidYAML(handle, pubkey string) string {
	return fmt.Sprintf(`schema_version: byreis.request_access.v1
github_handle: %s
age_pubkey: %s
justification: "testing"
requested_at: "2026-05-21T00:00:00Z"
`, handle, pubkey)
}

// A valid age X25519 public key for use in tests (real age1 address format).
const testAgePubkey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

// TestFetchRequestAccessYAML_HappyPath exercises the full happy-path: open, non-draft,
// non-merged PR from a User author; single file in requests/ namespace; valid YAML.
func TestFetchRequestAccessYAML_HappyPath(t *testing.T) {
	fx := &prReadFixture{
		prState:            "open",
		prDraft:            false,
		prMerged:           false,
		prAuthorLogin:      "alice",
		prAuthorType:       "User",
		prHeadSHA:          "abc123def456",
		prHeadRepoOwner:    "alice",
		prHeadRepoFullName: "alice/registry",
		prFiles:            []string{"requests/alice.yaml"},
		prCommitAuthors:    []string{"alice"},
		yamlContent:        minimalValidYAML("alice", testAgePubkey),
	}

	client := newPRReadServer(t, fx, 42)
	reader, err := NewRequestAccessReader(client, "owner/registry")
	if err != nil {
		t.Fatalf("NewRequestAccessReader: %v", err)
	}

	ctx := context.Background()
	prRef := coregit.PRRef{Project: "owner/registry", Number: 42}

	file, meta, err := reader.FetchRequestAccessYAML(ctx, prRef)
	if err != nil {
		t.Fatalf("FetchRequestAccessYAML: %v", err)
	}

	// Assert domain type fields are populated correctly.
	if file.GitHubHandle != "alice" {
		t.Errorf("GitHubHandle = %q, want %q", file.GitHubHandle, "alice")
	}
	if file.AgePubkey != testAgePubkey {
		t.Errorf("AgePubkey = %q, want %q", file.AgePubkey, testAgePubkey)
	}
	if meta.AuthorLogin != "alice" {
		t.Errorf("meta.AuthorLogin = %q, want alice", meta.AuthorLogin)
	}
	if meta.State != "open" {
		t.Errorf("meta.State = %q, want open", meta.State)
	}
	if meta.IsDraft {
		t.Error("meta.IsDraft should be false")
	}
	if meta.IsMerged {
		t.Error("meta.IsMerged should be false")
	}
	if meta.HeadSHA != "abc123def456" {
		t.Errorf("meta.HeadSHA = %q, want abc123def456", meta.HeadSHA)
	}
	if meta.HeadRepoOwnerLogin != "alice" {
		t.Errorf("meta.HeadRepoOwnerLogin = %q, want alice", meta.HeadRepoOwnerLogin)
	}
	if meta.AuthorType != "User" {
		t.Errorf("meta.AuthorType = %q, want User", meta.AuthorType)
	}
	if len(meta.Commits) != 1 {
		t.Errorf("len(meta.Commits) = %d, want 1", len(meta.Commits))
	}
	if len(meta.Commits) > 0 {
		if meta.Commits[0].AuthorLogin != "alice" {
			t.Errorf("Commits[0].AuthorLogin = %q, want alice", meta.Commits[0].AuthorLogin)
		}
		// Body must be populated from the commit message (no extra HTTP call).
		if meta.Commits[0].Body != "commit message 00" {
			t.Errorf("Commits[0].Body = %q, want %q", meta.Commits[0].Body, "commit message 00")
		}
	}
}

// TestFetchRequestAccessYAML_MultiFilePRRefused asserts that a PR changing more
// than one file is refused with ErrRequestAccessPRFilePathInvalid.
func TestFetchRequestAccessYAML_MultiFilePRRefused(t *testing.T) {
	fx := &prReadFixture{
		prState:            "open",
		prDraft:            false,
		prMerged:           false,
		prAuthorLogin:      "alice",
		prAuthorType:       "User",
		prHeadSHA:          "abc123def456",
		prHeadRepoOwner:    "alice",
		prHeadRepoFullName: "alice/registry",
		prFiles:            []string{"requests/alice.yaml", "admins.yaml"},
		prCommitAuthors:    []string{"alice"},
		yamlContent:        minimalValidYAML("alice", testAgePubkey),
	}

	client := newPRReadServer(t, fx, 43)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	_, _, err := reader.FetchRequestAccessYAML(context.Background(),
		coregit.PRRef{Project: "owner/registry", Number: 43})

	if !errors.Is(err, rotate.ErrRequestAccessPRFilePathInvalid) {
		t.Errorf("expected ErrRequestAccessPRFilePathInvalid, got %v", err)
	}
}

// TestFetchRequestAccessYAML_InvalidPathRefused asserts that a PR touching a file
// outside the requests/ namespace is refused.
func TestFetchRequestAccessYAML_InvalidPathRefused(t *testing.T) {
	fx := &prReadFixture{
		prState:            "open",
		prDraft:            false,
		prMerged:           false,
		prAuthorLogin:      "alice",
		prAuthorType:       "User",
		prHeadSHA:          "abc123def456",
		prHeadRepoOwner:    "alice",
		prHeadRepoFullName: "alice/registry",
		prFiles:            []string{"admins.yaml"},
		prCommitAuthors:    []string{"alice"},
		yamlContent:        minimalValidYAML("alice", testAgePubkey),
	}

	client := newPRReadServer(t, fx, 44)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	_, _, err := reader.FetchRequestAccessYAML(context.Background(),
		coregit.PRRef{Project: "owner/registry", Number: 44})

	if !errors.Is(err, rotate.ErrRequestAccessPRFilePathInvalid) {
		t.Errorf("expected ErrRequestAccessPRFilePathInvalid, got %v", err)
	}
}

// TestFetchRequestAccessYAML_BotAuthorRefused asserts that a PR from a Bot author
// is refused with ErrRequestAccessIdentityMismatch.
func TestFetchRequestAccessYAML_BotAuthorRefused(t *testing.T) {
	fx := &prReadFixture{
		prState:            "open",
		prDraft:            false,
		prMerged:           false,
		prAuthorLogin:      "renovate-bot",
		prAuthorType:       "Bot",
		prHeadSHA:          "abc123def456",
		prHeadRepoOwner:    "renovate-bot",
		prHeadRepoFullName: "renovate-bot/registry",
		prFiles:            []string{"requests/renovate-bot.yaml"},
		prCommitAuthors:    []string{"renovate-bot"},
		yamlContent:        minimalValidYAML("renovate-bot", testAgePubkey),
	}

	client := newPRReadServer(t, fx, 45)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	_, _, err := reader.FetchRequestAccessYAML(context.Background(),
		coregit.PRRef{Project: "owner/registry", Number: 45})

	if !errors.Is(err, rotate.ErrRequestAccessIdentityMismatch) {
		t.Errorf("expected ErrRequestAccessIdentityMismatch, got %v", err)
	}
}

// TestFetchPRHeadSHA returns the head SHA and fork-repo owner login from the fixture PR.
func TestFetchPRHeadSHA(t *testing.T) {
	fx := &prReadFixture{
		prState:            "open",
		prAuthorLogin:      "alice",
		prAuthorType:       "User",
		prHeadSHA:          "deadbeef1234",
		prHeadRepoOwner:    "alice",
		prHeadRepoFullName: "alice/registry",
		prFiles:            []string{"requests/alice.yaml"},
		prCommitAuthors:    []string{"alice"},
		yamlContent:        minimalValidYAML("alice", testAgePubkey),
	}

	client := newPRReadServer(t, fx, 100)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	sha, ownerLogin, err := reader.FetchPRHeadSHA(context.Background(),
		coregit.PRRef{Project: "owner/registry", Number: 100})
	if err != nil {
		t.Fatalf("FetchPRHeadSHA: %v", err)
	}
	if sha != "deadbeef1234" {
		t.Errorf("FetchPRHeadSHA sha = %q, want deadbeef1234", sha)
	}
	if ownerLogin != "alice" {
		t.Errorf("FetchPRHeadSHA ownerLogin = %q, want alice", ownerLogin)
	}
}

// TestFetchPRHeadSHA_OwnerLoginLowercased verifies that the fork-repo owner login
// is returned in lowercase regardless of the casing GitHub returns.
func TestFetchPRHeadSHA_OwnerLoginLowercased(t *testing.T) {
	fx := &prReadFixture{
		prState:            "open",
		prAuthorLogin:      "Alice",
		prAuthorType:       "User",
		prHeadSHA:          "cafecafe5678",
		prHeadRepoOwner:    "Alice", // mixed-case: SDK returns as-is; adapter lowercases
		prHeadRepoFullName: "Alice/registry",
		prFiles:            []string{"requests/alice.yaml"},
		prCommitAuthors:    []string{"alice"},
		yamlContent:        minimalValidYAML("alice", testAgePubkey),
	}

	client := newPRReadServer(t, fx, 101)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	_, ownerLogin, err := reader.FetchPRHeadSHA(context.Background(),
		coregit.PRRef{Project: "owner/registry", Number: 101})
	if err != nil {
		t.Fatalf("FetchPRHeadSHA: %v", err)
	}
	if ownerLogin != "alice" {
		t.Errorf("FetchPRHeadSHA ownerLogin = %q, want alice (lowercased)", ownerLogin)
	}
}

// TestNewRequestAccessReader_MalformedProject asserts that a malformed project
// string returns ErrInvalidProject.
func TestNewRequestAccessReader_MalformedProject(t *testing.T) {
	client := ghsdk.NewClient(nil)

	for _, bad := range []string{"", "onlyone", "three/parts/bad"} {
		_, err := NewRequestAccessReader(client, bad)
		if !errors.Is(err, coregit.ErrInvalidProject) {
			t.Errorf("NewRequestAccessReader(%q): want ErrInvalidProject, got %v", bad, err)
		}
	}
}

// TestFetchRequestAccessYAML_ContextCancelled asserts that a cancelled context
// is returned immediately before any network call.
func TestFetchRequestAccessYAML_ContextCancelled(t *testing.T) {
	client := ghsdk.NewClient(nil)
	reader, _ := NewRequestAccessReader(client, "owner/registry")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, _, err := reader.FetchRequestAccessYAML(ctx,
		coregit.PRRef{Project: "owner/registry", Number: 1})
	if err == nil {
		t.Fatal("expected non-nil error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled in error chain, got %v", err)
	}
}
