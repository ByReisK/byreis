package github_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ghsdk "github.com/google/go-github/v72/github"

	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase"

	. "github.com/ByReisK/byreis/internal/adapter/git/github"
)

// prCloserFixture is the per-test server state for PR closer tests.
type prCloserFixture struct {
	prState    string // "open", "closed"
	prMerged   bool
	branchName string
	labels     []string

	// recorded side-effects
	commentPosted string
	prClosed      bool
}

// newPRCloserServerWithSingleHandler is a variant that dispatches GET and PATCH
// on the same PR path by method (the ghsdk router sends PATCH as a separate
// call to Edit). Replaces the mux-based server for full round-trip tests.
func newPRCloserServerFull(t *testing.T, fx *prCloserFixture, prNumber int) *ghsdk.Client {
	t.Helper()

	mux := http.NewServeMux()
	prPath := fmt.Sprintf("/api/v3/repos/owner/project/pulls/%d", prNumber)
	commentPath := fmt.Sprintf("/api/v3/repos/owner/project/issues/%d/comments", prNumber)

	mux.HandleFunc(prPath, func(w http.ResponseWriter, r *http.Request) {
		type labelJSON struct {
			Name string `json:"name"`
		}
		type headJSON struct {
			Ref string `json:"ref"`
		}
		type prJSON struct {
			Number int         `json:"number"`
			State  string      `json:"state"`
			Merged bool        `json:"merged"`
			Head   headJSON    `json:"head"`
			Labels []labelJSON `json:"labels"`
		}
		if r.Method == http.MethodGet {
			var ljs []labelJSON
			for _, l := range fx.labels {
				ljs = append(ljs, labelJSON{Name: l})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(prJSON{
				Number: prNumber, State: fx.prState, Merged: fx.prMerged,
				Head:   headJSON{Ref: fx.branchName},
				Labels: ljs,
			})
			return
		}
		if r.Method == http.MethodPatch {
			var body struct {
				State string `json:"state"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.State == "closed" {
				fx.prClosed = true
				fx.prState = "closed"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(prJSON{Number: prNumber, State: "closed"})
			return
		}
		http.Error(w, "unexpected method "+r.Method, http.StatusMethodNotAllowed)
	})

	mux.HandleFunc(commentPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		fx.commentPosted = body.Body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "body": body.Body})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := ghsdk.NewClient(nil)
	client, _ = client.WithAuthToken("fake").WithEnterpriseURLs(srv.URL+"/", srv.URL+"/")
	return client
}

// ─── NewProjectRepoPRCloser / NewRegistryRepoPRCloser constructor tests ──────

func TestNewProjectRepoPRCloser_NilClient(t *testing.T) {
	t.Parallel()
	_, err := NewProjectRepoPRCloser(nil, "owner/project")
	if err == nil {
		t.Fatal("expected error for nil client, got nil")
	}
}

func TestNewRegistryRepoPRCloser_MalformedRepo(t *testing.T) {
	t.Parallel()
	client := ghsdk.NewClient(nil)
	_, err := NewRegistryRepoPRCloser(client, "no-slash")
	if err == nil {
		t.Fatal("expected error for malformed repo, got nil")
	}
}

// ─── FetchPRStateForReject tests ─────────────────────────────────────────────

func TestFetchPRStateForReject_OpenSubmission(t *testing.T) {
	t.Parallel()
	fx := &prCloserFixture{
		prState:    "open",
		prMerged:   false,
		branchName: "byreis/add-MY_KEY-1234567890",
		labels:     []string{"submission"},
	}
	client := newPRCloserServerFull(t, fx, 7)
	adapter, err := NewProjectRepoPRCloser(client, "owner/project")
	if err != nil {
		t.Fatalf("NewProjectRepoPRCloser: %v", err)
	}

	state, err := adapter.FetchPRStateForReject(context.Background(),
		coregit.PRRef{Project: "owner/project", Number: 7})
	if err != nil {
		t.Fatalf("FetchPRStateForReject: %v", err)
	}
	if state.Merged {
		t.Error("Merged should be false for open PR")
	}
	if state.Closed {
		t.Error("Closed should be false for open PR")
	}
	if state.BranchName != "byreis/add-MY_KEY-1234567890" {
		t.Errorf("BranchName = %q, want %q", state.BranchName, "byreis/add-MY_KEY-1234567890")
	}
	if state.SourceRepo != usecase.RepoKindProject {
		t.Errorf("SourceRepo = %v, want RepoKindProject", state.SourceRepo)
	}
	if len(state.Labels) != 1 || state.Labels[0] != "submission" {
		t.Errorf("Labels = %v, want [submission]", state.Labels)
	}
}

func TestFetchPRStateForReject_MergedPR(t *testing.T) {
	t.Parallel()
	fx := &prCloserFixture{
		prState:    "closed",
		prMerged:   true,
		branchName: "byreis/add-KEY-1111",
	}
	client := newPRCloserServerFull(t, fx, 9)
	adapter, err := NewProjectRepoPRCloser(client, "owner/project")
	if err != nil {
		t.Fatalf("NewProjectRepoPRCloser: %v", err)
	}

	state, err := adapter.FetchPRStateForReject(context.Background(),
		coregit.PRRef{Project: "owner/project", Number: 9})
	if err != nil {
		t.Fatalf("FetchPRStateForReject: %v", err)
	}
	if !state.Merged {
		t.Error("Merged should be true for merged PR")
	}
	if !state.Closed {
		t.Error("Closed should be true for merged PR")
	}
}

func TestFetchPRStateForReject_AlreadyClosedPR(t *testing.T) {
	t.Parallel()
	fx := &prCloserFixture{
		prState:    "closed",
		prMerged:   false,
		branchName: "requests/alice.yaml",
	}
	client := newPRCloserServerFull(t, fx, 11)
	adapter, err := NewRegistryRepoPRCloser(client, "owner/project")
	if err != nil {
		t.Fatalf("NewRegistryRepoPRCloser: %v", err)
	}

	state, err := adapter.FetchPRStateForReject(context.Background(),
		coregit.PRRef{Project: "owner/project", Number: 11})
	if err != nil {
		t.Fatalf("FetchPRStateForReject: %v", err)
	}
	if !state.Closed {
		t.Error("Closed should be true for closed PR")
	}
	if state.Merged {
		t.Error("Merged should be false for non-merged closed PR")
	}
	if state.SourceRepo != usecase.RepoKindRegistry {
		t.Errorf("SourceRepo = %v, want RepoKindRegistry", state.SourceRepo)
	}
}

// TestFetchPRStateForReject_SourceRepoStampedByAdapter verifies that a
// project-repo adapter and a registry-repo adapter querying the same PR number
// stamp different SourceRepo values — the discriminator is repo-bound, not
// derived from the branch name.
func TestFetchPRStateForReject_SourceRepoStampedByAdapter(t *testing.T) {
	t.Parallel()
	fx := &prCloserFixture{
		prState:    "open",
		prMerged:   false,
		branchName: "some-branch",
	}
	clientProject := newPRCloserServerFull(t, fx, 5)
	fxReg := &prCloserFixture{
		prState:    "open",
		prMerged:   false,
		branchName: "some-branch",
	}
	clientRegistry := newPRCloserServerFull(t, fxReg, 5)

	projAdapter, _ := NewProjectRepoPRCloser(clientProject, "owner/project")
	regAdapter, _ := NewRegistryRepoPRCloser(clientRegistry, "owner/project")

	projState, err := projAdapter.FetchPRStateForReject(context.Background(),
		coregit.PRRef{Project: "owner/project", Number: 5})
	if err != nil {
		t.Fatalf("project adapter FetchPRStateForReject: %v", err)
	}
	regState, err := regAdapter.FetchPRStateForReject(context.Background(),
		coregit.PRRef{Project: "owner/project", Number: 5})
	if err != nil {
		t.Fatalf("registry adapter FetchPRStateForReject: %v", err)
	}

	if projState.SourceRepo != usecase.RepoKindProject {
		t.Errorf("project adapter SourceRepo = %v, want RepoKindProject", projState.SourceRepo)
	}
	if regState.SourceRepo != usecase.RepoKindRegistry {
		t.Errorf("registry adapter SourceRepo = %v, want RepoKindRegistry", regState.SourceRepo)
	}
}

// ─── CloseWithComment tests ───────────────────────────────────────────────────

func TestCloseWithComment_PostsThenCloses(t *testing.T) {
	t.Parallel()
	fx := &prCloserFixture{
		prState:    "open",
		branchName: "byreis/add-STRIPE_KEY-1234",
	}
	client := newPRCloserServerFull(t, fx, 3)
	adapter, err := NewProjectRepoPRCloser(client, "owner/project")
	if err != nil {
		t.Fatalf("NewProjectRepoPRCloser: %v", err)
	}

	err = adapter.CloseWithComment(context.Background(),
		coregit.PRRef{Project: "owner/project", Number: 3},
		"Not aligned with project requirements.")
	if err != nil {
		t.Fatalf("CloseWithComment: %v", err)
	}
	if fx.commentPosted != "Not aligned with project requirements." {
		t.Errorf("comment body = %q, want %q",
			fx.commentPosted, "Not aligned with project requirements.")
	}
	if !fx.prClosed {
		t.Error("PR should be closed after CloseWithComment")
	}
}

func TestCloseWithComment_CancelledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	fx := &prCloserFixture{prState: "open"}
	client := newPRCloserServerFull(t, fx, 1)
	adapter, _ := NewProjectRepoPRCloser(client, "owner/project")

	err := adapter.CloseWithComment(ctx,
		coregit.PRRef{Project: "owner/project", Number: 1}, "reason")
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("error %q should mention cancelled", err.Error())
	}
}

func TestFetchPRStateForReject_CancelledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fx := &prCloserFixture{prState: "open"}
	client := newPRCloserServerFull(t, fx, 1)
	adapter, _ := NewProjectRepoPRCloser(client, "owner/project")

	_, err := adapter.FetchPRStateForReject(ctx,
		coregit.PRRef{Project: "owner/project", Number: 1})
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}

// TestCloseWithComment_404Returns_ActionableError exercises the 404 branch of
// wrapErr so that "not found" produces an actionable hint string.
func TestCloseWithComment_404Returns_ActionableError(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/owner/project/issues/99/comments",
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := ghsdk.NewClient(nil)
	client, _ = client.WithAuthToken("fake").WithEnterpriseURLs(srv.URL+"/", srv.URL+"/")

	adapter, _ := NewProjectRepoPRCloser(client, "owner/project")
	err := adapter.CloseWithComment(context.Background(),
		coregit.PRRef{Project: "owner/project", Number: 99}, "reason")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if !strings.Contains(err.Error(), "check the PR number") {
		t.Errorf("error %q should contain actionable hint about PR number", err.Error())
	}
}

// TestFetchPRStateForReject_401Returns_ActionableError exercises the 401 auth
// branch so that expired-auth produces the re-auth hint.
func TestFetchPRStateForReject_401Returns_ActionableError(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/owner/project/pulls/55",
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
		})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := ghsdk.NewClient(nil)
	client, _ = client.WithAuthToken("fake").WithEnterpriseURLs(srv.URL+"/", srv.URL+"/")

	adapter, _ := NewProjectRepoPRCloser(client, "owner/project")
	_, err := adapter.FetchPRStateForReject(context.Background(),
		coregit.PRRef{Project: "owner/project", Number: 55})
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
	if !strings.Contains(err.Error(), "byreis auth login") {
		t.Errorf("error %q should mention byreis auth login", err.Error())
	}
}
