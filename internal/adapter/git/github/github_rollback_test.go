//go:build testhook

// Tests for the real RollbackSignedFile implementation (B3d-4 adapter half).
//
// Named obligations covered:
//   - N-11 (adapter half): foreign-commit-on-top (live tip != CommitSHA) =>
//     ErrRollbackAmbiguous, ZERO mutation calls, never a revert that drops or
//     reverts across the foreign commit.
//   - N-6 (adapter half): legitimate step-5-done/step-6-failed window (live tip
//     == CommitSHA) => reverts ONLY the identified signed-file commit (exactly
//     one revert mutation, no force-push, no history rewrite beyond it).
//   - PendingIdentity mismatch / empty + RollbackInput.Validate failures =>
//     ErrRollbackAmbiguous, no mutation.
//   - Auth failure (401) => actionable hint, NO token in the error string.
//   - Transient 5xx => bounded retry then fail-closed, no partial/unbounded retry.
//   - Context cancellation honored.
//   - Already-applied / commit-never-written => correct no-op nil (only when the
//     commit was never written), distinguished from the tip-mismatch refuse.
//   - The adapter does NOT consult PR-merged state to decide rollback: a
//     "PR merged" signal does not change the tip-guarded decision.
package github_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ghsdk "github.com/google/go-github/v72/github"

	githubadapter "github.com/ByReisK/byreis/internal/adapter/git/github"
	coregit "github.com/ByReisK/byreis/internal/core/git"
)

// rollbackSetup returns a Provider pointed at the given httptest mux. It uses
// the same testSetup helper already defined in github_test.go.
func rollbackProvider(t *testing.T, mux *http.ServeMux) *githubadapter.Provider {
	t.Helper()
	client := testSetup(t, mux)
	p, err := githubadapter.NewWithClient(client, "myorg/my-secrets", "main", "submissions")
	if err != nil {
		t.Fatalf("NewWithClient: %v", err)
	}
	return p
}

// registerRefHandler registers the GET base-branch ref endpoint on mux,
// returning tipSHA as the current tip.
func registerRefHandler(mux *http.ServeMux, tipSHA string) {
	mux.HandleFunc("/repos/myorg/my-secrets/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, ghsdk.Reference{
			Ref:    ptr("refs/heads/main"),
			Object: &ghsdk.GitObject{SHA: &tipSHA, Type: ptr("commit")},
		})
	})
}

// registerGetCommitHandler registers the GET /git/commits/:sha endpoint.
// If sha is in the known map, it returns the given Commit; otherwise 404.
func registerGetCommitHandler(mux *http.ServeMux, commits map[string]*ghsdk.Commit) {
	mux.HandleFunc("/repos/myorg/my-secrets/git/commits/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		sha := r.URL.Path[len("/repos/myorg/my-secrets/git/commits/"):]
		c, ok := commits[sha]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]any{"message": "Not Found"})
			return
		}
		writeJSON(w, c)
	})
}

// mutationCounter returns a handler that counts calls and always returns 500,
// so tests can assert no mutations were made.
func noMutationHandler(t *testing.T, counter *atomic.Int32, pattern string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			counter.Add(1)
			t.Errorf("unexpected mutation call to %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, "not expected", http.StatusInternalServerError)
	}
}

// ----- N-6 (adapter half): legitimate window, live tip == CommitSHA ----------
// Verifies:
//   - exactly one revert commit is created (CreateCommit call);
//   - the branch ref is advanced (UpdateRef call, non-force);
//   - no force-push (UpdateRef force flag = false);
//   - no other mutation calls.

func TestRollbackSignedFile_LegitimateWindow_RevertsOnlyIdentifiedCommit(t *testing.T) {
	t.Parallel()

	// The orphaned signed-file commit and its parent.
	const (
		orphanCommitSHA = "orphan-commit-sha-001"
		parentCommitSHA = "parent-commit-sha-000"
		parentTreeSHA   = "parent-tree-sha-000"
		revertCommitSHA = "revert-commit-sha-002"
	)

	mux := http.NewServeMux()

	// GET base-branch tip == orphanCommitSHA (the step-5-done window).
	registerRefHandler(mux, orphanCommitSHA)

	// GET git commits: orphan and its parent.
	commits := map[string]*ghsdk.Commit{
		orphanCommitSHA: {
			SHA:     ptr(orphanCommitSHA),
			Message: ptr("byreis: add signed file"),
			Tree:    &ghsdk.Tree{SHA: ptr("orphan-tree-sha")},
			Parents: []*ghsdk.Commit{{SHA: ptr(parentCommitSHA)}},
		},
		parentCommitSHA: {
			SHA:     ptr(parentCommitSHA),
			Message: ptr("previous commit"),
			Tree:    &ghsdk.Tree{SHA: ptr(parentTreeSHA)},
		},
	}
	registerGetCommitHandler(mux, commits)

	var createCommitCalled atomic.Int32
	var updateRefCalled atomic.Int32
	var updateRefForce atomic.Bool

	// POST /git/commits — create the revert commit.
	mux.HandleFunc("/repos/myorg/my-secrets/git/commits", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		createCommitCalled.Add(1)
		// Decode the request to verify it uses the parent's tree and parent = orphanCommitSHA.
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		tree, _ := body["tree"].(string)
		if tree != parentTreeSHA {
			t.Errorf("revert commit tree: got %q, want %q", tree, parentTreeSHA)
		}
		parents, _ := body["parents"].([]any)
		if len(parents) != 1 {
			t.Errorf("revert commit parents count: got %d, want 1", len(parents))
		} else if p, _ := parents[0].(string); p != orphanCommitSHA {
			t.Errorf("revert commit parent: got %q, want %q", p, orphanCommitSHA)
		}
		writeJSON(w, ghsdk.Commit{
			SHA:     ptr(revertCommitSHA),
			Message: ptr("Revert orphan-commit-sha-001"),
		})
	})

	// PATCH /git/refs/heads/main — advance the branch to revert commit.
	mux.HandleFunc("/repos/myorg/my-secrets/git/refs/heads/main", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		updateRefCalled.Add(1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		// Verify force is NOT set (or false) — no force-push.
		force, _ := body["force"].(bool)
		updateRefForce.Store(force)
		sha, _ := body["sha"].(string)
		if sha != revertCommitSHA {
			t.Errorf("UpdateRef sha: got %q, want %q", sha, revertCommitSHA)
		}
		writeJSON(w, ghsdk.Reference{
			Ref:    ptr("refs/heads/main"),
			Object: &ghsdk.GitObject{SHA: ptr(revertCommitSHA)},
		})
	})

	p := rollbackProvider(t, mux)

	err := p.RollbackSignedFile(context.Background(), coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 42},
		CommitSHA:       orphanCommitSHA,
		PendingIdentity: "pending-identity-abc",
	})
	if err != nil {
		t.Fatalf("RollbackSignedFile: unexpected error: %v", err)
	}

	if n := createCommitCalled.Load(); n != 1 {
		t.Errorf("CreateCommit called %d times, want exactly 1", n)
	}
	if n := updateRefCalled.Load(); n != 1 {
		t.Errorf("UpdateRef called %d times, want exactly 1", n)
	}
	if updateRefForce.Load() {
		t.Error("UpdateRef called with force=true — must not force-push")
	}
}

// ----- N-11 (adapter half): foreign-commit-on-top => ErrRollbackAmbiguous -----
// Live tip != CommitSHA. Zero mutation calls. Never a revert across the foreign
// commit.

func TestRollbackSignedFile_ForeignCommitOnTop_ErrRollbackAmbiguous(t *testing.T) {
	t.Parallel()

	const (
		orphanCommitSHA  = "orphan-commit-sha-100"
		foreignCommitSHA = "foreign-commit-sha-101" // this is on top of the orphan
	)

	mux := http.NewServeMux()

	// Live tip is the foreign commit — NOT the orphan.
	registerRefHandler(mux, foreignCommitSHA)

	// The orphan commit exists (it was written) but has something on top.
	commits := map[string]*ghsdk.Commit{
		orphanCommitSHA: {
			SHA:     ptr(orphanCommitSHA),
			Message: ptr("byreis: add signed file"),
			Tree:    &ghsdk.Tree{SHA: ptr("orphan-tree")},
			Parents: []*ghsdk.Commit{{SHA: ptr("pre-orphan-sha")}},
		},
		foreignCommitSHA: {
			SHA:     ptr(foreignCommitSHA),
			Message: ptr("foreign work"),
			Tree:    &ghsdk.Tree{SHA: ptr("foreign-tree")},
			Parents: []*ghsdk.Commit{{SHA: ptr(orphanCommitSHA)}},
		},
	}
	registerGetCommitHandler(mux, commits)

	var mutationCount atomic.Int32
	// Any CreateCommit or UpdateRef call is a test failure (no mutation allowed).
	mux.HandleFunc("/repos/myorg/my-secrets/git/commits", noMutationHandler(t, &mutationCount, "create commit"))
	mux.HandleFunc("/repos/myorg/my-secrets/git/refs/heads/main", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutationCount.Add(1)
			t.Errorf("unexpected mutation: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not expected", http.StatusInternalServerError)
			return
		}
		http.Error(w, "should not be GETting this in the N-11 path", http.StatusInternalServerError)
	})

	p := rollbackProvider(t, mux)

	err := p.RollbackSignedFile(context.Background(), coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 42},
		CommitSHA:       orphanCommitSHA,
		PendingIdentity: "pending-identity-abc",
	})

	if err == nil {
		t.Fatal("want ErrRollbackAmbiguous for foreign-commit-on-top, got nil")
	}
	if !errors.Is(err, coregit.ErrRollbackAmbiguous) {
		t.Errorf("want ErrRollbackAmbiguous, got %v", err)
	}
	if n := mutationCount.Load(); n > 0 {
		t.Errorf("mutation was performed (%d calls) — must be zero for foreign-commit-on-top", n)
	}
}

// ----- PendingIdentity empty => ErrRollbackAmbiguous, no mutation -------------

func TestRollbackSignedFile_EmptyPendingIdentity_ErrRollbackAmbiguous(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	var mutationCount atomic.Int32
	mux.HandleFunc("/repos/myorg/my-secrets/git/commits", noMutationHandler(t, &mutationCount, "create commit"))

	p := rollbackProvider(t, mux)
	err := p.RollbackSignedFile(context.Background(), coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 1},
		CommitSHA:       "some-sha",
		PendingIdentity: "", // empty — structural failure
	})
	if err == nil {
		t.Fatal("want ErrRollbackAmbiguous for empty PendingIdentity, got nil")
	}
	if !errors.Is(err, coregit.ErrRollbackAmbiguous) {
		t.Errorf("want ErrRollbackAmbiguous, got %v", err)
	}
	if n := mutationCount.Load(); n > 0 {
		t.Errorf("unexpected mutation calls: %d", n)
	}
}

// ----- Empty CommitSHA => ErrRollbackAmbiguous, no mutation -------------------

func TestRollbackSignedFile_EmptyCommitSHA_ErrRollbackAmbiguous(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	var mutationCount atomic.Int32
	mux.HandleFunc("/repos/myorg/my-secrets/git/commits", noMutationHandler(t, &mutationCount, "create commit"))

	p := rollbackProvider(t, mux)
	err := p.RollbackSignedFile(context.Background(), coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 1},
		CommitSHA:       "", // empty — structural failure
		PendingIdentity: "pending-identity",
	})
	if err == nil {
		t.Fatal("want ErrRollbackAmbiguous for empty CommitSHA, got nil")
	}
	if !errors.Is(err, coregit.ErrRollbackAmbiguous) {
		t.Errorf("want ErrRollbackAmbiguous, got %v", err)
	}
	if n := mutationCount.Load(); n > 0 {
		t.Errorf("unexpected mutation calls: %d", n)
	}
}

// ----- Empty project / invalid ref => ErrRollbackAmbiguous -------------------

func TestRollbackSignedFile_InvalidInput_ErrRollbackAmbiguous(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	p := rollbackProvider(t, mux)

	// PR number 0 is invalid per RollbackInput.Validate.
	err := p.RollbackSignedFile(context.Background(), coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 0},
		CommitSHA:       "sha",
		PendingIdentity: "pending",
	})
	if err == nil {
		t.Fatal("want ErrRollbackAmbiguous for invalid PR number, got nil")
	}
	if !errors.Is(err, coregit.ErrRollbackAmbiguous) {
		t.Errorf("want ErrRollbackAmbiguous, got %v", err)
	}
}

// ----- Commit never written => no-op nil -------------------------------------
// CommitSHA was never written to the branch: GetRef returns a tip that is NOT
// CommitSHA, and GetCommit(CommitSHA) returns 404.

func TestRollbackSignedFile_CommitNeverWritten_NoOp(t *testing.T) {
	t.Parallel()

	const (
		tipSHA   = "current-tip-sha-200"
		neverSHA = "never-written-sha-201"
	)

	mux := http.NewServeMux()

	// Live tip is something else entirely.
	registerRefHandler(mux, tipSHA)

	// The CommitSHA was never written: GetCommit returns 404.
	registerGetCommitHandler(mux, map[string]*ghsdk.Commit{
		tipSHA: {
			SHA:     ptr(tipSHA),
			Message: ptr("some unrelated commit"),
			Tree:    &ghsdk.Tree{SHA: ptr("tip-tree")},
		},
		// neverSHA is absent from the map — 404 response.
	})

	var mutationCount atomic.Int32
	mux.HandleFunc("/repos/myorg/my-secrets/git/commits", noMutationHandler(t, &mutationCount, "create commit"))
	mux.HandleFunc("/repos/myorg/my-secrets/git/refs/heads/main", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mutationCount.Add(1)
			t.Errorf("unexpected mutation: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not expected", http.StatusInternalServerError)
		}
	})

	p := rollbackProvider(t, mux)

	err := p.RollbackSignedFile(context.Background(), coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 42},
		CommitSHA:       neverSHA,
		PendingIdentity: "pending-identity-xyz",
	})
	if err != nil {
		t.Fatalf("RollbackSignedFile: want nil (no-op) for never-written commit, got %v", err)
	}
	if n := mutationCount.Load(); n > 0 {
		t.Errorf("unexpected mutation calls: %d (want 0 for never-written no-op)", n)
	}
}

// ----- Auth failure (401) => actionable hint, no token in error ---------------

func TestRollbackSignedFile_AuthFailure_ActionableHintNoTokenLeak(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()

	// The GetRef call for the base branch tip returns 401.
	mux.HandleFunc("/repos/myorg/my-secrets/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"message": "Bad credentials"})
	})

	p := rollbackProvider(t, mux)
	err := p.RollbackSignedFile(context.Background(), coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 7},
		CommitSHA:       "some-sha",
		PendingIdentity: "some-pending",
	})
	if err == nil {
		t.Fatal("want error for 401, got nil")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "byreis auth login") {
		t.Errorf("error must contain 'byreis auth login' hint, got: %q", errStr)
	}
	// Token must not appear in the error string.
	if strings.Contains(errStr, "test-token") || strings.Contains(strings.ToLower(errStr), "bearer") {
		t.Errorf("error leaks token material: %q", errStr)
	}
}

// ----- Transient 5xx => bounded retry then fail-closed -----------------------

func TestRollbackSignedFile_Transient5xx_BoundedRetryThenFailClosed(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()

	var callCount atomic.Int32
	mux.HandleFunc("/repos/myorg/my-secrets/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"message": "internal server error"})
	})

	p := rollbackProvider(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := p.RollbackSignedFile(ctx, coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 7},
		CommitSHA:       "some-sha",
		PendingIdentity: "some-pending",
	})
	if err == nil {
		t.Fatal("want error after retries exhausted, got nil")
	}
	got := int(callCount.Load())
	// 1 initial + up to maxRetries (3) = 4 total calls.
	if got < 1 {
		t.Errorf("retry made %d calls (want ≥1)", got)
	}
	if got > 4 {
		t.Errorf("retry is unbounded: made %d calls (want ≤4)", got)
	}
}

// ----- Context cancellation honored ------------------------------------------

func TestRollbackSignedFile_CtxCancel_Honored(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()

	// Slow handler — blocks until client context is cancelled.
	mux.HandleFunc("/repos/myorg/my-secrets/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
			writeJSON(w, ghsdk.Reference{
				Ref:    ptr("refs/heads/main"),
				Object: &ghsdk.GitObject{SHA: ptr("sha"), Type: ptr("commit")},
			})
		}
	})

	p := rollbackProvider(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	err := p.RollbackSignedFile(ctx, coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 1},
		CommitSHA:       "sha",
		PendingIdentity: "pending",
	})
	if err == nil {
		t.Fatal("want error on context cancellation, got nil")
	}
}

// ----- PR-merged signal does NOT change the tip-guarded decision --------------
// A "PR merged" scenario where the branch has already advanced (tip != CommitSHA)
// still results in ErrRollbackAmbiguous regardless of what the PR state is.
// The adapter makes NO call to the PR endpoint to decide.

func TestRollbackSignedFile_PRMergedSignal_DoesNotChangeTipGuardedDecision(t *testing.T) {
	t.Parallel()

	const (
		orphanCommitSHA = "orphan-commit-sha-300"
		mergedTipSHA    = "merged-tip-sha-301" // PR was merged; this is the merged tip
	)

	mux := http.NewServeMux()
	var prAPICalled atomic.Bool

	// Live tip is the merged tip, NOT the orphan (PR was merged, tip advanced).
	registerRefHandler(mux, mergedTipSHA)

	// The orphan commit exists.
	commits := map[string]*ghsdk.Commit{
		orphanCommitSHA: {
			SHA:     ptr(orphanCommitSHA),
			Message: ptr("byreis: signed file commit"),
			Tree:    &ghsdk.Tree{SHA: ptr("orphan-tree")},
			Parents: []*ghsdk.Commit{{SHA: ptr("pre-orphan")}},
		},
		mergedTipSHA: {
			SHA:     ptr(mergedTipSHA),
			Message: ptr("Merge pull request"),
			Tree:    &ghsdk.Tree{SHA: ptr("merged-tree")},
			Parents: []*ghsdk.Commit{{SHA: ptr(orphanCommitSHA)}},
		},
	}
	registerGetCommitHandler(mux, commits)

	// Register a PR endpoint that records if it's ever called.
	mux.HandleFunc("/repos/myorg/my-secrets/pulls/42", func(w http.ResponseWriter, r *http.Request) {
		prAPICalled.Store(true)
		// Return "merged" to simulate the merged-after-timeout scenario.
		writeJSON(w, ghsdk.PullRequest{
			Number: ptr(42),
			Merged: ptr(true),
			MergedAt: func() *ghsdk.Timestamp {
				ts := ghsdk.Timestamp{}
				return &ts
			}(),
		})
	})

	var mutationCount atomic.Int32
	mux.HandleFunc("/repos/myorg/my-secrets/git/commits", noMutationHandler(t, &mutationCount, "create commit"))

	p := rollbackProvider(t, mux)

	err := p.RollbackSignedFile(context.Background(), coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 42},
		CommitSHA:       orphanCommitSHA,
		PendingIdentity: "pending-identity-abc",
	})

	// Even though the PR is "merged", the tip-guard fires first.
	// tip (mergedTipSHA) != CommitSHA (orphanCommitSHA) => ErrRollbackAmbiguous.
	if err == nil {
		t.Fatal("want ErrRollbackAmbiguous when tip != CommitSHA, got nil")
	}
	if !errors.Is(err, coregit.ErrRollbackAmbiguous) {
		t.Errorf("want ErrRollbackAmbiguous, got %v", err)
	}
	if n := mutationCount.Load(); n > 0 {
		t.Errorf("unexpected mutation calls: %d", n)
	}
	// The adapter must NOT have consulted the PR endpoint to decide.
	if prAPICalled.Load() {
		t.Error("adapter consulted the PR API endpoint to decide rollback — must use tip guard only")
	}
}

// ----- CreateCommit 5xx during revert => fail-closed -------------------------

func TestRollbackSignedFile_CreateCommitFails_FailClosed(t *testing.T) {
	t.Parallel()

	const (
		orphanCommitSHA = "orphan-commit-sha-400"
		parentCommitSHA = "parent-commit-sha-399"
		parentTreeSHA   = "parent-tree-sha-399"
	)

	mux := http.NewServeMux()

	// Live tip == orphanCommitSHA (legitimate window).
	registerRefHandler(mux, orphanCommitSHA)

	commits := map[string]*ghsdk.Commit{
		orphanCommitSHA: {
			SHA:     ptr(orphanCommitSHA),
			Message: ptr("byreis: add signed file"),
			Tree:    &ghsdk.Tree{SHA: ptr("orphan-tree")},
			Parents: []*ghsdk.Commit{{SHA: ptr(parentCommitSHA)}},
		},
		parentCommitSHA: {
			SHA:     ptr(parentCommitSHA),
			Message: ptr("previous"),
			Tree:    &ghsdk.Tree{SHA: ptr(parentTreeSHA)},
		},
	}
	registerGetCommitHandler(mux, commits)

	// CreateCommit fails with 5xx.
	mux.HandleFunc("/repos/myorg/my-secrets/git/commits", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"message": "server error"})
	})

	// UpdateRef must NOT be called.
	var updateRefCalled atomic.Int32
	mux.HandleFunc("/repos/myorg/my-secrets/git/refs/heads/main", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			updateRefCalled.Add(1)
			t.Errorf("UpdateRef called despite CreateCommit failure: %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})

	p := rollbackProvider(t, mux)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := p.RollbackSignedFile(ctx, coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 5},
		CommitSHA:       orphanCommitSHA,
		PendingIdentity: "pending-identity-abc",
	})
	if err == nil {
		t.Fatal("want error when CreateCommit fails, got nil")
	}
	if n := updateRefCalled.Load(); n > 0 {
		t.Errorf("UpdateRef was called %d times after CreateCommit failure — must not advance branch on partial failure", n)
	}
}

// ----- UpdateRef (non-force) fails => error, consistent state -----------------

func TestRollbackSignedFile_UpdateRefFails_Error(t *testing.T) {
	t.Parallel()

	const (
		orphanCommitSHA = "orphan-commit-sha-500"
		parentCommitSHA = "parent-commit-sha-499"
		parentTreeSHA   = "parent-tree-sha-499"
		revertCommitSHA = "revert-commit-sha-501"
	)

	mux := http.NewServeMux()

	registerRefHandler(mux, orphanCommitSHA)

	commits := map[string]*ghsdk.Commit{
		orphanCommitSHA: {
			SHA:     ptr(orphanCommitSHA),
			Message: ptr("byreis: signed"),
			Tree:    &ghsdk.Tree{SHA: ptr("orphan-tree")},
			Parents: []*ghsdk.Commit{{SHA: ptr(parentCommitSHA)}},
		},
		parentCommitSHA: {
			SHA:     ptr(parentCommitSHA),
			Message: ptr("parent"),
			Tree:    &ghsdk.Tree{SHA: ptr(parentTreeSHA)},
		},
	}
	registerGetCommitHandler(mux, commits)

	mux.HandleFunc("/repos/myorg/my-secrets/git/commits", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, ghsdk.Commit{
			SHA: ptr(revertCommitSHA),
		})
	})

	// UpdateRef fails.
	mux.HandleFunc("/repos/myorg/my-secrets/git/refs/heads/main", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusInternalServerError)
			writeJSON(w, map[string]any{"message": "conflict"})
			return
		}
		http.Error(w, "unexpected GET", http.StatusInternalServerError)
	})

	p := rollbackProvider(t, mux)

	err := p.RollbackSignedFile(context.Background(), coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/my-secrets", Number: 5},
		CommitSHA:       orphanCommitSHA,
		PendingIdentity: "pending-identity-def",
	})
	if err == nil {
		t.Fatal("want error when UpdateRef fails, got nil")
	}
}
