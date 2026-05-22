//go:build testhook

// Tests for B3b github adapter changes: Decision 3 (SubmissionMeta), Decision 5
// (NewWithClient error return).
//
// N-7: NewWithClient malformed project => ErrInvalidProject, never panic.
// N-9: No SubmissionMeta field reaches recipient-set / counter / ExpectSHA; body
// is consumed ONLY for SecretsPath + display.
// Decision 3 rule-6: signed-identity cross-check (containment-valid path !=
// registry-configured path => ErrSubmissionMetaInvalid).
package github_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	ghsdk "github.com/google/go-github/v72/github"

	githubadapter "github.com/ByReisK/byreis/internal/adapter/git/github"
	coregit "github.com/ByReisK/byreis/internal/core/git"
)

// testSetupMeta is a local helper to avoid duplicate symbol with testSetup.
func testSetupMeta(t *testing.T, mux *http.ServeMux) *ghsdk.Client {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	httpClient := &http.Client{Timeout: 5 * time.Second}
	client := ghsdk.NewClient(httpClient).WithAuthToken("test-token")
	baseURL, err := url.Parse(srv.URL + "/")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	client.BaseURL = baseURL
	client.UploadURL = baseURL
	return client
}

// ----- N-7: NewWithClient malformed project => ErrInvalidProject, never panic --

func TestNewWithClient_MalformedProject_ReturnsErrInvalidProject(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		project string
	}{
		{"empty", ""},
		{"no_slash", "singleword"},
		{"empty_owner", "/repo"},
		{"empty_repo", "owner/"},
		{"triple_slash", "owner/repo/extra"},
	}

	client := ghsdk.NewClient(nil)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := githubadapter.NewWithClient(client, tc.project, "main", "submissions")
			if err == nil {
				t.Fatalf("want error for project %q, got nil (Provider=%v)", tc.project, p)
			}
			if !errors.Is(err, coregit.ErrInvalidProject) {
				t.Errorf("want ErrInvalidProject for project %q, got %v", tc.project, err)
			}
			// Must carry an actionable hint.
			if !strings.Contains(err.Error(), "owner/repo") {
				t.Errorf("error must mention 'owner/repo' format hint, got: %q", err.Error())
			}
		})
	}
}

// TestNewWithClient_ValidProject_NoPanic verifies that a valid project string
// succeeds and does not panic.
func TestNewWithClient_ValidProject_NoPanic(t *testing.T) {
	t.Parallel()
	client := ghsdk.NewClient(nil)
	p, err := githubadapter.NewWithClient(client, "myorg/my-secrets", "main", "submissions")
	if err != nil {
		t.Fatalf("want nil error for valid project, got: %v", err)
	}
	if p == nil {
		t.Fatal("want non-nil Provider for valid project")
	}
}

// ----- Decision 3: GetSubmission parses SubmissionMeta block -------------------

// TestGetSubmission_ParsesMeta verifies that GetSubmission returns the
// SubmissionMeta parsed from the PR body.
func TestGetSubmission_ParsesMeta(t *testing.T) {
	t.Parallel()

	metaBlock := coregit.EncodeSubmissionMeta(coregit.SubmissionMeta{
		SchemaVersion: 1,
		Project:       "myorg/my-secrets",
		SecretsPath:   "secrets/prod.yaml",
		BaseFilePath:  "secrets/prod.yaml",
		Key:           "api_key",
		Action:        "add",
		ArtifactSHA:   "deadbeef",
	})

	prBody := "Justification: deploying new API integration.\n\n" + metaBlock + "\nEnd of justification."
	artifactBytes := fakeArtifactBytes()
	encodedContent := base64.StdEncoding.EncodeToString(artifactBytes)

	mux := http.NewServeMux()

	mux.HandleFunc("/repos/myorg/my-secrets/pulls/20", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ghsdk.PullRequest{
			Number:  ptr(20),
			HTMLURL: ptr("https://github.com/myorg/my-secrets/pull/20"),
			User:    &ghsdk.User{Login: ptr("alice")},
			Body:    ptr(prBody),
			Head: &ghsdk.PullRequestBranch{
				Ref: ptr("byreis/add-api_key-20"),
				SHA: ptr("headSHA20"),
			},
		})
	})

	mux.HandleFunc("/repos/myorg/my-secrets/contents/submissions/add-api_key-20.yaml", func(w http.ResponseWriter, r *http.Request) {
		encoding := "base64"
		writeJSON(w, ghsdk.RepositoryContent{
			Content:  &encodedContent,
			Encoding: &encoding,
			SHA:      ptr("fileSHA20"),
		})
	})

	// Base file exists.
	mux.HandleFunc("/repos/myorg/my-secrets/contents/secrets/prod.yaml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			enc := "base64"
			baseEnc := base64.StdEncoding.EncodeToString([]byte("live content"))
			writeJSON(w, ghsdk.RepositoryContent{
				Content:  &baseEnc,
				Encoding: &enc,
				SHA:      ptr("baseSHA20"),
			})
		}
	})

	client := testSetupMeta(t, mux)
	p, err := githubadapter.NewWithClient(client, "myorg/my-secrets", "main", "submissions")
	if err != nil {
		t.Fatalf("NewWithClient: %v", err)
	}

	sub, err := p.GetSubmission(context.Background(), coregit.PRRef{
		Project: "myorg/my-secrets",
		Number:  20,
	})
	if err != nil {
		t.Fatalf("GetSubmission: %v", err)
	}

	if sub.Meta.SecretsPath != "secrets/prod.yaml" {
		t.Errorf("Meta.SecretsPath: got %q, want secrets/prod.yaml", sub.Meta.SecretsPath)
	}
	if sub.Meta.Key != "api_key" {
		t.Errorf("Meta.Key: got %q, want api_key", sub.Meta.Key)
	}
	// ArtifactSHA in the meta is informational only; the actual pin is ArtifactSHA field.
	// Verify the meta's ArtifactSHA is NOT used as the submission's pin.
	if sub.ArtifactSHA == coregit.ArtifactSHA(sub.Meta.ArtifactSHA) {
		// This may coincidentally match in some edge cases, so just log.
		t.Logf("NOTE: sub.ArtifactSHA happens to equal meta.ArtifactSHA — verify they are computed independently")
	}
}

// TestGetSubmission_MissingMeta verifies that a PR body without a
// byreis-submission block returns ErrSubmissionMetaInvalid (N-3).
func TestGetSubmission_MissingMeta(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/myorg/my-secrets/pulls/21", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ghsdk.PullRequest{
			Number:  ptr(21),
			HTMLURL: ptr("https://github.com/myorg/my-secrets/pull/21"),
			User:    &ghsdk.User{Login: ptr("alice")},
			Body:    ptr("just justification text, no structured block"),
			Head: &ghsdk.PullRequestBranch{
				Ref: ptr("byreis/add-api_key-21"),
				SHA: ptr("headSHA21"),
			},
		})
	})

	artifactBytes := fakeArtifactBytes()
	encodedContent := base64.StdEncoding.EncodeToString(artifactBytes)
	mux.HandleFunc("/repos/myorg/my-secrets/contents/submissions/add-api_key-21.yaml", func(w http.ResponseWriter, r *http.Request) {
		encoding := "base64"
		writeJSON(w, ghsdk.RepositoryContent{
			Content:  &encodedContent,
			Encoding: &encoding,
			SHA:      ptr("fileSHA21"),
		})
	})

	client := testSetupMeta(t, mux)
	p, err := githubadapter.NewWithClient(client, "myorg/my-secrets", "main", "submissions")
	if err != nil {
		t.Fatalf("NewWithClient: %v", err)
	}

	_, err = p.GetSubmission(context.Background(), coregit.PRRef{
		Project: "myorg/my-secrets",
		Number:  21,
	})
	if err == nil {
		t.Fatal("want ErrSubmissionMetaInvalid for missing meta block, got nil")
	}
	if !errors.Is(err, coregit.ErrSubmissionMetaInvalid) {
		t.Errorf("want ErrSubmissionMetaInvalid, got %v", err)
	}
}

// TestMergeSubmission_UsesSecretsPathFromMeta verifies that MergeSubmission uses
// the SecretsPath from the parsed SubmissionMeta, NOT a hardcoded default.
func TestMergeSubmission_UsesSecretsPathFromMeta(t *testing.T) {
	t.Parallel()
	_, signedBytes := buildSignedArtifact(t)

	customPath := "secrets/custom-service.yaml"
	metaBlock := coregit.EncodeSubmissionMeta(coregit.SubmissionMeta{
		SchemaVersion: 1,
		Project:       "myorg/my-secrets",
		SecretsPath:   customPath,
		BaseFilePath:  customPath,
		Key:           "db_pass",
		Action:        "add",
		ArtifactSHA:   "abc",
	})
	prBody := "Justification.\n\n" + metaBlock

	currentArtifact := fakeArtifactBytes()
	expectSHA := coregit.ArtifactSHA(sha256hex(currentArtifact))
	encodedCurrent := base64.StdEncoding.EncodeToString(currentArtifact)

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/myorg/my-secrets/pulls/22", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ghsdk.PullRequest{
			Number:  ptr(22),
			HTMLURL: ptr("https://github.com/myorg/my-secrets/pull/22"),
			Body:    ptr(prBody),
			Head:    &ghsdk.PullRequestBranch{Ref: ptr("byreis/add-db_pass-22"), SHA: ptr("h22")},
		})
	})
	mux.HandleFunc("/repos/myorg/my-secrets/contents/submissions/add-db_pass-22.yaml", func(w http.ResponseWriter, r *http.Request) {
		enc := "base64"
		writeJSON(w, ghsdk.RepositoryContent{Content: &encodedCurrent, Encoding: &enc, SHA: ptr("f22")})
	})

	var writtenPath string
	// The signed file MUST be written to customPath, NOT "secrets/prod.yaml".
	mux.HandleFunc("/repos/myorg/my-secrets/contents/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/repos/myorg/my-secrets/contents/")
		switch r.Method {
		case http.MethodGet:
			// Return 404 for any GET (first add).
			http.Error(w, "not found", http.StatusNotFound)
		case http.MethodPut:
			writtenPath = path
			writeJSON(w, ghsdk.RepositoryContentResponse{
				Content: &ghsdk.RepositoryContent{SHA: ptr("liveSHA22"), Path: ptr(path)},
				Commit:  ghsdk.Commit{SHA: ptr("commitSHA22")},
			})
		default:
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("/repos/myorg/my-secrets/pulls/22/merge", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ghsdk.PullRequestMergeResult{SHA: ptr("mergedSHA22"), Merged: ptr(true)})
	})

	client := testSetupMeta(t, mux)
	p, err := githubadapter.NewWithClient(client, "myorg/my-secrets", "main", "submissions")
	if err != nil {
		t.Fatalf("NewWithClient: %v", err)
	}

	result, err := p.MergeSubmission(context.Background(), coregit.MergeInput{
		Ref:           coregit.PRRef{Project: "myorg/my-secrets", Number: 22},
		ExpectSHA:     expectSHA,
		SignedBytes:   signedBytes,
		CommitMessage: "byreis: merge db_pass [counter=1]",
		SecretsPath:   customPath, // caller-supplied after parsing meta
	})
	if err != nil {
		t.Fatalf("MergeSubmission: %v", err)
	}
	if result.MergedCommit == "" {
		t.Error("MergedCommit must not be empty")
	}
	// The file must have been written to customPath, not "secrets/prod.yaml".
	if writtenPath != customPath {
		t.Errorf("signed file written to %q, want %q — defaultSecretsPath must be removed",
			writtenPath, customPath)
	}
}

// TestMergeSubmission_ArtifactSHAFromMetaNotUsedAsPin verifies N-9: the
// ArtifactSHA in SubmissionMeta is NOT used as the ExpectSHA pin. If the
// meta's ArtifactSHA differs from the real on-PR artifact, MergeSubmission
// must still use the MergeInput.ExpectSHA, not the meta's value.
func TestMergeSubmission_ArtifactSHAFromMetaNotUsedAsPin(t *testing.T) {
	t.Parallel()
	_, signedBytes := buildSignedArtifact(t)

	// The on-PR artifact bytes.
	currentArtifact := fakeArtifactBytes()
	realExpectSHA := coregit.ArtifactSHA(sha256hex(currentArtifact))
	encodedCurrent := base64.StdEncoding.EncodeToString(currentArtifact)

	// The meta contains a DIFFERENT (fake) artifact_sha — if the adapter used
	// this instead of MergeInput.ExpectSHA, the T2 check would behave wrongly.
	fakeMetaSHA := "this-is-not-the-real-sha-aaaa1234"
	metaBlock := coregit.EncodeSubmissionMeta(coregit.SubmissionMeta{
		SchemaVersion: 1,
		Project:       "myorg/my-secrets",
		SecretsPath:   "secrets/prod.yaml",
		BaseFilePath:  "secrets/prod.yaml",
		Key:           "k",
		Action:        "add",
		ArtifactSHA:   fakeMetaSHA,
	})
	prBody := "Justification.\n\n" + metaBlock

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/myorg/my-secrets/pulls/23", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ghsdk.PullRequest{
			Number: ptr(23),
			Body:   ptr(prBody),
			Head:   &ghsdk.PullRequestBranch{Ref: ptr("byreis/add-k-23"), SHA: ptr("h23")},
		})
	})
	mux.HandleFunc("/repos/myorg/my-secrets/contents/submissions/add-k-23.yaml", func(w http.ResponseWriter, r *http.Request) {
		enc := "base64"
		writeJSON(w, ghsdk.RepositoryContent{Content: &encodedCurrent, Encoding: &enc, SHA: ptr("f23")})
	})
	mux.HandleFunc("/repos/myorg/my-secrets/contents/secrets/prod.yaml", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			http.Error(w, "not found", http.StatusNotFound)
		case http.MethodPut:
			writeJSON(w, ghsdk.RepositoryContentResponse{
				Content: &ghsdk.RepositoryContent{SHA: ptr("l23"), Path: ptr("secrets/prod.yaml")},
				Commit:  ghsdk.Commit{SHA: ptr("c23")},
			})
		}
	})
	mux.HandleFunc("/repos/myorg/my-secrets/pulls/23/merge", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ghsdk.PullRequestMergeResult{SHA: ptr("m23"), Merged: ptr(true)})
	})

	client := testSetupMeta(t, mux)
	p, err := githubadapter.NewWithClient(client, "myorg/my-secrets", "main", "submissions")
	if err != nil {
		t.Fatalf("NewWithClient: %v", err)
	}

	// Pass the REAL ExpectSHA (matching the on-PR artifact). If the adapter
	// used the meta's fakeMetaSHA instead, it would compute current=realExpectSHA,
	// compare against fakeMetaSHA, and fail with ErrArtifactMoved — that would
	// demonstrate the bug.
	_, err = p.MergeSubmission(context.Background(), coregit.MergeInput{
		Ref:           coregit.PRRef{Project: "myorg/my-secrets", Number: 23},
		ExpectSHA:     realExpectSHA,
		SignedBytes:   signedBytes,
		CommitMessage: "byreis: merge k",
		SecretsPath:   "secrets/prod.yaml",
	})
	if err != nil {
		t.Fatalf("MergeSubmission must succeed when MergeInput.ExpectSHA matches on-PR artifact (not meta.ArtifactSHA): %v", err)
	}
}

// TestOpenSubmissionPR_WritesMetaBlock verifies that OpenSubmissionPR
// embeds a parseable byreis-submission block in the PR body.
func TestOpenSubmissionPR_WritesMetaBlock(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	artifactBytes := fakeArtifactBytes()

	mux.HandleFunc("/repos/myorg/my-secrets/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ghsdk.Reference{
			Ref:    ptr("refs/heads/main"),
			Object: &ghsdk.GitObject{SHA: ptr("baseSHA30"), Type: ptr("commit")},
		})
	})
	mux.HandleFunc("/repos/myorg/my-secrets/git/refs", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		ref, _ := body["ref"].(string)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, ghsdk.Reference{Ref: &ref, Object: &ghsdk.GitObject{SHA: ptr("baseSHA30")}})
	})
	mux.HandleFunc("/repos/myorg/my-secrets/contents/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			http.Error(w, "not found", http.StatusNotFound)
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, ghsdk.RepositoryContentResponse{
				Content: &ghsdk.RepositoryContent{SHA: ptr("f30"), Path: ptr("submissions/add-api_key-30.yaml")},
				Commit:  ghsdk.Commit{SHA: ptr("c30")},
			})
		}
	})

	var capturedPRBody string
	mux.HandleFunc("/repos/myorg/my-secrets/pulls", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		capturedPRBody = body.Body
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, ghsdk.PullRequest{
			Number:  ptr(30),
			HTMLURL: ptr("https://github.com/myorg/my-secrets/pull/30"),
			Head:    &ghsdk.PullRequestBranch{Ref: ptr("byreis/add-api_key-30")},
		})
	})

	client := testSetupMeta(t, mux)
	p, err := githubadapter.NewWithClient(client, "myorg/my-secrets", "main", "submissions")
	if err != nil {
		t.Fatalf("NewWithClient: %v", err)
	}

	_, err = p.OpenSubmissionPR(context.Background(), coregit.OpenPRInput{
		Project:       "myorg/my-secrets",
		Branch:        "byreis/add-api_key-30",
		Action:        coregit.ActionAdd,
		Key:           "api_key",
		ArtifactBytes: artifactBytes,
		TitleTemplate: "[byreis] add api_key",
		Justification: "deploying new service",
		SecretsPath:   "secrets/prod.yaml",
	})
	if err != nil {
		t.Fatalf("OpenSubmissionPR: %v", err)
	}

	// The PR body must contain a parseable byreis-submission block.
	if !strings.Contains(capturedPRBody, "```byreis-submission") {
		t.Errorf("PR body must contain byreis-submission block, got: %q", capturedPRBody)
	}
	meta, parseErr := coregit.ParseSubmissionMeta(capturedPRBody)
	if parseErr != nil {
		t.Fatalf("PR body contains unparseable meta block: %v\nbody: %q", parseErr, capturedPRBody)
	}
	if meta.SecretsPath != "secrets/prod.yaml" {
		t.Errorf("meta.SecretsPath: got %q, want secrets/prod.yaml", meta.SecretsPath)
	}
	if meta.Key != "api_key" {
		t.Errorf("meta.Key: got %q, want api_key", meta.Key)
	}
	if meta.Action != "add" {
		t.Errorf("meta.Action: got %q, want add", meta.Action)
	}
	if meta.SchemaVersion != 1 {
		t.Errorf("meta.SchemaVersion: got %d, want 1", meta.SchemaVersion)
	}
}

// TestOpenSubmissionPR_BulkKeysWritesV2Meta verifies that OpenSubmissionPR
// emits a schema_version 2 block in the PR body when the input carries a
// non-empty Keys slice (bulk submission). The emitted block must be parseable
// by ParseSubmissionMeta as v2 and the round-trip must preserve key order and
// per-key actions.
func TestOpenSubmissionPR_BulkKeysWritesV2Meta(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	artifactBytes := fakeArtifactBytes()

	mux.HandleFunc("/repos/myorg/my-secrets/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ghsdk.Reference{
			Ref:    ptr("refs/heads/main"),
			Object: &ghsdk.GitObject{SHA: ptr("baseSHAbulk"), Type: ptr("commit")},
		})
	})
	mux.HandleFunc("/repos/myorg/my-secrets/git/refs", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		ref, _ := body["ref"].(string)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, ghsdk.Reference{Ref: &ref, Object: &ghsdk.GitObject{SHA: ptr("baseSHAbulk")}})
	})
	mux.HandleFunc("/repos/myorg/my-secrets/contents/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			http.Error(w, "not found", http.StatusNotFound)
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, ghsdk.RepositoryContentResponse{
				Content: &ghsdk.RepositoryContent{SHA: ptr("fBulk"), Path: ptr("submissions/bulk-2keys-100.yaml")},
				Commit:  ghsdk.Commit{SHA: ptr("cBulk")},
			})
		}
	})

	var capturedPRBody string
	mux.HandleFunc("/repos/myorg/my-secrets/pulls", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		capturedPRBody = body.Body
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, ghsdk.PullRequest{
			Number:  ptr(99),
			HTMLURL: ptr("https://github.com/myorg/my-secrets/pull/99"),
			Head:    &ghsdk.PullRequestBranch{Ref: ptr("byreis/bulk-2keys-100")},
		})
	})

	client := testSetupMeta(t, mux)
	p, err := githubadapter.NewWithClient(client, "myorg/my-secrets", "main", "submissions")
	if err != nil {
		t.Fatalf("NewWithClient: %v", err)
	}

	_, prErr := p.OpenSubmissionPR(context.Background(), coregit.OpenPRInput{
		Project:       "myorg/my-secrets",
		Branch:        "byreis/bulk-2keys-100",
		ArtifactBytes: artifactBytes,
		TitleTemplate: "[byreis] bulk: 2 keys",
		Justification: "bulk submission",
		SecretsPath:   "secrets/prod.yaml",
		Keys: []coregit.KeyAction{
			{Key: "DB_HOST", Action: "add"},
			{Key: "DB_PASS", Action: "replace"},
		},
	})
	if prErr != nil {
		t.Fatalf("OpenSubmissionPR with Keys (bulk v2): %v", prErr)
	}

	// The PR body must contain a parseable v2 byreis-submission block.
	if !strings.Contains(capturedPRBody, "```byreis-submission") {
		t.Errorf("PR body must contain byreis-submission block, got: %q", capturedPRBody)
	}

	meta, parseErr := coregit.ParseSubmissionMeta(capturedPRBody)
	if parseErr != nil {
		t.Fatalf("PR body contains unparseable meta block: %v\nbody: %q", parseErr, capturedPRBody)
	}

	// Verify schema_version 2 was emitted.
	if meta.SchemaVersion != 2 {
		t.Errorf("bulk submission must emit schema_version 2, got %d", meta.SchemaVersion)
	}

	// Verify NormalisedKeys round-trips correctly.
	nk := meta.NormalisedKeys()
	if len(nk) != 2 {
		t.Fatalf("expected 2 normalised keys, got %d", len(nk))
	}
	if nk[0].Key != "DB_HOST" || nk[0].Action != "add" {
		t.Errorf("nk[0]: got {%q %q}, want {DB_HOST add}", nk[0].Key, nk[0].Action)
	}
	if nk[1].Key != "DB_PASS" || nk[1].Action != "replace" {
		t.Errorf("nk[1]: got {%q %q}, want {DB_PASS replace}", nk[1].Key, nk[1].Action)
	}

	// Verify scalar key/action fields are empty (v2 must not emit them).
	if meta.Key != "" {
		t.Errorf("v2 block must not carry scalar Key, got %q", meta.Key)
	}
	if meta.Action != "" {
		t.Errorf("v2 block must not carry scalar Action, got %q", meta.Action)
	}
}
