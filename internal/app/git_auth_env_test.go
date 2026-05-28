package app_test

// Tests for buildGitAuthEnv host-scoping predicate and auth-scheme correctness.
//
// The helper must return a scoped env block only for github.com HTTPS URLs and
// must return nil for file://, SSH, bare-owner/repo, non-GitHub HTTPS, and
// empty-token inputs. This property ensures the token is never injected for a
// non-GitHub host, even if git follows a cross-host redirect.
//
// The auth-scheme tests verify that the Authorization header value uses HTTP
// Basic (not Bearer) and that the base64-encoded credential has the canonical
// x-access-token:<token> form required by GitHub's git-over-HTTPS endpoint.

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
)

func TestBuildGitAuthEnv_Predicate(t *testing.T) {
	const scopedKey = "GIT_CONFIG_KEY_2=http.https://github.com/.extraHeader"
	const token = "ghp_testtoken"

	tests := []struct {
		name       string
		url        string
		token      string
		wantNil    bool
		wantScoped bool // when non-nil, KEY_2 must be the scoped form
	}{
		{
			name:       "github-https-full-url",
			url:        "https://github.com/owner/repo",
			token:      token,
			wantNil:    false,
			wantScoped: true,
		},
		{
			name:       "github-https-trailing-git",
			url:        "https://github.com/owner/repo.git",
			token:      token,
			wantNil:    false,
			wantScoped: true,
		},
		{
			name:    "empty-token-github-url",
			url:     "https://github.com/owner/repo",
			token:   "",
			wantNil: true,
		},
		{
			name:    "file-triple-slash",
			url:     "file:///absolute/path/to/repo",
			token:   token,
			wantNil: true,
		},
		{
			name:    "ssh-form",
			url:     "git@github.com:owner/repo",
			token:   token,
			wantNil: true,
		},
		{
			name:    "bare-owner-repo-no-scheme",
			url:     "owner/repo",
			token:   token,
			wantNil: true,
		},
		{
			name:    "non-github-https",
			url:     "https://gitlab.com/owner/repo",
			token:   token,
			wantNil: true,
		},
		{
			name:    "empty-url-empty-token",
			url:     "",
			token:   "",
			wantNil: true,
		},
		{
			name:    "empty-url-with-token",
			url:     "",
			token:   token,
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := app.BuildGitAuthEnvForTest(tc.url, tc.token)

			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil env block, got %v", got)
				}
				return
			}

			if got == nil {
				t.Fatal("expected non-nil env block, got nil")
			}

			// Verify the scoped key is present (not the bare form).
			var foundScopedKey bool
			for _, entry := range got {
				if entry == scopedKey {
					foundScopedKey = true
				}
				// No bare http.extraHeader must appear.
				if entry == "GIT_CONFIG_KEY_2=http.extraHeader" {
					t.Errorf("found bare (unscoped) GIT_CONFIG_KEY_2 entry: %q", entry)
				}
			}
			if tc.wantScoped && !foundScopedKey {
				t.Errorf("expected scoped key %q in env block, got %v", scopedKey, got)
			}

			// Verify the auth value entry exists, uses Basic scheme, and encodes
			// the token in the x-access-token:<token> credential form.
			var foundValue bool
			for _, entry := range got {
				if strings.HasPrefix(entry, "GIT_CONFIG_VALUE_2=") {
					headerVal := strings.TrimPrefix(entry, "GIT_CONFIG_VALUE_2=")
					// Scheme must be Basic, not Bearer.
					if !strings.HasPrefix(headerVal, "Authorization: Basic ") {
						t.Errorf("GIT_CONFIG_VALUE_2 scheme is not Basic: %q", headerVal)
					}
					// Decode and verify the credential payload.
					encoded := strings.TrimPrefix(headerVal, "Authorization: Basic ")
					decoded, decErr := base64.StdEncoding.DecodeString(encoded)
					if decErr != nil {
						t.Errorf("GIT_CONFIG_VALUE_2 base64 decode failed: %v (value: %q)", decErr, encoded)
					} else {
						want := "x-access-token:" + tc.token
						if string(decoded) != want {
							t.Errorf("GIT_CONFIG_VALUE_2 decoded credential = %q, want %q",
								string(decoded), want)
						}
					}
					foundValue = true
				}
			}
			if !foundValue {
				t.Error("GIT_CONFIG_VALUE_2 entry not found in env block")
			}

			// Verify GIT_CONFIG_COUNT=3 (exactly one count entry, value 3).
			var countEntry string
			for _, entry := range got {
				if strings.HasPrefix(entry, "GIT_CONFIG_COUNT=") {
					if countEntry != "" {
						t.Errorf("duplicate GIT_CONFIG_COUNT entries: %q and %q", countEntry, entry)
					}
					countEntry = entry
				}
			}
			if countEntry != "GIT_CONFIG_COUNT=3" {
				t.Errorf("expected GIT_CONFIG_COUNT=3, got %q", countEntry)
			}
		})
	}
}

// TestBuildGitAuthEnv_CrossHostDropsToken demonstrates the host-scoping
// property at the git-config level: the http.https://github.com/.extraHeader
// key is a URL-qualified config key, so git's per-URL config lookup only
// matches requests whose URL begins with https://github.com/. A request to
// any other host — such as one following a cross-host redirect — will not
// match and the header is dropped.
//
// The test verifies this by checking that the env block's KEY_2 value would
// not match a non-github.com URL under git's url-match semantics (the qualified
// config key acts as a URL prefix guard).
func TestBuildGitAuthEnv_CrossHostDropsToken(t *testing.T) {
	env := app.BuildGitAuthEnvForTest("https://github.com/owner/repo", "ghp_secret")
	if env == nil {
		t.Fatal("expected non-nil env block for github.com URL")
	}

	// The scoped key includes the host prefix. Git applies
	// http.<url>.extraHeader only to requests matching that URL prefix, so
	// a redirect to attacker.example.com receives no Authorization header.
	const scopedKey = "GIT_CONFIG_KEY_2=http.https://github.com/.extraHeader"
	var foundScoped bool
	for _, entry := range env {
		if entry == scopedKey {
			foundScoped = true
		}
	}
	if !foundScoped {
		t.Errorf("scoped key %q not found; token would apply globally", scopedKey)
	}

	// Confirm that building the env block for a non-github host returns nil,
	// i.e. the predicate is closed on non-GitHub hosts.
	for _, nonGitHub := range []string{
		"https://attacker.example.com/owner/repo",
		"https://gitlab.com/owner/repo",
		"file:///tmp/local-repo",
	} {
		if got := app.BuildGitAuthEnvForTest(nonGitHub, "ghp_secret"); got != nil {
			t.Errorf("buildGitAuthEnv(%q) should return nil, got %v", nonGitHub, got)
		}
	}
}
