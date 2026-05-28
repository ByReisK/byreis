package registry

// White-box tests for gitAuthEnvBlock host-scoping and auth-scheme correctness.
//
// These tests run in package registry (not registry_test) to access the
// unexported helper directly. They assert that:
//
//   - A GitHub HTTPS URL with a non-empty token produces a GIT_CONFIG block
//     with the URL-qualified key http.https://github.com/.extraHeader.
//   - A non-GitHub URL (file://, SSH, plain HTTPS on another host) returns nil
//     so the token is never injected.
//   - An empty token always returns nil regardless of URL.
//   - The produced block contains exactly one GIT_CONFIG_COUNT entry equal to 3
//     and no bare http.extraHeader key.
//   - The Authorization header value uses HTTP Basic auth with the
//     x-access-token:<token> credential form, not Bearer.

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
)

func TestGitAuthEnvBlock_Predicate(t *testing.T) {
	const scopedKey = "GIT_CONFIG_KEY_2=http.https://github.com/.extraHeader"
	const token = "ghp_testtoken"

	tests := []struct {
		name       string
		url        string
		token      string
		wantNil    bool
		wantScoped bool
	}{
		{
			name:       "github-https",
			url:        "https://github.com/owner/repo",
			token:      token,
			wantNil:    false,
			wantScoped: true,
		},
		{
			name:       "github-https-dotgit",
			url:        "https://github.com/org/secrets-repo.git",
			token:      token,
			wantNil:    false,
			wantScoped: true,
		},
		{
			name:    "empty-token",
			url:     "https://github.com/owner/repo",
			token:   "",
			wantNil: true,
		},
		{
			name:    "file-url",
			url:     "file:///tmp/test-registry",
			token:   token,
			wantNil: true,
		},
		{
			name:    "ssh-url",
			url:     "git@github.com:owner/repo",
			token:   token,
			wantNil: true,
		},
		{
			name:    "bare-owner-repo",
			url:     "owner/repo",
			token:   token,
			wantNil: true,
		},
		{
			name:    "gitlab-https",
			url:     "https://gitlab.com/owner/repo",
			token:   token,
			wantNil: true,
		},
		{
			name:    "arbitrary-https-non-github",
			url:     "https://example.com/repo",
			token:   token,
			wantNil: true,
		},
		{
			name:    "empty-url-empty-token",
			url:     "",
			token:   "",
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := gitAuthEnvBlock(tc.url, tc.token)

			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil env block for url=%q token=%q, got %v",
						tc.url, tc.token, got)
				}
				return
			}

			if got == nil {
				t.Fatalf("expected non-nil env block for url=%q, got nil", tc.url)
			}

			// Exactly one GIT_CONFIG_COUNT entry, value must be 3.
			var countVal string
			for _, e := range got {
				if strings.HasPrefix(e, "GIT_CONFIG_COUNT=") {
					if countVal != "" {
						t.Errorf("duplicate GIT_CONFIG_COUNT: %q and %q", countVal, e)
					}
					countVal = strings.TrimPrefix(e, "GIT_CONFIG_COUNT=")
				}
			}
			if countVal != "3" {
				t.Errorf("GIT_CONFIG_COUNT=%q, want 3", countVal)
			}

			// Scoped key must be present.
			var foundScoped bool
			for _, e := range got {
				if e == scopedKey {
					foundScoped = true
				}
				// Bare global form must not appear.
				if e == "GIT_CONFIG_KEY_2=http.extraHeader" {
					t.Errorf("bare unscoped GIT_CONFIG_KEY_2 found: %q", e)
				}
			}
			if tc.wantScoped && !foundScoped {
				t.Errorf("expected %q in block, got %v", scopedKey, got)
			}

			// Authorization value must use Basic scheme and encode the token as
			// x-access-token:<token> in base64 — Bearer is rejected by GitHub.
			var foundValue bool
			for _, e := range got {
				if strings.HasPrefix(e, "GIT_CONFIG_VALUE_2=") {
					headerVal := strings.TrimPrefix(e, "GIT_CONFIG_VALUE_2=")
					if !strings.HasPrefix(headerVal, "Authorization: Basic ") {
						t.Errorf("GIT_CONFIG_VALUE_2 scheme is not Basic: %q", headerVal)
					}
					encoded := strings.TrimPrefix(headerVal, "Authorization: Basic ")
					decoded, decErr := base64.StdEncoding.DecodeString(encoded)
					if decErr != nil {
						t.Errorf("GIT_CONFIG_VALUE_2 base64 decode failed: %v (encoded: %q)",
							decErr, encoded)
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
				t.Error("GIT_CONFIG_VALUE_2 entry not found")
			}
		})
	}
}

// TestGitAuthEnvBlock_NoBareGlobalKey verifies that no variant of the input
// produces the unqualified http.extraHeader key. This is the core
// host-scoping invariant: the token must only travel to github.com.
func TestGitAuthEnvBlock_NoBareGlobalKey(t *testing.T) {
	urls := []string{
		"https://github.com/owner/repo",
		"https://github.com/org/registry.git",
		// Non-GitHub forms should return nil, but double-check no bare key leaks.
		"https://gitlab.com/owner/repo",
		"git@github.com:owner/repo",
		"owner/repo",
		"",
	}
	for _, u := range urls {
		env := gitAuthEnvBlock(u, "tok")
		for _, entry := range env {
			if entry == "GIT_CONFIG_KEY_2=http.extraHeader" {
				t.Errorf("url=%q: bare unscoped http.extraHeader key found in env block", u)
			}
		}
	}
}

// TestRotationReverserBuildEnv_Scoping verifies that RotationReverserAdapter.buildEnv
// produces a host-scoped Authorization header for GitHub HTTPS URLs and omits
// it entirely for non-GitHub URLs — covering the CR-1 rotation write paths.
func TestRotationReverserBuildEnv_Scoping(t *testing.T) {
	const scopedKey = "GIT_CONFIG_KEY_2=http.https://github.com/.extraHeader"
	const token = "ghp_rottoken"

	// Build a minimal adapter for testing buildEnv directly.
	// NewRotationReverserAdapter validates required fields; use a nop runner.
	nopRunner := &nopCommandRunner{}
	nopSigner := &nopWriteSigner{}
	nopTokenProv := &nopTokenProvider{}

	adapter, err := NewRotationReverserAdapter(RotationReverserDeps{
		RegistryURL:    "https://github.com/org/registry",
		ProjectRepoURL: "https://github.com/org/project",
		Signer:         nopSigner,
		TokenProvider:  nopTokenProv,
		Runner:         nopRunner,
		MkdirTemp:      func(dir, pattern string) (string, error) { return t.TempDir(), nil },
		RemoveAll:      func(path string) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewRotationReverserAdapter: %v", err)
	}

	tmpDir := t.TempDir()

	t.Run("github-url-with-token-produces-scoped-key", func(t *testing.T) {
		env := adapter.buildEnv(tmpDir, "https://github.com/org/repo", token, true)
		assertScopedKey(t, scopedKey, token, env)
	})

	t.Run("non-github-url-produces-no-auth", func(t *testing.T) {
		env := adapter.buildEnv(tmpDir, "https://gitlab.com/org/repo", token, true)
		assertNoAuthKey(t, env)
		// Count must be 2 (noauth block).
		assertConfigCount(t, "2", env)
	})

	t.Run("file-url-produces-no-auth", func(t *testing.T) {
		env := adapter.buildEnv(tmpDir, "file:///tmp/local", token, true)
		assertNoAuthKey(t, env)
	})

	t.Run("withAuth-false-always-no-auth", func(t *testing.T) {
		env := adapter.buildEnv(tmpDir, "https://github.com/org/repo", token, false)
		assertNoAuthKey(t, env)
	})
}

// assertScopedKey checks that env contains the scoped GIT_CONFIG_KEY_2 entry
// and that GIT_CONFIG_VALUE_2 encodes the token as Basic x-access-token:<token>.
// No bare http.extraHeader allowed.
func assertScopedKey(t *testing.T, scopedKey, token string, env []string) {
	t.Helper()
	var found bool
	for _, e := range env {
		if e == scopedKey {
			found = true
		}
		if e == "GIT_CONFIG_KEY_2=http.extraHeader" {
			t.Errorf("bare unscoped http.extraHeader present in env: %q", e)
		}
	}
	if !found {
		t.Errorf("scoped key %q not found in env %v", scopedKey, env)
	}
	var foundVal bool
	for _, e := range env {
		if strings.HasPrefix(e, "GIT_CONFIG_VALUE_2=") {
			headerVal := strings.TrimPrefix(e, "GIT_CONFIG_VALUE_2=")
			if !strings.HasPrefix(headerVal, "Authorization: Basic ") {
				t.Errorf("assertScopedKey: GIT_CONFIG_VALUE_2 scheme is not Basic: %q", headerVal)
			}
			encoded := strings.TrimPrefix(headerVal, "Authorization: Basic ")
			decoded, decErr := base64.StdEncoding.DecodeString(encoded)
			if decErr != nil {
				t.Errorf("assertScopedKey: base64 decode failed: %v (encoded: %q)", decErr, encoded)
			} else if string(decoded) == "x-access-token:"+token {
				foundVal = true
			} else {
				t.Errorf("assertScopedKey: decoded credential = %q, want x-access-token:%s",
					string(decoded), token)
			}
		}
	}
	if !foundVal {
		t.Errorf("token not found in GIT_CONFIG_VALUE_2 (via Basic base64) in env %v", env)
	}
}

// assertNoAuthKey checks that no GIT_CONFIG_KEY_2 appears in env — the noauth
// block must not inject any HTTP header at all.
func assertNoAuthKey(t *testing.T, env []string) {
	t.Helper()
	for _, e := range env {
		if strings.HasPrefix(e, "GIT_CONFIG_KEY_2=") {
			t.Errorf("GIT_CONFIG_KEY_2 present in noauth env: %q", e)
		}
	}
}

// assertConfigCount checks that GIT_CONFIG_COUNT has the expected value.
func assertConfigCount(t *testing.T, want string, env []string) {
	t.Helper()
	for _, e := range env {
		if strings.HasPrefix(e, "GIT_CONFIG_COUNT=") {
			got := strings.TrimPrefix(e, "GIT_CONFIG_COUNT=")
			if got != want {
				t.Errorf("GIT_CONFIG_COUNT=%q, want %q", got, want)
			}
			return
		}
	}
	t.Errorf("GIT_CONFIG_COUNT entry not found in env %v", env)
}

// nopCommandRunner is a no-op CommandRunner for tests that do not invoke git.
type nopCommandRunner struct{}

func (r *nopCommandRunner) Run(_ context.Context, _ string, _ []string, _ string, _ ...string) ([]byte, []byte, int, error) {
	return nil, nil, 0, nil
}

// Compile-time assertion that nopCommandRunner satisfies fetchtransport.CommandRunner.
var _ fetchtransport.CommandRunner = (*nopCommandRunner)(nil)

// nopWriteSigner is a no-op RegistryWriteSigner.
type nopWriteSigner struct{}

func (s *nopWriteSigner) SignText(_ context.Context, _ []byte) (string, []byte, error) {
	return "test-signer", make([]byte, 64), nil
}

// Compile-time assertion that nopWriteSigner satisfies RegistryWriteSigner.
var _ RegistryWriteSigner = (*nopWriteSigner)(nil)

// nopTokenProvider is a no-op RegistryWriteTokenProvider.
type nopTokenProvider struct{}

func (p *nopTokenProvider) RegistryWriteToken(_ context.Context, _ string) (string, error) {
	return "tok", nil
}

// Compile-time assertion that nopTokenProvider satisfies RegistryWriteTokenProvider.
var _ RegistryWriteTokenProvider = (*nopTokenProvider)(nil)
