package app_test

import (
	"os"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
)

// TestScrubSecretEnvVars_RemovesSecretVars verifies that ScrubSecretEnvVars
// removes BYREIS_KEY, BYREIS_KEY_FILE, BYREIS_SIGN_KEY, BYREIS_SIGN_KEY_FILE,
// and BYREIS_GITHUB_TOKEN from the process environment while leaving unrelated
// BYREIS_* vars (BYREIS_REGISTRY, BYREIS_PROJECT) untouched.
func TestScrubSecretEnvVars_RemovesSecretVars(t *testing.T) {
	// Set all secret vars and some non-secret vars.
	t.Setenv("BYREIS_KEY", "AGE-SECRET-KEY-1FAKE")
	t.Setenv("BYREIS_KEY_FILE", "/tmp/fake.age")
	t.Setenv("BYREIS_SIGN_KEY", "base64fakesignkey")
	t.Setenv("BYREIS_SIGN_KEY_FILE", "/tmp/fake-sign.age")
	t.Setenv("BYREIS_GITHUB_TOKEN", "ghp_faketoken")
	t.Setenv("BYREIS_REGISTRY", "https://example.com/registry")
	t.Setenv("BYREIS_PROJECT", "my-project")

	app.ScrubSecretEnvVars()

	// Secret vars must be gone.
	for _, name := range []string{
		"BYREIS_KEY",
		"BYREIS_KEY_FILE",
		"BYREIS_SIGN_KEY",
		"BYREIS_SIGN_KEY_FILE",
		"BYREIS_GITHUB_TOKEN",
	} {
		if v := os.Getenv(name); v != "" {
			t.Errorf("ScrubSecretEnvVars: %s not scrubbed (still %q)", name, v)
		}
	}

	// Non-secret vars must be preserved.
	if v := os.Getenv("BYREIS_REGISTRY"); v != "https://example.com/registry" {
		t.Errorf("ScrubSecretEnvVars: BYREIS_REGISTRY was incorrectly scrubbed (got %q)", v)
	}
	if v := os.Getenv("BYREIS_PROJECT"); v != "my-project" {
		t.Errorf("ScrubSecretEnvVars: BYREIS_PROJECT was incorrectly scrubbed (got %q)", v)
	}
}
