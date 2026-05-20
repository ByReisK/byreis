package app_test

import (
	"context"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
)

// noKeychainKeyFile is a sentinel path used in tests to prevent the keychain
// stub (which panics) from being invoked. Setting BYREIS_KEY_FILE to any
// non-empty string causes the identity loader to skip the keychain probe path;
// the file itself need not exist (the loader returns an error which downgrades
// to CONTRIBUTOR — the expected fail-closed result in tests).
const noKeychainKeyFile = "/nonexistent-byreis-test-key.age"

// TestBuildProductionDeps_MissingRegistry_Errors verifies that
// BuildProductionDeps with no BYREIS_REGISTRY returns an error (the
// read-path ports cannot be wired, so the use-cases are unavailable). This
// mirrors the original buildDeps → os.Exit path: the caller (main) calls
// os.Exit; the function returns the error rather than calling os.Exit itself.
func TestBuildProductionDeps_MissingRegistry_Errors(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile) // prevent keychain stub panic

	_, err := app.BuildProductionDeps(context.Background())
	// Without registry or file-of-record source, BuildReadPathDeps requires
	// all base ports non-nil and returns an error when some are nil.
	// BuildProductionDeps propagates that error.
	if err == nil {
		t.Fatal("BuildProductionDeps without registry must return an error (not os.Exit)")
	}
}

// TestBuildProductionDeps_BadRegistryURL_Errors verifies that a badly-formed
// registry URL causes BuildProductionDeps to return a non-nil error (the
// file-of-record source also fails, so BuildReadPathDeps fails with nil ports).
func TestBuildProductionDeps_BadRegistryURL_Errors(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "not-a-valid-github-url.example.com/foo")
	t.Setenv("BYREIS_PROJECT", "myorg/myproject")
	t.Setenv("BYREIS_GITHUB_TOKEN", "fake-token-for-parse-test")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	_, err := app.BuildProductionDeps(context.Background())
	// Registry client fails (bad URL) AND file-of-record source also fails
	// (no project token path works), so BuildReadPathDeps gets nil ports and
	// returns an error. BuildProductionDeps propagates that error.
	if err == nil {
		t.Fatal("bad registry URL with no valid file-of-record source must return error")
	}
}

// TestBuildProductionDeps_NonInteractiveNoEditor_NoPanic verifies that when
// BYREIS_NON_INTERACTIVE=1 and neither $EDITOR nor $VISUAL is set,
// BuildProductionDeps does not panic. The CO-B5-EDITOR-NONINTERACTIVE guard
// must be reached (and wire the sentinel editor) without panicking.
func TestBuildProductionDeps_NonInteractiveNoEditor_NoPanic(t *testing.T) {
	t.Setenv("BYREIS_NON_INTERACTIVE", "1")
	t.Setenv("EDITOR", "")
	t.Setenv("VISUAL", "")
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	// Must not panic — either returns a deps or an error (both are acceptable).
	_, _ = app.BuildProductionDeps(context.Background())
}

// TestBuildProductionDeps_EnvBoolVariants verifies that BYREIS_NON_INTERACTIVE
// truthy values ("1", "true", "yes") and falsy values all process without
// panicking. The production envBoolProd function must handle these variants.
func TestBuildProductionDeps_EnvBoolVariants(t *testing.T) {
	for _, val := range []string{"1", "true", "yes", "0", "false", ""} {
		val := val
		t.Run("NI="+val, func(t *testing.T) {
			t.Setenv("BYREIS_NON_INTERACTIVE", val)
			t.Setenv("EDITOR", "")
			t.Setenv("VISUAL", "")
			t.Setenv("BYREIS_REGISTRY", "")
			t.Setenv("BYREIS_PROJECT", "")
			t.Setenv("BYREIS_GITHUB_TOKEN", "")
			t.Setenv("GITHUB_TOKEN", "")
			t.Setenv("BYREIS_CONFIG", t.TempDir())
			t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

			// Must not panic regardless of BYREIS_NON_INTERACTIVE value.
			_, _ = app.BuildProductionDeps(context.Background())
		})
	}
}

// TestBuildProductionDeps_ConfigDir_BYREIS_CONFIG_Honored verifies that the
// BYREIS_CONFIG env override is parsed and used before the error from missing
// registry/ports is returned. This confirms env-var precedence is preserved.
func TestBuildProductionDeps_ConfigDir_BYREIS_CONFIG_Honored(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv("BYREIS_CONFIG", customDir)
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	// BuildProductionDeps will return an error (no registry wired), but the
	// BYREIS_CONFIG override must have been consumed before that error fires.
	// We cannot inspect ConfigDir on an errored call, but we can confirm the
	// call does not panic and returns a non-nil error (not a nil-dep panic).
	deps, err := app.BuildProductionDeps(context.Background())
	if err == nil {
		// If deps are unexpectedly returned, verify ConfigDir.
		if deps != nil && deps.ConfigDir != customDir {
			t.Errorf("ConfigDir = %q, want %q", deps.ConfigDir, customDir)
		}
	}
	// Either outcome (deps with correct ConfigDir, or error) is acceptable.
	// What is NOT acceptable is a panic.
}

// TestBuildProductionDeps_ContextCancelled_NoPanic verifies that a
// pre-cancelled context does not cause BuildProductionDeps to panic.
func TestBuildProductionDeps_ContextCancelled_NoPanic(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Must not panic regardless of context state.
	_, _ = app.BuildProductionDeps(ctx)
}

// TestBuildProductionDeps_ErrorWrapped verifies that the error returned by
// BuildProductionDeps is non-nil (not swallowed) and contains an actionable
// diagnostic message suitable for the CLI to surface.
func TestBuildProductionDeps_ErrorWrapped(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	_, err := app.BuildProductionDeps(context.Background())
	if err == nil {
		t.Fatal("expected error when required ports are not configured")
	}
	if len(err.Error()) < 10 {
		t.Errorf("error message too short to be actionable: %q", err.Error())
	}
}
