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

// TestBuildProductionDeps_MissingRegistry_NilUseCases verifies that
// BuildProductionDeps with no BYREIS_REGISTRY succeeds (returns non-nil deps,
// nil error) but leaves all read-path use-cases nil. This is the correct
// first-run UX behaviour: `byreis --help`, `byreis version`, and
// `byreis completion` all succeed in an unconfigured environment; each command
// that actually needs a configured registry surfaces its own "not configured"
// error at command time (fail-closed posture is unchanged, merely deferred).
func TestBuildProductionDeps_MissingRegistry_NilUseCases(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile) // prevent keychain stub panic

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps without registry must succeed (deferred fail-closed): %v", err)
	}
	if deps == nil {
		t.Fatal("BuildProductionDeps must return non-nil deps even without registry")
	}
	// All read-path use-cases must be nil when registry is absent (fail-closed
	// at command time, not at startup).
	if deps.Getter != nil {
		t.Error("deps.Getter must be nil without a registry")
	}
	if deps.Decryptor != nil {
		t.Error("deps.Decryptor must be nil without a registry")
	}
	if deps.Editor != nil {
		t.Error("deps.Editor must be nil without a registry")
	}
}

// TestBuildProductionDeps_BadRegistryURL_NilUseCases verifies that a
// badly-formed registry URL causes BuildProductionDeps to succeed (return
// non-nil deps) but leave all read-path use-cases nil. The fail-closed
// posture is maintained at command time when those nil use-cases are invoked.
func TestBuildProductionDeps_BadRegistryURL_NilUseCases(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "not-a-valid-github-url.example.com/foo")
	t.Setenv("BYREIS_PROJECT", "myorg/myproject")
	t.Setenv("BYREIS_GITHUB_TOKEN", "fake-token-for-parse-test")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps with bad registry URL must succeed (deferred fail-closed): %v", err)
	}
	if deps == nil {
		t.Fatal("BuildProductionDeps must return non-nil deps even with a bad registry URL")
	}
	// Read-path use-cases are nil because the registry client and
	// file-of-record source could not be constructed.
	if deps.Getter != nil {
		t.Error("deps.Getter must be nil when registry URL is invalid")
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
// BYREIS_CONFIG env override is reflected in the returned deps.ConfigDir.
// BuildProductionDeps now succeeds (nil error) even without a registry.
func TestBuildProductionDeps_ConfigDir_BYREIS_CONFIG_Honored(t *testing.T) {
	customDir := t.TempDir()
	t.Setenv("BYREIS_CONFIG", customDir)
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps must succeed in unconfigured environment: %v", err)
	}
	if deps == nil {
		t.Fatal("BuildProductionDeps returned nil deps")
	}
	if deps.ConfigDir != customDir {
		t.Errorf("ConfigDir = %q, want %q", deps.ConfigDir, customDir)
	}
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

// TestBuildProductionDeps_UnconfiguredSucceedsWithNilUseCases verifies that
// BuildProductionDeps returns non-nil deps (nil error) even when no env is set.
// Individual use-cases are nil; each command's RunE surfaces its own actionable
// "not configured" message, preserving the fail-closed posture at command time.
func TestBuildProductionDeps_UnconfiguredSucceedsWithNilUseCases(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	deps, err := app.BuildProductionDeps(context.Background())
	if err != nil {
		t.Fatalf("BuildProductionDeps must succeed in unconfigured environment: %v", err)
	}
	if deps == nil {
		t.Fatal("BuildProductionDeps must return non-nil deps in unconfigured environment")
	}
	// Read-path use-cases are nil — commands will surface "not configured" at
	// command time. This is the intentional fail-closed-at-command-time posture.
	if deps.Getter != nil {
		t.Error("Getter must be nil in an unconfigured environment")
	}
	if deps.Merger != nil {
		t.Error("Merger must be nil in an unconfigured environment")
	}
}
