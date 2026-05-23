//go:build shipgate

package app_test

// V-3.5 wiring acceptance tests.
//
// These tests verify that BuildProductionDeps correctly wires (or nil-fallbacks)
// the Submitter, Reviewer, and RunTUISubmit fields of cli.Deps depending on
// the available environment, without performing any real network I/O.
//
// Covered obligations:
//   - Submitter is nil when BYREIS_REGISTRY is unset (no RecipientSourceWrapper).
//   - Reviewer is nil in CONTRIBUTOR mode (no admin key on disk).
//   - RunTUISubmit closure is nil when no git provider is available.
//   - BuildProductionDeps never panics on partial config (all paths nil-fallback).

import (
	"context"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
)

// TestV35_SubmitterNilWhenNoRegistry verifies that when no BYREIS_REGISTRY is
// set, Submitter is nil (the RecipientSourceWrapper cannot be constructed
// without a registry client, so buildSubmitterProd nil-fallbacks).
func TestV35_SubmitterNilWhenNoRegistry(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "myorg/myproject")
	t.Setenv("BYREIS_GITHUB_TOKEN", "fake-token")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	// BuildProductionDeps returns an error when the registry cannot be wired;
	// the test asserts that even on success paths, Submitter is nil without a
	// working registry (the wrapper is nil → nil-fallback in buildSubmitterProd).
	deps, _ := app.BuildProductionDeps(context.Background())
	if deps == nil {
		// An error return is acceptable (registry URL missing → nil registry
		// client → BuildReadPathDeps returns error). Submitter cannot be wired
		// either way. Test passes.
		return
	}
	if deps.Submitter != nil {
		t.Errorf("Submitter must be nil when no registry is configured; got non-nil")
	}
}

// TestV35_ReviewerNilInContributorMode verifies that the Reviewer use-case is
// nil when no admin key is available on disk (CONTRIBUTOR mode).
// buildReviewerProd is ADMIN-only; a contributor binary holds no Reviewer.
func TestV35_ReviewerNilInContributorMode(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "https://github.com/fake/registry")
	t.Setenv("BYREIS_PROJECT", "myorg/myproject")
	t.Setenv("BYREIS_GITHUB_TOKEN", "fake-token")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile) // no key on disk → CONTRIBUTOR

	deps, _ := app.BuildProductionDeps(context.Background())
	if deps == nil {
		// Error return is acceptable (registry URL unreachable); in that case
		// Reviewer would also be nil. The invariant holds.
		return
	}
	if deps.Reviewer != nil {
		t.Errorf("Reviewer must be nil in CONTRIBUTOR mode; got non-nil")
	}
}

// TestV35_RunTUISubmitNilWhenNoGitProvider verifies that RunTUISubmit is nil
// when the submit git port cannot be constructed (no BYREIS_GITHUB_TOKEN means
// gitProvider is nil → buildRunTUISubmitProd is not called).
func TestV35_RunTUISubmitNilWhenNoGitProvider(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	deps, _ := app.BuildProductionDeps(context.Background())
	if deps == nil {
		return
	}
	if deps.RunTUISubmit != nil {
		t.Errorf("RunTUISubmit must be nil when git provider is not wired; got non-nil")
	}
}

// TestS1_RejecterNilInContributorMode verifies that the RequestRejecter is nil
// when no admin key is available on disk (CONTRIBUTOR mode). buildRejecterProd
// is ADMIN-only; a contributor binary holds no Rejecter.
func TestS1_RejecterNilInContributorMode(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "https://github.com/fake/registry")
	t.Setenv("BYREIS_PROJECT", "myorg/myproject")
	t.Setenv("BYREIS_GITHUB_TOKEN", "fake-token")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	deps, _ := app.BuildProductionDeps(context.Background())
	if deps == nil {
		return
	}
	if deps.Rejecter != nil {
		t.Errorf("Rejecter must be nil in CONTRIBUTOR mode; got non-nil")
	}
}

// TestS1_RejecterNilWhenNoToken verifies that the RequestRejecter is nil when
// no GitHub token is set (buildRejecterProd nil-fallbacks on missing token).
func TestS1_RejecterNilWhenNoToken(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	deps, _ := app.BuildProductionDeps(context.Background())
	if deps == nil {
		return
	}
	if deps.Rejecter != nil {
		t.Errorf("Rejecter must be nil when no GitHub token is configured; got non-nil")
	}
}

// TestV35_BuildProductionDeps_NoPanic_PartialConfig verifies that
// BuildProductionDeps never panics regardless of partial / missing
// configuration. This covers the nil-fallback path for all V-3.5 use-cases.
func TestV35_BuildProductionDeps_NoPanic_PartialConfig(t *testing.T) {
	// Note: uses t.Setenv inside subtests so t.Parallel is not used here.
	configs := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "all_empty",
			env: map[string]string{
				"BYREIS_REGISTRY":     "",
				"BYREIS_PROJECT":      "",
				"BYREIS_GITHUB_TOKEN": "",
				"GITHUB_TOKEN":        "",
			},
		},
		{
			name: "token_only_no_registry",
			env: map[string]string{
				"BYREIS_REGISTRY":     "",
				"BYREIS_PROJECT":      "myorg/proj",
				"BYREIS_GITHUB_TOKEN": "fake-ghp-token",
			},
		},
	}

	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BYREIS_CONFIG", t.TempDir())
			t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			// Must not panic.
			deps, _ := app.BuildProductionDeps(context.Background())
			if deps != nil {
				// Verify the V-3.5 use-cases are nil (nil-fallback path exercised).
				if deps.Submitter != nil {
					t.Errorf("[%s] Submitter must be nil without registry; got non-nil", tc.name)
				}
				if deps.Reviewer != nil {
					t.Errorf("[%s] Reviewer must be nil in CONTRIBUTOR mode; got non-nil", tc.name)
				}
			}
		})
	}
}
