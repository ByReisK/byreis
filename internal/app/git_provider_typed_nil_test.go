package app_test

// Regression tests for the typed-nil trap in buildGitProviderProd.
//
// When gitadapter.New returns (*Provider)(nil) + a non-nil error, naively
// returning that pair from buildGitProviderProd produces a coregit.GitProvider
// interface that wraps a nil concrete pointer — a "typed nil". Typed nils are
// NOT equal to the untyped nil that == nil checks expect, so the downstream
// guards in buildReviewerProd and buildSubmitterProd silently pass, and the
// first real method call on the broken provider panics.
//
// The fix: capture gitadapter.New's result and return an explicit untyped nil
// on error. This test locks that invariant: on any malformed project string,
// the returned coregit.GitProvider must be a true nil (== nil passes).

import (
	"errors"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
	coregit "github.com/ByReisK/byreis/internal/core/git"
)

// TestBuildGitProviderProd_MalformedProject_TrueNilInterface verifies that
// buildGitProviderProd returns a true untyped-nil interface value (not a typed
// nil wrapping *Provider(nil)) whenever the project string is malformed.
//
// A typed-nil coregit.GitProvider would pass a "!= nil" guard, defeat the
// nil-fallback in buildReviewerProd / buildSubmitterProd, and eventually panic
// on the first real method call. An untyped nil is == nil and triggers the
// intended graceful fallback.
func TestBuildGitProviderProd_MalformedProject_TrueNilInterface(t *testing.T) {
	cases := []struct {
		name    string
		token   string
		project string
		base    string
	}{
		{
			name:    "three_part_path",
			token:   "tok",
			project: "a/b/c",
			base:    "main",
		},
		{
			name:    "no_slash",
			token:   "tok",
			project: "noslash",
			base:    "main",
		},
		{
			name:    "trailing_slash_empty_repo",
			token:   "tok",
			project: "a/",
			base:    "main",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := app.BuildGitProviderProdForTest(tc.token, tc.project, tc.base)

			// The malformed project must always produce an error.
			if err == nil {
				t.Fatalf("[%s] expected non-nil error for malformed project %q; got nil",
					tc.name, tc.project)
			}

			// The error must wrap ErrInvalidProject (confirms the right code path fired).
			if !errors.Is(err, coregit.ErrInvalidProject) {
				t.Errorf("[%s] error = %v; want errors.Is(err, coregit.ErrInvalidProject)",
					tc.name, err)
			}

			// PRIMARY regression assertion: the returned interface must be a true
			// nil, not a typed nil wrapping (*Provider)(nil).
			//
			// Before the fix, gitadapter.New returned (*Provider)(nil) and
			// buildGitProviderProd passed that through directly.  The interface
			// then held a non-nil type descriptor, making `got != nil` true and
			// defeating the downstream nil-fallback guards.  This assertion would
			// have FAILED against the pre-fix code.
			if got != nil {
				t.Errorf("[%s] returned coregit.GitProvider interface is non-nil "+
					"(typed-nil regression): got %T %v; want true nil",
					tc.name, got, got)
			}
		})
	}
}
