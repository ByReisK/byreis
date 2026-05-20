package app_test

// Tests for baseBranchFromEnvProd and the underlying validateBaseBranch
// helper. This file is in package app_test (black-box); we exercise the
// env-reader end-to-end via the exported BaseBranchFromEnvForTest shim
// defined in export_test.go and via t.Setenv.
//
// NEW-1-BASE-BRANCH-NO-DASH-GUARD: positive-whitelist regex guard on
// BYREIS_BASE_BRANCH. See STATE §4.10 item #10 and ADR-0012 E14/E15.

import (
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
)

// TestValidateBaseBranch exercises every category of accept/reject input
// defined in the NEW-1 slice spec. t.Setenv is used for env isolation and
// restores the env automatically on sub-test cleanup. Sub-tests are NOT
// marked parallel because t.Setenv cannot be combined with t.Parallel
// (they share the process environment).
func TestValidateBaseBranch(t *testing.T) {
	const maxLen = 200 // must match the cap in production.go

	// Build a valid branch name of exactly maxLen bytes.
	maxLenValue := strings.Repeat("a", maxLen)
	// Build a name of maxLen+1 bytes (should be rejected).
	overLenValue := strings.Repeat("a", maxLen+1)

	cases := []struct {
		name    string
		env     string // value of BYREIS_BASE_BRANCH; "" means unset
		want    string // expected return value
		wantSet bool   // true when we care that the env var was set
	}{
		// ------------------------------------------------------------------ ACCEPT
		{name: "accept/main", env: "main", want: "main", wantSet: true},
		{name: "accept/master", env: "master", want: "master", wantSet: true},
		{name: "accept/develop", env: "develop", want: "develop", wantSet: true},
		{name: "accept/release-slash", env: "release/1.0", want: "release/1.0", wantSet: true},
		{name: "accept/feature-slash-dash", env: "feature/foo-bar", want: "feature/foo-bar", wantSet: true},
		{name: "accept/users-multi-slash", env: "users/alice/x_y", want: "users/alice/x_y", wantSet: true},
		{name: "accept/version-dots", env: "v1.2.3", want: "v1.2.3", wantSet: true},
		{name: "accept/single-char", env: "a", want: "a", wantSet: true},
		{name: "accept/max-length", env: maxLenValue, want: maxLenValue, wantSet: true},

		// ------------------------------------------------------------------ REJECT: empty (unset) — existing guard unchanged
		{name: "reject/empty-unset", env: "", want: "main", wantSet: false},

		// ------------------------------------------------------------------ REJECT: leading dash (the primary exploit shape)
		{name: "reject/leading-dashdash-uploadpack", env: "--upload-pack=/tmp/x", want: "main", wantSet: true},
		{name: "reject/leading-dash-c", env: "-c", want: "main", wantSet: true},
		{name: "reject/leading-dash-x", env: "-x", want: "main", wantSet: true},

		// ------------------------------------------------------------------ REJECT: path traversal
		{name: "reject/dotdot-bare", env: "..", want: "main", wantSet: true},
		{name: "reject/dotdot-suffix", env: "foo/..", want: "main", wantSet: true},
		{name: "reject/dotdot-mid", env: "foo/../bar", want: "main", wantSet: true},

		// ------------------------------------------------------------------ REJECT: bad git ref tokens
		{name: "reject/at-brace", env: "foo@{0}", want: "main", wantSet: true},
		{name: "reject/dotlock-suffix", env: "foo.lock", want: "main", wantSet: true},
		{name: "reject/trailing-dot", env: "foo.", want: "main", wantSet: true},
		{name: "reject/leading-dot", env: ".foo", want: "main", wantSet: true},
		{name: "reject/double-slash", env: "foo//bar", want: "main", wantSet: true},
		{name: "reject/leading-slash", env: "/foo", want: "main", wantSet: true},
		{name: "reject/trailing-slash", env: "foo/", want: "main", wantSet: true},

		// ------------------------------------------------------------------ REJECT: control bytes / whitespace
		// NUL byte: the OS-level setenv(3) call rejects NUL in env values
		// before any userspace code runs, so we cannot exercise this via
		// t.Setenv. The character whitelist ([A-Za-z0-9._/-]) would also
		// reject it. This is defence-in-depth: OS blocks first, regex second.
		// The NUL case is covered by a dedicated direct-validator test below.
		{name: "reject/newline", env: "foo\nbar", want: "main", wantSet: true},
		{name: "reject/tab", env: "foo\tbar", want: "main", wantSet: true},
		{name: "reject/leading-space", env: " foo", want: "main", wantSet: true},
		{name: "reject/trailing-space", env: "foo ", want: "main", wantSet: true},

		// ------------------------------------------------------------------ REJECT: over-length
		{name: "reject/over-length", env: overLenValue, want: "main", wantSet: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantSet {
				t.Setenv("BYREIS_BASE_BRANCH", tc.env)
			} else {
				// Ensure the env var is absent so the "unset" path is exercised.
				t.Setenv("BYREIS_BASE_BRANCH", "")
			}

			got := app.BaseBranchFromEnvForTest()
			if got != tc.want {
				t.Errorf("BaseBranchFromEnv(%q) = %q, want %q", tc.env, got, tc.want)
			}
		})
	}
}

// TestBaseBranchFromEnv_WarnOnReject_NoPanic verifies that a rejected value
// causes the function to return "main" without panicking. This test intentionally
// does NOT assert the exact log text — we only assert a non-panic call with
// the correct fallback return value.
//
// The structured log assertion is omitted because production.go uses
// fmt.Fprintf(os.Stderr) and injecting a different writer would require
// changing the function signature — out of scope for this slice.
func TestBaseBranchFromEnv_WarnOnReject_NoPanic(t *testing.T) {
	t.Setenv("BYREIS_BASE_BRANCH", "--upload-pack=evil")

	got := app.BaseBranchFromEnvForTest()
	if got != "main" {
		t.Errorf("rejected value must fall back to %q, got %q", "main", got)
	}
}

// TestBaseBranchFromEnv_ValidCharsEdgeCases covers boundary characters that
// sit right at the edge of the allowed set (letters, digits, ., _, -, /).
// Sub-tests are sequential (no t.Parallel) so that t.Setenv is safe.
func TestBaseBranchFromEnv_ValidCharsEdgeCases(t *testing.T) {
	accept := []string{
		"a-b",           // dash in middle
		"a_b",           // underscore
		"a.b",           // dot in middle (not trailing)
		"release/1.0.0", // multi-segment with dots
		"A",             // uppercase
		"Z9",            // uppercase + digit
	}
	reject := []string{
		"a b",  // space in middle
		"a:b",  // colon
		"a^b",  // caret
		"a~b",  // tilde
		"a?b",  // question mark
		"a*b",  // glob
		"a\\b", // backslash
		"a[b]", // square bracket
	}

	for _, v := range accept {
		v := v
		t.Run("accept/"+v, func(t *testing.T) {
			t.Setenv("BYREIS_BASE_BRANCH", v)
			got := app.BaseBranchFromEnvForTest()
			if got != v {
				t.Errorf("expected %q to be accepted, got %q", v, got)
			}
		})
	}

	for _, v := range reject {
		v := v
		t.Run("reject/"+v, func(t *testing.T) {
			t.Setenv("BYREIS_BASE_BRANCH", v)
			got := app.BaseBranchFromEnvForTest()
			if got != "main" {
				t.Errorf("expected %q to be rejected (want %q), got %q", v, "main", got)
			}
		})
	}
}

// TestValidateBaseBranch_NULByte tests NUL byte rejection directly via the
// exported validator shim. The OS-level setenv(3) rejects NUL bytes in env
// values before userspace can observe them, so this case cannot be covered
// via t.Setenv. Testing via the validator directly preserves the assertion
// that the character whitelist would also catch this input independently.
func TestValidateBaseBranch_NULByte(t *testing.T) {
	got, ok := app.ValidateBaseBranchForTest("foo\x00bar")
	if ok {
		t.Errorf("NUL byte must be rejected, got accepted value %q", got)
	}
	if got != "main" {
		t.Errorf("NUL byte rejection must return fallback %q, got %q", "main", got)
	}
}
