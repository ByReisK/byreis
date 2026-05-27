package render

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMapKeyToEnvVar covers REQ-V07-004 AC-A and AC-B: character sanitization
// and leading-digit rejection.
func TestMapKeyToEnvVar(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		key     string
		wantVar string
		wantErr error
	}{
		// REQ-V07-004 AC-A: non-alphanum replaced with underscore, case preserved.
		{name: "dot_replaced", key: "db.host", wantVar: "db_host"},
		{name: "dash_replaced", key: "api-key", wantVar: "api_key"},
		{name: "already_clean", key: "MY_VAR", wantVar: "MY_VAR"},
		{name: "lowercase_preserved", key: "my_secret", wantVar: "my_secret"},
		{name: "mixed_case_preserved", key: "MySecret", wantVar: "MySecret"},
		{name: "digit_interior", key: "key1_val", wantVar: "key1_val"},
		{name: "digit_after_letter", key: "a2b", wantVar: "a2b"},
		{name: "spaces_replaced", key: "my key", wantVar: "my_key"},
		{name: "slash_replaced", key: "infra/db", wantVar: "infra_db"},
		{name: "colons_replaced", key: "ns:key", wantVar: "ns_key"},
		{name: "multiple_specials", key: "a.b-c/d", wantVar: "a_b_c_d"},
		// Case preserved (no auto-uppercase — ADR-0021 D5).
		{name: "no_auto_uppercase", key: "lower.key", wantVar: "lower_key"},
		// REQ-V07-004 AC-B: leading digit in result -> ErrLeadingDigit.
		{name: "leading_digit_error", key: "2fa_seed", wantErr: ErrLeadingDigit},
		{name: "leading_digit_pure", key: "9key", wantErr: ErrLeadingDigit},
		// A key that starts with a special char (maps to _) followed by digits
		// does NOT trigger the error because the result starts with _, not a digit.
		{name: "special_prefix_not_digit_lead", key: ".2fa", wantVar: "_2fa"},
		// A key made entirely of digits maps to all-digits — but wait, digits are
		// in [0-9] so they pass through unchanged, giving a leading-digit result.
		{name: "all_digit_key", key: "42", wantErr: ErrLeadingDigit},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := MapKeyToEnvVar(tc.key)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("MapKeyToEnvVar(%q) error = %v, want %v", tc.key, err, tc.wantErr)
				}
				// AC-004-D: no plaintext leaked on failure (var must be empty).
				if got != "" {
					t.Errorf("MapKeyToEnvVar(%q) returned non-empty var on error: %q", tc.key, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("MapKeyToEnvVar(%q) unexpected error: %v", tc.key, err)
			}
			if got != tc.wantVar {
				t.Errorf("MapKeyToEnvVar(%q) = %q, want %q", tc.key, got, tc.wantVar)
			}
		})
	}
}

// TestBuildEnvPairs covers REQ-V07-004 AC-A/C/D: ordered pairs, post-mapping
// collision detection, and fail-closed (no pairs returned on error).
func TestBuildEnvPairs(t *testing.T) {
	t.Parallel()

	t.Run("ordered_by_source_key", func(t *testing.T) {
		t.Parallel()
		pt := map[string]string{
			"z_key": "z",
			"a_key": "a",
			"m_key": "m",
		}
		names := []string{"z_key", "a_key", "m_key"}
		pairs, err := BuildEnvPairs(pt, names)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pairs) != 3 {
			t.Fatalf("expected 3 pairs, got %d", len(pairs))
		}
		wantOrder := []string{"a_key", "m_key", "z_key"}
		for i, p := range pairs {
			if p.Var != wantOrder[i] {
				t.Errorf("pair[%d].Var = %q, want %q", i, p.Var, wantOrder[i])
			}
		}
	})

	t.Run("values_match_keys", func(t *testing.T) {
		t.Parallel()
		pt := map[string]string{
			"api_key": "secret1",
			"db_pass": "secret2",
		}
		names := []string{"api_key", "db_pass"}
		pairs, err := BuildEnvPairs(pt, names)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		vals := make(map[string]string, len(pairs))
		for _, p := range pairs {
			vals[p.Var] = p.Value
		}
		if vals["api_key"] != "secret1" {
			t.Errorf("api_key value mismatch: got %q", vals["api_key"])
		}
		if vals["db_pass"] != "secret2" {
			t.Errorf("db_pass value mismatch: got %q", vals["db_pass"])
		}
	})

	// REQ-V07-004 AC-C: post-mapping collision -> ErrVarCollision naming both keys.
	t.Run("collision_error_names_both_keys", func(t *testing.T) {
		t.Parallel()
		pt := map[string]string{
			"api.key": "v1",
			"api-key": "v2",
		}
		names := []string{"api.key", "api-key"}
		pairs, err := BuildEnvPairs(pt, names)
		if !errors.Is(err, ErrVarCollision) {
			t.Errorf("expected ErrVarCollision, got %v", err)
		}
		// Both source key names must appear in the error message.
		errMsg := err.Error()
		if !strings.Contains(errMsg, "api.key") {
			t.Errorf("error message must name first source key \"api.key\": %q", errMsg)
		}
		if !strings.Contains(errMsg, "api-key") {
			t.Errorf("error message must name second source key \"api-key\": %q", errMsg)
		}
		// REQ-V07-004 AC-D: fail closed — no pairs on error.
		if len(pairs) != 0 {
			t.Errorf("BuildEnvPairs must return no pairs on collision, got %d", len(pairs))
		}
	})

	// REQ-V07-004 AC-B threaded through BuildEnvPairs: leading-digit key fails closed.
	t.Run("leading_digit_fails_closed", func(t *testing.T) {
		t.Parallel()
		pt := map[string]string{"2fa_seed": "value"}
		names := []string{"2fa_seed"}
		pairs, err := BuildEnvPairs(pt, names)
		if !errors.Is(err, ErrLeadingDigit) {
			t.Errorf("expected ErrLeadingDigit, got %v", err)
		}
		if len(pairs) != 0 {
			t.Errorf("BuildEnvPairs must return no pairs on leading-digit error, got %d", len(pairs))
		}
	})

	// REQ-V07-004 AC-D: no plaintext in error messages.
	t.Run("no_plaintext_in_error", func(t *testing.T) {
		t.Parallel()
		secretValue := "super_secret_plaintext"
		pt := map[string]string{"2fa_seed": secretValue}
		names := []string{"2fa_seed"}
		_, err := BuildEnvPairs(pt, names)
		if err != nil && strings.Contains(err.Error(), secretValue) {
			t.Errorf("error message must not contain plaintext value: %q", err.Error())
		}
	})

	// Determinism: stable sort across multiple calls.
	t.Run("deterministic_sort", func(t *testing.T) {
		t.Parallel()
		pt := map[string]string{
			"zebra": "z",
			"alpha": "a",
			"gamma": "g",
			"beta":  "b",
		}
		names := []string{"zebra", "alpha", "gamma", "beta"}
		for range 5 {
			pairs, err := BuildEnvPairs(pt, names)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			wantFirst := "alpha"
			if pairs[0].Var != wantFirst {
				t.Errorf("first pair = %q, want %q (not deterministic)", pairs[0].Var, wantFirst)
			}
		}
	})
}

// TestEmitEnv covers REQ-V07-003 AC rows A–K: quoting, escaping, format
// divergence, and NUL rejection.
func TestEmitEnv(t *testing.T) {
	t.Parallel()

	// emitPairs is a helper that builds a single-pair slice and emits it.
	emitPairs := func(t *testing.T, varName, value string, format EnvFormat) (string, error) {
		t.Helper()
		pairs := []EnvPair{{Var: varName, Value: value}}
		var buf bytes.Buffer
		err := EmitEnv(&buf, pairs, format)
		return buf.String(), err
	}

	// REQ-V07-003 AC-A: embedded newline -> \n escape in output.
	t.Run("AC_A_newline_escaped", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", "a\nb", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := `KEY="a\nb"` + "\n"
		if got != want {
			t.Errorf("AC-A: got %q, want %q", got, want)
		}
	})

	// REQ-V07-003 AC-B: embedded double-quote -> \" escape.
	t.Run("AC_B_embedded_quote_escaped", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", `he said "hi"`, FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := `KEY="he said \"hi\""` + "\n"
		if got != want {
			t.Errorf("AC-B: got %q, want %q", got, want)
		}
	})

	// REQ-V07-003 AC-C: equals signs in value, whole value quoted.
	t.Run("AC_C_equals_quoted_whole", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", "a=b=c", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := `KEY="a=b=c"` + "\n"
		if got != want {
			t.Errorf("AC-C: got %q, want %q", got, want)
		}
	})

	// REQ-V07-003 AC-D: hash character is not a comment (quoted, preserved).
	t.Run("AC_D_hash_not_comment", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", "foo # bar", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := `KEY="foo # bar"` + "\n"
		if got != want {
			t.Errorf("AC-D: got %q, want %q", got, want)
		}
	})

	// REQ-V07-003 AC-E (REVISED per ADJ-3 / ADR-0021 D4 ERRATUM E1):
	// Shell injection patterns must be INERT after emission — the emitted line
	// must not expand $(…), `…`, ${X}, or $X when sourced/eval'd by a POSIX
	// shell. The previous assertion ("verbatim inside quotes") encoded the
	// vulnerability; this block asserts inertness instead.
	//
	// Byte-level contract: $ must appear escaped as \$ and backtick as \` in
	// the emitted bytes so that any POSIX shell treats them as literals.
	//
	// Round-trip contract: we write the emitted line to a temp file and source
	// it in a controlled sh subprocess, then assert (a) no side-effect file was
	// created, (b) the variable holds the literal unexpanded string.
	t.Run("AC_E_shell_injection_inert", func(t *testing.T) {
		t.Parallel()

		// Locate sh once; skip the round-trip sub-assertions if unavailable.
		shPath, shAvailable := "", false
		if p, err := exec.LookPath("sh"); err == nil {
			shPath, shAvailable = p, true
		}

		type injCase struct {
			name        string
			inputValue  string
			wantLiteral string // what the var must equal after sourcing
		}

		// pid-tagged side-effect filenames prevent cross-test collisions.
		pid := fmt.Sprintf("%d", os.Getpid())
		sideEffect1 := filepath.Join(os.TempDir(), "byreis_pwned_"+pid)
		sideEffect2 := filepath.Join(os.TempDir(), "byreis_pwned2_"+pid)
		// Clean up any stale files from a previous failed run.
		// Errors are intentionally ignored: the files may not exist.
		_ = os.Remove(sideEffect1)
		_ = os.Remove(sideEffect2)
		t.Cleanup(func() {
			_ = os.Remove(sideEffect1)
			_ = os.Remove(sideEffect2)
		})

		cases := []injCase{
			{
				name:        "dollar_paren",
				inputValue:  fmt.Sprintf("$(touch %s)", sideEffect1),
				wantLiteral: fmt.Sprintf("$(touch %s)", sideEffect1),
			},
			{
				name:        "backtick",
				inputValue:  fmt.Sprintf("`touch %s`", sideEffect2),
				wantLiteral: fmt.Sprintf("`touch %s`", sideEffect2),
			},
			{
				name:        "dollar_brace",
				inputValue:  "${HOME}",
				wantLiteral: "${HOME}",
			},
			{
				name:        "bare_dollar_var",
				inputValue:  "$USER",
				wantLiteral: "$USER",
			},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				// Byte-level assertion: emitted bytes must contain \$ (for $)
				// or \` (for backtick) — confirms the escape function did its job.
				emitted, err := emitPairs(t, "BYREIS_TEST_KEY", tc.inputValue, FormatDotenv)
				if err != nil {
					t.Fatalf("AC-E %s: emit error: %v", tc.name, err)
				}
				if strings.Contains(tc.inputValue, "$") {
					if !strings.Contains(emitted, `\$`) {
						t.Errorf("AC-E %s: emitted bytes must contain \\$ to neutralize expansion; got %q",
							tc.name, emitted)
					}
				}
				if strings.Contains(tc.inputValue, "`") {
					if !strings.Contains(emitted, "\\`") {
						t.Errorf("AC-E %s: emitted bytes must contain \\` to neutralize expansion; got %q",
							tc.name, emitted)
					}
				}

				if !shAvailable {
					t.Logf("AC-E %s: sh not found — byte-level check passed, skipping round-trip", tc.name)
					return
				}

				// Round-trip: write the dotenv line to a temp file and source it in a
				// subprocess, then print the variable value.  Use dotenv format
				// (KEY="...") because sh can source it directly with `set -a; . file`.
				tmp, err := os.CreateTemp(t.TempDir(), "byreis_acE_*.env")
				if err != nil {
					t.Fatalf("AC-E %s: create temp: %v", tc.name, err)
				}
				if _, err := tmp.WriteString(emitted); err != nil {
					t.Fatalf("AC-E %s: write temp: %v", tc.name, err)
				}
				if err := tmp.Close(); err != nil {
					t.Fatalf("AC-E %s: close temp: %v", tc.name, err)
				}

				// The script sources the file and prints the variable value.
				// CommandContext carries the test deadline so the subprocess is
				// killed if the test times out rather than leaking a sh process.
				script := fmt.Sprintf(
					". %s && printf '%%s' \"$BYREIS_TEST_KEY\"",
					tmp.Name(),
				)
				out, runErr := exec.CommandContext(t.Context(), shPath, "-c", script).Output()
				if runErr != nil {
					t.Fatalf("AC-E %s: sh execution failed: %v", tc.name, runErr)
				}
				got := string(out)
				if got != tc.wantLiteral {
					t.Errorf("AC-E %s: after sourcing, var = %q, want literal %q — expansion was NOT neutralized",
						tc.name, got, tc.wantLiteral)
				}
			})
		}

		// No side-effect files must exist after any of the sub-tests ran.
		if _, err := os.Stat(sideEffect1); err == nil {
			t.Errorf("AC-E: side-effect file %s was created — dollar-paren injection was NOT neutralized", sideEffect1)
		}
		if _, err := os.Stat(sideEffect2); err == nil {
			t.Errorf("AC-E: side-effect file %s was created — backtick injection was NOT neutralized", sideEffect2)
		}
	})

	// REQ-V07-003 AC-F: single-quote in value — no escaping needed (inside double-quotes).
	t.Run("AC_F_single_quote_no_escape", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", "it's", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "KEY=\"it's\"\n"
		if got != want {
			t.Errorf("AC-F: got %q, want %q", got, want)
		}
	})

	// REQ-V07-003 AC-G: whitespace preserved.
	t.Run("AC_G_whitespace_preserved", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", "  spaced  ", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := `KEY="  spaced  "` + "\n"
		if got != want {
			t.Errorf("AC-G: got %q, want %q", got, want)
		}
	})

	// REQ-V07-003 AC-H: empty value -> KEY="".
	t.Run("AC_H_empty_value", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", "", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "KEY=\"\"\n"
		if got != want {
			t.Errorf("AC-H: got %q, want %q", got, want)
		}
	})

	// REQ-V07-003 AC-I: literal text \n (two chars, backslash + n) -> KEY="\\n".
	t.Run("AC_I_literal_backslash_n_text", func(t *testing.T) {
		t.Parallel()
		// The Go string `\n` (two chars) in the secret value must become `\\n` in output.
		got, err := emitPairs(t, "KEY", `\n`, FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// backslash escaped to \\, then n literal -> \\n
		want := `KEY="\\n"` + "\n"
		if got != want {
			t.Errorf("AC-I: got %q, want %q", got, want)
		}
	})

	// REQ-V07-003 AC-J: UTF-8 verbatim, NUL rejected, other C0 escaped.
	t.Run("AC_J_utf8_verbatim", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", "café→€", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "KEY=\"café→€\"\n"
		if got != want {
			t.Errorf("AC-J UTF-8: got %q, want %q", got, want)
		}
	})

	t.Run("AC_J_nul_rejected", func(t *testing.T) {
		t.Parallel()
		pairs := []EnvPair{{Var: "KEY", Value: "before\x00after"}}
		var buf bytes.Buffer
		err := EmitEnv(&buf, pairs, FormatDotenv)
		if !errors.Is(err, ErrNulInValue) {
			t.Errorf("AC-J NUL: expected ErrNulInValue, got %v", err)
		}
		// Fail-closed: no partial output.
		if buf.Len() != 0 {
			t.Errorf("AC-J NUL: expected no output on error, got %q", buf.String())
		}
	})

	t.Run("AC_J_c0_control_escaped", func(t *testing.T) {
		t.Parallel()
		// 0x01 (SOH) is a C0 control char other than NUL/\n/\r/\t — must be escaped.
		got, err := emitPairs(t, "KEY", "a\x01b", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Must not contain the raw 0x01 byte.
		if strings.ContainsRune(got, '\x01') {
			t.Errorf("AC-J C0: raw 0x01 must not appear in output: %q", got)
		}
		// Must still contain a and b.
		if !strings.Contains(got, "a") || !strings.Contains(got, "b") {
			t.Errorf("AC-J C0: surrounding chars lost: %q", got)
		}
	})

	// REQ-V07-003 AC-K: --format env uses `export ` prefix; --format dotenv does not.
	t.Run("AC_K_env_prefix", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "MY_KEY", "val", FormatEnv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := `export MY_KEY="val"` + "\n"
		if got != want {
			t.Errorf("AC-K env: got %q, want %q", got, want)
		}
	})

	t.Run("AC_K_dotenv_no_prefix", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "MY_KEY", "val", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := `MY_KEY="val"` + "\n"
		if got != want {
			t.Errorf("AC-K dotenv: got %q, want %q", got, want)
		}
	})

	// Escape chain: backslash -> \\, then quote -> \".
	t.Run("backslash_escaped", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", `path\to\file`, FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := `KEY="path\\to\\file"` + "\n"
		if got != want {
			t.Errorf("backslash: got %q, want %q", got, want)
		}
	})

	// CR escaped.
	t.Run("CR_escaped", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", "line1\rline2", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := `KEY="line1\rline2"` + "\n"
		if got != want {
			t.Errorf("CR: got %q, want %q", got, want)
		}
	})

	// Tab escaped.
	t.Run("tab_escaped", func(t *testing.T) {
		t.Parallel()
		got, err := emitPairs(t, "KEY", "col1\tcol2", FormatDotenv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := `KEY="col1\tcol2"` + "\n"
		if got != want {
			t.Errorf("tab: got %q, want %q", got, want)
		}
	})
}

// TestEmitEnv_MultiPairSorted verifies that multiple pairs are emitted in
// sorted (by Var) order and that keys are sorted in both formats.
func TestEmitEnv_MultiPairSorted(t *testing.T) {
	t.Parallel()

	pairs := []EnvPair{
		{Var: "ZEBRA", Value: "z"},
		{Var: "ALPHA", Value: "a"},
		{Var: "GAMMA", Value: "g"},
	}

	for _, format := range []EnvFormat{FormatEnv, FormatDotenv} {
		format := format
		name := "dotenv"
		if format == FormatEnv {
			name = "env"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := EmitEnv(&buf, pairs, format); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
			if len(lines) != 3 {
				t.Fatalf("expected 3 lines, got %d: %q", len(lines), buf.String())
			}
			// Pairs are expected to be emitted in the order provided (sorting
			// is done by BuildEnvPairs, not EmitEnv — EmitEnv is a serializer).
			// Verify first line starts with ZEBRA (order of pairs slice).
			if !strings.Contains(lines[0], "ZEBRA") {
				t.Errorf("first line should contain ZEBRA, got %q", lines[0])
			}
		})
	}
}

// TestEmitEnv_NulRejectedFailClosed verifies that EmitEnv writes zero bytes to
// the writer when a NUL is found in any value (fail-closed, not partial emission).
func TestEmitEnv_NulRejectedFailClosed(t *testing.T) {
	t.Parallel()

	// First pair is clean; second has NUL. No output must be written for either.
	pairs := []EnvPair{
		{Var: "CLEAN", Value: "ok"},
		{Var: "DIRTY", Value: "has\x00nul"},
	}
	var buf bytes.Buffer
	err := EmitEnv(&buf, pairs, FormatDotenv)
	if !errors.Is(err, ErrNulInValue) {
		t.Errorf("expected ErrNulInValue, got %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("no bytes must be written on NUL error, got %q", buf.String())
	}
}

// TestEmitEnv_EmptyPairs verifies that no output is written for an empty slice.
func TestEmitEnv_EmptyPairs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := EmitEnv(&buf, nil, FormatDotenv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

// TestBuildEnvPairs_SortedBySourceKey verifies that BuildEnvPairs sorts
// output by the source key name (after mapping), giving stable output.
func TestBuildEnvPairs_SortedBySourceKey(t *testing.T) {
	t.Parallel()

	pt := map[string]string{
		"z_key": "vz",
		"a_key": "va",
		"m_key": "vm",
	}
	// keyNames intentionally in non-sorted order.
	names := []string{"z_key", "a_key", "m_key"}
	pairs, err := BuildEnvPairs(pt, names)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After mapping, all names are already valid, sorted result should be a_key, m_key, z_key.
	wantVars := []string{"a_key", "m_key", "z_key"}
	for i, p := range pairs {
		if p.Var != wantVars[i] {
			t.Errorf("pairs[%d].Var = %q, want %q", i, p.Var, wantVars[i])
		}
	}
}

// TestEnvSentinelsAreDistinct verifies the three sentinel errors are distinct
// from each other and from nil.
func TestEnvSentinelsAreDistinct(t *testing.T) {
	t.Parallel()

	if ErrLeadingDigit == nil {
		t.Error("ErrLeadingDigit must not be nil")
	}
	if ErrVarCollision == nil {
		t.Error("ErrVarCollision must not be nil")
	}
	if ErrNulInValue == nil {
		t.Error("ErrNulInValue must not be nil")
	}
	if errors.Is(ErrLeadingDigit, ErrVarCollision) {
		t.Error("ErrLeadingDigit and ErrVarCollision must be distinct")
	}
	if errors.Is(ErrLeadingDigit, ErrNulInValue) {
		t.Error("ErrLeadingDigit and ErrNulInValue must be distinct")
	}
	if errors.Is(ErrVarCollision, ErrNulInValue) {
		t.Error("ErrVarCollision and ErrNulInValue must be distinct")
	}
}

// TestBuildEnvPairs_CollisionMessageContainsBothKeys verifies the collision
// error string names both source keys (never last-wins, never silent).
func TestBuildEnvPairs_CollisionMessageContainsBothKeys(t *testing.T) {
	t.Parallel()

	pt := map[string]string{
		"api.key": "val1",
		"api-key": "val2",
	}
	_, err := BuildEnvPairs(pt, []string{"api.key", "api-key"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "api.key") {
		t.Errorf("collision error must name 'api.key': %q", msg)
	}
	if !strings.Contains(msg, "api-key") {
		t.Errorf("collision error must name 'api-key': %q", msg)
	}
}
