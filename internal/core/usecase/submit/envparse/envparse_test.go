package envparse_test

// Table-driven tests for the .env bulk-submit parser.
//
// The parser is pure: it takes raw bytes and returns an ordered slice of
// (Key, Value) pairs or a line-numbered error. It never touches fs/net/clock
// and never judges value CONTENT (the value validator owns that policy); it
// only tokenises and enforces the structural well-formedness rules.
//
// Each test names the parse resolution it pins (ADR-0016 §13.4 R1..R10):
//   R1  comment only at line-start; '#' inside a value is literal data.
//   R2  strip a leading "export " prefix.
//   R3  split on the FIRST '='.
//   R4  strip exactly one matching outer quote pair; no escape interpretation.
//   R5  duplicate key within the file = HARD ERROR, refuse-all.
//   R6  empty value is a well-formed pair (the validator judges it later).
//   R7  N <= 100 pairs hard ceiling.
//   R8  key ordering = file order (stable).
//   R9  (CLI-layer: 1-pair takes the bulk path — exercised by reaching N==1.)
//   R10 (CLI-layer: --file/--key mutual exclusion — not a parser concern.)

import (
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/core/usecase/submit/envparse"
)

// ---- happy path + ordering (R3, R8) ----

func TestParse_HappyPath_PreservesFileOrder(t *testing.T) {
	t.Parallel()
	in := []byte("DATABASE_URL=postgres://localhost\nAPI_TOKEN=abc123\nZ_LAST=z\n")
	got, err := envparse.Parse(in)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	want := []envparse.Pair{
		{Key: "DATABASE_URL", Value: "postgres://localhost"},
		{Key: "API_TOKEN", Value: "abc123"},
		{Key: "Z_LAST", Value: "z"},
	}
	assertPairs(t, got, want)
}

// ---- R1: comment only at line-start; '#' in value is literal ----

func TestParse_CommentRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want []envparse.Pair
	}{
		{
			name: "leading-hash line is a comment",
			in:   "# this is a comment\nKEY=value\n",
			want: []envparse.Pair{{Key: "KEY", Value: "value"}},
		},
		{
			name: "indented hash is still a comment",
			in:   "   \t # indented comment\nKEY=value\n",
			want: []envparse.Pair{{Key: "KEY", Value: "value"}},
		},
		{
			name: "hash inside value is literal data, not an inline comment",
			in:   "PASSWORD=p@ss#word#1\n",
			want: []envparse.Pair{{Key: "PASSWORD", Value: "p@ss#word#1"}},
		},
		{
			name: "blank lines are skipped",
			in:   "\n\nKEY=value\n\n",
			want: []envparse.Pair{{Key: "KEY", Value: "value"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := envparse.Parse([]byte(tc.in))
			if err != nil {
				t.Fatalf("Parse: unexpected error: %v", err)
			}
			assertPairs(t, got, tc.want)
		})
	}
}

// ---- R2: strip a leading "export " prefix ----

func TestParse_ExportPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want []envparse.Pair
	}{
		{
			name: "export with single space",
			in:   "export KEY=value\n",
			want: []envparse.Pair{{Key: "KEY", Value: "value"}},
		},
		{
			name: "export with tab",
			in:   "export\tKEY=value\n",
			want: []envparse.Pair{{Key: "KEY", Value: "value"}},
		},
		{
			name: "export with multiple spaces",
			in:   "export   KEY=value\n",
			want: []envparse.Pair{{Key: "KEY", Value: "value"}},
		},
		{
			name: "a key literally named exported is not stripped",
			in:   "exportedKEY=value\n",
			want: []envparse.Pair{{Key: "exportedKEY", Value: "value"}},
		},
		{
			name: "export not followed by whitespace is part of the key",
			in:   "export=value\n",
			want: []envparse.Pair{{Key: "export", Value: "value"}},
		},
		{
			name: "export appearing in the value is not stripped",
			in:   "CMD=export FOO=bar\n",
			want: []envparse.Pair{{Key: "CMD", Value: "export FOO=bar"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := envparse.Parse([]byte(tc.in))
			if err != nil {
				t.Fatalf("Parse: unexpected error: %v", err)
			}
			assertPairs(t, got, tc.want)
		})
	}
}

// ---- R3: split on the FIRST '=' ----

func TestParse_SplitOnFirstEquals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want []envparse.Pair
	}{
		{
			name: "value contains further equals signs (base64 padding)",
			in:   "TOKEN=YWJjZGVm==\n",
			want: []envparse.Pair{{Key: "TOKEN", Value: "YWJjZGVm=="}},
		},
		{
			name: "connection string with equals",
			in:   "CONN=Server=db;Port=5432\n",
			want: []envparse.Pair{{Key: "CONN", Value: "Server=db;Port=5432"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := envparse.Parse([]byte(tc.in))
			if err != nil {
				t.Fatalf("Parse: unexpected error: %v", err)
			}
			assertPairs(t, got, tc.want)
		})
	}
}

// ---- R4: strip exactly one matching outer quote pair; no escapes ----

func TestParse_QuoteHandling(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want []envparse.Pair
	}{
		{
			name: "double-quoted value strips one outer pair",
			in:   `KEY="hello world"` + "\n",
			want: []envparse.Pair{{Key: "KEY", Value: "hello world"}},
		},
		{
			name: "single-quoted value strips one outer pair",
			in:   "KEY='hello world'\n",
			want: []envparse.Pair{{Key: "KEY", Value: "hello world"}},
		},
		{
			name: "whitespace inside quotes is preserved",
			in:   `KEY="  spaced  "` + "\n",
			want: []envparse.Pair{{Key: "KEY", Value: "  spaced  "}},
		},
		{
			name: "whitespace outside quotes is trimmed before the quote check",
			in:   `KEY=   "quoted"   ` + "\n",
			want: []envparse.Pair{{Key: "KEY", Value: "quoted"}},
		},
		{
			name: "unquoted value is trimmed both ends",
			in:   "KEY=   bare value   \n",
			want: []envparse.Pair{{Key: "KEY", Value: "bare value"}},
		},
		{
			name: "no escape interpretation: backslash-n is literal",
			in:   `KEY="line1\nline2"` + "\n",
			want: []envparse.Pair{{Key: "KEY", Value: `line1\nline2`}},
		},
		{
			name: "mismatched quote chars are taken literally",
			in:   `KEY="mismatch'` + "\n",
			want: []envparse.Pair{{Key: "KEY", Value: `"mismatch'`}},
		},
		{
			name: "leading quote without matching trailing quote is literal",
			in:   `KEY="unterminated` + "\n",
			want: []envparse.Pair{{Key: "KEY", Value: `"unterminated`}},
		},
		{
			name: "a single quote char alone is literal (length < 2)",
			in:   `KEY="` + "\n",
			want: []envparse.Pair{{Key: "KEY", Value: `"`}},
		},
		{
			name: "inner quote of the same char is preserved",
			in:   `KEY="say ""hi"""` + "\n",
			want: []envparse.Pair{{Key: "KEY", Value: `say ""hi""`}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := envparse.Parse([]byte(tc.in))
			if err != nil {
				t.Fatalf("Parse: unexpected error: %v", err)
			}
			assertPairs(t, got, tc.want)
		})
	}
}

// ---- R5: duplicate key = HARD ERROR, refuse-all (names both line numbers) ----

func TestParse_DuplicateKey_RefusesAll(t *testing.T) {
	t.Parallel()
	in := []byte("FIRST=a\nDUP=1\nOTHER=b\nDUP=2\n")
	got, err := envparse.Parse(in)
	if err == nil {
		t.Fatalf("want a hard error for a duplicate key, got nil (pairs=%v)", got)
	}
	if !errors.Is(err, envparse.ErrDuplicateKey) {
		t.Fatalf("want ErrDuplicateKey, got %v", err)
	}
	if got != nil {
		t.Fatalf("refuse-all: no pairs must be returned on duplicate, got %v", got)
	}
	// The error must name the duplicated key and BOTH offending line numbers.
	msg := err.Error()
	for _, want := range []string{"DUP", "2", "4"} {
		if !strings.Contains(msg, want) {
			t.Errorf("duplicate error %q must mention %q (key + both line numbers)", msg, want)
		}
	}
}

// ---- R6: empty value is a well-formed pair (validator judges later) ----

func TestParse_EmptyValueIsWellFormed(t *testing.T) {
	t.Parallel()
	in := []byte("EMPTY=\nQUOTED_EMPTY=\"\"\n")
	got, err := envparse.Parse(in)
	if err != nil {
		t.Fatalf("Parse: empty value must not be a parse error: %v", err)
	}
	assertPairs(t, got, []envparse.Pair{
		{Key: "EMPTY", Value: ""},
		{Key: "QUOTED_EMPTY", Value: ""},
	})
}

// ---- R7: N <= 100 pairs hard ceiling ----

func TestParse_MaxPairsCeiling(t *testing.T) {
	t.Parallel()

	exactly100 := buildPairs(t, 100)
	if _, err := envparse.Parse(exactly100); err != nil {
		t.Fatalf("exactly 100 pairs must be accepted: %v", err)
	}

	over := buildPairs(t, 101)
	got, err := envparse.Parse(over)
	if err == nil {
		t.Fatalf("101 pairs must be rejected by the ceiling, got nil")
	}
	if !errors.Is(err, envparse.ErrTooManyPairs) {
		t.Fatalf("want ErrTooManyPairs, got %v", err)
	}
	if got != nil {
		t.Fatalf("refuse-all on ceiling: no pairs returned, got %d", len(got))
	}
	if !strings.Contains(err.Error(), "100") {
		t.Errorf("ceiling error %q must name the 100 limit", err.Error())
	}
}

// ---- oversize total input -> ErrInputTooLarge before full allocation ----

func TestParse_OversizeInput_RejectsBeforeAllocation(t *testing.T) {
	t.Parallel()

	// Build an input that is exactly one byte over the 4 MiB ceiling. We use
	// a comment line so that even if the ceiling check were absent the line loop
	// would only see comments — confirming the error comes from the byte check
	// and not from a structural parse rule.
	const limit = 4 * 1024 * 1024
	over := make([]byte, limit+1)
	for i := range over {
		over[i] = 'x'
	}
	// Make it look like a single very long comment so no line rule fires first.
	over[0] = '#'

	got, err := envparse.Parse(over)
	if err == nil {
		t.Fatalf("want ErrInputTooLarge for %d-byte input, got nil (pairs=%v)", len(over), got)
	}
	if !errors.Is(err, envparse.ErrInputTooLarge) {
		t.Fatalf("want ErrInputTooLarge, got %v", err)
	}
	if got != nil {
		t.Fatalf("refuse-all: no pairs must be returned on oversize input, got %d", len(got))
	}
	// Error message must name the byte count and the limit.
	msg := err.Error()
	for _, want := range []string{"4194305", "4194304"} {
		if !strings.Contains(msg, want) {
			t.Errorf("ErrInputTooLarge message %q must mention %q", msg, want)
		}
	}
}

func TestParse_ExactlyAtInputCeiling_Accepted(t *testing.T) {
	t.Parallel()

	// An input whose byte count is exactly the ceiling must be accepted. We use
	// many short comment lines (each well within the per-line cap) so that only
	// the total-input ceiling is exercised — this purely tests that the boundary
	// condition is strictly-greater-than, not greater-than-or-equal.
	//
	// Each comment line is "# x\n" = 4 bytes. We write ceiling/4 lines to reach
	// exactly the ceiling byte count.
	const limit = 4 * 1024 * 1024
	const lineLen = 4 // "# x\n"
	var b strings.Builder
	b.Grow(limit)
	for i := 0; i < limit/lineLen; i++ {
		b.WriteString("# x\n")
	}
	at := []byte(b.String())
	if len(at) != limit {
		t.Fatalf("test setup: built %d bytes, want exactly %d", len(at), limit)
	}

	got, err := envparse.Parse(at)
	if err != nil {
		t.Fatalf("input at the ceiling (%d bytes) must be accepted: %v", limit, err)
	}
	if len(got) != 0 {
		t.Fatalf("comment-only input must yield zero pairs, got %d", len(got))
	}
}

// ---- oversize single line -> ErrLineTooLong before per-line processing ----

func TestParse_OversizeLine_RejectsWithLineNumber(t *testing.T) {
	t.Parallel()

	// Build an input under the total-input ceiling but with a single line that
	// exceeds the 64 KiB per-line cap. We use two short leading lines so the
	// oversize line is line 3, allowing the test to verify the line number.
	const lineLimit = 64 * 1024
	var b strings.Builder
	b.WriteString("# comment\n")
	b.WriteString("GOOD=ok\n")
	// Line 3: a KEY= prefix followed by enough bytes to exceed lineLimit.
	b.WriteString("TOOLONG=")
	for i := 0; i < lineLimit; i++ {
		b.WriteByte('v')
	}
	b.WriteByte('\n')

	got, err := envparse.Parse([]byte(b.String()))
	if err == nil {
		t.Fatalf("want ErrLineTooLong for oversize line, got nil (pairs=%v)", got)
	}
	if !errors.Is(err, envparse.ErrLineTooLong) {
		t.Fatalf("want ErrLineTooLong, got %v", err)
	}
	if got != nil {
		t.Fatalf("refuse-all: no pairs must be returned on oversize line, got %d", len(got))
	}
	// Error must name the offending line number.
	if !strings.Contains(err.Error(), "3") {
		t.Errorf("ErrLineTooLong message %q must mention the offending line number 3", err.Error())
	}
}

func TestParse_LineExactlyAtLineCeiling_Accepted(t *testing.T) {
	t.Parallel()

	// A line whose byte count is exactly the ceiling must be accepted. The line
	// is a comment so no pair-level processing fires — this tests that the
	// boundary is < not <=.
	const lineLimit = 64 * 1024
	var b strings.Builder
	b.WriteByte('#')
	for i := 1; i < lineLimit; i++ {
		b.WriteByte('x')
	}
	b.WriteByte('\n')

	got, err := envparse.Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("line at the ceiling (%d bytes) must be accepted: %v", lineLimit, err)
	}
	if len(got) != 0 {
		t.Fatalf("comment-only input must yield zero pairs, got %d", len(got))
	}
}

// ---- malformed / unbalanced lines -> line-numbered error ----

func TestParse_MalformedLines(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		wantErr error
		// wantLine, when non-empty, must appear in the error message.
		wantLine string
	}{
		{
			name:     "line with no equals sign",
			in:       "GOOD=ok\nthisHasNoEquals\n",
			wantErr:  envparse.ErrMalformedLine,
			wantLine: "2",
		},
		{
			name:     "empty key (line starts with equals)",
			in:       "=valueWithNoKey\n",
			wantErr:  envparse.ErrMalformedLine,
			wantLine: "1",
		},
		{
			name:     "export with nothing after it",
			in:       "export \n",
			wantErr:  envparse.ErrMalformedLine,
			wantLine: "1",
		},
		{
			name:     "key with embedded space before equals",
			in:       "BAD KEY=value\n",
			wantErr:  envparse.ErrMalformedLine,
			wantLine: "1",
		},
		{
			name:     "key containing a hash before the equals",
			in:       "BAD#KEY=value\n",
			wantErr:  envparse.ErrMalformedLine,
			wantLine: "1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := envparse.Parse([]byte(tc.in))
			if err == nil {
				t.Fatalf("want error %v, got nil (pairs=%v)", tc.wantErr, got)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
			if got != nil {
				t.Fatalf("refuse-all on malformed line: no pairs returned, got %v", got)
			}
			if tc.wantLine != "" && !strings.Contains(err.Error(), tc.wantLine) {
				t.Errorf("error %q must name the offending line number %q", err.Error(), tc.wantLine)
			}
		})
	}
}

// ---- empty input / comments-only yields zero pairs, no error ----

func TestParse_NoPairs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
	}{
		{"empty input", ""},
		{"comments and blank lines only", "# a\n\n   # b\n\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := envparse.Parse([]byte(tc.in))
			if err != nil {
				t.Fatalf("Parse: unexpected error: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("want zero pairs, got %v", got)
			}
		})
	}
}

// ---- CRLF line endings tolerated ----

func TestParse_CRLF(t *testing.T) {
	t.Parallel()
	in := []byte("KEY=value\r\nOTHER=v2\r\n")
	got, err := envparse.Parse(in)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	assertPairs(t, got, []envparse.Pair{
		{Key: "KEY", Value: "value"},
		{Key: "OTHER", Value: "v2"},
	})
}

// ---- helpers ----

func assertPairs(t *testing.T, got, want []envparse.Pair) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("pair count: got %d, want %d (%v vs %v)", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i].Key != want[i].Key || got[i].Value != want[i].Value {
			t.Errorf("pair[%d]: got {%q,%q}, want {%q,%q}",
				i, got[i].Key, got[i].Value, want[i].Key, want[i].Value)
		}
	}
}

func buildPairs(t *testing.T, n int) []byte {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("KEY")
		b.WriteString(itoa(i))
		b.WriteString("=v")
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
