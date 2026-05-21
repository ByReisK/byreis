package render

import (
	"strings"
	"testing"
	"testing/quick"
	"unicode/utf8"
)

// TestSanitizeForTerminal_BasicPassThrough verifies that plain ASCII text with
// no control codes is returned unchanged.
func TestSanitizeForTerminal_BasicPassThrough(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"hello world", "hello world"},
		{"line1\nline2", "line1\nline2"},
		{"tab\there", "tab\there"},
		{"", ""},
		{"abc", "abc"},
	}
	for _, tc := range cases {
		got := SanitizeForTerminal(tc.in)
		if got != tc.want {
			t.Errorf("SanitizeForTerminal(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSanitizeForTerminal_ANSIStripped verifies that ANSI CSI escape sequences
// are removed entirely.
func TestSanitizeForTerminal_ANSIStripped(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"\x1b[0mhello\x1b[0m", "hello"},
		{"\x1b[31mred\x1b[0m", "red"},
		{"\x1b[1;32mbold-green\x1b[0m text", "bold-green text"},
		{"before\x1b[2Jafter", "beforeafter"},
		{"\x1b[?25l", ""},     // cursor-hide
		{"\x1b[H\x1b[2J", ""}, // home + clear
	}
	for _, tc := range cases {
		got := SanitizeForTerminal(tc.in)
		if got != tc.want {
			t.Errorf("SanitizeForTerminal(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSanitizeForTerminal_OSCStripped verifies that OSC escape sequences are removed.
func TestSanitizeForTerminal_OSCStripped(t *testing.T) {
	// OSC terminated by BEL
	in1 := "\x1b]0;window title\x07normal"
	got1 := SanitizeForTerminal(in1)
	if got1 != "normal" {
		t.Errorf("OSC/BEL: got %q, want %q", got1, "normal")
	}

	// OSC terminated by ST (\x1b\\)
	in2 := "\x1b]8;;https://example.com\x1b\\link\x1b]8;;\x1b\\end"
	got2 := SanitizeForTerminal(in2)
	if got2 != "linkend" {
		t.Errorf("OSC/ST: got %q, want %q", got2, "linkend")
	}
}

// TestSanitizeForTerminal_CarriageReturn verifies that \r is replaced with a space.
func TestSanitizeForTerminal_CarriageReturn(t *testing.T) {
	got := SanitizeForTerminal("line1\rline2")
	if !strings.Contains(got, "line2") {
		t.Errorf("expected line2 in output, got %q", got)
	}
	if strings.ContainsRune(got, '\r') {
		t.Errorf("\\r must not appear in output, got %q", got)
	}
}

// TestSanitizeForTerminal_C0ControlRemoved verifies that C0 control characters
// below 0x20 (except \n and \t) are removed.
func TestSanitizeForTerminal_C0ControlRemoved(t *testing.T) {
	for b := byte(0x00); b < 0x20; b++ {
		if b == '\n' || b == '\t' {
			continue
		}
		in := "before" + string([]byte{b}) + "after"
		got := SanitizeForTerminal(in)
		if strings.Contains(got, string([]byte{b})) {
			t.Errorf("C0 byte 0x%02X must be removed, got %q", b, got)
		}
		if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
			t.Errorf("surrounding text lost for C0 byte 0x%02X, got %q", b, got)
		}
	}
}

// TestSanitizeForTerminal_BidiControlsRemoved verifies that bidi control
// characters are stripped.
func TestSanitizeForTerminal_BidiControlsRemoved(t *testing.T) {
	bidiControls := []rune{
		0x061C, // ARABIC LETTER MARK
		0x200E, // LEFT-TO-RIGHT MARK
		0x200F, // RIGHT-TO-LEFT MARK
		0x202A, // LEFT-TO-RIGHT EMBEDDING
		0x202B, // RIGHT-TO-LEFT EMBEDDING
		0x202C, // POP DIRECTIONAL FORMATTING
		0x202D, // LEFT-TO-RIGHT OVERRIDE
		0x202E, // RIGHT-TO-LEFT OVERRIDE
		0x2066, // LEFT-TO-RIGHT ISOLATE
		0x2067, // RIGHT-TO-LEFT ISOLATE
		0x2068, // FIRST STRONG ISOLATE
		0x2069, // POP DIRECTIONAL ISOLATE
	}
	for _, ctrl := range bidiControls {
		in := "before" + string(ctrl) + "after"
		got := SanitizeForTerminal(in)
		if strings.ContainsRune(got, ctrl) {
			t.Errorf("bidi U+%04X must be removed, got %q", ctrl, got)
		}
		if got != "beforeafter" {
			t.Errorf("bidi U+%04X: got %q, want %q", ctrl, got, "beforeafter")
		}
	}
}

// TestSanitizeForTerminal_LengthBound verifies that output never exceeds
// maxSanitizedLen bytes.
func TestSanitizeForTerminal_LengthBound(t *testing.T) {
	long := strings.Repeat("a", maxSanitizedLen+500)
	got := SanitizeForTerminal(long)
	if len(got) > maxSanitizedLen {
		t.Errorf("output length %d exceeds maxSanitizedLen %d", len(got), maxSanitizedLen)
	}
}

// TestSanitizeForTerminal_LengthBound_ValidUTF8 verifies that after truncation
// the output is still valid UTF-8.
func TestSanitizeForTerminal_LengthBound_ValidUTF8(t *testing.T) {
	// A 3-byte UTF-8 rune repeated past the limit.
	long := strings.Repeat("こ", (maxSanitizedLen/3)+10)
	got := SanitizeForTerminal(long)
	if !utf8.ValidString(got) {
		t.Errorf("output is not valid UTF-8 after truncation")
	}
	if len(got) > maxSanitizedLen {
		t.Errorf("output length %d exceeds maxSanitizedLen %d", len(got), maxSanitizedLen)
	}
}

// TestSanitizeForTerminal_Idempotent verifies that applying SanitizeForTerminal
// twice produces the same result as applying it once.
func TestSanitizeForTerminal_Idempotent(t *testing.T) {
	inputs := []string{
		"\x1b[31mhello\x1b[0m",
		"hello\rworld\nfoo\t bar",
		"\x1b]0;title\x07text",
		string([]rune{0x202E, 'a', 'b', 'c'}),
		strings.Repeat("x", maxSanitizedLen+100),
	}
	for _, in := range inputs {
		once := SanitizeForTerminal(in)
		twice := SanitizeForTerminal(once)
		if once != twice {
			t.Errorf("SanitizeForTerminal not idempotent for %q: once=%q twice=%q", in, once, twice)
		}
	}
}

// TestSanitizeForTerminal_OutputValidUTF8 verifies that every output is valid UTF-8.
func TestSanitizeForTerminal_OutputValidUTF8(t *testing.T) {
	cases := []string{
		"hello world",
		"\x1b[0mtext",
		"\xFF\xFE invalid utf-8 bytes",
		"valid 中文 text",
	}
	for _, in := range cases {
		got := SanitizeForTerminal(in)
		if !utf8.ValidString(got) {
			t.Errorf("output is not valid UTF-8 for input %q: got %q", in, got)
		}
	}
}

// TestSanitizeForTerminal_QuickCheck is a property test: for any string s,
// SanitizeForTerminal(s) must:
//   - be valid UTF-8
//   - have length <= maxSanitizedLen
//   - not contain ANSI ESC byte
//   - not contain \r
//   - equal SanitizeForTerminal(SanitizeForTerminal(s)) (idempotent)
func TestSanitizeForTerminal_QuickCheck(t *testing.T) {
	f := func(s string) bool {
		out := SanitizeForTerminal(s)
		if !utf8.ValidString(out) {
			return false
		}
		if len(out) > maxSanitizedLen {
			return false
		}
		if strings.ContainsRune(out, '\x1b') {
			return false
		}
		if strings.ContainsRune(out, '\r') {
			return false
		}
		// Idempotency.
		if SanitizeForTerminal(out) != out {
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Errorf("property test failed: %v", err)
	}
}
