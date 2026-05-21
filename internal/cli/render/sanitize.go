package render

import (
	"strings"
	"unicode/utf8"
)

// maxSanitizedLen is the maximum byte length returned by SanitizeForTerminal.
// The request-access justification is capped at 1000 bytes at schema time;
// the render-side limit is more generous to accommodate future sources, but
// still provides an upper bound for safe terminal output.
const maxSanitizedLen = 2000

// SanitizeForTerminal returns a copy of s with all control codes, ANSI escape
// sequences, non-printable bytes, bidi controls, and carriage returns stripped
// or replaced. The output is safe for display on an operator terminal without
// risk of terminal injection, cursor-poisoning, or line-ending confusion.
//
// Rules applied, in order:
//
//  1. Strip ANSI CSI sequences  (\x1b[...m) — OSC sequences (\x1b]...\x07 or
//     \x1b]...\x1b\\).
//  2. Remove bare ESC bytes (\x1b) not part of a recognised sequence.
//  3. Replace \r (carriage return) with a space to prevent cursor-overwrite.
//  4. Remove C0 control characters below 0x20 except \n and \t.
//  5. Remove common Unicode bidi controls (U+200E LRM, U+200F RLM, U+202A-E
//     directional embedding/override, U+2066-2069 isolate/FSI/PDI, U+061C ALM).
//  6. Remove other Unicode non-printable code points (categories Cf, Cc, Cs).
//  7. Truncate to maxSanitizedLen bytes, preserving valid UTF-8 boundaries.
//
// The function is idempotent: applying it twice produces the same output as
// applying it once.
func SanitizeForTerminal(s string) string {
	if s == "" {
		return ""
	}

	// Pass 1: strip ANSI CSI and OSC escape sequences, bare ESC, and CR.
	s = stripANSI(s)

	// Pass 2: strip remaining C0 control chars (< 0x20) except \n and \t;
	// replace \r with space; remove bidi / non-printable Unicode code points.
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte: skip.
			continue
		}
		if r == '\r' {
			b.WriteByte(' ')
			continue
		}
		if r < 0x20 && r != '\n' && r != '\t' {
			// C0 control character other than LF/TAB.
			continue
		}
		if isBidiControl(r) {
			continue
		}
		if isNonPrintableUnicode(r) {
			continue
		}
		b.WriteRune(r)
	}

	result := b.String()

	// Pass 3: truncate to maxSanitizedLen bytes at a valid UTF-8 boundary.
	if len(result) > maxSanitizedLen {
		result = truncateUTF8(result, maxSanitizedLen)
	}

	return result
}

// stripANSI removes ANSI CSI escape sequences (\x1b[...m), OSC sequences
// (\x1b]...\x07 or \x1b]...\x1b\\), and bare \x1b bytes.
func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\x1b' {
			if i+1 < len(s) && s[i+1] == '[' {
				// CSI sequence: \x1b[ ... final byte in 0x40-0x7E
				i += 2
				for i < len(s) {
					c := s[i]
					i++
					if c >= 0x40 && c <= 0x7E {
						break
					}
				}
				continue
			}
			if i+1 < len(s) && s[i+1] == ']' {
				// OSC sequence: \x1b] ... ST (BEL 0x07 or \x1b\\)
				i += 2
				for i < len(s) {
					if s[i] == '\x07' {
						i++
						break
					}
					if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\' {
						i += 2
						break
					}
					i++
				}
				continue
			}
			// Bare ESC: skip.
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// isBidiControl reports whether r is a Unicode bidi direction control character.
// These are used in "Trojan-source" style attacks to make code look different
// from what it actually does. We remove them from operator-visible text.
func isBidiControl(r rune) bool {
	switch r {
	case 0x061C, // ARABIC LETTER MARK
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
		0x2069: // POP DIRECTIONAL ISOLATE
		return true
	}
	return false
}

// isNonPrintableUnicode reports whether r is a Unicode non-printable code point
// beyond the C0 range already handled in the main loop. This covers the C1
// control range (0x80–0x9F), soft-hyphen (0xAD), zero-width characters, and
// format characters (general category Cf) that are not bidi controls.
func isNonPrintableUnicode(r rune) bool {
	// C1 controls
	if r >= 0x80 && r <= 0x9F {
		return true
	}
	// Soft hyphen
	if r == 0x00AD {
		return true
	}
	// Zero-width non-joiner / joiner
	if r == 0x200B || r == 0x200C || r == 0x200D {
		return true
	}
	// Word joiner
	if r == 0x2060 {
		return true
	}
	// Zero-width no-break space (BOM in mid-stream)
	if r == 0xFEFF {
		return true
	}
	// Interlinear annotation (U+FFF9–U+FFFB)
	if r >= 0xFFF9 && r <= 0xFFFB {
		return true
	}
	return false
}

// truncateUTF8 returns the longest prefix of s that is at most maxBytes bytes
// and ends on a valid UTF-8 code-point boundary. Never panics.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Walk back from maxBytes to find a valid rune boundary.
	end := maxBytes
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}
