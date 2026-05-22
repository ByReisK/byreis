// Package envparse is the pure .env tokeniser for bulk submit. It turns the
// raw bytes of a dotenv-style file into an ordered slice of (Key, Value) pairs,
// or a line-numbered error.
//
// It is deliberately conservative and stdlib-only: it has no third-party
// dependency and imports nothing from the byreis module, so its full transitive
// dependency set is the standard library. That keeps it safely on the Submit
// import allowlist — there is no route from here to identity, decrypt, or
// counter-authority material.
//
// Separation of concerns: this parser tokenises and enforces STRUCTURAL
// well-formedness only. It never judges value CONTENT — whether an empty value,
// a long value, or a particular byte sequence is an acceptable secret is the
// value validator's policy, applied downstream. The cross-cutting limits it
// enforces are:
//
//   - A hard ceiling on the number of pairs (a denial-of-service bound on
//     encryption work and PR-body metadata).
//   - A hard ceiling on the total input byte length (defense-in-depth: the
//     CLI/adapter layer has its own outer cap, but this package is a core
//     package and may be called from any site — it must be self-bounding).
//   - A per-line byte cap during tokenization so a single pathologically long
//     line cannot OOM the line-level processing.
//
// Parse rules (a conservative dotenv subset):
//
//   - A line whose first non-whitespace byte is '#' is a comment and is
//     skipped. A '#' after the '=' (inside the value) is a literal value byte;
//     there is no inline-comment stripping (secret values legitimately contain
//     '#').
//   - A leading "export " token (followed by at least one space or tab) is
//     stripped before the key is read.
//   - The line is split on the FIRST '='. The key is everything to its left;
//     the value is everything to its right (which may contain further '=').
//   - The value is trimmed of leading/trailing ASCII whitespace; if it then
//     begins and ends with a matching outer quote pair (the same double- or
//     single-quote char at both ends, length >= 2), exactly that one outer pair
//     is stripped and the inner bytes are taken verbatim (no escape
//     interpretation). Whitespace inside the quotes is preserved.
//   - A duplicate key anywhere in the file is a hard error: the whole file is
//     refused (no pairs returned), naming the key and both line numbers.
//   - An empty value (KEY=) is a well-formed pair; the validator judges it.
//   - More than maxPairs pairs is a hard error (DoS bound).
//   - Parsed pairs preserve file order.
package envparse

import (
	"errors"
	"fmt"
	"strings"
)

// maxPairs is the hard ceiling on the number of key/value pairs a single bulk
// submission may carry. It bounds the per-submission encryption work and the
// PR-body metadata size; it sits comfortably above realistic .env sizes.
const maxPairs = 100

// maxInputBytes is the core-layer ceiling on the total byte length of a raw
// .env input. This is a defense-in-depth bound: the CLI/adapter layer enforces
// its own outer file-size cap before calling Parse, but this package is a core
// package callable from any site and must be self-bounding. The ceiling is set
// to match the CLI outer cap (4 MiB), which is already well above any realistic
// dotenv file.
const maxInputBytes = 4 * 1024 * 1024 // 4 MiB

// maxLineBytes is the per-line byte ceiling. A single .env line longer than
// this cannot be a valid KEY=VALUE pair (keys are short identifiers; values are
// secrets, not documents). Enforcing it prevents a pathologically long line
// from causing an unbounded allocation in string-level processing. The limit is
// generous enough that no legitimate secret value would approach it.
const maxLineBytes = 64 * 1024 // 64 KiB per line

// Pair is one parsed key/value entry. Value is the literal secret value after
// quote-stripping; it is never escape-decoded.
type Pair struct {
	Key   string
	Value string
}

// Sentinel errors. Each wraps with %w and carries an actionable hint for the
// CLI layer to surface. None ever contains a secret value.
var (
	// ErrDuplicateKey is returned when the same key appears more than once in
	// one file. The whole file is refused (no pairs returned) so a contributor
	// can never silently lose a value to a last-wins overwrite.
	ErrDuplicateKey = errors.New(
		"refusing the .env file: a key appears more than once — " +
			"resolve the duplicate so it is unambiguous which value to submit")

	// ErrTooManyPairs is returned when a file yields more than the hard ceiling
	// of pairs. The whole file is refused.
	ErrTooManyPairs = errors.New(
		"refusing the .env file: too many key/value pairs in one submission")

	// ErrMalformedLine is returned when a non-comment, non-blank line is not a
	// well-formed KEY=VALUE assignment. The whole file is refused.
	ErrMalformedLine = errors.New(
		"refusing the .env file: a line is not a valid KEY=VALUE assignment")

	// ErrInputTooLarge is returned when the raw input byte length exceeds the
	// hard ceiling. The whole file is refused before any per-line allocation.
	ErrInputTooLarge = errors.New(
		"refusing the .env file: input exceeds the maximum allowed size")

	// ErrLineTooLong is returned when a single line exceeds the per-line byte
	// ceiling. The whole file is refused.
	ErrLineTooLong = errors.New(
		"refusing the .env file: a line exceeds the maximum allowed line length")
)

// Parse tokenises raw .env bytes into an ordered slice of pairs, or returns a
// line-numbered error. On any error it returns a nil slice (refuse-all): a
// caller never receives a partial set.
//
// Parse checks the total input byte length before converting to string or
// splitting, so an oversized input is rejected before any full-content
// allocation.
func Parse(raw []byte) ([]Pair, error) {
	// Total-input byte ceiling: refuse before the string(raw) conversion that
	// would allocate a full copy of the input. This is the earliest practical
	// rejection point.
	if int64(len(raw)) > maxInputBytes {
		return nil, fmt.Errorf(
			"%w: input is %d bytes, which exceeds the %d-byte limit — "+
				"split into multiple submissions or remove unused entries",
			ErrInputTooLarge, len(raw), maxInputBytes)
	}

	lines := splitLines(string(raw))

	pairs := make([]Pair, 0)
	// firstSeen maps a key to the 1-based line number where it first appeared,
	// so a duplicate can name both offending lines.
	firstSeen := make(map[string]int)

	for i, line := range lines {
		lineNo := i + 1

		// Per-line byte cap: checked on the raw line from splitLines before any
		// further string processing, so a single gigantic line cannot cause an
		// unbounded allocation in TrimRight, IndexByte, or TrimSpace.
		if len(line) > maxLineBytes {
			return nil, fmt.Errorf(
				"%w: line %d is %d bytes, which exceeds the %d-byte per-line limit — "+
					"split the value across multiple keys or remove the entry",
				ErrLineTooLong, lineNo, len(line), maxLineBytes)
		}

		trimmed := strings.TrimRight(line, "\r")
		if isBlankOrComment(trimmed) {
			continue
		}

		key, value, err := parseAssignment(trimmed, lineNo)
		if err != nil {
			return nil, err
		}

		if prev, dup := firstSeen[key]; dup {
			return nil, fmt.Errorf(
				"%w: key %q appears on line %d and again on line %d",
				ErrDuplicateKey, key, prev, lineNo)
		}
		firstSeen[key] = lineNo

		if len(pairs) >= maxPairs {
			return nil, fmt.Errorf(
				"%w: a bulk submission is limited to %d key/value pairs; "+
					"split into multiple submissions",
				ErrTooManyPairs, maxPairs)
		}
		pairs = append(pairs, Pair{Key: key, Value: value})
	}

	return pairs, nil
}

// splitLines splits on '\n' without dropping a trailing empty line's content,
// while not producing a spurious final empty element for a trailing newline.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\n")
	// A trailing '\n' yields a final empty element; drop it so it is not counted
	// as a line. A file with no trailing newline keeps its last line intact.
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// isBlankOrComment reports whether a line is blank or a full-line comment (its
// first non-whitespace byte is '#').
func isBlankOrComment(line string) bool {
	t := strings.TrimLeft(line, " \t")
	return t == "" || strings.HasPrefix(t, "#")
}

// parseAssignment parses one non-comment, non-blank line into (key, value).
func parseAssignment(line string, lineNo int) (string, string, error) {
	// The "export " prefix is shell ergonomics: strip exactly one leading
	// "export" token that is followed by at least one space or tab.
	body := stripExportPrefix(line)

	eq := strings.IndexByte(body, '=')
	if eq < 0 {
		return "", "", fmt.Errorf(
			"%w: line %d has no '=' (expected KEY=VALUE)",
			ErrMalformedLine, lineNo)
	}

	key := strings.TrimSpace(body[:eq])
	if key == "" {
		return "", "", fmt.Errorf(
			"%w: line %d has an empty key before '='",
			ErrMalformedLine, lineNo)
	}
	if !isValidKeyToken(key) {
		return "", "", fmt.Errorf(
			"%w: line %d has an invalid key %q "+
				"(a key must not contain spaces or '#')",
			ErrMalformedLine, lineNo, key)
	}

	value := unquoteValue(body[eq+1:])
	return key, value, nil
}

// stripExportPrefix removes a single leading "export" token followed by at
// least one space or tab. "export" elsewhere, "exportFOO", or "export=" (no
// whitespace after the token) are left untouched.
func stripExportPrefix(line string) string {
	const tok = "export"
	if !strings.HasPrefix(line, tok) {
		return line
	}
	rest := line[len(tok):]
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return line
	}
	return strings.TrimLeft(rest, " \t")
}

// unquoteValue trims surrounding ASCII whitespace, then strips exactly one
// matching outer quote pair if present. Inner bytes are taken verbatim (no
// escape interpretation). A value with no matching outer pair is taken
// literally after the whitespace trim.
func unquoteValue(raw string) string {
	v := strings.TrimSpace(raw)
	if len(v) >= 2 {
		first, last := v[0], v[len(v)-1]
		if (first == '"' || first == '\'') && first == last {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// isValidKeyToken reports whether key is a plausible env key: it must be
// non-empty and contain no ASCII whitespace and no '#'. The value validator
// applies the authoritative key-name policy downstream; this is only the
// structural well-formedness the parser owns.
func isValidKeyToken(key string) bool {
	for i := 0; i < len(key); i++ {
		switch key[i] {
		case ' ', '\t', '#':
			return false
		}
	}
	return true
}
