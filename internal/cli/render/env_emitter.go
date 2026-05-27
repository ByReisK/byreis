package render

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// EnvFormat selects the env-vs-dotenv serialization shape. The ONLY difference
// between the two formats is the presence of the "export " prefix per line;
// quoting, escaping, sort order, NUL rejection, and collision rules are
// byte-identical.
type EnvFormat int

const (
	// FormatEnv emits one `export KEY="..."` line per entry, suitable for
	// shell sourcing (`set -a; .`) and direct `eval`/`source` use.
	FormatEnv EnvFormat = iota
	// FormatDotenv emits one `KEY="..."` line per entry, suitable for
	// docker --env-file and .env-file consumers that reject the `export ` prefix.
	FormatDotenv
)

// EnvPair holds a single mapped key-value pair ready for serialization.
// The Value field is plaintext; it must never be logged or included in errors.
type EnvPair struct {
	// Var is the mapped, validated shell variable name.
	Var string
	// Value is the plaintext secret value.
	Value string
}

// Sentinel errors for the env emitter. All map to ExitGeneralError (=1) at
// the verb layer. Messages carry actionable hints and never contain plaintext.
var (
	// ErrLeadingDigit is returned when a secret key maps to a shell variable
	// name that begins with a digit. POSIX shell disallows such names.
	ErrLeadingDigit = errors.New(
		"secret key maps to a variable name that begins with a digit, which is " +
			"not a legal shell variable — rename the key to start with a letter or _")

	// ErrVarCollision is returned when two or more secret keys map to the same
	// shell variable name after character sanitization. Silently dropping a
	// value would be a data-loss security defect; we fail closed instead.
	ErrVarCollision = errors.New(
		"two secret keys map to the same environment variable name — rename one " +
			"key so the mapping is unambiguous (export refuses to silently drop a value)")

	// ErrNulInValue is returned when a secret value contains a NUL byte (0x00),
	// which cannot be represented in an env/dotenv stream.
	ErrNulInValue = errors.New(
		"secret value contains a NUL byte, which cannot be represented in an env " +
			"stream — this value cannot be exported")
)

// MapKeyToEnvVar maps a secret key name to a legal POSIX shell variable name.
// Every character outside [A-Za-z0-9_] is replaced with an underscore;
// case is preserved (no auto-uppercase, no prefix-strip).
//
// Returns ErrLeadingDigit if the resulting name begins with a digit.
// The key name is not secret; it may appear in error messages.
func MapKeyToEnvVar(key string) (string, error) {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	v := b.String()
	if len(v) > 0 && v[0] >= '0' && v[0] <= '9' {
		return "", fmt.Errorf("%w: key %q maps to %q", ErrLeadingDigit, key, v)
	}
	return v, nil
}

// BuildEnvPairs maps every key in keyNames using MapKeyToEnvVar, checks for
// post-mapping collisions (two source keys → same var is an error), and
// returns the results sorted by the mapped variable name for stable output.
//
// On any error (leading-digit, collision) it returns nil, err so the caller
// can enforce the fail-closed ordering: no plaintext must be written before
// this call succeeds.
//
// The plaintext map is accessed only to populate EnvPair.Value; values never
// appear in errors or logs.
func BuildEnvPairs(plaintext map[string]string, keyNames []string) ([]EnvPair, error) {
	type mapping struct {
		sourceKey string
		varName   string
	}

	// Phase 1: map each key, fail on first leading-digit error.
	mappings := make([]mapping, 0, len(keyNames))
	for _, k := range keyNames {
		v, err := MapKeyToEnvVar(k)
		if err != nil {
			// Error message from MapKeyToEnvVar already names the key.
			return nil, err
		}
		mappings = append(mappings, mapping{sourceKey: k, varName: v})
	}

	// Phase 2: detect post-mapping collisions.
	// Build a map from varName to the first source key that claimed it.
	seen := make(map[string]string, len(mappings))
	for _, m := range mappings {
		if prior, conflict := seen[m.varName]; conflict {
			return nil, fmt.Errorf("%w: %q and %q both map to %q",
				ErrVarCollision, prior, m.sourceKey, m.varName)
		}
		seen[m.varName] = m.sourceKey
	}

	// Phase 3: sort by the mapped variable name for stable output.
	sort.Slice(mappings, func(i, j int) bool {
		return mappings[i].varName < mappings[j].varName
	})

	// Phase 4: build the output pairs.
	pairs := make([]EnvPair, len(mappings))
	for i, m := range mappings {
		pairs[i] = EnvPair{
			Var:   m.varName,
			Value: plaintext[m.sourceKey],
		}
	}
	return pairs, nil
}

// BuildChildEnvBlock merges the parent environment (in os.Environ() "KEY=VALUE"
// form) with the injected secret pairs and returns the complete child
// environment block as a "KEY=VALUE" slice.
//
// Merge rule (injected-wins): a byreis-injected variable OVERRIDES an inherited
// parent-env entry of the same name. Internal secret-vs-secret collisions are
// already rejected upstream by BuildEnvPairs (ErrVarCollision) before this is
// called, so the only collisions handled here are injected-vs-inherited.
//
// Every injected value is checked for a NUL byte; a NUL (which cannot appear in
// a process environment entry) is rejected with ErrNulInValue and no block is
// returned. Errors never contain a secret value — only the variable NAME — and
// the inherited entry that gets overridden is never echoed (the var name is the
// only non-secret part).
//
// The returned block has the inherited entries first (in their original order,
// with overridden names removed) followed by the injected pairs in their
// provided order. Order is not security-relevant for a process environment.
func BuildChildEnvBlock(parentEnv []string, pairs []EnvPair) ([]string, error) {
	// Reject NUL in any injected value before assembling the block.
	for _, p := range pairs {
		if strings.ContainsRune(p.Value, '\x00') {
			return nil, fmt.Errorf("%w: variable %q", ErrNulInValue, p.Var)
		}
	}

	// Collect the set of injected names so inherited entries of the same name
	// are dropped (injected-wins).
	injected := make(map[string]struct{}, len(pairs))
	for _, p := range pairs {
		injected[p.Var] = struct{}{}
	}

	block := make([]string, 0, len(parentEnv)+len(pairs))
	for _, e := range parentEnv {
		name := e
		if eq := strings.IndexByte(e, '='); eq >= 0 {
			name = e[:eq]
		}
		if _, overridden := injected[name]; overridden {
			continue
		}
		block = append(block, e)
	}
	for _, p := range pairs {
		block = append(block, p.Var+"="+p.Value)
	}
	return block, nil
}

// EmitEnv writes the env or dotenv serialization of pairs to w.
//
// Every value is always double-quoted and escaped:
//   - \ → \\   (first, prevents double-escaping of subsequent sequences)
//   - " → \"
//   - $ → \$   (prevents POSIX shell expansion of $(...), ${...}, $VAR inside double-quotes)
//   - ` → \`   (prevents backtick command substitution inside double-quotes)
//   - newline (0x0A) → \n
//   - carriage return (0x0D) → \r
//   - tab (0x09) → \t
//   - NUL (0x00) → error (ErrNulInValue); no partial output is written
//   - other C0 control chars (0x01–0x1F, excl. 0x09/0x0A/0x0D) → \xNN hex escape
//
// Both FormatEnv and FormatDotenv apply identical escaping because either can
// be shell-sourced (eval, source, set -a; .) and both carry the same injection risk.
//
// UTF-8 multibyte sequences are passed through verbatim.
//
// Format divergence:
//   - FormatEnv:    emits `export KEY="..."` per line
//   - FormatDotenv: emits `KEY="..."` per line (no prefix)
//
// Pairs are emitted in the order provided; callers should use BuildEnvPairs
// which sorts by variable name before calling EmitEnv.
//
// On ErrNulInValue the writer receives zero bytes (fail-closed; the internal
// buffer is not flushed to w).
func EmitEnv(w io.Writer, pairs []EnvPair, format EnvFormat) error {
	// Validate all values first so we never write partial output (fail-closed).
	for _, p := range pairs {
		if strings.ContainsRune(p.Value, '\x00') {
			return fmt.Errorf("%w: variable %q", ErrNulInValue, p.Var)
		}
	}

	// Build the full output in a string builder before writing to w, so that
	// a write error on w does not produce partial output.
	var out strings.Builder
	for _, p := range pairs {
		if format == FormatEnv {
			out.WriteString("export ")
		}
		out.WriteString(p.Var)
		out.WriteString(`="`)
		out.WriteString(escapeEnvValue(p.Value))
		out.WriteString("\"\n")
	}

	_, err := io.WriteString(w, out.String())
	return err
}

// escapeEnvValue applies the env-stream escaping rules to a single secret
// value. It never logs the value. NUL rejection is performed by EmitEnv
// before this function is called.
//
// Escaping rules:
//   - \ → \\   (must be first to avoid double-escaping other sequences)
//   - " → \"
//   - $ → \$   (neutralizes $(...), ${...}, and $VAR expansion inside double-quotes)
//   - ` → \`   (neutralizes backtick command substitution inside double-quotes)
//   - newline (LF, 0x0A) → \n
//   - carriage return (CR, 0x0D) → \r
//   - tab (HT, 0x09) → \t
//   - other C0 controls (0x01–0x1F excl. 0x09/0x0A/0x0D) → \xNN
//   - all other bytes (including UTF-8 multibyte) → verbatim
//
// The $ and backtick escapes are applied to both FormatEnv and FormatDotenv
// because either can be sourced by a POSIX shell and POSIX shells expand both
// forms inside double-quoted strings.
func escapeEnvValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '$':
			b.WriteString(`\$`)
		case '`':
			b.WriteString("\\`")
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			// Other C0 control chars (0x01–0x1F, excluding 0x09/0x0A/0x0D)
			// and 0x7F (DEL) are escaped as \xNN. NUL (0x00) is already
			// rejected by EmitEnv before this point.
			if (c >= 0x01 && c <= 0x1F) || c == 0x7F {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}
