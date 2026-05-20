// Package identity provides the production admin identity loader.
// It resolves an age X25519 private key from one of four sources in a fixed,
// fail-closed precedence order:
//
//  1. BYREIS_KEY  — the literal "AGE-SECRET-KEY-1…" string in the environment
//     (CI / ephemeral; documented as the least-safe channel).
//  2. BYREIS_KEY_FILE — an explicit path to a key file.
//  3. OS keychain via the KeychainSource port (go-keyring-backed in production).
//  4. Default key file path (~/.config/byreis/identity/admin.key).
//
// File-sourced keys (sources 2 and 4) are read through internal/core/trust's
// O_NOFOLLOW+fstat-on-fd TOCTOU discipline. Only exactly 0600 is accepted;
// 0400, 0644, symlinks, wrong-owner, and non-regular files are HARD ERRORs
// that refuse to run, surfaced with a "chmod 600 <path>" hint.
//
// A keychain access failure fails closed to ErrNoAdminKey (the normal
// contributor case) — it is not a hard error. BYREIS_KEY and keychain sources
// carry no file and no perm check; they are parsed directly via identity.Parse.
//
// Zeroization: the adapter-side raw-secret buffer (env copy, file read,
// keychain blob) is explicitly zeroed via ZeroizeBuffer immediately after
// identity.Parse consumes it. The parsed identity holds no extra adapter copy.
package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"unsafe"

	coreidentity "github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/trust"
)

// inProcessMarker is a stable non-filesystem in-process constant returned by
// ResolvedPath when a non-file key source (BYREIS_KEY env or keychain) is
// genuinely present. It is not a real filesystem path and cannot be stat-ed.
// Its sole purpose is to prevent the frozen mode.Detector step-1 from treating
// a keychain/env key as "no key file" and returning CONTRIBUTOR prematurely —
// the substantive promotion checks (CanDecryptAny + IsRegisteredAdmin) still run.
// The marker is an in-process constant, never derived from attacker-controlled input.
const inProcessMarker = "\x00:byreis:non-file-key-present:"

// ErrNoAdminKey is the typed "no admin key present" result. It is not a hard
// error — callers (the mode detector) map it to CONTRIBUTOR (step 1). It is
// distinct from identity.ErrParseIdentity (malformed key) and from hard
// file-permission errors so callers can differentiate cleanly.
var ErrNoAdminKey = errors.New(
	"no admin key configured — run `byreis auth login` or set BYREIS_KEY / BYREIS_KEY_FILE")

// KeychainSource is the port for retrieving the admin identity secret from the
// OS keychain. It is defined here (consumer = identity adapter) and implemented
// by the keychain adapter. Defining the interface in this package avoids an
// adapter→sibling-adapter import.
type KeychainSource interface {
	// GetIdentitySecret returns the raw "AGE-SECRET-KEY-1…" string stored for
	// the admin identity, or ("", nil) when no entry exists (not an error).
	// An OS-keychain access failure returns ("", non-nil error).
	GetIdentitySecret(ctx context.Context) (string, error)
}

// Config holds the resolved inputs for the identity loader. In production the
// composition root populates EnvKey/EnvKeyFile from os.Getenv and injects the
// real keychain adapter as Keychain. In tests, fakes are injected for every
// field so no real keychain, environment, or filesystem is touched beyond
// temp dirs.
type Config struct {
	// EnvKey is the value of the BYREIS_KEY environment variable. Empty means
	// not set. The caller reads os.Getenv outside this package so tests never
	// touch real env vars.
	EnvKey string

	// EnvKeyFile is the value of BYREIS_KEY_FILE. Empty means not set.
	EnvKeyFile string

	// Keychain is the OS keychain source. Nil is treated as "not injected"
	// and fails closed to ErrNoAdminKey when all other sources are absent.
	Keychain KeychainSource

	// DefaultKeyPath is a function that returns the default key file path
	// (typically ~/.config/byreis/identity/admin.key). A function rather
	// than a string allows tests to inject func() string { return "" } and
	// the composition root to lazily resolve the real path. Returning ""
	// means "no default path configured".
	DefaultKeyPath func() string
}

// loader is the concrete identity.Loader. It holds the Config at construction
// time and stores no raw key material.
type loader struct {
	cfg Config
}

// New constructs the identity loader from cfg. cfg.DefaultKeyPath must be
// non-nil; use func() string { return "" } if a default path is not required.
func New(cfg Config) *loader {
	if cfg.DefaultKeyPath == nil {
		cfg.DefaultKeyPath = func() string { return "" }
	}
	return &loader{cfg: cfg}
}

// Load resolves the admin identity from the first available source in the fixed
// precedence order (BYREIS_KEY → BYREIS_KEY_FILE → keychain → default path).
//
// Return values:
//   - (Identity, nil)            on success.
//   - (nil, ErrParseIdentity)    when a source is present but the key material
//     is malformed; never echoes the raw bytes.
//   - (nil, ErrNoAdminKey)       when no source is configured or the keychain
//     returns empty / an access error (fail closed to contributor).
//   - (nil, hard-perm-wrapped-error) when a file source exists but violates
//     the 0600/owner/symlink/non-regular rule — refuse-to-run with chmod hint.
//   - (nil, ctx.Err())           when the context is cancelled before the load.
func (l *loader) Load(ctx context.Context) (coreidentity.Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("identity load cancelled: %w", err)
	}

	// Source 1: BYREIS_KEY env literal.
	if l.cfg.EnvKey != "" {
		return parseAndZeroize([]byte(l.cfg.EnvKey))
	}

	// Source 2: BYREIS_KEY_FILE explicit path.
	if l.cfg.EnvKeyFile != "" {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("identity load cancelled: %w", err)
		}
		return loadFromFile(l.cfg.EnvKeyFile)
	}

	// Source 3: OS keychain.
	if l.cfg.Keychain != nil {
		secret, err := l.cfg.Keychain.GetIdentitySecret(ctx)
		if err != nil {
			// Keychain access failure → fail closed to ErrNoAdminKey (not a hard error).
			return nil, ErrNoAdminKey
		}
		if secret != "" {
			return parseAndZeroize([]byte(secret))
		}
		// Empty secret with nil error means "no keychain entry".
	}

	// Source 4: default key path.
	if l.cfg.DefaultKeyPath != nil {
		if defaultPath := l.cfg.DefaultKeyPath(); defaultPath != "" {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("identity load cancelled: %w", err)
			}
			return loadFromFile(defaultPath)
		}
	}

	return nil, ErrNoAdminKey
}

// ResolvedPath returns the path the identity loader would report for mode
// detection step 1 (the KeyProbe.KeyFilePath contract). This is the SINGLE
// shared resolver so the Loader and the KeyProbe adapter are always consistent.
//
// Return values:
//   - The real BYREIS_KEY_FILE or default path when a file source is configured
//     (regardless of whether the file currently exists or has the right perms —
//     existence/perm checks happen at Load time).
//   - inProcessMarker (stable in-process constant) when BYREIS_KEY env or the
//     keychain source is genuinely present but there is no file path. This
//     prevents the frozen Detect step-1 from treating a non-file key as absent.
//   - "" when no source is configured — the detector correctly maps this to
//     CONTRIBUTOR (step 1: no key file → CONTRIBUTOR).
func ResolvedPath(cfg Config) string {
	// File source 2: explicit BYREIS_KEY_FILE.
	if cfg.EnvKeyFile != "" {
		return cfg.EnvKeyFile
	}
	// Non-file source 1: BYREIS_KEY env present → marker.
	if cfg.EnvKey != "" {
		return inProcessMarker
	}
	// Non-file source 3: keychain has a key → marker.
	if cfg.Keychain != nil {
		// Probe the keychain synchronously. OS keychain is a local call with
		// no network I/O, so a Background context is appropriate here.
		secret, err := cfg.Keychain.GetIdentitySecret(context.Background())
		if err == nil && secret != "" {
			return inProcessMarker
		}
	}
	// File source 4: default path.
	if cfg.DefaultKeyPath != nil {
		if p := cfg.DefaultKeyPath(); p != "" {
			return p
		}
	}
	return ""
}

// LoaderResolvedPath exposes the loader's resolved path for test assertions.
// It enables the single-resolver test to verify that the loader and
// the standalone ResolvedPath function compute byte-identical results.
func LoaderResolvedPath(l *loader) string {
	return ResolvedPath(l.cfg)
}

// IsInProcessMarker reports whether path is the non-file key-present marker.
// The KeyProbe adapter uses this to implement KeyFilePerms: a marker path
// returns the perm-OK value (0600) because there is no file to check.
func IsInProcessMarker(path string) bool {
	return path == inProcessMarker
}

// ZeroizeBuffer explicitly zeroes every byte in buf. It is exported so tests
// can pin the backing-array address (unsafe.SliceData) and assert all-zero
// after the call, satisfying the GC/escape-resistant zeroization standard.
// Production code calls this inline on the same slice it allocated; never on a copy.
func ZeroizeBuffer(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// loadFromFile opens a key file with O_NOFOLLOW+fstat-on-fd via
// internal/core/trust (the single shared TOCTOU primitive), reads the content
// into a pinned buffer, parses the identity, and immediately zeroizes the buffer.
func loadFromFile(path string) (coreidentity.Identity, error) {
	f, err := trust.CheckTrustFileTOCTOU(path)
	if err != nil {
		// trust wraps with ErrTrustAnchorPerms / ErrTrustAnchorSymlink and the
		// chmod hint. Add key-file context so the caller sees the source.
		return nil, fmt.Errorf("admin key file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(f)
	if err != nil {
		// Zeroize any partial read before returning.
		ZeroizeBuffer(raw)
		return nil, fmt.Errorf("reading admin key file %q: %w", path, err)
	}

	// Trim trailing whitespace (editors commonly append a newline) in-place
	// so no second heap allocation is created. bytes_trimRight returns a
	// sub-slice of raw (no copy); we pass that directly to parseAndZeroize.
	trimmed := bytes_trimRight(raw, "\r\n")

	// parseAndZeroize builds the string view via unsafe (zero extra alloc),
	// calls identity.Parse, then zeroes the buffer before returning.
	id, parseErr := parseAndZeroize(trimmed)

	// Zero the remainder of raw that was not covered by trimmed (the trailing
	// whitespace bytes). The trimmed sub-slice already points into raw's
	// backing array, so the parseAndZeroize call above zeroed those bytes.
	// This call zeroes any trailing bytes past len(trimmed).
	ZeroizeBuffer(raw)

	if parseErr != nil {
		return nil, fmt.Errorf("admin key file %q: %w", path, parseErr)
	}
	return id, nil
}

// parseAndZeroize converts a raw key byte slice to an identity, zeroizes the
// slice immediately after parse, and returns the identity. buf must be a
// freshly-allocated slice not aliased anywhere else.
func parseAndZeroize(buf []byte) (coreidentity.Identity, error) {
	// Build the string view without a second allocation using unsafe.
	// The string is valid only until ZeroizeBuffer is called; identity.Parse
	// must finish before we wipe the buffer.
	s := bytesToStringUnsafe(buf)
	id, err := coreidentity.Parse(s)
	// Zeroize the backing buffer immediately; the string header s is now invalid
	// but we do not use it again.
	ZeroizeBuffer(buf)
	if err != nil {
		return nil, err
	}
	return id, nil
}

// bytesToStringUnsafe converts []byte to string without copying the backing
// array. The returned string MUST NOT be used after ZeroizeBuffer is called on
// buf. This is intentional: we pass the string to identity.Parse (which
// internally calls age.ParseX25519Identity and does NOT retain a reference to
// the input string after parsing), then immediately wipe buf.
//
// Rationale: avoids a second heap allocation of the key material, reducing the
// window between allocation and erasure. The unsafe usage is confined to this
// package and directly serves the GC-resistant zeroization obligation.
func bytesToStringUnsafe(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b)) //nolint:gosec // G103: intentional unsafe alias to avoid a second heap allocation of key material; the string is used only within parseAndZeroize before ZeroizeBuffer wipes the backing array
}

// bytes_trimRight returns the subslice of b with trailing chars in cutset
// removed, without allocating. It works on the existing slice to avoid
// creating an extra copy of key material.
func bytes_trimRight(b []byte, cutset string) []byte { //nolint:revive // underscore name is intentional to match bytes.TrimRight semantics clearly
	end := len(b)
	for end > 0 && strings.ContainsRune(cutset, rune(b[end-1])) {
		end--
	}
	return b[:end]
}
