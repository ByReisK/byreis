// Package signingkey provides the production manifestsigner.Ed25519KeySource
// adapter for the admin Ed25519 signing key. The signing key is DISTINCT from
// the age X25519 decryption identity: it is a 64-byte Ed25519 private key used
// only to sign canonical manifests.
//
// Source precedence:
//
//  1. BYREIS_SIGN_KEY — the literal base64-std encoded 64-byte Ed25519 private
//     key in the environment (CI / ephemeral; least-safe channel).
//  2. BYREIS_SIGN_KEY_FILE — an explicit path to a key file.
//  3. A distinct OS keychain entry (separate from the age identity slot).
//  4. Default key file path (~/.config/byreis/identity/admin-sign.key).
//
// File-sourced keys (sources 2 and 4) are read via internal/core/trust's
// O_NOFOLLOW + fstat-on-fd TOCTOU discipline (exactly 0600, owner-only,
// regular file). Environment and keychain sources carry no file and no perm check.
//
// Zeroization: ProvideKey returns a freshly-allocated slice; the caller (the
// manifestsigner adapter) owns the zeroization via its deferred ZeroizeBuffer.
//
// Placement: OUTER adapter layer (internal/adapter/signingkey). Core packages
// never import this adapter; it is injected at the composition root into the
// manifestsigner adapter. It MUST NOT appear in the submit/encrypt closed-world
// compilation units.
package signingkey

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/core/trust"
)

// KeychainSigningSource is the port for retrieving the admin Ed25519 signing
// key raw bytes from the OS keychain. It is defined here (consumer =
// signingkey adapter) and implemented by the keychain adapter.
//
// The keychain stores the signing key in a distinct slot from the age identity.
//
// Contract: GetSigningKey returns the raw 64-byte Ed25519 private key bytes,
// or (nil, nil) when no entry exists (not an error). On OS keychain access
// failure it returns (nil, non-nil error).
type KeychainSigningSource interface {
	GetSigningKey(ctx context.Context) ([]byte, error)
}

// Config holds the resolved inputs for the signing key source. In production
// the composition root populates EnvSignKey/EnvSignKeyFile from os.Getenv and
// injects the real keychain adapter. Tests inject fakes.
type Config struct {
	// EnvSignKey is the value of BYREIS_SIGN_KEY. If non-empty it is decoded
	// as a base64-std 64-byte Ed25519 private key. The caller reads os.Getenv
	// outside this package so tests never touch real env vars.
	EnvSignKey string

	// EnvSignKeyFile is the value of BYREIS_SIGN_KEY_FILE. If non-empty it is
	// a path to a 0600 file containing the raw 64-byte Ed25519 private key.
	EnvSignKeyFile string

	// Keychain is the OS keychain source for the signing key. Nil means the
	// keychain source is not configured.
	Keychain KeychainSigningSource

	// DefaultKeyPath is a function returning the default signing key file path
	// (typically ~/.config/byreis/identity/admin-sign.key). A function rather
	// than a string allows tests to inject a lazily-evaluated path.
	// Returning "" means no default path configured.
	DefaultKeyPath func() string
}

// source is the concrete manifestsigner.Ed25519KeySource implementation.
type source struct {
	cfg Config
}

// ErrNoSigningKey is returned when no Ed25519 signing key is configured in
// any source. Callers map this to "admin signing not available" — not a hard
// error (absence is the normal contributor case).
var ErrNoSigningKey = errors.New(
	"no Ed25519 admin signing key configured — " +
		"set BYREIS_SIGN_KEY or BYREIS_SIGN_KEY_FILE, or store the key in the OS keychain, " +
		"or place the key at ~/.config/byreis/identity/admin-sign.key with mode 0600")

// New constructs the Ed25519KeySource from cfg. cfg.DefaultKeyPath must be
// non-nil; use func() string { return "" } if a default path is not needed.
func New(cfg Config) *source {
	if cfg.DefaultKeyPath == nil {
		cfg.DefaultKeyPath = func() string { return "" }
	}
	return &source{cfg: cfg}
}

// ProvideKey returns a freshly-allocated 64-byte Ed25519 private key buffer.
// The caller (manifestsigner adapter) is responsible for zeroizing the buffer
// after use via identity.ZeroizeBuffer (deferred unconditionally per the
// manifestsigner signer.Sign contract).
//
// Return values:
//   - ([]byte{64 bytes}, nil)  on success.
//   - (nil, ErrNoSigningKey)   when no source is configured.
//   - (nil, err)               on file perm / keychain / parse failure.
func (s *source) ProvideKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("signingkey.ProvideKey cancelled: %w", err)
	}

	// Source 1: BYREIS_SIGN_KEY env (base64-std encoded 64-byte raw private key).
	if s.cfg.EnvSignKey != "" {
		return decodeEnvKey(s.cfg.EnvSignKey)
	}

	// Source 2: BYREIS_SIGN_KEY_FILE explicit path.
	if s.cfg.EnvSignKeyFile != "" {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("signingkey.ProvideKey cancelled: %w", err)
		}
		return readKeyFile(s.cfg.EnvSignKeyFile)
	}

	// Source 3: OS keychain (distinct slot from the age identity).
	if s.cfg.Keychain != nil {
		raw, err := s.cfg.Keychain.GetSigningKey(ctx)
		if err != nil {
			// Keychain failure → fail closed (treated as "not configured").
			return nil, fmt.Errorf(
				"%w: OS keychain access failed: %v",
				ErrNoSigningKey, err)
		}
		if len(raw) > 0 {
			// Return a copy; zeroize the keychain-returned buffer.
			result := make([]byte, len(raw))
			copy(result, raw)
			identityadapter.ZeroizeBuffer(raw)
			return result, nil
		}
		// No keychain entry: fall through to default path.
	}

	// Source 4: default key file path.
	if s.cfg.DefaultKeyPath != nil {
		if p := s.cfg.DefaultKeyPath(); p != "" {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("signingkey.ProvideKey cancelled: %w", err)
			}
			return readKeyFile(p)
		}
	}

	return nil, ErrNoSigningKey
}

// decodeEnvKey decodes the BYREIS_SIGN_KEY environment value. The value must
// be base64-std encoded, producing exactly 64 bytes.
func decodeEnvKey(envVal string) ([]byte, error) {
	buf, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envVal))
	if err != nil {
		// Do not echo envVal: it contains the private key material.
		return nil, fmt.Errorf(
			"BYREIS_SIGN_KEY: base64-std decoding failed — "+
				"must be a base64-std encoded 64-byte Ed25519 private key: %w",
			err)
	}
	if len(buf) != 64 {
		identityadapter.ZeroizeBuffer(buf)
		return nil, fmt.Errorf(
			"BYREIS_SIGN_KEY: decoded to %d bytes, expected 64 — "+
				"must be a base64-std encoded 64-byte Ed25519 private key",
			len(buf))
	}
	return buf, nil
}

// readKeyFile reads a 64-byte Ed25519 private key from a 0600 file using the
// shared TOCTOU-safe trust.CheckTrustFileTOCTOU primitive.
func readKeyFile(path string) ([]byte, error) {
	f, err := trust.CheckTrustFileTOCTOU(path)
	if err != nil {
		// Map "does not exist" to ErrNoSigningKey so the caller treats it as
		// "not configured" rather than a hard error.
		if os.IsNotExist(err) || isNotExistMsg(err.Error()) {
			return nil, ErrNoSigningKey
		}
		return nil, fmt.Errorf("Ed25519 signing key file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(f)
	if err != nil {
		identityadapter.ZeroizeBuffer(raw)
		return nil, fmt.Errorf("reading Ed25519 signing key file %q: %w", path, err)
	}

	// Trim trailing whitespace/newline that editors commonly append.
	trimmed := byteTrimRight(raw, "\r\n \t")

	if len(trimmed) != 64 {
		identityadapter.ZeroizeBuffer(raw)
		return nil, fmt.Errorf(
			"Ed25519 signing key file %q: file contains %d raw bytes (after trim), expected 64 — "+
				"the file must contain exactly 64 raw bytes of an Ed25519 private key",
			path, len(trimmed))
	}

	// Copy trimmed into a fresh allocation then zeroize the original read buffer.
	result := make([]byte, 64)
	copy(result, trimmed)
	identityadapter.ZeroizeBuffer(raw)
	return result, nil
}

// byteTrimRight returns the subslice of b with trailing bytes in cutset removed,
// without allocating a new backing array.
func byteTrimRight(b []byte, cutset string) []byte {
	end := len(b)
	for end > 0 && strings.ContainsRune(cutset, rune(b[end-1])) {
		end--
	}
	return b[:end]
}

// isNotExistMsg reports whether an error message contains "does not exist",
// which the trust package embeds in its error strings.
func isNotExistMsg(msg string) bool {
	return strings.Contains(msg, "does not exist") || strings.Contains(msg, "no such file")
}
