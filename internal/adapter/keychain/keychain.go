// Package keychain implements the OS keychain-backed token store using
// go-keyring. It sits behind the core/auth port; core never imports this
// package. The real go-keyring backend is injected via the KeyringClient
// interface so unit tests can operate without a real OS keychain.
//
// GetRegistryWriteToken enforces the ADMIN-mode gate at the keychain load-site:
// the OS keychain is never queried in CONTRIBUTOR mode. This is the canonical
// single site for the credential-separation invariant (CONTRIBUTOR never reads
// registry-write credentials).
package keychain

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/zalando/go-keyring"

	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/auth"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// ErrNotFound is re-exported so tests can reference it without importing
// go-keyring directly. It matches keyring.ErrNotFound.
var ErrNotFound = keyring.ErrNotFound

// identityService / identityAccount are the keychain slot constants for the
// admin age identity. These mirror the slot written by `byreis auth login`.
const identityService = "byreis"
const identityAccount = "admin-identity"

// tokenSanitiseRE matches substrings that look like path components or
// token-like strings. When a go-keyring backend error embeds path or
// credential-like content, the sanitiser replaces each match with a fixed
// placeholder so no sensitive material crosses the adapter boundary.
var tokenSanitiseRE = regexp.MustCompile(
	`(?i)(ghp_|ghs_|token=|secret=|password=|key=|/etc/|/home/|/root/|/proc/|/var/|/tmp/)[^\s]*`)

// sanitiseKeychainError strips any path-like or token-like substring from the
// raw go-keyring error message before it is embedded in a returned error. The
// returned string is always safe to include in structured logs and JSON.
func sanitiseKeychainError(raw error) string {
	if raw == nil {
		return ""
	}
	msg := raw.Error()
	sanitised := tokenSanitiseRE.ReplaceAllString(msg, "<redacted>")
	// Also replace any long (~20+char) alphanumeric strings that look like
	// tokens (e.g. personal-access-tokens, UUIDs).
	tokenLike := regexp.MustCompile(`[A-Za-z0-9_\-]{20,}`)
	sanitised = tokenLike.ReplaceAllString(sanitised, "<redacted>")
	return sanitised
}

// classifyKeychainError maps a raw go-keyring error to a stable suffix for the
// returned ErrRegistryWriteAuth wrapper. It never includes the raw error text
// directly in the returned error.
func classifyKeychainError(err error) error {
	if err == nil {
		return nil
	}
	sanitised := sanitiseKeychainError(err)
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "user cancelled") ||
		strings.Contains(msg, "locked") ||
		strings.Contains(msg, "cancelled"):
		return fmt.Errorf("%w: keychain access denied: %s",
			registryadapter.ErrRegistryWriteAuth, sanitised)
	default:
		return fmt.Errorf("%w: keychain unavailable: %s",
			registryadapter.ErrRegistryWriteAuth, sanitised)
	}
}

// ModeProvider is the port through which the keychain load-site consults the
// mode resolved at composition time. The production bridge in internal/app
// captures the mode once at BuildProductionDeps and returns it verbatim. Tests
// inject a fake that returns any desired mode.
//
// CurrentMode must return the captured value from construction time with NO
// fallback that calls the mode detector again; a race against a key-perm flip
// must not smuggle ADMIN through this gate after the binary started as
// CONTRIBUTOR.
type ModeProvider interface {
	CurrentMode(ctx context.Context) (mode.Mode, error)
}

// KeyringClient is the port for the underlying OS keychain operations. It is
// implemented by the real go-keyring shim (realKeyringClient) in production
// and by a fake in unit tests. No real keychain is ever touched in unit tests.
type KeyringClient interface {
	Get(service, account string) (string, error)
	Set(service, account, secret string) error
	Delete(service, account string) error
}

// realKeyringClient is the production implementation backed by go-keyring.
type realKeyringClient struct{}

func (realKeyringClient) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func (realKeyringClient) Set(service, account, secret string) error {
	return keyring.Set(service, account, secret)
}

func (realKeyringClient) Delete(service, account string) error {
	return keyring.Delete(service, account)
}

// Store is the OS keychain-backed token store. It satisfies both the
// auth.TokenStore and auth.RegistryWriteTokenStore ports. The modeProvider is
// required only for GetRegistryWriteToken; the generic GetToken/SetToken/
// DeleteToken methods work without it.
type Store struct {
	modeProvider ModeProvider
	kr           KeyringClient
}

// RealKeyring returns the production go-keyring client. Used by internal/app to
// construct a Store instance with mode-provider injection without exposing the
// realKeyringClient type.
func RealKeyring() KeyringClient {
	return realKeyringClient{}
}

// New constructs a Store backed by the real OS keychain.
func New() *Store {
	return &Store{kr: realKeyringClient{}}
}

// NewWithDeps constructs a Store with injected dependencies (for testing).
// Both modeProvider and kr must be non-nil.
func NewWithDeps(mp ModeProvider, kr KeyringClient) *Store {
	return &Store{modeProvider: mp, kr: kr}
}

// NewWithKeychainOnly constructs a Store with an injected KeyringClient but no
// ModeProvider. This is for tests of the generic TokenStore methods only.
func NewWithKeychainOnly(kr KeyringClient) *Store {
	return &Store{kr: kr}
}

// GetRegistryWriteToken returns the registry-write credential. It enforces the
// ADMIN-mode gate at the load-site: the OS keychain is never queried in
// CONTRIBUTOR mode.
//
// The registryURL parameter is accepted for forward compatibility but is not
// used to derive the keychain slot. The slot is always
// (auth.RegistryWriteService, auth.RegistryWriteAccount). Any future change
// that begins consuming registryURL to derive the slot re-opens the PRE-impl
// crypto+threat ack on slot scoping.
func (s *Store) GetRegistryWriteToken(ctx context.Context, registryURL string) (string, error) {
	// Honour context cancellation first.
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("keychain lookup cancelled: %w", err)
	}

	if s.modeProvider == nil {
		return "", fmt.Errorf("%w: no mode provider configured",
			registryadapter.ErrRegistryWriteAuth)
	}

	// Consult the mode gate BEFORE any keychain read.
	m, err := s.modeProvider.CurrentMode(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: mode unavailable: %s",
			registryadapter.ErrRegistryWriteAuth, sanitiseKeychainError(err))
	}

	switch m {
	case mode.ModeAdmin, mode.ModeSuper:
		// Permitted — proceed to keychain read below.
	case mode.ModeContributor:
		return "", fmt.Errorf("%w: caller mode is not ADMIN",
			registryadapter.ErrRegistryWriteAuth)
	default:
		// Forged or uninitialised iota — treat as CONTRIBUTOR (fail closed).
		return "", fmt.Errorf("%w: caller mode is not ADMIN",
			registryadapter.ErrRegistryWriteAuth)
	}

	// Read from the fixed registry-write keychain slot.
	tok, kerr := s.kr.Get(auth.RegistryWriteService, auth.RegistryWriteAccount)
	if kerr != nil {
		if errors.Is(kerr, keyring.ErrNotFound) {
			return "", fmt.Errorf("%w: registry-write slot empty — "+
				"run `byreis admin register` to store a registry-write credential",
				registryadapter.ErrRegistryWriteAuth)
		}
		return "", classifyKeychainError(kerr)
	}

	if tok == "" {
		return "", fmt.Errorf("%w: registry-write slot empty — "+
			"run `byreis admin register` to store a registry-write credential",
			registryadapter.ErrRegistryWriteAuth)
	}

	// Never log the token; return it directly.
	return tok, nil
}

// GetToken retrieves a stored OAuth token for the given service/account pair.
// Returns ("", nil) when no entry exists (not an error — normal contributor case).
func (s *Store) GetToken(_ context.Context, service, account string) (string, error) {
	tok, err := s.kr.Get(service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("keychain GetToken(%q, %q): %w",
			service, account, err)
	}
	return tok, nil
}

// SetToken stores an OAuth token for the given service/account pair.
func (s *Store) SetToken(_ context.Context, service, account, token string) error {
	if err := s.kr.Set(service, account, token); err != nil {
		return fmt.Errorf("keychain SetToken(%q, %q): %w", service, account, err)
	}
	return nil
}

// DeleteToken removes the stored token for the given service/account pair.
func (s *Store) DeleteToken(_ context.Context, service, account string) error {
	if err := s.kr.Delete(service, account); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil // idempotent delete
		}
		return fmt.Errorf("keychain DeleteToken(%q, %q): %w", service, account, err)
	}
	return nil
}

// GetIdentitySecret retrieves the raw "AGE-SECRET-KEY-1…" admin identity string
// from the OS keychain. Returns ("", nil) when no admin identity entry exists
// (the normal contributor case). Returns ("", non-nil) on any OS keychain
// access failure.
func (s *Store) GetIdentitySecret(_ context.Context) (string, error) {
	secret, err := s.kr.Get(identityService, identityAccount)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("keychain GetIdentitySecret: %w", err)
	}
	return secret, nil
}
