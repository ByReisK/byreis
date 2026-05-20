// Package auth defines the core port for OS keychain access and OAuth flow.
// The interface is consumer-defined here (inner layer); the concrete implementation
// lives in internal/adapter/keychain. No go-keyring import here.
package auth

import "context"

// RegistryWriteService is the canonical keychain service key for the
// registry-write credential (OAuth / PAT with push access to the admin
// registry repo). It is distinct from the project-repo PAT (separation of
// project-repo and registry-repo credentials).
const RegistryWriteService = "byreis-registry"

// RegistryWriteAccount is the canonical keychain account key for the
// registry-write credential entry. Combined with RegistryWriteService,
// this uniquely identifies the ADMIN-only registry-write slot.
const RegistryWriteAccount = "registry-write"

// TokenStore is the port for storing and retrieving OAuth tokens.
// Implementations MUST use the OS keychain (go-keyring) — tokens are NEVER
// stored in plaintext config files.
type TokenStore interface {
	// GetToken retrieves a stored OAuth token for the given service/account.
	// Returns ("", nil) if no token exists (not an error).
	GetToken(ctx context.Context, service, account string) (string, error)

	// SetToken stores an OAuth token for the given service/account.
	SetToken(ctx context.Context, service, account, token string) error

	// DeleteToken removes the stored token (used during logout / key rotation).
	DeleteToken(ctx context.Context, service, account string) error
}

// RegistryWriteTokenStore is the ADMIN-only port for the registry-write
// credential. It is a distinct interface from TokenStore to make the
// ADMIN-only constraint explicit and testable. Implementations MUST check the
// caller's mode before returning the token: a CONTRIBUTOR-mode caller MUST
// receive an error, never a token.
//
// The service+account keychain slot is (RegistryWriteService, RegistryWriteAccount).
// This is a DIFFERENT slot from the project-repo PAT (contributor/admin
// credential separation).
type RegistryWriteTokenStore interface {
	// GetRegistryWriteToken returns the registry-write credential for the
	// given registryURL. Returns ("", wrapped ErrRegistryWriteAuth sentinel
	// from the adapter package) when absent or mode is not ADMIN/SUPER.
	// Must fail closed if mode cannot be determined.
	GetRegistryWriteToken(ctx context.Context, registryURL string) (string, error)
}
