// Package auth defines the core port for OS keychain access and OAuth flow.
// The interface is consumer-defined here (inner layer); the concrete implementation
// lives in internal/adapter/keychain. No go-keyring import here.
package auth

import "context"

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
