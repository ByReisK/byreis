// Package keychain implements the auth token store using the OS keychain
// (go-keyring). It sits behind the core/auth port; core never imports this
// package. This is a stub until the real implementation lands.
package keychain

import "context"

// Store is the OS keychain-backed token store.
type Store struct {
	// The go-keyring client will be injected here for testability.
}

// New constructs a Store.
func New() *Store {
	return &Store{}
}

// GetToken retrieves a stored OAuth token for the given service/account pair.
func (s *Store) GetToken(_ context.Context, service, account string) (string, error) {
	panic("not implemented") // stub: real implementation pending
}

// SetToken stores an OAuth token for the given service/account pair.
func (s *Store) SetToken(_ context.Context, service, account, token string) error {
	panic("not implemented") // stub: real implementation pending
}

// DeleteToken removes the stored token.
func (s *Store) DeleteToken(_ context.Context, service, account string) error {
	panic("not implemented") // stub: real implementation pending
}

// GetIdentitySecret retrieves the raw "AGE-SECRET-KEY-1…" admin identity string
// from the OS keychain. It satisfies the identity adapter's KeychainSource port.
// Returns ("", nil) when no admin identity entry exists in the keychain (not an
// error — absence is the normal contributor case). Returns ("", non-nil) on
// any OS keychain access failure.
//
// The service and account key names match the byreis identity keychain slot
// defined at the composition root. This method is adapter-side only and is NOT
// part of the auth.TokenStore core port.
func (s *Store) GetIdentitySecret(_ context.Context) (string, error) {
	panic("not implemented") // stub: real go-keyring integration pending
}
