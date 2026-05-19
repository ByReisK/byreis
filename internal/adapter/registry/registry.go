// Package registry implements the internal/core/registry.RegistryClient
// interface. It uses go-git for transport and shells to `git verify-commit`
// for signed-commit verification, and manages the offline cache, anti-rollback
// checks, and the counter/audit store. This is a stub until the real
// implementation lands.
//
// # Counter-authority production
//
// CounterAuthority values are produced here via capmint.Mint — the sole
// module-reachable constructor for Valid()==true CounterAuthority values.
// capmint lives at internal/adapter/registry/internal/capmint and is importable
// only by code rooted at internal/adapter/registry (Go internal/ rule). There
// is deliberately no exported Valid()-producing symbol anywhere module-wide, so
// counter authority cannot be forged from outside this adapter.
//
// A compile-time negative test (in internal/core/registry/countertypes/)
// verifies that importing capmint from a non-adapter package is rejected by the
// Go toolchain.
//
// This adapter does not import internal/core/crypto/verify, which keeps the
// dependency direction clean and avoids an import cycle.
package registry

import (
	"context"

	"github.com/ByReisK/byreis/internal/adapter/registry/internal/capmint"
	"github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// Client is the RegistryClient implementation.
type Client struct {
	// Clock, fs, net, git transport, trust anchor path, and cache dir will be
	// injected here. All injected; no real fs/net/clock in unit tests.
}

// New constructs a Client. Constructor parameters are added with the real
// implementation.
func New() *Client {
	return &Client{}
}

// Compile-time assertion.
var _ registry.RegistryClient = (*Client)(nil)

// FetchAdminSet returns the admin recipient and signer set for a project.
// Stub: real implementation pending.
func (c *Client) FetchAdminSet(_ context.Context, _ string) (registry.AdminSet, error) {
	panic("not implemented") // stub: real implementation pending
}

// VerifyRegistryFreshness enforces anti-rollback for the registry HEAD.
// Stub: real implementation pending.
func (c *Client) VerifyRegistryFreshness(_ context.Context, _ string) error {
	panic("not implemented") // stub: real implementation pending
}

// CounterAuthority returns the per-(project,file) anti-replay view.
// Stub: real implementation calls capmint.Mint after reading the
// signature-verified counter store. Pending — see capmint package doc.
func (c *Client) CounterAuthority(_ context.Context, _, _ string) (countertypes.CounterAuthority, error) {
	// Real implementation: read the signature-verified counter store and the
	// anti-rollback cache, then call capmint.Mint(lastAccepted, pending).
	// capmint is the sole Valid()-producing constructor; it is importable only
	// by this adapter (internal/adapter/registry subtree — Go internal/ rule):
	//   last, pending, err := c.readVerifiedCounterStore(ctx, projectID, fileName)
	//   if err != nil { return countertypes.CounterAuthority{}, err }
	//   return capmint.Mint(last, pending), nil
	//
	// capmint.Mint itself panics until it is bridged to
	// countertypes.newCounterAuthority (see the open design question in the
	// capmint package doc). The call below is a temporary stub.
	return capmint.Mint(0, nil), nil // stub: capmint.Mint panics; line replaced with the real read
}

// RecordPendingBump records the write-ahead merge intent in the registry.
// Stub: real implementation pending.
func (c *Client) RecordPendingBump(_ context.Context, _ registry.PendingBumpInput) error {
	panic("not implemented") // stub: real implementation pending
}

// CommitBump finalizes a counter bump after the secrets-repo merge has landed.
// Stub: real implementation pending.
func (c *Client) CommitBump(_ context.Context, _ registry.CommitBumpInput) error {
	panic("not implemented") // stub: real implementation pending
}
