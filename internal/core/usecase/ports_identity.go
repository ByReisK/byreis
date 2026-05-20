package usecase

import (
	"context"

	"github.com/ByReisK/byreis/internal/core/crypto/identity"
)

// IDLoader is the consumer-defined port for loading the executing admin's age
// identity. The usecase layer owns this interface; any outer adapter
// (file-on-disk loader, keychain loader, env loader) satisfies it structurally
// and is injected at composition time.
//
// IDLoader is admin-only by intent: every consumer is reachable only behind
// the mode gate, and a contributor-mode caller never reaches the load site
// (denied at the gate before any IDLoader.Load is invoked). A nil identity
// returned without error is treated as the decrypt-no-identity error class by
// the caller — IDLoader itself neither holds nor logs private-key material.
type IDLoader interface {
	Load(ctx context.Context) (identity.Identity, error)
}
