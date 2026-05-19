// Package decrypt implements admin decrypt and the post-merge round-trip check.
// It imports internal/core/crypto/identity and age. It is never imported by
// crypto/encrypt or by any path reachable from a contributor submit, so the
// contributor code path can never reach private-key material.
package decrypt

import (
	"context"
	"errors"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
)

// ErrDecrypt is returned when no available identity could decrypt a value.
var ErrDecrypt = errors.New(
	"no available identity could decrypt the value — " +
		"run `byreis auth login` or check that your admin key is present")

// Decryptor decrypts age ciphertexts using admin identity material.
// Consumer-defined interface (decrypt package is the consumer of identity).
type Decryptor interface {
	// Decrypt decrypts all values in the signed artifact using the provided
	// identity. Returns ErrDecrypt (wrapping the underlying age error) if the
	// identity cannot decrypt any value.
	//
	// The plaintext values must be zeroized by the caller after use.
	Decrypt(ctx context.Context, art artifact.Signed, id identity.Identity) (map[string]string, error)

	// RoundTripAll verifies that every value in the artifact can be decrypted
	// by every recipient's identity (post-merge integrity check).
	// Returns ErrDecrypt for any value that cannot be decrypted by any provided
	// identity.
	RoundTripAll(ctx context.Context, art artifact.Signed, ids []identity.Identity) error
}

// New returns the concrete Decryptor implementation.
func New() Decryptor {
	return &decryptor{}
}

type decryptor struct{}

func (d *decryptor) Decrypt(_ context.Context, _ artifact.Signed, _ identity.Identity) (map[string]string, error) {
	panic("not implemented") // stub: real implementation pending
}

func (d *decryptor) RoundTripAll(_ context.Context, _ artifact.Signed, _ []identity.Identity) error {
	panic("not implemented") // stub: real implementation pending
}
