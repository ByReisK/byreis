// Package decrypt implements admin decrypt and the post-merge round-trip check.
// It imports internal/core/crypto/identity and age. It is never imported by
// crypto/encrypt or by any path reachable from a contributor submit, so the
// contributor code path can never reach private-key material.
package decrypt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
)

// ErrDecrypt is returned when no available identity could decrypt a value. The
// error never contains plaintext or key material.
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
	// by every provided identity (post-merge integrity check). Returns
	// ErrDecrypt for any (identity, value) pair that fails.
	RoundTripAll(ctx context.Context, art artifact.Signed, ids []identity.Identity) error
}

// New returns the concrete Decryptor implementation.
func New() Decryptor {
	return &decryptor{}
}

type decryptor struct{}

func (d *decryptor) Decrypt(
	ctx context.Context, art artifact.Signed, id identity.Identity,
) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("decrypt cancelled: %w", err)
	}
	if id == nil || id.AgeIdentity() == nil {
		return nil, fmt.Errorf("%w: no admin identity provided", ErrDecrypt)
	}

	out := make(map[string]string, len(art.Values))
	for name, ct := range art.Values {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("decrypt cancelled: %w", err)
		}
		pt, err := decryptValue(string(ct), id.AgeIdentity())
		if err != nil {
			// Never include plaintext, ciphertext, or key material in the error.
			return nil, fmt.Errorf("%w: key %q", ErrDecrypt, name)
		}
		out[name] = pt
	}
	return out, nil
}

func (d *decryptor) RoundTripAll(
	ctx context.Context, art artifact.Signed, ids []identity.Identity,
) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("round-trip cancelled: %w", err)
	}
	if len(ids) == 0 {
		return fmt.Errorf("%w: no identities provided for round-trip", ErrDecrypt)
	}
	// Every value MUST decrypt under EVERY recipient identity (post-merge
	// integrity: confirms the live file is readable by all current admins).
	for _, id := range ids {
		if id == nil || id.AgeIdentity() == nil {
			return fmt.Errorf("%w: nil identity in round-trip set", ErrDecrypt)
		}
		for name, ct := range art.Values {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("round-trip cancelled: %w", err)
			}
			if _, err := decryptValue(string(ct), id.AgeIdentity()); err != nil {
				return fmt.Errorf("%w: key %q not decryptable by recipient %q",
					ErrDecrypt, name, id.Recipient())
			}
		}
	}
	return nil
}

// decryptValue decrypts ONE armored age ciphertext with the given identity.
// The plaintext is read fully into memory; the caller is responsible for
// zeroizing the returned string's backing where practical.
func decryptValue(armored string, id *age.X25519Identity) (string, error) {
	ar := armor.NewReader(strings.NewReader(armored))
	r, err := age.Decrypt(ar, id)
	if err != nil {
		// age error may name identities; do not propagate verbatim plaintext.
		return "", fmt.Errorf("age decrypt: %w", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return "", fmt.Errorf("read plaintext: %w", err)
	}
	return buf.String(), nil
}
