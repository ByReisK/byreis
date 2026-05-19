//go:build testhook

package verify_test

import (
	"crypto/sha256"
	"testing"

	"filippo.io/age"

	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// realRecipient generates a fresh age X25519 recipient so encrypt produces real
// ciphertext. The private key is discarded — verify never decrypts.
func realRecipient(t *testing.T) rectypes.Recipient {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	pub := id.Recipient().String()
	return rectypes.Recipient{
		Label:       "r",
		AgePubKey:   pub,
		Fingerprint: rectypes.Fingerprint(sha256.Sum256([]byte(pub))),
	}
}
