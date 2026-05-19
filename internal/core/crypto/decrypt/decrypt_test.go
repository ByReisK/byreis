package decrypt_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"filippo.io/age"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// recip generates a fresh age identity and returns its rectypes view plus the
// admin identity wrapper (the decrypt-side private-key holder).
func recip(t *testing.T) (rectypes.Recipient, identity.Identity) {
	t.Helper()
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub := ageID.Recipient().String()
	id, err := identity.Parse(ageID.String())
	if err != nil {
		t.Fatalf("identity.Parse: %v", err)
	}
	return rectypes.Recipient{
		Label:       "admin",
		AgePubKey:   pub,
		Fingerprint: rectypes.Fingerprint(sha256.Sum256([]byte(pub))),
	}, id
}

// signedFrom encrypts plaintext to recips and lifts the unsigned artifact to a
// Signed shell (decrypt only needs the Values + Byreis; the signature is
// VerifyOfRecord's concern, not decrypt's).
func signedFrom(t *testing.T, vals map[string]string, rs ...rectypes.Recipient) artifact.Signed {
	t.Helper()
	u, err := encrypt.New().Encrypt(context.Background(), encrypt.EncryptInput{
		ProjectID: "p", LogicalFileName: "prod", Counter: 1,
		Recipients: rs, Values: vals,
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return artifact.Signed{Values: u.Values, Byreis: u.Byreis}
}

func TestDecrypt_AdminRoundTrip_CrossProduct(t *testing.T) {
	t.Parallel()
	r1, id1 := recip(t)
	r2, id2 := recip(t)
	vals := map[string]string{"DB": "db-secret", "API": "api-secret"}
	art := signedFrom(t, vals, r1, r2)

	d := decrypt.New()
	for _, id := range []identity.Identity{id1, id2} {
		got, err := d.Decrypt(context.Background(), art, id)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		for k, want := range vals {
			if got[k] != want {
				t.Fatalf("Decrypt[%s] = %q, want %q", k, got[k], want)
			}
		}
	}
}

func TestDecrypt_WrongRecipientFailsClosed(t *testing.T) {
	t.Parallel()
	r1, _ := recip(t)
	_, wrongID := recip(t) // not in the recipient set
	art := signedFrom(t, map[string]string{"DB": "db-secret"}, r1)

	_, err := decrypt.New().Decrypt(context.Background(), art, wrongID)
	if !errors.Is(err, decrypt.ErrDecrypt) {
		t.Fatalf("Decrypt with wrong identity: err = %v, want ErrDecrypt", err)
	}
}

func TestDecrypt_NeverLeaksPlaintextInError(t *testing.T) {
	t.Parallel()
	r1, _ := recip(t)
	_, wrongID := recip(t)
	const secret = "TOP-SECRET-PLAINTEXT-VALUE"
	art := signedFrom(t, map[string]string{"DB": secret}, r1)

	_, err := decrypt.New().Decrypt(context.Background(), art, wrongID)
	if err == nil {
		t.Fatalf("expected failure")
	}
	if bytes.Contains([]byte(err.Error()), []byte(secret)) {
		t.Fatalf("error text leaked plaintext: %v", err)
	}
}

func TestRoundTripAll_PostMergeIntegrity(t *testing.T) {
	t.Parallel()
	r1, id1 := recip(t)
	r2, id2 := recip(t)
	art := signedFrom(t, map[string]string{"DB": "x", "API": "y"}, r1, r2)

	d := decrypt.New()
	if err := d.RoundTripAll(context.Background(), art, []identity.Identity{id1, id2}); err != nil {
		t.Fatalf("RoundTripAll all-recipients: %v", err)
	}

	// A recipient removed from the set (but a value still encrypted only to the
	// others) must fail closed: id3 cannot decrypt.
	_, id3 := recip(t)
	if err := d.RoundTripAll(context.Background(), art, []identity.Identity{id1, id3}); !errors.Is(err, decrypt.ErrDecrypt) {
		t.Fatalf("RoundTripAll with a non-recipient identity: err = %v, want ErrDecrypt", err)
	}
}

func TestDecrypt_ContextCancelled(t *testing.T) {
	t.Parallel()
	r1, id1 := recip(t)
	art := signedFrom(t, map[string]string{"DB": "x"}, r1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := decrypt.New().Decrypt(ctx, art, id1); err == nil {
		t.Fatalf("expected cancellation error")
	}
}
