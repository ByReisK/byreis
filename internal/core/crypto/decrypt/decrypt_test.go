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
	u, err := encrypt.New(encrypt.NewX25519Parser()).Encrypt(context.Background(), encrypt.EncryptInput{
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

// fakeAgeIdentity is a non-X25519 age.Identity that never matches a recipient.
// It exercises the widened identity.AgeIdentity() age.Identity return type:
// decrypt must accept any age.Identity (the seam a future plugin-backed
// identity flows through), and a non-matching one must fail closed via the
// existing "no identity matched" path — never decrypt, never panic.
type fakeAgeIdentity struct{}

func (fakeAgeIdentity) Unwrap([]*age.Stanza) ([]byte, error) {
	return nil, age.ErrIncorrectIdentity
}

// nonX25519Identity is a core identity.Identity backed by a non-X25519
// age.Identity.
type nonX25519Identity struct{}

func (nonX25519Identity) Recipient() string         { return "age1nonx25519" }
func (nonX25519Identity) AgeIdentity() age.Identity { return fakeAgeIdentity{} }

// TestDecrypt_NonX25519Identity_FailsClosed proves the widened decrypt path
// accepts a non-X25519 age.Identity and, when it is not a recipient of the
// value, fails closed to ErrDecrypt rather than decrypting or panicking. This
// is the cross-backend-mismatch invariant at the core seam.
func TestDecrypt_NonX25519Identity_FailsClosed(t *testing.T) {
	t.Parallel()
	r1, _ := recip(t)
	art := signedFrom(t, map[string]string{"DB": "db-secret"}, r1)

	_, err := decrypt.New().Decrypt(context.Background(), art, nonX25519Identity{})
	if !errors.Is(err, decrypt.ErrDecrypt) {
		t.Fatalf("Decrypt with non-recipient non-X25519 identity: err = %v, want ErrDecrypt", err)
	}
}

// TestDecrypt_NilAgeIdentity_FailsClosed proves the nil-guard survives the
// widening: an identity whose AgeIdentity() returns a nil interface fails
// closed to ErrDecrypt, never reaching age.Decrypt.
func TestDecrypt_NilAgeIdentity_FailsClosed(t *testing.T) {
	t.Parallel()
	r1, _ := recip(t)
	art := signedFrom(t, map[string]string{"DB": "db-secret"}, r1)

	_, err := decrypt.New().Decrypt(context.Background(), art, nilAgeIdentity{})
	if !errors.Is(err, decrypt.ErrDecrypt) {
		t.Fatalf("Decrypt with nil AgeIdentity: err = %v, want ErrDecrypt", err)
	}

	if err := decrypt.New().RoundTripAll(context.Background(), art,
		[]identity.Identity{nilAgeIdentity{}}); !errors.Is(err, decrypt.ErrDecrypt) {
		t.Fatalf("RoundTripAll with nil AgeIdentity: err = %v, want ErrDecrypt", err)
	}
}

// nilAgeIdentity returns a nil age.Identity, exercising the nil-guard.
type nilAgeIdentity struct{}

func (nilAgeIdentity) Recipient() string         { return "age1nil" }
func (nilAgeIdentity) AgeIdentity() age.Identity { return nil }

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
