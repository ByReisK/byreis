package sign_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
)

// keypair returns a fresh Ed25519 keypair. The private key never leaves the
// test process and is not shared across cases.
func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}
	return pub, priv
}

func goodManifest() manifest.Manifest {
	return manifest.Manifest{
		FormatVersion:   "byreis.native.v1",
		ProjectID:       "proj-x",
		LogicalFileName: "prod",
		Counter:         7,
		Values:          map[string][]byte{"DB": []byte("ct-db"), "API": []byte("ct-api")},
		RecipientFingerprints: []string{
			strings.Repeat("aa", 32), strings.Repeat("bb", 32),
		},
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv := keypair(t)
	m := goodManifest()
	sig, err := sign.Sign(priv, m)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sign.Verify(pub, m, sig); err != nil {
		t.Fatalf("Verify round-trip: %v", err)
	}
}

func TestVerify_Forgery(t *testing.T) {
	t.Parallel()
	pub, priv := keypair(t)
	m := goodManifest()
	sig, err := sign.Sign(priv, m)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cases := []struct {
		name string
		run  func() error
	}{
		{"single-byte signature tamper", func() error {
			bad := append([]byte(nil), sig...)
			bad[0] ^= 0xff
			return sign.Verify(pub, m, bad)
		}},
		{"mutated counter under old signature", func() error {
			m2 := goodManifest()
			m2.Counter = 8
			return sign.Verify(pub, m2, sig)
		}},
		{"mutated ciphertext under old signature", func() error {
			m2 := goodManifest()
			m2.Values = map[string][]byte{"DB": []byte("TAMPERED"), "API": []byte("ct-api")}
			return sign.Verify(pub, m2, sig)
		}},
		{"forged signer key", func() error {
			otherPub, _ := keypair(t)
			return sign.Verify(otherPub, m, sig)
		}},
		{"empty signature", func() error { return sign.Verify(pub, m, nil) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.run(); err == nil {
				t.Fatalf("Verify accepted an invalid case: %s", tc.name)
			}
		})
	}
}

func TestVerify_WrongKeyLength(t *testing.T) {
	t.Parallel()
	m := goodManifest()
	if err := sign.Verify(ed25519.PublicKey{1, 2, 3}, m, make([]byte, 64)); !errors.Is(err, sign.ErrBadSignerKeyLength) {
		t.Fatalf("Verify with short key: err = %v, want ErrBadSignerKeyLength", err)
	}
}

func TestSign_RejectsBadManifestBeforeSigning(t *testing.T) {
	t.Parallel()
	_, priv := keypair(t)
	m := goodManifest()
	m.FormatVersion = "nope"
	if _, err := sign.Sign(priv, m); !errors.Is(err, manifest.ErrFormatVersion) {
		t.Fatalf("Sign bad format: err = %v, want manifest.ErrFormatVersion", err)
	}
}
