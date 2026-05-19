package encrypt_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// testRecipient generates a fresh age identity and returns the rectypes
// Recipient view (public-key only) plus the identity so the test alone can
// decrypt and assert round-trip. The identity is NEVER handed to the encryptor.
func testRecipient(t *testing.T) (rectypes.Recipient, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	pub := id.Recipient().String()
	fp := rectypes.Fingerprint(sha256.Sum256([]byte(pub)))
	return rectypes.Recipient{Label: "test", AgePubKey: pub, Fingerprint: fp}, id
}

func fpHex(r rectypes.Recipient) string {
	return hex.EncodeToString(r.Fingerprint[:])
}

func baseInput(recips ...rectypes.Recipient) encrypt.EncryptInput {
	return encrypt.EncryptInput{
		ProjectID:       "proj-x",
		LogicalFileName: "prod",
		Counter:         3,
		Recipients:      recips,
		Values: map[string]string{
			"DB_PASSWORD": "s3cr3t-db",
			"API_KEY":     "s3cr3t-api",
		},
	}
}

func TestEncrypt_NoRecipients(t *testing.T) {
	t.Parallel()
	enc := encrypt.New()
	in := baseInput()
	_, err := enc.Encrypt(context.Background(), in)
	if !errors.Is(err, encrypt.ErrNoRecipients) {
		t.Fatalf("Encrypt with zero recipients: err = %v, want ErrNoRecipients", err)
	}
}

func TestEncrypt_BadFormatInputs(t *testing.T) {
	t.Parallel()
	r, _ := testRecipient(t)
	enc := encrypt.New()

	cases := []struct {
		name   string
		mutate func(in *encrypt.EncryptInput)
	}{
		{"separator in project id", func(in *encrypt.EncryptInput) { in.ProjectID = "p\x1fx" }},
		{"separator in key name", func(in *encrypt.EncryptInput) {
			in.Values = map[string]string{"BA\x1eD": "v"}
		}},
		{"no values", func(in *encrypt.EncryptInput) { in.Values = map[string]string{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := baseInput(r)
			tc.mutate(&in)
			if _, err := enc.Encrypt(context.Background(), in); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestEncrypt_UnsignedArtifact_RoundTrip(t *testing.T) {
	t.Parallel()
	r1, id1 := testRecipient(t)
	r2, id2 := testRecipient(t)
	enc := encrypt.New()

	art, err := enc.Encrypt(context.Background(), baseInput(r1, r2))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// The artifact is UNSIGNED by type: artifact.Unsigned has no manifest_sig
	// field at all, so there is nothing to assert-absent — the type enforces it.
	if art.Byreis.FormatVersion != "byreis.native.v1" {
		t.Fatalf("format version = %q", art.Byreis.FormatVersion)
	}
	if art.Byreis.ProjectID != "proj-x" || art.Byreis.File != "prod" || art.Byreis.Counter != 3 {
		t.Fatalf("metadata not bound: %+v", art.Byreis)
	}
	if len(art.Values) != 2 {
		t.Fatalf("want 2 values, got %d", len(art.Values))
	}
	// recipients display block carries BOTH fingerprints.
	gotFPs := map[string]bool{}
	for _, re := range art.Byreis.Recipients {
		gotFPs[re.FP] = true
	}
	if !gotFPs[fpHex(r1)] || !gotFPs[fpHex(r2)] {
		t.Fatalf("recipient fingerprints not in display block: %+v", art.Byreis.Recipients)
	}

	// Each value must independently decrypt with EACH recipient's identity.
	for name, want := range map[string]string{"DB_PASSWORD": "s3cr3t-db", "API_KEY": "s3cr3t-api"} {
		ct := string(art.Values[name])
		for _, id := range []*age.X25519Identity{id1, id2} {
			r := armor.NewReader(strings.NewReader(ct))
			dec, err := age.Decrypt(r, id)
			if err != nil {
				t.Fatalf("Decrypt %s with a recipient: %v", name, err)
			}
			var out bytes.Buffer
			if _, err := out.ReadFrom(dec); err != nil {
				t.Fatalf("read plaintext %s: %v", name, err)
			}
			if out.String() != want {
				t.Fatalf("%s round-trip = %q, want %q", name, out.String(), want)
			}
		}
	}
}

func TestEncrypt_FreshCiphertextPerValue_NoReuse(t *testing.T) {
	t.Parallel()
	r, _ := testRecipient(t)
	enc := encrypt.New()

	in := baseInput(r)
	// Two keys with the SAME plaintext must still get distinct ciphertext
	// (fresh age.Encrypt per value → fresh nonce/file key, §3.0).
	in.Values = map[string]string{"A": "identical", "B": "identical"}
	art, err := enc.Encrypt(context.Background(), in)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal([]byte(art.Values["A"]), []byte(art.Values["B"])) {
		t.Fatalf("AEAD-freshness violated: equal plaintext produced byte-identical ciphertext")
	}

	// Re-encrypting the SAME input must regenerate ciphertext (no reuse across
	// calls / counter generations).
	art2, err := enc.Encrypt(context.Background(), baseInput(r))
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}
	art3, err := enc.Encrypt(context.Background(), baseInput(r))
	if err != nil {
		t.Fatalf("Encrypt 3: %v", err)
	}
	if bytes.Equal([]byte(art2.Values["DB_PASSWORD"]), []byte(art3.Values["DB_PASSWORD"])) {
		t.Fatalf("AEAD-freshness violated: re-encrypt reused prior ciphertext bytes")
	}
}

func TestEncrypt_WrongRecipientCannotDecrypt(t *testing.T) {
	t.Parallel()
	r, _ := testRecipient(t)
	_, wrongID := testRecipient(t) // not in the recipient set
	enc := encrypt.New()

	art, err := enc.Encrypt(context.Background(), baseInput(r))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ar := armor.NewReader(strings.NewReader(string(art.Values["API_KEY"])))
	if _, err := age.Decrypt(ar, wrongID); err == nil {
		t.Fatalf("a non-recipient identity decrypted the value — fail-closed broken")
	}
}
