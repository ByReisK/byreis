package modeprobe

import (
	"bytes"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// fakeAgeIdentity is a non-X25519 age.Identity that never matches a recipient.
// It exercises the widened probeDecryptOne(..., age.Identity) parameter: the
// probe must accept any age.Identity (the seam a future plugin-backed identity
// flows through) and fail closed when it is not a recipient.
type fakeAgeIdentity struct{}

func (fakeAgeIdentity) Unwrap([]*age.Stanza) ([]byte, error) {
	return nil, age.ErrIncorrectIdentity
}

// armoredCiphertext encrypts plaintext to a fresh X25519 recipient and returns
// the armored age value — a value the fake identity is NOT a recipient of.
func armoredCiphertext(t *testing.T, plaintext string) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var buf bytes.Buffer
	armorW := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorW, id.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := armorW.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}
	return buf.String()
}

// TestProbeDecryptOne_NonX25519Identity_FailsClosed proves the widened
// probeDecryptOne accepts a non-X25519 age.Identity and, when that identity is
// not a recipient of the value, returns (false, nil) via the existing
// isNotRecipientError path — cross-backend mismatch degrades to CONTRIBUTOR,
// never false-ADMIN, never a probe error.
func TestProbeDecryptOne_NonX25519Identity_FailsClosed(t *testing.T) {
	t.Parallel()
	ct := armoredCiphertext(t, "secret-not-for-the-fake")

	ok, err := probeDecryptOne(ct, fakeAgeIdentity{})
	if err != nil {
		t.Fatalf("probeDecryptOne non-recipient: err = %v, want nil (not a recipient is not an error)", err)
	}
	if ok {
		t.Fatal("probeDecryptOne returned ok=true for a non-recipient identity — false-ADMIN")
	}
}

// TestProbeDecryptOne_X25519Recipient_Unchanged pins the X25519 behaviour
// through the widened parameter: a real recipient decrypts (ok=true) exactly as
// before the widening.
func TestProbeDecryptOne_X25519Recipient_Unchanged(t *testing.T) {
	t.Parallel()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var buf bytes.Buffer
	armorW := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorW, id.Recipient())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := w.Write([]byte("recipient-plaintext")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := armorW.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}

	// Pass the X25519 identity through the widened age.Identity parameter.
	ok, probeErr := probeDecryptOne(buf.String(), id)
	if probeErr != nil {
		t.Fatalf("probeDecryptOne X25519 recipient: %v", probeErr)
	}
	if !ok {
		t.Fatal("probeDecryptOne returned ok=false for a true X25519 recipient")
	}
}
