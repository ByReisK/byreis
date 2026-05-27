package identity_test

import (
	"errors"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/ByReisK/byreis/internal/core/crypto/identity"
)

// TestParse_X25519_RoundTrip proves the unchanged X25519 construction: a valid
// AGE-SECRET-KEY-1 string yields an Identity whose Recipient() is the matching
// public string and whose AgeIdentity() is non-nil.
func TestParse_X25519_RoundTrip(t *testing.T) {
	t.Parallel()
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	id, err := identity.Parse(ageID.String())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := id.Recipient(), ageID.Recipient().String(); got != want {
		t.Fatalf("Recipient() = %q, want %q", got, want)
	}
	if id.AgeIdentity() == nil {
		t.Fatal("AgeIdentity() = nil, want non-nil age.Identity")
	}
}

// TestParse_InvalidSecret_NoEcho proves a malformed secret returns
// ErrParseIdentity without echoing the (private) input.
func TestParse_InvalidSecret_NoEcho(t *testing.T) {
	t.Parallel()
	const bad = "AGE-SECRET-KEY-1-NOT-A-REAL-KEY-DO-NOT-LEAK"
	_, err := identity.Parse(bad)
	if !errors.Is(err, identity.ErrParseIdentity) {
		t.Fatalf("Parse(bad) err = %v, want ErrParseIdentity", err)
	}
	if got := err.Error(); strings.Contains(got, bad) {
		t.Fatalf("error leaked the secret input: %q", got)
	}
}

// fakeAgeIdentity is a non-X25519 age.Identity. It exists only to prove the
// widened interface accepts any age.Identity (the seam a future plugin-backed
// identity flows through), not just *age.X25519Identity. It never decrypts.
type fakeAgeIdentity struct{}

func (fakeAgeIdentity) Unwrap([]*age.Stanza) ([]byte, error) {
	return nil, age.ErrIncorrectIdentity
}

// nonX25519Identity is a core Identity whose AgeIdentity() returns a non-X25519
// age.Identity, exercising the widened return type.
type nonX25519Identity struct{}

func (nonX25519Identity) Recipient() string         { return "age1fake" }
func (nonX25519Identity) AgeIdentity() age.Identity { return fakeAgeIdentity{} }

// TestIdentity_AgeIdentity_AcceptsInterface proves AgeIdentity() returns the
// age.Identity interface so a non-X25519 backend (e.g. a future plugin
// identity) satisfies the core Identity contract without any concrete-type
// coupling. This is a compile-and-assign assertion plus a usage check.
func TestIdentity_AgeIdentity_AcceptsInterface(t *testing.T) {
	t.Parallel()
	// nonX25519Identity satisfying identity.Identity is the load-bearing
	// compile-time assertion: its AgeIdentity() returns a non-X25519 age.Identity,
	// which only compiles because the interface was widened from *age.X25519Identity.
	var id identity.Identity = nonX25519Identity{}
	ageID := id.AgeIdentity() // typed age.Identity
	if ageID == nil {
		t.Fatal("AgeIdentity() = nil for a non-X25519 identity")
	}
	// The interface value must be usable as an age.Identity (Unwrap callable).
	if _, err := ageID.Unwrap(nil); err == nil {
		t.Fatal("expected the fake identity Unwrap to fail closed")
	}
}
