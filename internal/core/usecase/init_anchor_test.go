package usecase_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ByReisK/byreis/internal/core/usecase"
)

// genSigner returns a fresh ed25519 public key and its canonical hex fingerprint
// (sha256 of the 32 raw key bytes), as the loader/probe compute it.
func genSigner(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sum := sha256.Sum256(pub)
	return pub, hex.EncodeToString(sum[:])
}

// --- key<->fingerprint integrity at the loader (deliverable 2) ---

// TestValidateTrustAnchor_ValidPair: a key whose sha256 == stored fingerprint
// and is exactly 32 bytes yields a usable anchor with no error.
func TestValidateTrustAnchor_ValidPair(t *testing.T) {
	t.Parallel()

	key, fp := genSigner(t)
	anchor := usecase.TrustAnchor{
		SignerKey:         key,
		SignerFingerprint: fp,
	}
	got, err := usecase.ValidateTrustAnchor(anchor)
	if err != nil {
		t.Fatalf("expected valid pair to pass, got %v", err)
	}
	if !got.SignerKey.Equal(key) {
		t.Error("validated anchor must carry the same key")
	}
	if got.SignerFingerprint != fp {
		t.Errorf("validated anchor fingerprint = %q, want %q", got.SignerFingerprint, fp)
	}
}

// TestValidateTrustAnchor_StaleFingerprint: a real 32-byte key paired with a
// fingerprint that is NOT sha256(key) fails closed with the dedicated integrity
// sentinel — never ErrSignerChanged, never a perms error.
func TestValidateTrustAnchor_StaleFingerprint(t *testing.T) {
	t.Parallel()

	key, _ := genSigner(t)
	anchor := usecase.TrustAnchor{
		SignerKey:         key,
		SignerFingerprint: "deadbeef", // not sha256(key)
	}
	_, err := usecase.ValidateTrustAnchor(anchor)
	if !errors.Is(err, usecase.ErrTrustAnchorIntegrity) {
		t.Fatalf("expected ErrTrustAnchorIntegrity, got %v", err)
	}
	if errors.Is(err, usecase.ErrSignerChanged) {
		t.Error("integrity mismatch must NOT be reported as ErrSignerChanged")
	}
}

// TestValidateTrustAnchor_TamperedFingerprintRealKey: the fingerprint was
// tampered to a different valid-looking hex; the key is genuine. The recompute
// catches it as an integrity violation.
func TestValidateTrustAnchor_TamperedFingerprintRealKey(t *testing.T) {
	t.Parallel()

	key, fp := genSigner(t)
	// Flip the first hex nibble of the legitimate fingerprint.
	fpb := []byte(fp)
	if fpb[0] == 'a' {
		fpb[0] = 'b'
	} else {
		fpb[0] = 'a'
	}
	anchor := usecase.TrustAnchor{
		SignerKey:         key,
		SignerFingerprint: string(fpb),
	}
	_, err := usecase.ValidateTrustAnchor(anchor)
	if !errors.Is(err, usecase.ErrTrustAnchorIntegrity) {
		t.Fatalf("expected ErrTrustAnchorIntegrity for tampered fp, got %v", err)
	}
}

// --- downgrade / truncation at the loader (deliverable 2) ---

// TestValidateTrustAnchor_LengthGate covers empty / short / long key material:
// every non-32-byte key is a hard fail-closed BEFORE any key could reach
// registry.New — never silent-different, never accept-unverified.
func TestValidateTrustAnchor_LengthGate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		key  []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"short_31", make([]byte, 31)},
		{"long_33", make([]byte, 33)},
		{"long_64", make([]byte, 64)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Fingerprint is irrelevant: the length gate fires first.
			sum := sha256.Sum256(tc.key)
			anchor := usecase.TrustAnchor{
				SignerKey:         ed25519.PublicKey(tc.key),
				SignerFingerprint: hex.EncodeToString(sum[:]),
			}
			_, err := usecase.ValidateTrustAnchor(anchor)
			if !errors.Is(err, usecase.ErrTrustAnchorIntegrity) {
				t.Fatalf("expected ErrTrustAnchorIntegrity for %s key, got %v", tc.name, err)
			}
			if errors.Is(err, usecase.ErrSignerChanged) {
				t.Error("length failure must NOT be ErrSignerChanged")
			}
		})
	}
}

// TestValidateTrustAnchor_LegacyFingerprintOnly: a legacy fp-only file (no key
// material at all) is rejected hard — never accepted unverified.
func TestValidateTrustAnchor_LegacyFingerprintOnly(t *testing.T) {
	t.Parallel()

	anchor := usecase.TrustAnchor{
		SignerKey:         nil,
		SignerFingerprint: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
	}
	_, err := usecase.ValidateTrustAnchor(anchor)
	if !errors.Is(err, usecase.ErrTrustAnchorIntegrity) {
		t.Fatalf("expected ErrTrustAnchorIntegrity for legacy fp-only anchor, got %v", err)
	}
}

// --- SignerProbe widening + probe-boundary self-check (deliverable 3/4) ---

// TestProbe_RejectsKeyWhoseSha256NeqClaimedFp: a probe surfacing a key whose
// sha256 does not equal its claimed fingerprint is rejected at the probe
// boundary; Init writes nothing.
func TestProbe_RejectsKeyWhoseSha256NeqClaimedFp(t *testing.T) {
	t.Parallel()

	key, _ := genSigner(t)
	ts := &fakeTrustAnchorStore{exists: false}
	sp := &fakeSignerProbe{
		signer: usecase.ProbedSigner{Key: key, Fingerprint: "bogusfp"},
	}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL:  "https://example.com/registry",
		ProjectID:    "p",
		ConfigDir:    "/tmp/p",
		AcceptSigner: "bogusfp",
	})
	if !errors.Is(err, usecase.ErrTrustAnchorIntegrity) {
		t.Fatalf("expected ErrTrustAnchorIntegrity from probe self-check, got %v", err)
	}
	if ts.written != nil {
		t.Error("nothing must be pinned when the probe self-check fails")
	}
	if len(cw.written) != 0 {
		t.Error("no project config on probe self-check failure")
	}
}

// --- REQ-B-005: first-init pins the full key, displays the fingerprint ---

// TestInit_FirstInit_PinsFullKey: --accept-signer matching the probed signer
// writes trust.yaml carrying {key, fp=sha256(key)}; the result fingerprint
// equals the accepted one (operator sees the fingerprint, never the blob).
func TestInit_FirstInit_PinsFullKey(t *testing.T) {
	t.Parallel()

	key, fp := genSigner(t)
	ts := &fakeTrustAnchorStore{exists: false}
	sp := &fakeSignerProbe{signer: usecase.ProbedSigner{Key: key, Fingerprint: fp}}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	res, err := u.Init(context.Background(), usecase.InitInput{
		RegistryURL:  "https://example.com/registry",
		ProjectID:    "p",
		ConfigDir:    "/tmp/p",
		AcceptSigner: fp,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !res.PinWritten {
		t.Fatal("expected PinWritten=true")
	}
	if ts.written == nil {
		t.Fatal("expected trust anchor to be written")
	}
	if !ts.written.SignerKey.Equal(key) {
		t.Error("pinned anchor must carry the full probed key")
	}
	sum := sha256.Sum256(key)
	if ts.written.SignerFingerprint != hex.EncodeToString(sum[:]) {
		t.Error("pinned fingerprint must be sha256(key)")
	}
	if res.SignerFingerprint != fp {
		t.Errorf("result fingerprint = %q, want %q", res.SignerFingerprint, fp)
	}
}

// TestInit_NonInteractive_NoAccept_NothingPinned: --non-interactive without
// --accept-signer fails closed; not even a widened/odd probe result causes a
// partial pin.
func TestInit_NonInteractive_NoAccept_NothingPinned(t *testing.T) {
	t.Parallel()

	key, fp := genSigner(t)
	ts := &fakeTrustAnchorStore{exists: false}
	sp := &fakeSignerProbe{signer: usecase.ProbedSigner{Key: key, Fingerprint: fp}}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "p",
		ConfigDir:      "/tmp/p",
		NonInteractive: true,
	})
	if !errors.Is(err, usecase.ErrSignerNotAccepted) {
		t.Fatalf("expected ErrSignerNotAccepted, got %v", err)
	}
	if ts.written != nil {
		t.Error("no partial pin permitted on ErrSignerNotAccepted")
	}
	if len(cw.written) != 0 {
		t.Error("no project config on ErrSignerNotAccepted")
	}
}

// --- ErrSignerChanged is a FULL-KEY compare (deliverable 3) ---

// TestInit_ErrSignerChanged_FullKeyCompare: an existing pin {K1,fp1} with the
// registry presenting a different key K2 ⇒ ErrSignerChanged, nothing rewritten.
func TestInit_ErrSignerChanged_FullKeyCompare(t *testing.T) {
	t.Parallel()

	k1, fp1 := genSigner(t)
	k2, fp2 := genSigner(t)

	ts := &fakeTrustAnchorStore{
		exists: true,
		anchor: usecase.TrustAnchor{SignerKey: k1, SignerFingerprint: fp1},
	}
	sp := &fakeSignerProbe{signer: usecase.ProbedSigner{Key: k2, Fingerprint: fp2}}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL: "https://example.com/registry",
		ProjectID:   "p",
		ConfigDir:   "/tmp/p",
	})
	if !errors.Is(err, usecase.ErrSignerChanged) {
		t.Fatalf("expected ErrSignerChanged, got %v", err)
	}
	if ts.written != nil {
		t.Error("ErrSignerChanged must never auto-replace the pin")
	}
	if len(cw.written) != 0 {
		t.Error("no project config on ErrSignerChanged")
	}
}

// TestInit_ErrSignerChanged_FingerprintCollision: a synthetic fingerprint
// collision (same stored fingerprint, different key) must STILL be
// ErrSignerChanged — the key comparison is authoritative, a colliding
// fingerprint must not pass.
func TestInit_ErrSignerChanged_FingerprintCollision(t *testing.T) {
	t.Parallel()

	k1, fp1 := genSigner(t)
	k2, _ := genSigner(t)

	// Existing pin: K1 with fp1 (genuine pair).
	// Registry presents K2 but its probe claims the SAME fp1 (collision /
	// adversarial). The probe self-check rejects the K2/fp1 pair first
	// (sha256(K2) != fp1), which is itself a hard fail — never an accept.
	ts := &fakeTrustAnchorStore{
		exists: true,
		anchor: usecase.TrustAnchor{SignerKey: k1, SignerFingerprint: fp1},
	}
	sp := &fakeSignerProbe{signer: usecase.ProbedSigner{Key: k2, Fingerprint: fp1}}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL: "https://example.com/registry",
		ProjectID:   "p",
		ConfigDir:   "/tmp/p",
	})
	// Either the probe self-check (sha256(K2)!=fp1) or the key compare must
	// reject this; in NO case may it be accepted / rewritten.
	if err == nil {
		t.Fatal("a colliding fingerprint with a different key must never be accepted")
	}
	if !errors.Is(err, usecase.ErrTrustAnchorIntegrity) && !errors.Is(err, usecase.ErrSignerChanged) {
		t.Fatalf("expected ErrTrustAnchorIntegrity or ErrSignerChanged, got %v", err)
	}
	if ts.written != nil {
		t.Error("nothing may be rewritten on a collision attempt")
	}
}

// TestInit_SubsequentInit_FullKeyMatch: existing pin {K1,fp1}; registry
// presents the SAME K1 ⇒ success, no re-write.
func TestInit_SubsequentInit_FullKeyMatch(t *testing.T) {
	t.Parallel()

	k1, fp1 := genSigner(t)
	ts := &fakeTrustAnchorStore{
		exists: true,
		anchor: usecase.TrustAnchor{SignerKey: k1, SignerFingerprint: fp1},
	}
	sp := &fakeSignerProbe{signer: usecase.ProbedSigner{Key: k1, Fingerprint: fp1}}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	res, err := u.Init(context.Background(), usecase.InitInput{
		RegistryURL: "https://example.com/registry",
		ProjectID:   "p",
		ConfigDir:   "/tmp/p",
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if res.PinWritten {
		t.Error("matching full key must not re-write the pin")
	}
	if ts.written != nil {
		t.Error("no re-write when the pinned key already matches")
	}
}

// TestInit_SubsequentInit_StoredPinCorrupt: a stored pin whose own
// key<->fingerprint is inconsistent (on-disk tamper) fails closed with the
// integrity sentinel BEFORE any registry comparison — never silently trusted.
func TestInit_SubsequentInit_StoredPinCorrupt(t *testing.T) {
	t.Parallel()

	k1, _ := genSigner(t)
	ts := &fakeTrustAnchorStore{
		exists: true,
		anchor: usecase.TrustAnchor{SignerKey: k1, SignerFingerprint: "tampered"},
	}
	sp := &fakeSignerProbe{signer: usecase.ProbedSigner{Key: k1, Fingerprint: "tampered"}}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL: "https://example.com/registry",
		ProjectID:   "p",
		ConfigDir:   "/tmp/p",
	})
	if !errors.Is(err, usecase.ErrTrustAnchorIntegrity) {
		t.Fatalf("expected ErrTrustAnchorIntegrity for a corrupt stored pin, got %v", err)
	}
	if ts.written != nil {
		t.Error("a corrupt stored pin must never be auto-rewritten")
	}
}

// TestInit_ReadAnchorPermError_NoDowngrade: a TOCTOU/perms error surfaced by
// the store (the internal/core/trust hard errors) propagates as a refuse-to-run
// failure — never downgraded to accept-unverified, never silent.
func TestInit_ReadAnchorPermError_NoDowngrade(t *testing.T) {
	t.Parallel()

	permErr := errors.New(
		"trust anchor file has insecure permissions: must be exactly 0600 — run: chmod 600 <path>")
	ts := &fakeTrustAnchorStore{exists: true, readErr: permErr}
	key, fp := genSigner(t)
	sp := &fakeSignerProbe{signer: usecase.ProbedSigner{Key: key, Fingerprint: fp}}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL: "https://example.com/registry",
		ProjectID:   "p",
		ConfigDir:   "/tmp/p",
	})
	if err == nil {
		t.Fatal("a store perms/TOCTOU error must fail closed, not be ignored")
	}
	if !errors.Is(err, permErr) {
		t.Errorf("expected the store perm error to propagate, got %v", err)
	}
	if errors.Is(err, usecase.ErrSignerChanged) {
		t.Error("a perms error must not be reported as ErrSignerChanged")
	}
	if ts.written != nil || len(cw.written) != 0 {
		t.Error("nothing may be written when the store fails closed")
	}
}
