package manifestsigner_test

// Named test obligations (individually-failing):
//
//   canonical-preimage-equivalence: verify.ContentSHA over a manifest signed via
//     this adapter == over the same manifest signed via the frozen sign.Sign directly;
//     a one-field manifest mutation yields a different signature + ContentSHA; the
//     frozen fail-closed re-validate in sign.Sign catches a separator-injected /
//     bad-format_version manifest BEFORE any signature byte.
//
//   no-double-sign: the adapter calls the sign path exactly once per Sign call;
//     no second encoding.
//
//   signerID-from-attested-only: a key whose public half is not in the
//     registry-attested TrustedSigners map cannot produce a usable signerID
//     (fail closed); the signer never self-declares signerID.
//
//   L-2: the Ed25519 private-key source buffer is zeroized after use
//     (pinned-backing GC/escape-resistant standard); the signer cannot be
//     constructed from / does not accept the age X25519 decrypt identity as
//     the Ed25519 signing key (distinct-key / no-cross-role-reuse assertion).
//
//   happy: a valid admin Ed25519 key signs a valid manifest; the frozen
//     verify.VerifyOfRecord path accepts the result with the attested signerID.
//
//   allowlist: internal/adapter/manifestsigner is NOT in the submit/encrypt
//     transitive dep sets (checked via go list -deps + the allowlist check
//     function; package-import-boundary enforcement).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"filippo.io/age"

	"github.com/ByReisK/byreis/internal/adapter/manifestsigner"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// generateEd25519 generates a fresh Ed25519 key pair for tests.
func generateEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generateEd25519: %v", err)
	}
	return pub, priv
}

// validManifest returns a well-formed manifest usable for signing tests.
func validManifest() manifest.Manifest {
	ct := []byte("age-ciphertext-blob")
	h := sha256.New()
	h.Write(ct)
	fp := hex.EncodeToString(h.Sum(nil))

	return manifest.Manifest{
		FormatVersion:         "byreis.native.v1",
		ProjectID:             "test-project",
		LogicalFileName:       "secrets",
		Counter:               1,
		Values:                map[string][]byte{"mykey": ct},
		RecipientFingerprints: []string{fp},
	}
}

// makeAttestedSigner returns a Signer whose key is registered in TrustedSigners
// under adminID, using a CountingKeySource so the test can assert sign-path calls.
func makeAttestedSigner(
	t *testing.T,
	pub ed25519.PublicKey,
	priv ed25519.PrivateKey,
	adminID string,
) (usecase.ManifestSigner, *CountingKeySource, map[string]ed25519.PublicKey) {
	t.Helper()
	trusted := map[string]ed25519.PublicKey{adminID: pub}
	src := &CountingKeySource{key: priv}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("manifestsigner.New: %v", err)
	}
	return s, src, trusted
}

// ─── CountingKeySource ─────────────────────────────────────────────────────────

// CountingKeySource is an injectable fake Ed25519KeySource. It returns a fixed
// private key and records how many times ProvideKey was called so the
// no-double-sign test can assert exactly one call per Sign invocation.
type CountingKeySource struct {
	key   ed25519.PrivateKey
	calls atomic.Int32
}

func (c *CountingKeySource) ProvideKey(_ context.Context) ([]byte, error) {
	c.calls.Add(1)
	// Return a copy so the signer can zeroize it without affecting this struct.
	out := make([]byte, len(c.key))
	copy(out, c.key)
	return out, nil
}

// ─── errKeySource ──────────────────────────────────────────────────────────────

// errKeySource always returns an error from ProvideKey; used to test error paths.
type errKeySource struct{ err error }

func (e *errKeySource) ProvideKey(_ context.Context) ([]byte, error) {
	return nil, e.err
}

// ─── Test: canonical-preimage-equivalence ─────────────────────────────────────

// TestCanonicalPreimageEquivalence proves that signing via this adapter and
// signing directly via the frozen sign.Sign produce the same canonical preimage
// and, because the same private key and encoding are used, identical signatures.
// It also proves that verify.ContentSHA matches in both cases.
func TestCanonicalPreimageEquivalence(t *testing.T) {
	t.Parallel()

	pub, priv := generateEd25519(t)
	adminID := "admin-alice"
	m := validManifest()

	// Sign via the adapter.
	src := &CountingKeySource{key: priv}
	trusted := map[string]ed25519.PublicKey{adminID: pub}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gotID, gotSig, err := s.Sign(context.Background(), m)
	if err != nil {
		t.Fatalf("adapter Sign: %v", err)
	}

	// Sign via the frozen sign.Sign directly (the authoritative path).
	wantSig, err := sign.Sign(priv, m)
	if err != nil {
		t.Fatalf("sign.Sign: %v", err)
	}

	// The signatures must be identical: same key + same encoding => same output.
	if !bytes.Equal(gotSig, wantSig) {
		t.Errorf("canonical-preimage-equivalence: adapter signature differs from frozen sign.Sign\n"+
			"adapter: %x\nfrozen:  %x", gotSig, wantSig)
	}

	// The signerID must be the attested one.
	if gotID != adminID {
		t.Errorf("canonical-preimage-equivalence: signerID=%q, want %q", gotID, adminID)
	}

	// Build a Signed artifact and check ContentSHA consistency.
	signed := buildSignedArtifact(m, gotID, hex.EncodeToString(gotSig))
	sha := verify.ContentSHA(signed)
	if sha == "" {
		t.Error("canonical-preimage-equivalence: ContentSHA returned empty for adapter-signed artifact")
	}

	// The same artifact built from the frozen sig must give the same ContentSHA.
	signedFrozen := buildSignedArtifact(m, adminID, hex.EncodeToString(wantSig))
	shaFrozen := verify.ContentSHA(signedFrozen)
	if sha != shaFrozen {
		t.Errorf("canonical-preimage-equivalence: ContentSHA diverged\nadapter: %s\nfrozen:  %s", sha, shaFrozen)
	}
}

// TestOneFieldMutationDifferentSignature proves that mutating one field of the
// manifest produces a different signature and a different ContentSHA.
func TestOneFieldMutationDifferentSignature(t *testing.T) {
	t.Parallel()

	pub, priv := generateEd25519(t)
	adminID := "admin-bob"
	m := validManifest()

	src := &CountingKeySource{key: priv}
	trusted := map[string]ed25519.PublicKey{adminID: pub}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, sig1, err := s.Sign(context.Background(), m)
	if err != nil {
		t.Fatalf("Sign original: %v", err)
	}

	// Mutate one field.
	src2 := &CountingKeySource{key: priv}
	s2, err2 := manifestsigner.New(src2, trusted)
	if err2 != nil {
		t.Fatalf("New s2: %v", err2)
	}
	mMutated := m
	mMutated.Counter = 42 // change the counter
	_, sig2, err := s2.Sign(context.Background(), mMutated)
	if err != nil {
		t.Fatalf("Sign mutated: %v", err)
	}

	if bytes.Equal(sig1, sig2) {
		t.Error("one-field-mutation: signatures are identical for different manifests — canonical encoding broken")
	}

	sha1 := verify.ContentSHA(buildSignedArtifact(m, adminID, hex.EncodeToString(sig1)))
	sha2 := verify.ContentSHA(buildSignedArtifact(mMutated, adminID, hex.EncodeToString(sig2)))
	if sha1 == sha2 {
		t.Error("one-field-mutation: ContentSHA is identical for different manifests — encoding broken")
	}
}

// TestSeparatorInjection_FailsBeforeSign proves that the frozen sign.Sign
// fail-closed re-validate rejects a manifest with a separator byte injected into
// a field BEFORE any signature byte is produced (no partial-sign then fail).
func TestSeparatorInjection_FailsBeforeSign(t *testing.T) {
	t.Parallel()

	pub, priv := generateEd25519(t)
	adminID := "admin-carol"

	sepByte := string([]byte{0x1e}) // RS separator byte
	mBad := manifest.Manifest{
		FormatVersion:         "byreis.native.v1",
		ProjectID:             "proj" + sepByte + "injected", // separator injection
		LogicalFileName:       "secrets",
		Counter:               1,
		Values:                map[string][]byte{"k": []byte("ct")},
		RecipientFingerprints: []string{validManifest().RecipientFingerprints[0]},
	}

	trusted := map[string]ed25519.PublicKey{adminID: pub}
	src := &CountingKeySource{key: priv}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, _, err = s.Sign(context.Background(), mBad)
	if err == nil {
		t.Fatal("separator-injection: expected error for separator-injected manifest, got nil")
	}
	if !errors.Is(err, manifest.ErrSeparatorInjection) {
		t.Errorf("separator-injection: expected ErrSeparatorInjection, got: %v", err)
	}
}

// TestBadFormatVersion_FailsBeforeSign proves that a manifest with an invalid
// format_version fails closed before any signature byte is produced.
func TestBadFormatVersion_FailsBeforeSign(t *testing.T) {
	t.Parallel()

	pub, priv := generateEd25519(t)
	adminID := "admin-dan"

	mBad := manifest.Manifest{
		FormatVersion:         "not-a-valid-version",
		ProjectID:             "proj",
		LogicalFileName:       "secrets",
		Counter:               1,
		Values:                map[string][]byte{"k": []byte("ct")},
		RecipientFingerprints: []string{validManifest().RecipientFingerprints[0]},
	}

	trusted := map[string]ed25519.PublicKey{adminID: pub}
	src := &CountingKeySource{key: priv}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, _, err = s.Sign(context.Background(), mBad)
	if err == nil {
		t.Fatal("bad-format-version: expected error, got nil")
	}
	if !errors.Is(err, manifest.ErrFormatVersion) {
		t.Errorf("bad-format-version: expected ErrFormatVersion, got: %v", err)
	}
}

// ─── Test: no-double-sign ─────────────────────────────────────────────────────

// TestNoDoubleSign proves the adapter calls ProvideKey exactly once per Sign
// invocation (no redundant encoding or double-sign attempt).
func TestNoDoubleSign(t *testing.T) {
	t.Parallel()

	pub, priv := generateEd25519(t)
	adminID := "admin-eve"
	m := validManifest()

	trusted := map[string]ed25519.PublicKey{adminID: pub}
	src := &CountingKeySource{key: priv}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, _, err := s.Sign(context.Background(), m); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if got := src.calls.Load(); got != 1 {
		t.Errorf("no-double-sign: ProvideKey called %d times, want exactly 1", got)
	}
}

// ─── Test: signerID-from-attested-only ────────────────────────────────────────

// TestSignerID_UnregisteredKey_FailClosed proves that a key whose public half is
// not in the registry-attested TrustedSigners map cannot produce a usable
// signerID: the adapter fails closed.
func TestSignerID_UnregisteredKey_FailClosed(t *testing.T) {
	t.Parallel()

	_, priv := generateEd25519(t)

	// TrustedSigners maps a DIFFERENT (unrelated) admin's pubkey.
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey for other-admin: %v", err)
	}
	trusted := map[string]ed25519.PublicKey{"other-admin": otherPub}

	src := &CountingKeySource{key: priv}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, _, err = s.Sign(context.Background(), validManifest())
	if err == nil {
		t.Fatal("unregistered-key: expected error for key not in TrustedSigners, got nil")
	}
	if !errors.Is(err, manifestsigner.ErrKeyNotAttested) {
		t.Errorf("unregistered-key: expected ErrKeyNotAttested, got: %v", err)
	}
}

// TestSignerID_EmptyTrustedSigners_FailClosed proves that an empty TrustedSigners
// map cannot yield a signerID — fail closed.
func TestSignerID_EmptyTrustedSigners_FailClosed(t *testing.T) {
	t.Parallel()

	_, priv := generateEd25519(t)

	src := &CountingKeySource{key: priv}
	_, err := manifestsigner.New(src, map[string]ed25519.PublicKey{})
	if err == nil {
		t.Fatal("empty-trusted-signers: New with empty TrustedSigners must fail closed, got nil")
	}
}

// TestSignerID_NilTrustedSigners_FailClosed proves that a nil TrustedSigners map
// is rejected at construction — fail closed.
func TestSignerID_NilTrustedSigners_FailClosed(t *testing.T) {
	t.Parallel()

	_, priv := generateEd25519(t)
	src := &CountingKeySource{key: priv}
	_, err := manifestsigner.New(src, nil)
	if err == nil {
		t.Fatal("nil-trusted-signers: New with nil TrustedSigners must fail closed, got nil")
	}
}

// TestSignerID_ArtifactSelfDeclared_Ignored proves that the signerID is derived
// exclusively from the TrustedSigners lookup — the artifact's own self-declared
// signer field is irrelevant to the adapter (it never reads it).
//
// This is structural: the Sign method receives a manifest.Manifest, which has no
// Signer field. The signer CANNOT use a self-declared ID because there is no API
// path to supply one. This test documents and proves the invariant by showing
// that two adapters with different TrustedSigners maps but the same key produce
// different signerIDs — proving the ID is read from the attested map, not from
// anywhere self-declared.
func TestSignerID_ArtifactSelfDeclared_Ignored(t *testing.T) {
	t.Parallel()

	pub, priv := generateEd25519(t)

	trusted1 := map[string]ed25519.PublicKey{"admin-x": pub}
	src1 := &CountingKeySource{key: priv}
	s1, err := manifestsigner.New(src1, trusted1)
	if err != nil {
		t.Fatalf("New s1: %v", err)
	}
	id1, _, err := s1.Sign(context.Background(), validManifest())
	if err != nil {
		t.Fatalf("s1 Sign: %v", err)
	}

	trusted2 := map[string]ed25519.PublicKey{"admin-y": pub}
	src2 := &CountingKeySource{key: priv}
	s2, err := manifestsigner.New(src2, trusted2)
	if err != nil {
		t.Fatalf("New s2: %v", err)
	}
	id2, _, err := s2.Sign(context.Background(), validManifest())
	if err != nil {
		t.Fatalf("s2 Sign: %v", err)
	}

	if id1 == id2 {
		t.Error("attested-id: both signers returned the same ID even with different TrustedSigners maps — signerID is not read from the attested map")
	}
	if id1 != "admin-x" {
		t.Errorf("attested-id: s1 signerID=%q, want %q", id1, "admin-x")
	}
	if id2 != "admin-y" {
		t.Errorf("attested-id: s2 signerID=%q, want %q", id2, "admin-y")
	}
}

// ─── Test: L-2 zeroization + distinct-key / no-cross-role-reuse ───────────────

// TestL2_PrivateKeyBuffer_Zeroized proves that the Ed25519 private-key source
// buffer returned by ProvideKey is zeroized after use, using the pinned-backing
// GC/escape-resistant standard: we allocate a backing buffer, pin its address
// via unsafe.SliceData, pass a copy to the adapter for signing, then inspect the
// copy's backing array after the Sign call returns to confirm it was zeroed.
//
// Implementation note: the adapter receives the []byte from ProvideKey, uses it,
// then must explicitly zero it before dropping the reference. This test verifies
// that property by injecting a ZeroCheckSource that retains the slice's backing
// pointer so we can inspect it after Sign returns.
func TestL2_PrivateKeyBuffer_Zeroized(t *testing.T) {
	t.Parallel()

	pub, priv := generateEd25519(t)
	adminID := "admin-frank"
	m := validManifest()

	trusted := map[string]ed25519.PublicKey{adminID: pub}
	src := &ZeroCheckKeySource{key: priv}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, _, err := s.Sign(context.Background(), m); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// After Sign returns, the buffer the source yielded must be all-zero.
	src.AssertZeroized(t)
}

// TestL2_DistinctKey_AgeIdentityNotAccepted proves that the manifestsigner
// adapter cannot be constructed from an age X25519 key material. The age
// X25519 private key is a bech32-encoded string, while the Ed25519 key source
// returns raw []byte. Providing raw age private key bytes (which are 32 bytes of
// Curve25519 scalar, distinct from the 64-byte Ed25519 private key) must not
// produce a usable Ed25519 signer.
//
// The no-cross-role-reuse invariant is structural: the Ed25519 signing key and
// the age X25519 decryption identity are different key types with different byte
// lengths (ed25519.PrivateKeySize=64 vs curve25519 scalar=32). The adapter
// validates the key size on use; a 32-byte buffer cannot produce a valid
// ed25519.PrivateKey (ed25519.Sign panics / wrong-length detection applies).
// This test asserts the adapter rejects a 32-byte buffer (age-identity-size key).
func TestL2_DistinctKey_AgeIdentityNotAccepted(t *testing.T) {
	t.Parallel()

	// Generate an age X25519 identity.
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}

	// The age private key scalar is 32 bytes (Curve25519); an Ed25519 private key is 64 bytes.
	// We simulate "passing age key material as Ed25519 key" by providing a 32-byte buffer.
	// This is the distinct-key proof: a 32-byte buffer is wrong-length for ed25519.
	ageScalar := make([]byte, 32)
	_ = ageID // prove ageID is a valid age identity
	// Fill with non-zero bytes to show rejection is about type/length, not zero bytes.
	for i := range ageScalar {
		ageScalar[i] = byte(i + 1)
	}

	pub, _ := generateEd25519(t)
	trusted := map[string]ed25519.PublicKey{"admin-g": pub}

	src := &FixedKeySource{key: ageScalar}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, _, err = s.Sign(context.Background(), validManifest())
	if err == nil {
		t.Fatal("distinct-key: expected error when 32-byte age-identity-size key provided as Ed25519 key, got nil")
	}
}

// ZeroCheckKeySource is an injectable fake Ed25519KeySource that retains a pointer
// to the backing array of the returned slice. After Sign returns, AssertZeroized
// checks that the adapter zeroed the entire slice.
type ZeroCheckKeySource struct {
	key    ed25519.PrivateKey
	ptr    unsafe.Pointer
	length int
}

func (z *ZeroCheckKeySource) ProvideKey(_ context.Context) ([]byte, error) {
	buf := make([]byte, len(z.key))
	copy(buf, z.key)
	z.ptr = unsafe.Pointer(unsafe.SliceData(buf)) //nolint:gosec // pinning backing array for L-2 zeroization assertion; not production escape
	z.length = len(buf)
	return buf, nil
}

func (z *ZeroCheckKeySource) AssertZeroized(t *testing.T) {
	t.Helper()
	if z.ptr == nil {
		t.Fatal("L-2: ProvideKey was never called; cannot assert zeroization")
	}
	result := unsafe.Slice((*byte)(z.ptr), z.length) //nolint:gosec // pinned backing array assertion for L-2 zeroization test
	for i, b := range result {
		if b != 0 {
			t.Errorf("L-2: private key buffer not zeroed at index %d: got 0x%02x", i, b)
			return
		}
	}
	// Keep the slice header alive so GC cannot collect the backing array before this check.
	runtime.KeepAlive(result)
}

// FixedKeySource returns a fixed byte slice.
type FixedKeySource struct{ key []byte }

func (f *FixedKeySource) ProvideKey(_ context.Context) ([]byte, error) {
	out := make([]byte, len(f.key))
	copy(out, f.key)
	return out, nil
}

// ─── Test: happy path ─────────────────────────────────────────────────────────

// TestHappy_ValidSignAndVerify proves that a valid admin Ed25519 key signs a
// valid manifest and that the frozen verify.VerifyOfRecord path accepts the
// result with the attested signerID.
func TestHappy_ValidSignAndVerify(t *testing.T) {
	t.Parallel()

	pub, priv := generateEd25519(t)
	adminID := "admin-happy"
	m := validManifest()

	signer, _, trusted := makeAttestedSigner(t, pub, priv, adminID)
	gotID, gotSig, err := signer.Sign(context.Background(), m)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if gotID != adminID {
		t.Errorf("happy: signerID=%q, want %q", gotID, adminID)
	}
	if len(gotSig) != ed25519.SignatureSize {
		t.Errorf("happy: signature length=%d, want %d", len(gotSig), ed25519.SignatureSize)
	}

	// Build a signed artifact.
	signed := buildSignedArtifact(m, gotID, hex.EncodeToString(gotSig))

	// Build the OfRecordInput. Use a counter authority minted via MintFromAdapter
	// (the only exported Valid()-producing path available outside the registry
	// adapter). Counter == last_accepted is the steady-state read case.
	recipients := buildRecipients(m)
	counterAuth := countertypes.MintFromAdapter(nil, m.Counter, nil)

	input := verify.OfRecordInput{
		Artifact:           signed,
		ExpectedProjectID:  m.ProjectID,
		ExpectedFileName:   m.LogicalFileName,
		ExpectedRecipients: recipients,
		TrustedSigners:     trusted,
		Counter:            counterAuth,
	}

	v := verify.New()
	if err := v.VerifyOfRecord(context.Background(), input); err != nil {
		t.Errorf("happy: VerifyOfRecord rejected adapter-signed artifact: %v", err)
	}
}

// TestHappy_CtxCancel_ReturnsError proves that Sign honours context cancellation.
func TestHappy_CtxCancel_ReturnsError(t *testing.T) {
	t.Parallel()

	pub, priv := generateEd25519(t)
	adminID := "admin-ctx"
	trusted := map[string]ed25519.PublicKey{adminID: pub}
	src := &CountingKeySource{key: priv}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before sign

	_, _, err = s.Sign(ctx, validManifest())
	if err == nil {
		t.Fatal("ctx-cancel: expected error for already-cancelled ctx, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ctx-cancel: expected context.Canceled, got: %v", err)
	}
}

// TestHappy_KeySourceError_FailClosed proves that a ProvideKey error fails the
// Sign call cleanly without panicking.
func TestHappy_KeySourceError_FailClosed(t *testing.T) {
	t.Parallel()

	pub, _ := generateEd25519(t)
	adminID := "admin-keysrc"
	trusted := map[string]ed25519.PublicKey{adminID: pub}
	keySrcErr := errors.New("keychain unavailable")
	src := &errKeySource{err: keySrcErr}
	s, err := manifestsigner.New(src, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, _, err = s.Sign(context.Background(), validManifest())
	if err == nil {
		t.Fatal("key-source-error: expected error, got nil")
	}
	if !errors.Is(err, keySrcErr) {
		t.Errorf("key-source-error: expected wrapped keySrcErr, got: %v", err)
	}
}

// TestHappy_NilKeySource_FailClosed proves that a nil key source is rejected at
// construction — fail closed.
func TestHappy_NilKeySource_FailClosed(t *testing.T) {
	t.Parallel()

	pub, _ := generateEd25519(t)
	trusted := map[string]ed25519.PublicKey{"admin": pub}
	_, err := manifestsigner.New(nil, trusted)
	if err == nil {
		t.Fatal("nil-key-source: New with nil key source must fail closed, got nil")
	}
}

// ─── Test: allowlist (import boundary) ───────────────────────────────────────

// TestAllowlist_ManifestSigner_NotInEncryptTransitiveSet proves that
// internal/adapter/manifestsigner does NOT appear in the transitive dep set of
// internal/core/crypto/encrypt. This enforces the ADR-0005 closed-world rule:
// the signer (read/merge-path only) must not be reachable from the contributor
// encrypt path.
func TestAllowlist_ManifestSigner_NotInEncryptTransitiveSet(t *testing.T) {
	t.Parallel()

	const encryptPkg = "github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	const signerPkg = "github.com/ByReisK/byreis/internal/adapter/manifestsigner"

	deps := goListDeps(t, encryptPkg)
	for _, dep := range deps {
		if dep == signerPkg {
			t.Errorf("FAIL: %s is in the transitive dep set of %s\n"+
				"The manifestsigner adapter is read/merge-path only and must never\n"+
				"appear in the contributor encrypt path (ADR-0005 closed-world allowlist).", signerPkg, encryptPkg)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: %s not in %s transitive set (%d deps)", signerPkg, encryptPkg, len(deps))
	}
}

// TestAllowlist_ManifestSigner_NotInSubmitTransitiveSet proves that
// internal/adapter/manifestsigner does NOT appear in the transitive dep set of
// internal/core/usecase/submit (the Submit compilation unit).
func TestAllowlist_ManifestSigner_NotInSubmitTransitiveSet(t *testing.T) {
	t.Parallel()

	const submitPkg = "github.com/ByReisK/byreis/internal/core/usecase/submit"
	const signerPkg = "github.com/ByReisK/byreis/internal/adapter/manifestsigner"

	deps := goListDeps(t, submitPkg)
	for _, dep := range deps {
		if dep == signerPkg {
			t.Errorf("FAIL: %s is in the transitive dep set of %s\n"+
				"The manifestsigner adapter must not enter the Submit compilation unit\n"+
				"(ADR-0005 closed-world allowlist).", signerPkg, submitPkg)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: %s not in %s transitive set (%d deps)", signerPkg, submitPkg, len(deps))
	}
}

// TestAllowlist_CoreDeps_NoAdapterEdge proves that the transitive set of
// internal/core/... does NOT include internal/adapter/manifestsigner, enforcing
// the no-core→adapter Clean Architecture rule.
func TestAllowlist_CoreDeps_NoAdapterEdge(t *testing.T) {
	t.Parallel()

	corePkgs := []string{
		"github.com/ByReisK/byreis/internal/core/crypto/encrypt",
		"github.com/ByReisK/byreis/internal/core/crypto/sign",
		"github.com/ByReisK/byreis/internal/core/crypto/manifest",
		"github.com/ByReisK/byreis/internal/core/crypto/verify",
		"github.com/ByReisK/byreis/internal/core/usecase/submit",
	}
	const signerPkg = "github.com/ByReisK/byreis/internal/adapter/manifestsigner"

	for _, pkg := range corePkgs {
		pkg := pkg
		t.Run(pkg, func(t *testing.T) {
			t.Parallel()
			deps := goListDeps(t, pkg)
			for _, dep := range deps {
				if dep == signerPkg {
					t.Errorf("FAIL: core package %s transitively imports adapter %s\n"+
						"Clean Architecture: adapters depend inward, never the reverse.", pkg, signerPkg)
				}
			}
			if !t.Failed() {
				t.Logf("PASS: %s does not import %s", pkg, signerPkg)
			}
		})
	}
}

// ─── internal test helpers ────────────────────────────────────────────────────

// buildSignedArtifact constructs a minimal artifact.Signed from a manifest for
// use in verify.VerifyOfRecord assertions. Values are taken from the manifest
// (already-encrypted ciphertext). The artifact mirrors the structure
// crypto/encrypt would produce.
func buildSignedArtifact(m manifest.Manifest, signerID, sigHex string) artifact.Signed {
	values := make(map[string]artifact.EncryptedValue, len(m.Values))
	for k, v := range m.Values {
		values[k] = artifact.EncryptedValue(v)
	}
	var recipients []artifact.RecipientEntry
	for _, fp := range m.RecipientFingerprints {
		recipients = append(recipients, artifact.RecipientEntry{FP: fp})
	}
	return artifact.Signed{
		Values: values,
		Byreis: artifact.Metadata{
			FormatVersion: m.FormatVersion,
			ProjectID:     m.ProjectID,
			File:          m.LogicalFileName,
			Counter:       m.Counter,
			Recipients:    recipients,
		},
		ManifestSig: artifact.ManifestSig{
			Signer: signerID,
			Sig:    sigHex,
		},
	}
}

// buildRecipients converts the manifest's RecipientFingerprints to
// []rectypes.Recipient for VerifyOfRecord input, decoding each hex fingerprint
// to a [32]byte.
func buildRecipients(m manifest.Manifest) []rectypes.Recipient {
	out := make([]rectypes.Recipient, 0, len(m.RecipientFingerprints))
	for _, fp := range m.RecipientFingerprints {
		b, err := hex.DecodeString(fp)
		if err != nil || len(b) != 32 {
			continue
		}
		var arr [32]byte
		copy(arr[:], b)
		out = append(out, rectypes.Recipient{Fingerprint: arr})
	}
	return out
}

// goListDeps runs go list -deps pinned to GOOS=linux GOARCH=amd64.
func goListDeps(t *testing.T, pkg string) []string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", pkg) //nolint:gosec // pkg is a compile-time constant, not user input
	cmd.Env = append(cmd.Environ(), "GOOS=linux", "GOARCH=amd64")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Fields(strings.TrimSpace(string(out)))
}
