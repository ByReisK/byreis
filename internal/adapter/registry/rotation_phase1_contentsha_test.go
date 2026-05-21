package registry

// rotation_phase1_contentsha_test.go — byte-equivalence assertion between the
// adapter-local signedArtifactContentSHA replica and the canonical
// verify.ContentSHA implementation in internal/core/crypto/verify.
//
// WHY this file (package registry, internal test) CAN import verify:
//
// The allowlist gate TestRegistryAdapter_DoesNotImportVerify (allowlist_test.go)
// uses `go list -deps github.com/ByReisK/byreis/internal/adapter/registry` which
// resolves the SHIPPED (non-test) compilation unit only. Test files compiled into
// the _test binary are excluded from that graph. This file is therefore free to
// import internal/core/crypto/verify without violating the allowlist gate.
//
// The signedArtifactContentSHA function (rotation_phase1.go) is a local replica
// of verify.ContentSHA — the adapter cannot import verify in its production code
// (allowlist gate), but needs an identical SHA for the counter-authority CAS
// pinning. This test asserts byte-for-byte identity of the two implementations
// across representative fixtures so any divergence is caught immediately.
//
// A divergence in ANY fixture is a build-blocker: the counter-authority CAS
// would pin the wrong SHA, silently breaking the anti-rollback invariant.
//
// Internal IDs (GAP 3) ARE allowed in _test.go per CLAUDE.md code comment hygiene.

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
)

// TestSignedArtifactContentSHA_ByteEquivalenceWithVerifyContentSHA asserts
// that the adapter-local replica signedArtifactContentSHA returns the same
// bytes as verify.ContentSHA for every fixture variant.
//
// Fixture variants cover:
//   - empty values map + empty sig (nil-like sig fallback path)
//   - single-value + non-empty sig hex
//   - multi-value + multi-recipient + non-empty sig hex
//   - malformed sig hex (odd-length, non-hex chars) — both functions must
//     produce the same fallback value (both treat sig=nil on decode failure)
//   - non-zero epoch + empty recipients
//
// Any divergence means the counter-authority CAS would compute a different
// SHA than the verifier. Fail immediately with a diff.
func TestSignedArtifactContentSHA_ByteEquivalenceWithVerifyContentSHA(t *testing.T) {
	t.Parallel()

	fixtures := []struct {
		name   string
		signed artifact.Signed
	}{
		{
			name: "empty-values-empty-sig",
			signed: artifact.Signed{
				Values: map[string]artifact.EncryptedValue{},
				Byreis: artifact.Metadata{
					FormatVersion: "byreis.native.v1",
					ProjectID:     "proj",
					File:          "prod",
					Counter:       0,
					Recipients:    nil,
				},
				ManifestSig: artifact.ManifestSig{Signer: "", Sig: ""},
			},
		},
		{
			name: "single-value-valid-sig",
			signed: artifact.Signed{
				Values: map[string]artifact.EncryptedValue{
					"API_KEY": artifact.EncryptedValue("age1-armored-ciphertext-placeholder"),
				},
				Byreis: artifact.Metadata{
					FormatVersion: "byreis.native.v1",
					ProjectID:     "myapp",
					File:          "prod",
					Counter:       1,
					Recipients: []artifact.RecipientEntry{
						{FP: hex.EncodeToString(contentSHATestSHA256("age1recipient"))},
					},
				},
				ManifestSig: artifact.ManifestSig{
					Signer: "admin-1",
					// 64 zero bytes as a well-formed but non-real sig.
					Sig: hex.EncodeToString(make([]byte, 64)),
				},
			},
		},
		{
			name: "multi-value-multi-recipient",
			signed: artifact.Signed{
				Values: map[string]artifact.EncryptedValue{
					"DB_PASS":  artifact.EncryptedValue("age1-ct-for-db"),
					"API_KEY":  artifact.EncryptedValue("age1-ct-for-api"),
					"SMTP_KEY": artifact.EncryptedValue("age1-ct-for-smtp"),
				},
				Byreis: artifact.Metadata{
					FormatVersion: "byreis.native.v1",
					ProjectID:     "bigapp",
					File:          "secrets",
					Counter:       7,
					Recipients: []artifact.RecipientEntry{
						{FP: hex.EncodeToString(contentSHATestSHA256("recip-a"))},
						{FP: hex.EncodeToString(contentSHATestSHA256("recip-b"))},
					},
				},
				ManifestSig: artifact.ManifestSig{
					Signer: "admin-2",
					Sig:    hex.EncodeToString(contentSHATestFill(64, 0xab)),
				},
			},
		},
		{
			name: "malformed-sig-hex-odd-length",
			// Both implementations decode sig via hex.DecodeString; on error they
			// set sig=nil and continue. The resulting SHA covers the manifest stream
			// only (followed by 0x1f separator + 0 bytes).
			signed: artifact.Signed{
				Values: map[string]artifact.EncryptedValue{
					"KEY": artifact.EncryptedValue("somevalue"),
				},
				Byreis: artifact.Metadata{
					FormatVersion: "byreis.native.v1",
					ProjectID:     "p",
					File:          "f",
					Counter:       2,
				},
				ManifestSig: artifact.ManifestSig{Signer: "s", Sig: "oddlength1"},
			},
		},
		{
			name: "epoch-5-no-recipients",
			signed: artifact.Signed{
				Values: map[string]artifact.EncryptedValue{
					"TOKEN": artifact.EncryptedValue("age1armored"),
				},
				Byreis: artifact.Metadata{
					FormatVersion: "byreis.native.v1",
					ProjectID:     "proj2",
					File:          "prod2",
					Counter:       5,
					Recipients:    []artifact.RecipientEntry{},
				},
				ManifestSig: artifact.ManifestSig{
					Signer: "admin-3",
					Sig:    hex.EncodeToString(contentSHATestFill(64, 0x77)),
				},
			},
		},
		{
			name: "high-counter-many-recipients",
			signed: artifact.Signed{
				Values: map[string]artifact.EncryptedValue{
					"S1": artifact.EncryptedValue("ct1"),
					"S2": artifact.EncryptedValue("ct2"),
				},
				Byreis: artifact.Metadata{
					FormatVersion: "byreis.native.v1",
					ProjectID:     "enterprise",
					File:          "prod-secrets",
					Counter:       999,
					Recipients: []artifact.RecipientEntry{
						{FP: hex.EncodeToString(contentSHATestSHA256("r1"))},
						{FP: hex.EncodeToString(contentSHATestSHA256("r2"))},
						{FP: hex.EncodeToString(contentSHATestSHA256("r3"))},
						{FP: hex.EncodeToString(contentSHATestSHA256("r4"))},
					},
				},
				ManifestSig: artifact.ManifestSig{
					Signer: "admin-4",
					Sig:    hex.EncodeToString(contentSHATestFill(64, 0x13)),
				},
			},
		},
	}

	for _, tc := range fixtures {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := verify.ContentSHA(tc.signed)
			got := signedArtifactContentSHA(tc.signed)

			if got != want {
				t.Errorf("signedArtifactContentSHA != verify.ContentSHA for fixture %q:\n"+
					"  adapter replica: %q\n"+
					"  verify package:  %q\n"+
					"The adapter-local replica has diverged from verify.ContentSHA.\n"+
					"Update signedArtifactContentSHA in rotation_phase1.go to match exactly.",
					tc.name, got, want)
			}

			// Both must be either empty (encoding failure) or 64-char hex SHA-256.
			if got != "" && len(got) != 64 {
				t.Errorf("adapter replica SHA length %d (want 64 or empty): %q", len(got), got)
			}
			if want != "" && len(want) != 64 {
				t.Errorf("verify.ContentSHA length %d (want 64 or empty): %q", len(want), want)
			}
		})
	}
}

// contentSHATestSHA256 returns the SHA-256 hash of s as a byte slice.
// Used to produce stable fixture fingerprint bytes.
func contentSHATestSHA256(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// contentSHATestFill returns a slice of length n with every byte set to b.
// Used to produce stable fixture sig bytes without cryptographic randomness.
func contentSHATestFill(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
