//go:build testhook

// These tests require the `testhook` build tag so they can construct a Valid()
// countertypes.CounterAuthority via countertypes.NewForTest, which itself
// requires the unexported *testOnlyWitness minted by countertypes.ForTestWitness
// (caWitness below). Production builds never set this tag; even if one did,
// verify/mode/usecase/cli cannot name the witness type and so cannot call
// NewForTest. The shipped verify path can still only CONSUME an opaque
// authority produced by the registry adapter (proven by the no-tag
// visibility_boundary_test.go assertions).
package verify_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

const (
	signerID = "admin-1"
	projID   = "proj-x"
	fileName = "prod"
)

type fixture struct {
	signed     artifact.Signed
	recipients []rectypes.Recipient
	trusted    map[string]ed25519.PublicKey
	priv       ed25519.PrivateKey
}

func mkRecipient(t *testing.T) rectypes.Recipient {
	t.Helper()
	// A deterministic-enough pseudo age key string is sufficient: verify never
	// parses it; it only fingerprints it. Use a valid-shaped placeholder.
	pub := "age1" + hex.EncodeToString([]byte(t.Name()))[:50]
	return rectypes.Recipient{
		Label:       "r",
		AgePubKey:   pub,
		Fingerprint: rectypes.Fingerprint(sha256.Sum256([]byte(pub))),
	}
}

// buildSigned produces a real encrypted+signed artifact for (projID,fileName)
// at the given counter, signed by a fresh admin key.
func buildSigned(t *testing.T, counter uint64, vals map[string]string) fixture {
	t.Helper()
	// Use real age recipients so encrypt produces real ciphertext.
	r1 := realRecipient(t)
	r2 := realRecipient(t)
	u, err := encrypt.New(encrypt.NewX25519Parser()).Encrypt(context.Background(), encrypt.EncryptInput{
		ProjectID: projID, LogicalFileName: fileName, Counter: counter,
		Recipients: []rectypes.Recipient{r1, r2}, Values: vals,
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	man := manifestFromUnsigned(u)
	sig, err := sign.Sign(priv, man)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	s := artifact.Signed{
		Values: u.Values,
		Byreis: u.Byreis,
		ManifestSig: artifact.ManifestSig{
			Signer: signerID,
			Sig:    hex.EncodeToString(sig),
		},
	}
	return fixture{
		signed:     s,
		recipients: []rectypes.Recipient{r1, r2},
		trusted:    map[string]ed25519.PublicKey{signerID: pub},
		priv:       priv,
	}
}

func manifestFromUnsigned(u artifact.Unsigned) manifest.Manifest {
	m := manifest.Manifest{
		FormatVersion:   u.Byreis.FormatVersion,
		ProjectID:       u.Byreis.ProjectID,
		LogicalFileName: u.Byreis.File,
		Counter:         u.Byreis.Counter,
		Values:          map[string][]byte{},
	}
	for k, v := range u.Values {
		m.Values[k] = []byte(v)
	}
	for _, re := range u.Byreis.Recipients {
		m.RecipientFingerprints = append(m.RecipientFingerprints, re.FP)
	}
	return m
}

func ofRecordInput(f fixture, ca countertypes.CounterAuthority) verify.OfRecordInput {
	return verify.OfRecordInput{
		Artifact:           f.signed,
		ExpectedProjectID:  projID,
		ExpectedFileName:   fileName,
		ExpectedRecipients: f.recipients,
		TrustedSigners:     f.trusted,
		Counter:            ca,
	}
}

// caWitness is the unexported test capability token. It is produced once and
// reused: the witness type is unnameable outside countertypes, so this is the
// only way verify_test can reach a Valid() CounterAuthority — and only because
// this file is compiled under -tags testhook (never in a shipped build).
var caWitness = countertypes.ForTestWitness()

// steadyState returns a CounterAuthority where sc == la (committed live read).
func steadyState(la uint64) countertypes.CounterAuthority {
	return countertypes.NewForTest(caWitness, la, nil)
}

func TestVerifyOfRecord_HappyPath_SteadyState(t *testing.T) {
	f := buildSigned(t, 5, map[string]string{"DB": "x", "API": "y"})
	if err := verify.New().VerifyOfRecord(context.Background(),
		ofRecordInput(f, steadyState(5))); err != nil {
		t.Fatalf("VerifyOfRecord steady-state happy path: %v", err)
	}
}

func TestVerifyOfRecord_OrderedNegatives(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(in *verify.OfRecordInput)
		wantErr error
	}{
		{"unsupported format version", func(in *verify.OfRecordInput) {
			in.Artifact.Byreis.FormatVersion = "sops.v1"
		}, verify.ErrFormatVersion},
		{"format version separator", func(in *verify.OfRecordInput) {
			in.Artifact.Byreis.FormatVersion = "byreis.native.v\x1f9"
		}, verify.ErrFormatVersion},
		{"cross-project transplant", func(in *verify.OfRecordInput) {
			in.ExpectedProjectID = "other-proj"
		}, verify.ErrIdentityMismatch},
		{"cross-file transplant", func(in *verify.OfRecordInput) {
			in.ExpectedFileName = "staging"
		}, verify.ErrIdentityMismatch},
		{"recipient strip", func(in *verify.OfRecordInput) {
			in.ExpectedRecipients = in.ExpectedRecipients[:1]
		}, verify.ErrRecipientMismatch},
		{"wrong expected recipient", func(in *verify.OfRecordInput) {
			in.ExpectedRecipients = []rectypes.Recipient{mkRecipient(t), mkRecipient(t)}
		}, verify.ErrRecipientMismatch},
		// A ciphertext tamper changes the recomputed canonical stream, so the
		// Ed25519 signature (over the original stream) fails — fail-closed at
		// step 10. ErrSignatureInvalid is the correct rejection here.
		{"single-byte ciphertext tamper", func(in *verify.OfRecordInput) {
			for k, v := range in.Artifact.Values {
				b := []byte(v)
				b[len(b)/2] ^= 0x01
				in.Artifact.Values[k] = artifact.EncryptedValue(b)
				break
			}
		}, verify.ErrSignatureInvalid},
		// Deleting a key changes the signed key set → recomputed stream differs
		// → signature fails. Fail-closed rejection.
		{"key deleted from values", func(in *verify.OfRecordInput) {
			for k := range in.Artifact.Values {
				delete(in.Artifact.Values, k)
				break
			}
		}, verify.ErrSignatureInvalid},
		// Ciphertext-swap between two keys: the per-key digest binds name‖ct,
		// so both digests change → recomputed stream differs → signature fails.
		{"ciphertext swap between keys", func(in *verify.OfRecordInput) {
			var ks []string
			for k := range in.Artifact.Values {
				ks = append(ks, k)
			}
			if len(ks) >= 2 {
				in.Artifact.Values[ks[0]], in.Artifact.Values[ks[1]] =
					in.Artifact.Values[ks[1]], in.Artifact.Values[ks[0]]
			}
		}, verify.ErrSignatureInvalid},
		{"unsigned artifact presented", func(in *verify.OfRecordInput) {
			in.Artifact.ManifestSig = artifact.ManifestSig{}
		}, verify.ErrUnsigned},
		{"no trusted signer", func(in *verify.OfRecordInput) {
			in.TrustedSigners = map[string]ed25519.PublicKey{}
		}, verify.ErrNoTrustedSigner},
		{"signer id not in trusted set", func(in *verify.OfRecordInput) {
			in.Artifact.ManifestSig.Signer = "unknown-admin"
		}, verify.ErrNoTrustedSigner},
		{"forged signature", func(in *verify.OfRecordInput) {
			in.Artifact.ManifestSig.Sig = hex.EncodeToString(make([]byte, 64))
		}, verify.ErrSignatureInvalid},
		{"forged signer key", func(in *verify.OfRecordInput) {
			otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
			in.TrustedSigners[signerID] = otherPub
		}, verify.ErrSignatureInvalid},
		{"invalid (zero-value) counter authority", func(in *verify.OfRecordInput) {
			in.Counter = countertypes.CounterAuthority{}
		}, countertypes.ErrCounterReconcile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := buildSigned(t, 5, map[string]string{"DB": "x", "API": "y"})
			in := ofRecordInput(f, steadyState(5))
			tc.mutate(&in)
			err := verify.New().VerifyOfRecord(context.Background(), in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

// contentSHA mirrors the §3.5 preimage over the exact artifact bytes verify
// hashes. The test must derive it the same way verify does: over the
// deterministic serialized signed body. We expose verify.ContentSHA for that.
func TestVerifyOfRecord_CounterDecisionTable(t *testing.T) {
	// Build a fixed artifact; its content SHA is what the pending intent must
	// record for the OK-resume row.
	f := buildSigned(t, 6, map[string]string{"DB": "x"})
	sha := verify.ContentSHA(f.signed)

	pend := func(pc uint64, target string) *countertypes.PendingBump {
		return &countertypes.PendingBump{PendingCounter: pc, TargetArtifactSHA: target, TargetPR: "pr/9"}
	}

	cases := []struct {
		name    string
		ca      countertypes.CounterAuthority
		wantErr error // nil = expect success
	}{
		{
			name:    "sc < la replay",
			ca:      countertypes.NewForTest(caWitness, 10, nil), // sc=6 < la=10
			wantErr: countertypes.ErrReplay,
		},
		{
			name:    "sc == la steady-state OK",
			ca:      countertypes.NewForTest(caWitness, 6, nil),
			wantErr: nil,
		},
		{
			name:    "sc == la+1 with matching pending+SHA -> OK resume",
			ca:      countertypes.NewForTest(caWitness, 5, pend(6, sha)),
			wantErr: nil,
		},
		{
			name:    "sc == la+1 pending SHA mismatch -> reconcile",
			ca:      countertypes.NewForTest(caWitness, 5, pend(6, "deadbeef")),
			wantErr: countertypes.ErrCounterReconcile,
		},
		{
			name:    "sc == la+1 pending nil (merged-but-unbumped, intent lost) -> reconcile NOT replay",
			ca:      countertypes.NewForTest(caWitness, 5, nil),
			wantErr: countertypes.ErrCounterReconcile,
		},
		{
			name:    "sc == la+1 pending counter mismatch -> reconcile",
			ca:      countertypes.NewForTest(caWitness, 5, pend(99, sha)),
			wantErr: countertypes.ErrCounterReconcile,
		},
		{
			name:    "sc > la+1 gap -> reconcile",
			ca:      countertypes.NewForTest(caWitness, 2, nil), // sc=6 > la+1=3
			wantErr: countertypes.ErrCounterReconcile,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ofRecordInput(f, tc.ca)
			err := verify.New().VerifyOfRecord(context.Background(), in)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("%s: unexpected error %v", tc.name, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
			}
			// Explicit: intent-lost is reconcile, NOT replay (ADR-0006 H-1).
			if errors.Is(tc.wantErr, countertypes.ErrCounterReconcile) &&
				errors.Is(err, countertypes.ErrReplay) {
				t.Fatalf("%s: classified as ErrReplay; must be ErrCounterReconcile", tc.name)
			}
		})
	}
}

func TestVerifyOfRecord_ReadOnlyDoesNotMutateAuthority(t *testing.T) {
	// L3: a read-only VerifyOfRecord caller in the sc==la+1 window writes no
	// CommitBump and synthesizes no pending. verify has no registry handle and
	// returns only an error — there is no write path. We assert the call is
	// pure: the authority value passed in is unchanged after the call.
	f := buildSigned(t, 6, map[string]string{"DB": "x"})
	sha := verify.ContentSHA(f.signed)
	ca := countertypes.NewForTest(caWitness, 5, &countertypes.PendingBump{
		PendingCounter: 6, TargetArtifactSHA: sha, TargetPR: "pr/1",
	})
	in := ofRecordInput(f, ca)
	if err := verify.New().VerifyOfRecord(context.Background(), in); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ca.LastAccepted() != 5 || ca.Pending() == nil || ca.Pending().PendingCounter != 6 {
		t.Fatalf("authority mutated by a read-only verify call: %+v", ca)
	}
}

func TestVerifySubmission_StructuralOnly_NeverOfRecord(t *testing.T) {
	r1 := realRecipient(t)
	r2 := realRecipient(t)
	u, err := encrypt.New(encrypt.NewX25519Parser()).Encrypt(context.Background(), encrypt.EncryptInput{
		ProjectID: projID, LogicalFileName: fileName, Counter: 1,
		Recipients: []rectypes.Recipient{r1, r2},
		Values:     map[string]string{"DB": "x", "API": "y"},
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	res, err := verify.New().VerifySubmission(context.Background(), verify.SubmissionInput{
		Artifact:           u,
		ExpectedProjectID:  projID,
		ExpectedFileName:   fileName,
		ExpectedRecipients: []rectypes.Recipient{r1, r2},
	})
	if err != nil {
		t.Fatalf("VerifySubmission: %v", err)
	}
	if res.State != verify.StateUnverified {
		t.Fatalf("VerifySubmission State = %v, want StateUnverified (never StateOfRecord)", res.State)
	}
	if len(res.KeyNames) != 2 {
		t.Fatalf("KeyNames = %v, want 2 names", res.KeyNames)
	}
}

func TestVerifySubmission_StructuralNegatives(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(in *verify.SubmissionInput)
		wantErr error
	}{
		{"identity mismatch", func(in *verify.SubmissionInput) {
			in.ExpectedProjectID = "other"
		}, verify.ErrIdentityMismatch},
		{"recipient mismatch", func(in *verify.SubmissionInput) {
			in.ExpectedRecipients = []rectypes.Recipient{mkRecipient(t)}
		}, verify.ErrRecipientMismatch},
		{"bad format version", func(in *verify.SubmissionInput) {
			in.Artifact.Byreis.FormatVersion = "nope"
		}, verify.ErrFormatVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r1 := realRecipient(t)
			u, err := encrypt.New(encrypt.NewX25519Parser()).Encrypt(context.Background(), encrypt.EncryptInput{
				ProjectID: projID, LogicalFileName: fileName, Counter: 1,
				Recipients: []rectypes.Recipient{r1},
				Values:     map[string]string{"DB": "x"},
			})
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			in := verify.SubmissionInput{
				Artifact:           u,
				ExpectedProjectID:  projID,
				ExpectedFileName:   fileName,
				ExpectedRecipients: []rectypes.Recipient{r1},
			}
			tc.mutate(&in)
			_, err = verify.New().VerifySubmission(context.Background(), in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

// TestVerifySubmission_DoesNotCatch is the explicit C-6 characterization: a
// structurally-valid UNSIGNED submission with an attacker-chosen counter and no
// signature still returns StateUnverified with no error. VerifySubmission does
// NOT and CANNOT prove authenticity, counter authority, or signature — it only
// checks structure + recipient-set shape.
func TestVerifySubmission_DoesNotCatch(t *testing.T) {
	r1 := realRecipient(t)
	u, err := encrypt.New(encrypt.NewX25519Parser()).Encrypt(context.Background(), encrypt.EncryptInput{
		ProjectID: projID, LogicalFileName: fileName,
		Counter:    999999, // attacker-chosen; submission cannot gate on this
		Recipients: []rectypes.Recipient{r1},
		Values:     map[string]string{"DB": "x"},
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	res, err := verify.New().VerifySubmission(context.Background(), verify.SubmissionInput{
		Artifact:           u,
		ExpectedProjectID:  projID,
		ExpectedFileName:   fileName,
		ExpectedRecipients: []rectypes.Recipient{r1},
	})
	if err != nil {
		t.Fatalf("VerifySubmission unexpectedly errored on a structurally-valid submission: %v", err)
	}
	if res.State == verify.StateOfRecord {
		t.Fatalf("VerifySubmission returned StateOfRecord — it must NEVER yield an of-record state")
	}
	// Documented non-guarantee: the bogus counter was NOT rejected here (the
	// registry decides at merge). This test exists to pin that fact.
}
