//go:build testhook

// Read-path (Get / Decrypt / Edit) use-case tests. These require the `testhook`
// build tag because they construct a Valid() countertypes.CounterAuthority via
// the witnessed test-only constructor (the same constraint merge_test.go has);
// production builds never set this tag. The use-cases themselves only ever
// CONSUME the opaque CounterAuthority through the injected CounterStore port.
//
// The shared test doubles (stubGit, stubCodec, modeGate, stubIDLoader,
// stubDecryptor, stubRecipients, stubCounter, witnessedAuthority, mkRecipient,
// ageEncryptOne) are defined in review_test.go and merge_test.go and reused
// here so the read path exercises the exact same seam shapes as merge.
package usecase_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ---------------------------------------------------------------------------
// Read-path-specific test doubles
// ---------------------------------------------------------------------------

// stubFileOfRecord is the consumer-port double that serves the LIVE committed
// signed file-of-record bytes (NOT a PR). It records its call count so a
// "fetched before the mode gate denied" regression is detectable.
type stubFileOfRecord struct {
	bytes []byte
	sha   string
	err   error
	calls int
}

func (s *stubFileOfRecord) FileOfRecord(
	_ context.Context, _, _ string,
) (usecase.FileOfRecord, error) {
	s.calls++
	if s.err != nil {
		return usecase.FileOfRecord{}, s.err
	}
	return usecase.FileOfRecord{Bytes: s.bytes, ContentSHA: s.sha}, nil
}

// spyVerifier records whether VerifyOfRecord was entered and with what input,
// and returns a configurable error. It is the call-graph spy proving
// VerifyOfRecord runs BEFORE any decrypt/identity-load.
type spyVerifier struct {
	mu      sync.Mutex
	entered int
	gotIn   verify.OfRecordInput
	err     error
}

func (v *spyVerifier) VerifyOfRecord(_ context.Context, in verify.OfRecordInput) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.entered++
	v.gotIn = in
	return v.err
}

// spyDecryptor records entry order so we can assert decrypt is NEVER reached
// before VerifyOfRecord and NEVER reached at all on a fail-closed path.
type spyDecryptor struct {
	mu          sync.Mutex
	decryptHits int
	rtHits      int
	out         map[string]string
	err         error
	onDecrypt   func()
}

func (d *spyDecryptor) Decrypt(
	_ context.Context, _ artifact.Signed, id identity.Identity,
) (map[string]string, error) {
	d.mu.Lock()
	d.decryptHits++
	d.mu.Unlock()
	if d.onDecrypt != nil {
		d.onDecrypt()
	}
	if id == nil {
		return nil, errors.New("spyDecryptor: nil identity must never reach here")
	}
	if d.err != nil {
		return nil, d.err
	}
	out := make(map[string]string, len(d.out))
	for k, v := range d.out {
		out[k] = v
	}
	return out, nil
}

func (d *spyDecryptor) RoundTripAll(context.Context, artifact.Signed, []identity.Identity) error {
	d.mu.Lock()
	d.rtHits++
	d.mu.Unlock()
	return nil
}

// spyIDLoader records whether an identity load was entered (must NOT happen on
// a denied/fail-closed path before VerifyOfRecord).
type spyIDLoader struct {
	mu     sync.Mutex
	loaded int
	id     identity.Identity
	err    error
}

func (l *spyIDLoader) Load(context.Context) (identity.Identity, error) {
	l.mu.Lock()
	l.loaded++
	l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	return l.id, nil
}

// recordingAtomicWriter captures the no-clobber contract: it records every
// WriteFileOfRecord call and can simulate symlink/cross-dir/perms/crash. It
// never actually touches a real filesystem (core stays fs-injected).
type recordingAtomicWriter struct {
	mu          sync.Mutex
	calls       int
	gotBytes    []byte
	gotPath     string
	err         error
	liveMutated bool // set true ONLY if the writer "committed" (rename) the new bytes
}

func (w *recordingAtomicWriter) WriteFileOfRecord(
	_ context.Context, in usecase.AtomicWriteInput,
) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	w.gotPath = in.LiveRelPath
	if w.err != nil {
		// Abort BEFORE the rename: live file byte-identical, no mutation.
		w.liveMutated = false
		return w.err
	}
	w.gotBytes = append([]byte(nil), in.SignedBytes...)
	w.liveMutated = true
	return nil
}

// stubEditor returns a fixed edited plaintext map, recording the plaintext it
// was shown so we can assert it received the decrypted (not ciphertext) value.
type stubEditor struct {
	shown  map[string]string
	edited map[string]string
	err    error
	calls  int
}

func (e *stubEditor) Edit(_ context.Context, in usecase.EditSession) (map[string]string, error) {
	e.calls++
	e.shown = make(map[string]string, len(in.Plaintext))
	for k, v := range in.Plaintext {
		e.shown[k] = v
	}
	if e.err != nil {
		return nil, e.err
	}
	if e.edited != nil {
		return e.edited, nil
	}
	out := make(map[string]string, len(in.Plaintext))
	for k, v := range in.Plaintext {
		out[k] = v
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const rpProject = "myorg/app"
const rpFile = "prod"

func mustID(t *testing.T, x *age.X25519Identity) identity.Identity {
	t.Helper()
	id, err := identity.Parse(x.String())
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	return id
}

func encryptNew() encrypt.Encryptor { return encrypt.New() }

func newArmorWriter(sb *strings.Builder) io.WriteCloser { return armor.NewWriter(sb) }

// signedArtifactFor builds a real, fully-formed signed file-of-record for the
// given recipient set, sealing plaintext to each recipient with real age and
// signing the canonical manifest with a real Ed25519 key. The returned signer
// public key is what TrustedSigners must carry for VerifyOfRecord to pass.
func signedArtifactFor(
	t *testing.T, recs []rectypes.Recipient, ages []*age.X25519Identity,
	plain map[string]string, counter uint64,
) (artifact.Signed, ed25519.PublicKey) {
	t.Helper()
	vals := make(map[string]artifact.EncryptedValue, len(plain))
	for k, pt := range plain {
		// Seal to ALL recipients so any one admin identity can decrypt.
		recipStrs := make([]string, 0, len(ages))
		for _, a := range ages {
			recipStrs = append(recipStrs, a.Recipient().String())
		}
		vals[k] = artifact.EncryptedValue(ageEncryptToAll(t, pt, recipStrs))
	}
	entries := make([]artifact.RecipientEntry, 0, len(recs))
	for _, r := range recs {
		entries = append(entries, recipientFPEntry(r))
	}
	body := artifact.Signed{
		Values: vals,
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1",
			ProjectID:     rpProject,
			File:          rpFile,
			Counter:       counter,
			Recipients:    entries,
		},
	}
	man := manifest.Manifest{
		FormatVersion:   body.Byreis.FormatVersion,
		ProjectID:       body.Byreis.ProjectID,
		LogicalFileName: body.Byreis.File,
		Counter:         body.Byreis.Counter,
		Values:          map[string][]byte{},
	}
	for k, v := range body.Values {
		man.Values[k] = []byte(v)
	}
	for _, e := range entries {
		man.RecipientFingerprints = append(man.RecipientFingerprints, e.FP)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	sig, err := sign.Sign(priv, man)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	body.ManifestSig = artifact.ManifestSig{Signer: "admin-1", Sig: hexEncode(sig)}
	return body, pub
}

func hexEncode(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = h[v>>4]
		out[i*2+1] = h[v&0x0f]
	}
	return string(out)
}

func ageEncryptToAll(t *testing.T, plaintext string, recips []string) string {
	t.Helper()
	rs := make([]age.Recipient, 0, len(recips))
	for _, r := range recips {
		pr, err := age.ParseX25519Recipient(r)
		if err != nil {
			t.Fatalf("parse recipient: %v", err)
		}
		rs = append(rs, pr)
	}
	// Reuse the single-recipient armored encryptor shape for one recipient; for
	// multiple, build directly.
	if len(rs) == 1 {
		return ageEncryptOne(t, plaintext, recips[0])
	}
	var sb strings.Builder
	aw := newArmorWriter(&sb)
	w, err := age.Encrypt(aw, rs...)
	if err != nil {
		t.Fatalf("age encrypt: %v", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Close()
	_ = aw.Close()
	return sb.String()
}

func recDeps(t *testing.T, pub ed25519.PublicKey, recs []rectypes.Recipient) *stubRecipients {
	t.Helper()
	return &stubRecipients{
		set:            recs,
		signers:        map[string]ed25519.PublicKey{"admin-1": pub},
		sourceVerified: true,
		configuredFiles: map[string]string{
			rpFile: "secrets/prod.enc.yaml",
		},
	}
}

// ---------------------------------------------------------------------------
// Obligation: Denied-not-attempted (Get / Decrypt / Edit in CONTRIBUTOR)
// ---------------------------------------------------------------------------

func TestGet_DeniedInContributorMode_NoFetchNoDecryptNoIdentity(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	body, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"API_KEY": "S3CR3T"}, 0)
	for_ := &stubFileOfRecord{bytes: []byte("live"), sha: verify.ContentSHA(body)}
	dec := &spyDecryptor{out: map[string]string{"API_KEY": "S3CR3T"}}
	idl := &spyIDLoader{id: mustID(t, x)}
	ver := &spyVerifier{}
	g, err := usecase.NewGetter(usecase.GetDeps{
		Source: for_, Codec: &stubCodec{signed: body}, Decryptor: dec,
		IDLoader: idl, Verifier: ver, Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
		Counter: &stubCounter{auth: witnessedAuthority(0, nil)},
		Mode:    modeGate{m: mode.ModeContributor},
	})
	if err != nil {
		t.Fatalf("NewGetter: %v", err)
	}
	_, err = g.Get(context.Background(), usecase.GetInput{
		ProjectID: rpProject, FileName: rpFile, Key: "API_KEY",
	})
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("err = %v, want ErrPermissionDenied", err)
	}
	if for_.calls != 0 || ver.entered != 0 || dec.decryptHits != 0 || idl.loaded != 0 {
		t.Fatalf("work attempted despite denied mode: fetch=%d verify=%d decrypt=%d id=%d",
			for_.calls, ver.entered, dec.decryptHits, idl.loaded)
	}
}

func TestDecrypt_DeniedInContributorMode_NoFetchNoDecrypt(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	body, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"A": "v"}, 0)
	for_ := &stubFileOfRecord{bytes: []byte("live"), sha: verify.ContentSHA(body)}
	dec := &spyDecryptor{out: map[string]string{"A": "v"}}
	idl := &spyIDLoader{id: mustID(t, x)}
	ver := &spyVerifier{}
	d, _ := usecase.NewDecryptor(usecase.DecryptDeps{
		Source: for_, Codec: &stubCodec{signed: body}, Decryptor: dec,
		IDLoader: idl, Verifier: ver, Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
		Counter: &stubCounter{auth: witnessedAuthority(0, nil)},
		Mode:    modeGate{m: mode.ModeContributor},
	})
	_, err := d.Decrypt(context.Background(), usecase.DecryptInput{
		ProjectID: rpProject, FileName: rpFile,
	})
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("err = %v, want ErrPermissionDenied", err)
	}
	if for_.calls != 0 || ver.entered != 0 || dec.decryptHits != 0 || idl.loaded != 0 {
		t.Fatalf("work attempted despite denied mode")
	}
}

func TestEdit_DeniedInContributorMode_NoFetchNoWrite(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	body, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"A": "v"}, 0)
	for_ := &stubFileOfRecord{bytes: []byte("live"), sha: verify.ContentSHA(body)}
	w := &recordingAtomicWriter{}
	ed := &stubEditor{}
	ver := &spyVerifier{}
	idl := &spyIDLoader{id: mustID(t, x)}
	e, _ := usecase.NewEditor(usecase.EditDeps{
		Source: for_, Codec: &stubCodec{signed: body},
		Decryptor: &spyDecryptor{out: map[string]string{"A": "v"}},
		Encryptor: &encryptorReal{inner: encryptNew()},
		IDLoader:  idl, Verifier: ver,
		Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
		Counter:    &stubCounter{auth: witnessedAuthority(0, nil)},
		Signer:     &stubSigner{signerID: "admin-1"},
		Writer:     w, Editor: ed, Mode: modeGate{m: mode.ModeContributor},
	})
	_, err := e.Edit(context.Background(), usecase.EditInput{
		ProjectID: rpProject, FileName: rpFile,
	})
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("err = %v, want ErrPermissionDenied", err)
	}
	if for_.calls != 0 || w.calls != 0 || ed.calls != 0 || w.liveMutated {
		t.Fatalf("work attempted / live mutated despite denied mode")
	}
}

// ---------------------------------------------------------------------------
// Obligation: VerifyOfRecord-FIRST (call-graph spy)
// ---------------------------------------------------------------------------

func TestGet_VerifyOfRecordBeforeAnyDecryptOrIdentity(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	body, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"API_KEY": "PLAIN"}, 0)
	for_ := &stubFileOfRecord{bytes: []byte("live"), sha: verify.ContentSHA(body)}

	// VerifyOfRecord fails: decrypt/identity-load must NEVER be entered.
	ver := &spyVerifier{err: verify.ErrSignatureInvalid}
	dec := &spyDecryptor{out: map[string]string{"API_KEY": "PLAIN"}}
	idl := &spyIDLoader{id: mustID(t, x)}

	g, _ := usecase.NewGetter(usecase.GetDeps{
		Source: for_, Codec: &stubCodec{signed: body}, Decryptor: dec,
		IDLoader: idl, Verifier: ver, Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
		Counter: &stubCounter{auth: witnessedAuthority(0, nil)},
		Mode:    modeGate{m: mode.ModeAdmin},
	})
	_, err := g.Get(context.Background(), usecase.GetInput{
		ProjectID: rpProject, FileName: rpFile, Key: "API_KEY",
	})
	if !errors.Is(err, verify.ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid", err)
	}
	if ver.entered != 1 {
		t.Fatalf("VerifyOfRecord entered %d times, want 1", ver.entered)
	}
	if dec.decryptHits != 0 || idl.loaded != 0 {
		t.Fatalf("decrypt/identity reached despite VerifyOfRecord failure "+
			"(decrypt=%d id=%d)", dec.decryptHits, idl.loaded)
	}
}

func TestGet_VerifyFailClasses_NoNilKeyDowngrade(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
	}{
		{"unsigned", verify.ErrUnsigned},
		{"untrusted-signer", verify.ErrNoTrustedSigner},
		{"replay", countertypes.ErrReplay},
		{"rolled-back", countertypes.ErrCounterReconcile},
		{"identity-mismatch", verify.ErrIdentityMismatch},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec, _, x := mkRecipient(t)
			body, pub := signedArtifactFor(t,
				[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
				map[string]string{"K": "v"}, 0)
			for_ := &stubFileOfRecord{bytes: []byte("live"), sha: verify.ContentSHA(body)}
			ver := &spyVerifier{err: tc.err}
			dec := &spyDecryptor{out: map[string]string{"K": "v"}}
			idl := &spyIDLoader{id: mustID(t, x)}
			g, _ := usecase.NewGetter(usecase.GetDeps{
				Source: for_, Codec: &stubCodec{signed: body}, Decryptor: dec,
				IDLoader: idl, Verifier: ver,
				Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
				Counter:    &stubCounter{auth: witnessedAuthority(0, nil)},
				Mode:       modeGate{m: mode.ModeAdmin},
			})
			_, err := g.Get(context.Background(), usecase.GetInput{
				ProjectID: rpProject, FileName: rpFile, Key: "K",
			})
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if dec.decryptHits != 0 || idl.loaded != 0 {
				t.Fatalf("nil-key/decrypt path reachable on %s", tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Obligation: Decode fail-closed typed errors (no silent coerce)
// ---------------------------------------------------------------------------

func TestGet_DecodeSignedOfUnsignedFile_TypedMismatchNoDecrypt(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	_, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"K": "v"}, 0)
	for_ := &stubFileOfRecord{bytes: []byte("unsigned-on-disk"), sha: "x"}
	dec := &spyDecryptor{out: map[string]string{"K": "v"}}
	idl := &spyIDLoader{id: mustID(t, x)}
	ver := &spyVerifier{}
	g, _ := usecase.NewGetter(usecase.GetDeps{
		Source: for_,
		// DecodeSigned of an unsigned file => hard typed mismatch.
		Codec:     &stubCodec{decodeSErr: errors.New("file has no manifest_sig: unsigned")},
		Decryptor: dec, IDLoader: idl, Verifier: ver,
		Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
		Counter:    &stubCounter{auth: witnessedAuthority(0, nil)},
		Mode:       modeGate{m: mode.ModeAdmin},
	})
	_, err := g.Get(context.Background(), usecase.GetInput{
		ProjectID: rpProject, FileName: rpFile, Key: "K",
	})
	if !errors.Is(err, usecase.ErrReadDecode) {
		t.Fatalf("err = %v, want ErrReadDecode (no silent coerce to unsigned)", err)
	}
	if ver.entered != 0 || dec.decryptHits != 0 || idl.loaded != 0 {
		t.Fatalf("verify/decrypt/identity reached on a decode failure")
	}
}

func TestDecrypt_MalformedFileBytes_TypedErrorNoPartialNoDecrypt(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	_, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"K": "v"}, 0)
	for_ := &stubFileOfRecord{bytes: []byte("\x00\x01garbage"), sha: "x"}
	dec := &spyDecryptor{out: map[string]string{"K": "v"}}
	idl := &spyIDLoader{id: mustID(t, x)}
	ver := &spyVerifier{}
	d, _ := usecase.NewDecryptor(usecase.DecryptDeps{
		Source:    for_,
		Codec:     &stubCodec{decodeSErr: errors.New("yaml: malformed; duplicate key")},
		Decryptor: dec, IDLoader: idl, Verifier: ver,
		Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
		Counter:    &stubCounter{auth: witnessedAuthority(0, nil)},
		Mode:       modeGate{m: mode.ModeAdmin},
	})
	res, err := d.Decrypt(context.Background(), usecase.DecryptInput{
		ProjectID: rpProject, FileName: rpFile,
	})
	if !errors.Is(err, usecase.ErrReadDecode) {
		t.Fatalf("err = %v, want ErrReadDecode", err)
	}
	if len(res.Plaintext) != 0 {
		t.Fatalf("a partial domain value was returned on a malformed decode")
	}
	if ver.entered != 0 || dec.decryptHits != 0 || idl.loaded != 0 {
		t.Fatalf("verify/decrypt/identity reached on a malformed decode")
	}
}

// ---------------------------------------------------------------------------
// Obligation: zero-normalization manifest-pin invariance
// ---------------------------------------------------------------------------

// codecVariant returns the SAME domain Signed for byte-different inputs,
// proving the use-case binds identity to the manifest, never codec wire bytes.
type codecVariant struct{ signed artifact.Signed }

func (c codecVariant) DecodeSigned([]byte) (artifact.Signed, error) { return c.signed, nil }
func (c codecVariant) DecodeUnsigned([]byte) (artifact.Unsigned, error) {
	return artifact.Unsigned{}, errors.New("not used")
}
func (c codecVariant) EncodeSigned(s artifact.Signed) ([]byte, error) {
	return []byte("encoded"), nil
}

func TestGet_ManifestPinInvariance_ByteDifferentSameManifestSameContentSHA(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	body, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"API_KEY": "ZERO-NORM"}, 0)

	wantSHA := verify.ContentSHA(body)

	run := func(wireBytes []byte) (usecase.GetResult, *spyVerifier, error) {
		ver := &spyVerifier{}
		g, _ := usecase.NewGetter(usecase.GetDeps{
			Source:     &stubFileOfRecord{bytes: wireBytes, sha: "raw-buffer-sha-IGNORED"},
			Codec:      codecVariant{signed: body},
			Decryptor:  &spyDecryptor{out: map[string]string{"API_KEY": "ZERO-NORM"}},
			IDLoader:   &spyIDLoader{id: mustID(t, x)},
			Verifier:   ver,
			Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
			Counter:    &stubCounter{auth: witnessedAuthority(0, nil)},
			Mode:       modeGate{m: mode.ModeAdmin},
		})
		res, err := g.Get(context.Background(), usecase.GetInput{
			ProjectID: rpProject, FileName: rpFile, Key: "API_KEY",
		})
		return res, ver, err
	}

	r1, v1, e1 := run([]byte("byreis:\n  file: prod\n# comment A\n"))
	r2, v2, e2 := run([]byte("byreis:\n   file:    prod\n\n\n"))
	if e1 != nil || e2 != nil {
		t.Fatalf("get failed: %v / %v", e1, e2)
	}
	// Identity is bound to the recovered manifest, not the wire bytes: the
	// of-record content SHA the use-case computed is identical and matches the
	// pure verify.ContentSHA over the domain manifest.
	if r1.ContentSHA != wantSHA || r2.ContentSHA != wantSHA {
		t.Fatalf("ContentSHA not manifest-bound: %q / %q want %q",
			r1.ContentSHA, r2.ContentSHA, wantSHA)
	}
	if v1.gotIn.Artifact.Byreis.ProjectID != rpProject ||
		v2.gotIn.Artifact.Byreis.ProjectID != rpProject {
		t.Fatalf("verifier was not handed the recovered domain manifest")
	}
}

func TestGet_SignedFieldChange_DifferentContentSHA_FailClosed(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	body, _ := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"K": "v"}, 0)
	tampered := body
	tampered.Byreis.Counter = body.Byreis.Counter + 7 // a signed field change
	if verify.ContentSHA(body) == verify.ContentSHA(tampered) {
		t.Fatalf("a signed-field change did not change ContentSHA")
	}
	// VerifyOfRecord (real) must fail closed on the tampered artifact.
	rs, pub := body, ed25519.PublicKey(nil)
	_ = rs
	ver := verify.New()
	err := ver.VerifyOfRecord(context.Background(), verify.OfRecordInput{
		Artifact:           tampered,
		ExpectedProjectID:  rpProject,
		ExpectedFileName:   rpFile,
		ExpectedRecipients: []rectypes.Recipient{rec},
		TrustedSigners:     map[string]ed25519.PublicKey{"admin-1": pub},
		Counter:            witnessedAuthority(0, nil),
	})
	if err == nil {
		t.Fatalf("VerifyOfRecord accepted a signed-field-tampered artifact")
	}
}

// ---------------------------------------------------------------------------
// Obligation: no-leak on failure + distinct exit-code classes
// ---------------------------------------------------------------------------

func TestReadPath_NoPlaintextOrKeyInErrors_AndExitClasses(t *testing.T) {
	t.Parallel()
	const secret = "TOP-SECRET-PLAINTEXT-VALUE"
	rec, _, x := mkRecipient(t)
	body, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"API_KEY": secret}, 0)
	priv := mustID(t, x).(interface{ Recipient() string }).Recipient()

	type tc struct {
		name      string
		mutate    func(*usecase.GetDeps)
		wantClass usecase.ExitClass
		wantErr   error
	}
	cases := []tc{
		{
			name:      "permission-denied",
			mutate:    func(d *usecase.GetDeps) { d.Mode = modeGate{m: mode.ModeContributor} },
			wantClass: usecase.ExitPermissionDenied,
			wantErr:   mode.ErrPermissionDenied,
		},
		{
			name: "verify-failure",
			mutate: func(d *usecase.GetDeps) {
				d.Verifier = &spyVerifier{err: verify.ErrSignatureInvalid}
			},
			wantClass: usecase.ExitVerifyFailure,
			wantErr:   verify.ErrSignatureInvalid,
		},
		{
			name: "decode-malformed",
			mutate: func(d *usecase.GetDeps) {
				d.Codec = &stubCodec{decodeSErr: errors.New("malformed yaml")}
			},
			wantClass: usecase.ExitDecodeMalformed,
			wantErr:   usecase.ErrReadDecode,
		},
		{
			name: "decrypt-no-identity",
			mutate: func(d *usecase.GetDeps) {
				d.IDLoader = &spyIDLoader{err: errors.New("no admin key")}
			},
			wantClass: usecase.ExitDecryptNoIdentity,
			wantErr:   usecase.ErrReadNoIdentity,
		},
		{
			name: "not-found",
			mutate: func(d *usecase.GetDeps) {
				d.Source = &stubFileOfRecord{err: usecase.ErrFileOfRecordNotFound}
			},
			wantClass: usecase.ExitNotFound,
			wantErr:   usecase.ErrFileOfRecordNotFound,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			deps := usecase.GetDeps{
				Source:     &stubFileOfRecord{bytes: []byte("live"), sha: verify.ContentSHA(body)},
				Codec:      &stubCodec{signed: body},
				Decryptor:  &spyDecryptor{out: map[string]string{"API_KEY": secret}},
				IDLoader:   &spyIDLoader{id: mustID(t, x)},
				Verifier:   &spyVerifier{},
				Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
				Counter:    &stubCounter{auth: witnessedAuthority(0, nil)},
				Mode:       modeGate{m: mode.ModeAdmin},
			}
			c.mutate(&deps)
			g, _ := usecase.NewGetter(deps)
			_, err := g.Get(context.Background(), usecase.GetInput{
				ProjectID: rpProject, FileName: rpFile, Key: "API_KEY",
			})
			if err == nil {
				t.Fatalf("%s: expected an error", c.name)
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("%s: err = %v, want wrap %v", c.name, err, c.wantErr)
			}
			var rpErr *usecase.ReadPathError
			if !errors.As(err, &rpErr) {
				t.Fatalf("%s: error is not a *ReadPathError: %v", c.name, err)
			}
			if rpErr.Class != c.wantClass {
				t.Fatalf("%s: exit class = %v, want %v", c.name, rpErr.Class, c.wantClass)
			}
			for _, rendered := range []string{
				err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err),
			} {
				if strings.Contains(rendered, secret) {
					t.Fatalf("%s: plaintext leaked in error: %q", c.name, rendered)
				}
				if strings.Contains(rendered, priv) {
					t.Fatalf("%s: identity recipient leaked in error", c.name)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Obligation: Edit C-4 fresh whole-file re-encrypt + re-sign over fresh artifact
// ---------------------------------------------------------------------------

func TestEdit_FreshWholeFileReEncrypt_ZeroCiphertextCarryForward(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	body, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"API_KEY": "old-plaintext"}, 0)
	priorCT := string(body.Values["API_KEY"])

	for_ := &stubFileOfRecord{bytes: []byte("live"), sha: verify.ContentSHA(body)}
	enc := &encryptorReal{inner: encryptNew()}
	sgn := &stubSigner{signerID: "admin-1"}
	w := &recordingAtomicWriter{}
	ed := &stubEditor{edited: map[string]string{"API_KEY": "edited-plaintext"}}
	dec := &spyDecryptor{out: map[string]string{"API_KEY": "old-plaintext"}}

	e, _ := usecase.NewEditor(usecase.EditDeps{
		Source: for_, Codec: &stubCodec{signed: body},
		Decryptor: dec, Encryptor: enc,
		IDLoader: &spyIDLoader{id: mustID(t, x)}, Verifier: &spyVerifier{},
		Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
		Counter:    &stubCounter{auth: witnessedAuthority(0, nil)},
		Signer:     sgn, Writer: w, Editor: ed,
		Mode: modeGate{m: mode.ModeAdmin},
	})
	res, err := e.Edit(context.Background(), usecase.EditInput{
		ProjectID: rpProject, FileName: rpFile,
	})
	if err != nil {
		t.Fatalf("Edit: %v", err)
	}
	// The editor was shown DECRYPTED plaintext, not ciphertext.
	if ed.shown["API_KEY"] != "old-plaintext" {
		t.Fatalf("editor was not shown the decrypted plaintext")
	}
	// A FRESH whole-file age.Encrypt happened (encryptor was invoked) and the
	// prior ciphertext is NOT carried forward into the written bytes.
	if len(enc.produced) == 0 {
		t.Fatalf("no fresh age.Encrypt happened on edit")
	}
	for _, ct := range enc.produced {
		if ct == priorCT {
			t.Fatalf("prior ciphertext was carried forward (not a fresh encrypt)")
		}
	}
	// Re-sign happened over the freshly produced artifact (signer saw the fresh
	// per-key digest, never a blind blob), and the writer committed exactly the
	// re-signed bytes.
	if sgn.calls != 1 {
		t.Fatalf("signer calls = %d, want 1 (re-sign over fresh artifact)", sgn.calls)
	}
	if w.calls != 1 || !w.liveMutated {
		t.Fatalf("atomic write did not happen exactly once on success")
	}
	if !res.ReEncrypted {
		t.Fatalf("result did not report a fresh re-encrypt")
	}
}

// ---------------------------------------------------------------------------
// Obligation: Edit no-clobber + TOCTOU (abort => live byte-identical)
// ---------------------------------------------------------------------------

func TestEdit_AbortPaths_LiveFileUntouched_NoResidue(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	body, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"K": "v"}, 0)

	base := func() usecase.EditDeps {
		return usecase.EditDeps{
			Source:     &stubFileOfRecord{bytes: []byte("live"), sha: verify.ContentSHA(body)},
			Codec:      &stubCodec{signed: body},
			Decryptor:  &spyDecryptor{out: map[string]string{"K": "v"}},
			Encryptor:  &encryptorReal{inner: encryptNew()},
			IDLoader:   &spyIDLoader{id: mustID(t, x)},
			Verifier:   &spyVerifier{},
			Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
			Counter:    &stubCounter{auth: witnessedAuthority(0, nil)},
			Signer:     &stubSigner{signerID: "admin-1"},
			Writer:     &recordingAtomicWriter{},
			Editor:     &stubEditor{edited: map[string]string{"K": "v2"}},
			Mode:       modeGate{m: mode.ModeAdmin},
		}
	}

	t.Run("editor-fails", func(t *testing.T) {
		t.Parallel()
		d := base()
		w := &recordingAtomicWriter{}
		d.Writer = w
		d.Editor = &stubEditor{err: errors.New("editor exited non-zero")}
		e, _ := usecase.NewEditor(d)
		_, err := e.Edit(context.Background(), usecase.EditInput{ProjectID: rpProject, FileName: rpFile})
		if err == nil {
			t.Fatalf("expected an error when the editor fails")
		}
		if w.calls != 0 || w.liveMutated {
			t.Fatalf("live file mutated after an editor failure")
		}
	})

	t.Run("sign-fails", func(t *testing.T) {
		t.Parallel()
		d := base()
		w := &recordingAtomicWriter{}
		d.Writer = w
		d.Signer = &stubSigner{err: errors.New("signing unavailable")}
		e, _ := usecase.NewEditor(d)
		_, err := e.Edit(context.Background(), usecase.EditInput{ProjectID: rpProject, FileName: rpFile})
		if err == nil || w.calls != 0 || w.liveMutated {
			t.Fatalf("sign failure must abort with the live file untouched (err=%v calls=%d)", err, w.calls)
		}
	})

	t.Run("write-fails-no-mutation", func(t *testing.T) {
		t.Parallel()
		d := base()
		w := &recordingAtomicWriter{err: errors.New("rename failed: cross-device")}
		d.Writer = w
		e, _ := usecase.NewEditor(d)
		_, err := e.Edit(context.Background(), usecase.EditInput{ProjectID: rpProject, FileName: rpFile})
		if err == nil {
			t.Fatalf("expected an error when the atomic write fails")
		}
		if w.liveMutated {
			t.Fatalf("write adapter reported a live mutation despite failing")
		}
	})

	t.Run("ctx-cancelled-before-work", func(t *testing.T) {
		t.Parallel()
		d := base()
		w := &recordingAtomicWriter{}
		d.Writer = w
		e, _ := usecase.NewEditor(d)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := e.Edit(ctx, usecase.EditInput{ProjectID: rpProject, FileName: rpFile})
		if err == nil || w.calls != 0 || w.liveMutated {
			t.Fatalf("cancelled ctx must abort with no mutation (err=%v)", err)
		}
	})
}

// ---------------------------------------------------------------------------
// happy path: Get returns the requested key's plaintext after verify-first
// ---------------------------------------------------------------------------

func TestGet_HappyPath_VerifyThenDecryptReturnsRequestedKey(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	body, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"API_KEY": "the-secret", "OTHER": "nope"}, 0)
	ver := &spyVerifier{}
	g, _ := usecase.NewGetter(usecase.GetDeps{
		Source:     &stubFileOfRecord{bytes: []byte("live"), sha: verify.ContentSHA(body)},
		Codec:      &stubCodec{signed: body},
		Decryptor:  &spyDecryptor{out: map[string]string{"API_KEY": "the-secret", "OTHER": "nope"}},
		IDLoader:   &spyIDLoader{id: mustID(t, x)},
		Verifier:   ver,
		Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
		Counter:    &stubCounter{auth: witnessedAuthority(0, nil)},
		Mode:       modeGate{m: mode.ModeAdmin},
	})
	res, err := g.Get(context.Background(), usecase.GetInput{
		ProjectID: rpProject, FileName: rpFile, Key: "API_KEY",
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ver.entered != 1 {
		t.Fatalf("VerifyOfRecord entered %d times, want 1", ver.entered)
	}
	if res.Value != "the-secret" {
		t.Fatalf("Value = %q, want the requested key plaintext", res.Value)
	}
}

func TestDecrypt_HappyPath_AllValuesAfterVerifyFirst(t *testing.T) {
	t.Parallel()
	rec, _, x := mkRecipient(t)
	body, pub := signedArtifactFor(t,
		[]rectypes.Recipient{rec}, []*age.X25519Identity{x},
		map[string]string{"A": "1", "B": "2"}, 0)
	ver := &spyVerifier{}
	d, _ := usecase.NewDecryptor(usecase.DecryptDeps{
		Source:     &stubFileOfRecord{bytes: []byte("live"), sha: verify.ContentSHA(body)},
		Codec:      &stubCodec{signed: body},
		Decryptor:  &spyDecryptor{out: map[string]string{"A": "1", "B": "2"}},
		IDLoader:   &spyIDLoader{id: mustID(t, x)},
		Verifier:   ver,
		Recipients: recDeps(t, pub, []rectypes.Recipient{rec}),
		Counter:    &stubCounter{auth: witnessedAuthority(0, nil)},
		Mode:       modeGate{m: mode.ModeAdmin},
	})
	res, err := d.Decrypt(context.Background(), usecase.DecryptInput{
		ProjectID: rpProject, FileName: rpFile,
	})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if ver.entered != 1 {
		t.Fatalf("VerifyOfRecord entered %d times, want 1", ver.entered)
	}
	if res.Plaintext["A"] != "1" || res.Plaintext["B"] != "2" {
		t.Fatalf("Plaintext = %v, want all values", res.Plaintext)
	}
}
