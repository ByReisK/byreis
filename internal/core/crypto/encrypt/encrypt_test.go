package encrypt_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
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
	enc := encrypt.New(encrypt.NewX25519Parser())
	in := baseInput()
	_, err := enc.Encrypt(context.Background(), in)
	if !errors.Is(err, encrypt.ErrNoRecipients) {
		t.Fatalf("Encrypt with zero recipients: err = %v, want ErrNoRecipients", err)
	}
}

func TestEncrypt_BadFormatInputs(t *testing.T) {
	t.Parallel()
	r, _ := testRecipient(t)
	enc := encrypt.New(encrypt.NewX25519Parser())

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
	enc := encrypt.New(encrypt.NewX25519Parser())

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
	enc := encrypt.New(encrypt.NewX25519Parser())

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
	enc := encrypt.New(encrypt.NewX25519Parser())

	art, err := enc.Encrypt(context.Background(), baseInput(r))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ar := armor.NewReader(strings.NewReader(string(art.Values["API_KEY"])))
	if _, err := age.Decrypt(ar, wrongID); err == nil {
		t.Fatalf("a non-recipient identity decrypted the value — fail-closed broken")
	}
}

// stubParser is a RecipientParser test double that lets a test observe what the
// encrypt path hands to the parser and inject an arbitrary age.Recipient or
// error in its place. It models the adapter-supplied parser (e.g. a plugin-aware
// one) without importing any backend package into the core test.
type stubParser struct {
	gotRecipients []rectypes.Recipient
	delegate      func(rectypes.Recipient) (age.Recipient, error)
}

func (s *stubParser) ParseRecipient(_ context.Context, r rectypes.Recipient) (age.Recipient, error) {
	s.gotRecipients = append(s.gotRecipients, r)
	return s.delegate(r)
}

// TestEncrypt_InjectedParser_DrivesRecipientConstruction asserts the seam:
// Encrypt consumes the injected RecipientParser for every recipient rather than
// constructing the recipient itself, and the age.Recipient values the parser
// returns are the ones wrapped by age.Encrypt with zero call-site changes
// (AC-001-c). The stub returns a real X25519 recipient parsed independently, so
// the round-trip still succeeds — proving the value flowed through the seam.
func TestEncrypt_InjectedParser_DrivesRecipientConstruction(t *testing.T) {
	t.Parallel()
	r, id := testRecipient(t)
	parser := &stubParser{
		delegate: func(rr rectypes.Recipient) (age.Recipient, error) {
			return age.ParseX25519Recipient(rr.AgePubKey)
		},
	}
	enc := encrypt.New(parser)

	art, err := enc.Encrypt(context.Background(), baseInput(r))
	if err != nil {
		t.Fatalf("Encrypt with injected parser: %v", err)
	}
	if len(parser.gotRecipients) != 1 || parser.gotRecipients[0].AgePubKey != r.AgePubKey {
		t.Fatalf("encrypt did not route recipients through the injected parser: got %+v", parser.gotRecipients)
	}

	// The value must decrypt with the recipient identity — proving the parser's
	// age.Recipient is what age.Encrypt actually wrapped to.
	ar := armor.NewReader(strings.NewReader(string(art.Values["API_KEY"])))
	dec, err := age.Decrypt(ar, id)
	if err != nil {
		t.Fatalf("decrypt value built via injected parser: %v", err)
	}
	if _, err := io.Copy(io.Discard, dec); err != nil {
		t.Fatalf("drain plaintext: %v", err)
	}
}

// TestEncrypt_InjectedParser_ErrorFailsClosed asserts a parser error aborts the
// whole encrypt with no artifact (the per-recipient construction error is the
// fail-closed point for AC-003-b / C3 when a later slice's plugin parser fails).
func TestEncrypt_InjectedParser_ErrorFailsClosed(t *testing.T) {
	t.Parallel()
	r, _ := testRecipient(t)
	sentinel := errors.New("parser refused this recipient")
	parser := &stubParser{
		delegate: func(rectypes.Recipient) (age.Recipient, error) { return nil, sentinel },
	}
	enc := encrypt.New(parser)

	art, err := enc.Encrypt(context.Background(), baseInput(r))
	if !errors.Is(err, sentinel) {
		t.Fatalf("Encrypt err = %v, want wrapped sentinel from parser", err)
	}
	if len(art.Values) != 0 {
		t.Fatalf("fail-closed broken: artifact produced despite parser error: %+v", art)
	}
}

// TestX25519Parser_MalformedKey asserts the in-core default parser wraps a
// malformed recipient string with the actionable doctor hint and does not panic.
func TestX25519Parser_MalformedKey(t *testing.T) {
	t.Parallel()
	p := encrypt.NewX25519Parser()
	_, err := p.ParseRecipient(context.Background(), rectypes.Recipient{
		Label:     "broken",
		AgePubKey: "age1notavalidrecipient",
	})
	if err == nil {
		t.Fatalf("malformed recipient: want error, got nil")
	}
	if !strings.Contains(err.Error(), "byreis doctor") {
		t.Fatalf("error missing actionable hint: %v", err)
	}
}

// TestRecipientParser_ReflectionInvariant is the AC-001-d guard: an age.Recipient
// returned by the in-core X25519 parser must expose no field or method that
// yields an age.Identity / *age.X25519Identity (a private-key route). The
// contributor path consumes only this interface; if a Recipient could reflect
// down to an identity, the write-only wedge would be defeated.
func TestRecipientParser_ReflectionInvariant(t *testing.T) {
	t.Parallel()
	r, _ := testRecipient(t)
	rec, err := encrypt.NewX25519Parser().ParseRecipient(context.Background(), r)
	if err != nil {
		t.Fatalf("parse recipient: %v", err)
	}

	identityType := reflect.TypeOf((*age.Identity)(nil)).Elem()
	x25519IDType := reflect.TypeOf((*age.X25519Identity)(nil))

	v := reflect.ValueOf(rec)
	if assignableToIdentity(v.Type(), identityType, x25519IDType) {
		t.Fatalf("recipient type %s is itself assignable to an identity — private-key route", v.Type())
	}
	// Walk exported fields one level (the X25519Recipient is an opaque struct;
	// this guards against a future parser returning a recipient that embeds or
	// exposes identity material).
	rv := reflect.Indirect(v)
	if rv.Kind() == reflect.Struct {
		for i := 0; i < rv.NumField(); i++ {
			ft := rv.Type().Field(i)
			if !ft.IsExported() {
				continue
			}
			if assignableToIdentity(ft.Type, identityType, x25519IDType) {
				t.Fatalf("recipient exposes field %q of identity-bearing type %s", ft.Name, ft.Type)
			}
		}
	}
}

func assignableToIdentity(t, iface, concrete reflect.Type) bool {
	if t == concrete {
		return true
	}
	if iface.Kind() == reflect.Interface && t.Implements(iface) {
		return true
	}
	return false
}
