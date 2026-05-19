package manifest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
)

// goodManifest returns a structurally valid Manifest used as the baseline for
// the per-field mutation table.
func goodManifest() manifest.Manifest {
	return manifest.Manifest{
		FormatVersion:   "byreis.native.v1",
		ProjectID:       "proj-x",
		LogicalFileName: "prod",
		Counter:         7,
		Values: map[string][]byte{
			"DB_PASSWORD": []byte("ct-db"),
			"API_KEY":     []byte("ct-api"),
		},
		RecipientFingerprints: []string{
			strings.Repeat("bb", 32),
			strings.Repeat("aa", 32),
		},
	}
}

// perKeyDigest recomputes the §3.2 per-key digest = sha256(name ‖ 0x00 ‖ ct).
func perKeyDigest(name string, ct []byte) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x00})
	h.Write(ct)
	return hex.EncodeToString(h.Sum(nil))
}

func TestFormatVersionValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"v1 ok", "byreis.native.v1", true},
		{"v2 ok", "byreis.native.v2", true},
		{"multi-digit ok", "byreis.native.v10", true},
		{"empty", "", false},
		{"free form", "byreis.native.vX", false},
		{"wrong prefix", "byreis.v1", false},
		{"trailing junk", "byreis.native.v1x", false},
		{"leading junk", "xbyreis.native.v1", false},
		{"no version digits", "byreis.native.v", false},
		{"regex anchor bypass attempt newline", "byreis.native.v1\nbyreis.native.v9", false},
		{"contains US separator", "byreis.native.v\x1f1", false},
		{"contains RS separator", "byreis.native.v\x1e1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := manifest.FormatVersionValid(tc.in); got != tc.want {
				t.Fatalf("FormatVersionValid(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestEncode_Deterministic_MapOrderNeverReachesSigner(t *testing.T) {
	t.Parallel()
	// Two manifests with the SAME logical content but different map insertion
	// and fingerprint slice order must produce byte-identical output.
	a := goodManifest()
	b := manifest.Manifest{
		FormatVersion:   "byreis.native.v1",
		ProjectID:       "proj-x",
		LogicalFileName: "prod",
		Counter:         7,
		Values: map[string][]byte{
			"API_KEY":     []byte("ct-api"),
			"DB_PASSWORD": []byte("ct-db"),
		},
		RecipientFingerprints: []string{
			strings.Repeat("aa", 32),
			strings.Repeat("bb", 32),
		},
	}
	ba, err := manifest.Encode(a)
	if err != nil {
		t.Fatalf("Encode(a): %v", err)
	}
	bb, err := manifest.Encode(b)
	if err != nil {
		t.Fatalf("Encode(b): %v", err)
	}
	if !bytes.Equal(ba, bb) {
		t.Fatalf("Encode not deterministic across map/slice order:\n a=%q\n b=%q", ba, bb)
	}
	// Run repeatedly to flush out map-iteration nondeterminism.
	for i := 0; i < 50; i++ {
		bn, err := manifest.Encode(goodManifest())
		if err != nil {
			t.Fatalf("Encode iter %d: %v", i, err)
		}
		if !bytes.Equal(ba, bn) {
			t.Fatalf("Encode nondeterministic on iteration %d", i)
		}
	}
}

func TestEncode_FieldOrderAndSeparators(t *testing.T) {
	t.Parallel()
	out, err := manifest.Encode(goodManifest())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	const us, rs = 0x1f, 0x1e

	// Field 1..4 then sorted key block (US-terminated) then sorted fp block.
	fields := bytes.Split(out, []byte{us})
	// Expect: [fmtver][projid][file][counter8][keyblock][fpblock]
	if len(fields) != 6 {
		t.Fatalf("expected 6 US-separated fields, got %d: %q", len(fields), out)
	}
	if string(fields[0]) != "byreis.native.v1" {
		t.Fatalf("field1 format_version = %q", fields[0])
	}
	if string(fields[1]) != "proj-x" {
		t.Fatalf("field2 project_id = %q", fields[1])
	}
	if string(fields[2]) != "prod" {
		t.Fatalf("field3 file = %q", fields[2])
	}
	if len(fields[3]) != 8 {
		t.Fatalf("field4 counter must be 8 bytes big-endian, got %d bytes", len(fields[3]))
	}
	wantCounter := []byte{0, 0, 0, 0, 0, 0, 0, 7}
	if !bytes.Equal(fields[3], wantCounter) {
		t.Fatalf("field4 counter = % x, want % x", fields[3], wantCounter)
	}

	// Field 5: sorted key records, each "name RS digesthex", records RS-joined.
	keyParts := bytes.Split(fields[4], []byte{rs})
	// API_KEY < DB_PASSWORD ascending.
	if string(keyParts[0]) != "API_KEY" {
		t.Fatalf("first sorted key = %q, want API_KEY", keyParts[0])
	}
	if string(keyParts[1]) != perKeyDigest("API_KEY", []byte("ct-api")) {
		t.Fatalf("API_KEY digest = %q", keyParts[1])
	}
	if string(keyParts[2]) != "DB_PASSWORD" {
		t.Fatalf("second sorted key = %q, want DB_PASSWORD", keyParts[2])
	}
	if string(keyParts[3]) != perKeyDigest("DB_PASSWORD", []byte("ct-db")) {
		t.Fatalf("DB_PASSWORD digest = %q", keyParts[3])
	}

	// Field 6: sorted fingerprints, RS-joined, no trailing US.
	fpParts := bytes.Split(fields[5], []byte{rs})
	want := []string{strings.Repeat("aa", 32), strings.Repeat("bb", 32)}
	if len(fpParts) != 2 || string(fpParts[0]) != want[0] || string(fpParts[1]) != want[1] {
		t.Fatalf("fingerprint block not sorted ascending: %q", fields[5])
	}
	if bytes.HasSuffix(out, []byte{us}) {
		t.Fatalf("stream must not end with trailing US")
	}
}

func TestEncode_RejectsBadInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(m *manifest.Manifest)
		wantErr error
	}{
		{"bad format version", func(m *manifest.Manifest) { m.FormatVersion = "sops.v1" }, manifest.ErrFormatVersion},
		{"format version separator", func(m *manifest.Manifest) { m.FormatVersion = "byreis.native.v\x1f9" }, manifest.ErrFormatVersion},
		{"project id has US", func(m *manifest.Manifest) { m.ProjectID = "proj\x1fx" }, manifest.ErrSeparatorInjection},
		{"project id has RS", func(m *manifest.Manifest) { m.ProjectID = "proj\x1ex" }, manifest.ErrSeparatorInjection},
		{"file has US", func(m *manifest.Manifest) { m.LogicalFileName = "pr\x1fod" }, manifest.ErrSeparatorInjection},
		{"key name has RS", func(m *manifest.Manifest) {
			m.Values = map[string][]byte{"OK": []byte("c"), "BA\x1eD": []byte("c2")}
		}, manifest.ErrSeparatorInjection},
		{"fingerprint has US", func(m *manifest.Manifest) {
			m.RecipientFingerprints = []string{"aa\x1fbb"}
		}, manifest.ErrSeparatorInjection},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := goodManifest()
			tc.mutate(&m)
			_, err := manifest.Encode(m)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Encode err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestEncode_CiphertextSwapChangesDigest(t *testing.T) {
	t.Parallel()
	// Swapping two values' ciphertexts must change BOTH per-key digests, so
	// the encoded stream differs (defeats ciphertext-swap).
	base := goodManifest()
	swapped := goodManifest()
	swapped.Values = map[string][]byte{
		"DB_PASSWORD": []byte("ct-api"), // was ct-db
		"API_KEY":     []byte("ct-db"),  // was ct-api
	}
	a, err := manifest.Encode(base)
	if err != nil {
		t.Fatalf("Encode base: %v", err)
	}
	b, err := manifest.Encode(swapped)
	if err != nil {
		t.Fatalf("Encode swapped: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("ciphertext swap not detected: identical encoding")
	}
}

func TestEncode_SortIsBytewiseAscending(t *testing.T) {
	t.Parallel()
	m := goodManifest()
	m.Values = map[string][]byte{
		"b": []byte("1"), "A": []byte("2"), "a": []byte("3"), "B": []byte("4"),
	}
	out, err := manifest.Encode(m)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	fields := bytes.Split(out, []byte{0x1f})
	keyParts := bytes.Split(fields[4], []byte{0x1e})
	var gotKeys []string
	for i := 0; i < len(keyParts); i += 2 {
		gotKeys = append(gotKeys, string(keyParts[i]))
	}
	wantKeys := []string{"A", "B", "a", "b"} // bytewise ascending
	if !sort.StringsAreSorted(gotKeys) || strings.Join(gotKeys, ",") != strings.Join(wantKeys, ",") {
		t.Fatalf("keys not bytewise-ascending sorted: got %v want %v", gotKeys, wantKeys)
	}
}
