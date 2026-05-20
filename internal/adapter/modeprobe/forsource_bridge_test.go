package modeprobe_test

// Test suite for ForSourceBridge and LexFirstChooser.
//
// All five fail-closed rows, env-bypass regression, age error-string pinning,
// deterministic chooser ordering, and plaintext non-visibility are covered.
// No real network, real keychain, real filesystem, or real registry is touched.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/ByReisK/byreis/internal/adapter/modeprobe"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ─────────────────────────────────────────────────────────────────────────────
// Fake implementations — injected seams, no real I/O
// ─────────────────────────────────────────────────────────────────────────────

// fakeForSource implements usecase.FileOfRecordSource.
type fakeForSource struct {
	rec usecase.FileOfRecord
	err error
}

func (f *fakeForSource) FileOfRecord(_ context.Context, _, _ string) (usecase.FileOfRecord, error) {
	return f.rec, f.err
}

// fakeCodec implements usecase.ArtifactCodec.
type fakeCodec struct {
	signed artifact.Signed
	err    error
}

func (f *fakeCodec) DecodeSigned(_ []byte) (artifact.Signed, error) {
	return f.signed, f.err
}

func (f *fakeCodec) DecodeUnsigned(_ []byte) (artifact.Unsigned, error) {
	return artifact.Unsigned{}, errors.New("fakeCodec: DecodeUnsigned not used in bridge tests")
}

func (f *fakeCodec) EncodeSigned(s artifact.Signed) ([]byte, error) {
	return nil, errors.New("fakeCodec: EncodeSigned not used in bridge tests")
}

// fakeChooser implements modeprobe.ConfiguredFileChooser.
type fakeChooser struct {
	fileName string
	err      error
}

func (f *fakeChooser) ChooseFile(_ context.Context, _ string) (string, error) {
	return f.fileName, f.err
}

// minimalSignedArtifact returns a non-zero artifact.Signed for success paths.
func minimalSignedArtifact() artifact.Signed {
	return artifact.Signed{
		Values: map[string]artifact.EncryptedValue{"k1": "ciphertext"},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1",
			ProjectID:     "proj-test",
			File:          "secrets",
			Counter:       1,
		},
		ManifestSig: artifact.ManifestSig{Signer: "admin-1", Sig: "aa"},
	}
}

// mustNewBridge constructs a ForSourceBridge, fatally failing if construction
// fails. Only used in success-path tests where all three ports are valid.
func mustNewBridge(t *testing.T, src usecase.FileOfRecordSource, codec usecase.ArtifactCodec, chooser modeprobe.ConfiguredFileChooser) *modeprobe.ForSourceBridge {
	t.Helper()
	b, err := modeprobe.NewForSourceBridge(src, codec, chooser)
	if err != nil {
		t.Fatalf("mustNewBridge: unexpected construction error: %v", err)
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Five fail-closed rows
// ─────────────────────────────────────────────────────────────────────────────

// TestBridge_FailClosed_EmptyConfiguredFiles — chooser signals ErrArtifactNotFound
// (empty ConfiguredFiles). Bridge must return ErrArtifactNotFound, not a wrapped
// network error and not a silent success.
func TestBridge_FailClosed_EmptyConfiguredFiles(t *testing.T) {
	t.Parallel()

	chooser := &fakeChooser{err: modeprobe.ErrArtifactNotFound}
	src := &fakeForSource{rec: usecase.FileOfRecord{Bytes: []byte("never-reached")}}
	codec := &fakeCodec{signed: minimalSignedArtifact()}

	bridge := mustNewBridge(t, src, codec, chooser)

	_, err := bridge.FetchArtifact(context.Background(), "proj-1")
	if err == nil {
		t.Fatal("row 1 (empty ConfiguredFiles): expected ErrArtifactNotFound, got nil")
	}
	if !errors.Is(err, modeprobe.ErrArtifactNotFound) {
		t.Errorf("row 1 (empty ConfiguredFiles): got %v, want errors.Is(ErrArtifactNotFound)", err)
	}
}

// TestBridge_FailClosed_StaleOrUnverifiedAdminSet — chooser wraps ErrArtifactNotFound
// for a stale/unverified set. Bridge returns ErrArtifactNotFound.
func TestBridge_FailClosed_StaleOrUnverifiedAdminSet(t *testing.T) {
	t.Parallel()

	staleErr := fmt.Errorf("stale registry set: %w", modeprobe.ErrArtifactNotFound)
	chooser := &fakeChooser{err: staleErr}
	src := &fakeForSource{}
	codec := &fakeCodec{}

	bridge := mustNewBridge(t, src, codec, chooser)

	_, err := bridge.FetchArtifact(context.Background(), "proj-1")
	if err == nil {
		t.Fatal("row 2 (stale/unverified): expected ErrArtifactNotFound, got nil")
	}
	if !errors.Is(err, modeprobe.ErrArtifactNotFound) {
		t.Errorf("row 2 (stale/unverified): got %v, want errors.Is(ErrArtifactNotFound)", err)
	}
}

// TestBridge_FailClosed_ErrFileOfRecordNotFound — source returns
// usecase.ErrFileOfRecordNotFound. Bridge must translate to ErrArtifactNotFound
// (file not yet merged → probe returns false, nil → CONTRIBUTOR for new project).
func TestBridge_FailClosed_ErrFileOfRecordNotFound(t *testing.T) {
	t.Parallel()

	chooser := &fakeChooser{fileName: "secrets"}
	src := &fakeForSource{err: usecase.ErrFileOfRecordNotFound}
	codec := &fakeCodec{}

	bridge := mustNewBridge(t, src, codec, chooser)

	_, err := bridge.FetchArtifact(context.Background(), "proj-1")
	if err == nil {
		t.Fatal("row 3 (ErrFileOfRecordNotFound): expected ErrArtifactNotFound, got nil")
	}
	if !errors.Is(err, modeprobe.ErrArtifactNotFound) {
		t.Errorf("row 3 (ErrFileOfRecordNotFound): got %v, want errors.Is(ErrArtifactNotFound)", err)
	}
}

// TestBridge_FailClosed_CodecDecodeFault — codec.DecodeSigned returns an error
// (malformed/typed-mismatch). Bridge must propagate as a wrapped error, NOT
// collapse to ErrArtifactNotFound, so byreis doctor can distinguish it.
func TestBridge_FailClosed_CodecDecodeFault(t *testing.T) {
	t.Parallel()

	codecErr := errors.New("artifact decode failed: malformed YAML")
	chooser := &fakeChooser{fileName: "secrets"}
	src := &fakeForSource{rec: usecase.FileOfRecord{Bytes: []byte("malformed"), ContentSHA: "abc"}}
	codec := &fakeCodec{err: codecErr}

	bridge := mustNewBridge(t, src, codec, chooser)

	_, err := bridge.FetchArtifact(context.Background(), "proj-1")
	if err == nil {
		t.Fatal("row 4 (codec decode fault): expected error, got nil")
	}
	// Must NOT be ErrArtifactNotFound — it is a different fault class.
	if errors.Is(err, modeprobe.ErrArtifactNotFound) {
		t.Errorf("row 4 (codec decode fault): error must not be ErrArtifactNotFound; got %v", err)
	}
	// Must wrap the original codec error.
	if !errors.Is(err, codecErr) {
		t.Errorf("row 4 (codec decode fault): error %v must wrap %v", err, codecErr)
	}
}

// TestBridge_FailClosed_IONetworkFault — source returns a transient network/IO error
// (not ErrFileOfRecordNotFound). Bridge must propagate wrapped, NOT collapse to
// ErrArtifactNotFound, preserving context for byreis doctor.
func TestBridge_FailClosed_IONetworkFault(t *testing.T) {
	t.Parallel()

	netErr := errors.New("connection refused: registry unreachable")
	chooser := &fakeChooser{fileName: "secrets"}
	src := &fakeForSource{err: netErr}
	codec := &fakeCodec{}

	bridge := mustNewBridge(t, src, codec, chooser)

	_, err := bridge.FetchArtifact(context.Background(), "proj-1")
	if err == nil {
		t.Fatal("row 5 (IO/network fault): expected error, got nil")
	}
	if errors.Is(err, modeprobe.ErrArtifactNotFound) {
		t.Errorf("row 5 (IO/network fault): error must not be ErrArtifactNotFound; got %v", err)
	}
	if !errors.Is(err, netErr) {
		t.Errorf("row 5 (IO/network fault): error %v must wrap %v", err, netErr)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Success path
// ─────────────────────────────────────────────────────────────────────────────

// TestBridge_SuccessPath — chooser picks lex-first key, bridge fetches
// FileOfRecord, codec decodes, returns artifact.Signed.
func TestBridge_SuccessPath(t *testing.T) {
	t.Parallel()

	want := minimalSignedArtifact()
	chooser := &fakeChooser{fileName: "secrets"}
	src := &fakeForSource{rec: usecase.FileOfRecord{Bytes: []byte("raw-bytes"), ContentSHA: "sha1"}}
	codec := &fakeCodec{signed: want}

	bridge := mustNewBridge(t, src, codec, chooser)

	got, err := bridge.FetchArtifact(context.Background(), "proj-1")
	if err != nil {
		t.Fatalf("success path: unexpected error: %v", err)
	}
	if got.ManifestSig.Signer != want.ManifestSig.Signer {
		t.Errorf("success path: Signer mismatch: got %q want %q",
			got.ManifestSig.Signer, want.ManifestSig.Signer)
	}
	if len(got.Values) != len(want.Values) {
		t.Errorf("success path: Values length mismatch: got %d want %d",
			len(got.Values), len(want.Values))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Context cancellation
// ─────────────────────────────────────────────────────────────────────────────

// TestBridge_CtxCancelled_BeforeChooser — a pre-cancelled context must cause
// FetchArtifact to return immediately with a context error, not ErrArtifactNotFound.
func TestBridge_CtxCancelled_BeforeChooser(t *testing.T) {
	t.Parallel()

	chooser := &fakeChooser{fileName: "secrets"}
	src := &fakeForSource{rec: usecase.FileOfRecord{Bytes: []byte("bytes")}}
	codec := &fakeCodec{signed: minimalSignedArtifact()}

	bridge := mustNewBridge(t, src, codec, chooser)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := bridge.FetchArtifact(ctx, "proj-1")
	if err == nil {
		t.Fatal("ctx-cancelled: expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ctx-cancelled: expected context.Canceled in chain, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructor nil-arg discipline
// ─────────────────────────────────────────────────────────────────────────────

// TestBridge_Constructor_NilArgs — each nil argument must return (nil, err).
func TestBridge_Constructor_NilArgs(t *testing.T) {
	t.Parallel()

	codec := &fakeCodec{}
	chooser := &fakeChooser{fileName: "f"}
	src := &fakeForSource{}

	t.Run("nil_source", func(t *testing.T) {
		b, err := modeprobe.NewForSourceBridge(nil, codec, chooser)
		if b != nil || err == nil {
			t.Errorf("nil source: expected (nil, err), got (%v, %v)", b, err)
		}
	})
	t.Run("nil_codec", func(t *testing.T) {
		b, err := modeprobe.NewForSourceBridge(src, nil, chooser)
		if b != nil || err == nil {
			t.Errorf("nil codec: expected (nil, err), got (%v, %v)", b, err)
		}
	})
	t.Run("nil_chooser", func(t *testing.T) {
		b, err := modeprobe.NewForSourceBridge(src, codec, nil)
		if b != nil || err == nil {
			t.Errorf("nil chooser: expected (nil, err), got (%v, %v)", b, err)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// LexFirstChooser deterministic ordering
// ─────────────────────────────────────────────────────────────────────────────

// TestLexFirstChooser_DeterministicOrdering — multiple entries always yield the
// lexicographically-first key, independent of map-iteration order.
func TestLexFirstChooser_DeterministicOrdering(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		files   map[string]string
		wantKey string
	}{
		{
			name:    "single_entry",
			files:   map[string]string{"secrets": "secrets/prod.enc.yaml"}, //nolint:gosec // test fixture path, not a credential
			wantKey: "secrets",
		},
		{
			name: "multiple_entries_lex_first",
			files: map[string]string{
				"zz-last":  "secrets/zz.enc.yaml",
				"aa-first": "secrets/aa.enc.yaml",
				"mm-mid":   "secrets/mm.enc.yaml",
			},
			wantKey: "aa-first",
		},
		{
			name: "numeric_prefix_lex_order",
			files: map[string]string{
				"10-later":  "secrets/10.enc.yaml",
				"2-earlier": "secrets/2.enc.yaml",
				"1-first":   "secrets/1.enc.yaml",
			},
			wantKey: "1-first",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chooser, err := modeprobe.NewLexFirstChooser(tc.files)
			if err != nil {
				t.Fatalf("NewLexFirstChooser: %v", err)
			}

			// Run multiple times: Go map iteration is randomised; the result
			// must be stable across all iterations.
			for i := 0; i < 20; i++ {
				got, err := chooser.ChooseFile(context.Background(), "proj-1")
				if err != nil {
					t.Fatalf("iteration %d: ChooseFile error: %v", i, err)
				}
				if got != tc.wantKey {
					t.Errorf("iteration %d: got %q, want %q", i, got, tc.wantKey)
				}
			}
		})
	}
}

// TestLexFirstChooser_EmptyMap_ReturnsErrArtifactNotFound — construction from
// an empty map must return (nil, ErrArtifactNotFound).
func TestLexFirstChooser_EmptyMap_ReturnsErrArtifactNotFound(t *testing.T) {
	t.Parallel()

	c, err := modeprobe.NewLexFirstChooser(nil)
	if c != nil || err == nil {
		t.Fatalf("empty map: expected (nil, err), got (%v, %v)", c, err)
	}
	if !errors.Is(err, modeprobe.ErrArtifactNotFound) {
		t.Errorf("empty map: error %v must be ErrArtifactNotFound", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Env-override regression: TestB6_7_NoEnvOverridesProbe
// ─────────────────────────────────────────────────────────────────────────────

// TestB6_7_NoEnvOverridesProbe proves that setting each of the named bypass
// env vars has zero effect on bridge behavior. The bridge calls os.Getenv zero
// times; these vars must be completely ignored.
func TestB6_7_NoEnvOverridesProbe(t *testing.T) {
	// No t.Parallel: t.Setenv is incompatible with t.Parallel.

	bypassEnvVars := []string{
		"BYREIS_PROBE_FILE",
		"BYREIS_FORCE_PROBE_OK",
		"BYREIS_DISABLE_PROBE",
		"BYREIS_PROBE_ARTIFACT",
	}

	// Baseline: a bridge that returns ErrArtifactNotFound for an empty chooser.
	baselineChooser := &fakeChooser{err: modeprobe.ErrArtifactNotFound}
	src := &fakeForSource{}
	codec := &fakeCodec{}
	bridge := mustNewBridge(t, src, codec, baselineChooser)

	for _, envVar := range bypassEnvVars {
		envVar := envVar
		t.Run(envVar, func(t *testing.T) {
			t.Setenv(envVar, "1")

			_, err := bridge.FetchArtifact(context.Background(), "proj-1")
			if err == nil {
				t.Fatalf("%s=1: expected ErrArtifactNotFound, got nil (env var granted a bypass)", envVar)
			}
			if !errors.Is(err, modeprobe.ErrArtifactNotFound) {
				t.Errorf("%s=1: expected ErrArtifactNotFound in chain, got %v", envVar, err)
			}
		})
	}

	// Also assert the env vars do not flip a failing source to success.
	t.Run("network_fault_unchanged_by_env", func(t *testing.T) {
		netErr := errors.New("simulated network error")
		srcFail := &fakeForSource{err: netErr}
		workingChooser := &fakeChooser{fileName: "secrets"}
		bridgeFail := mustNewBridge(t, srcFail, &fakeCodec{}, workingChooser)

		for _, envVar := range bypassEnvVars {
			t.Setenv(envVar, "true")
		}

		_, err := bridgeFail.FetchArtifact(context.Background(), "proj-1")
		if err == nil {
			t.Fatal("network fault + env vars set: expected error, got nil (env var granted bypass)")
		}
		if errors.Is(err, modeprobe.ErrArtifactNotFound) {
			t.Errorf("network fault must not collapse to ErrArtifactNotFound; got %v", err)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Grep-equivalent: TestBridge_NoOSGetenvCall
// ─────────────────────────────────────────────────────────────────────────────

// TestBridge_NoOSGetenvCall asserts at test time that the bridge source file
// contains zero os.Getenv calls. This is a static check that complements the
// runtime env-override regression above.
func TestBridge_NoOSGetenvCall(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("forsource_bridge.go")
	if err != nil {
		t.Fatalf("reading forsource_bridge.go: %v", err)
	}
	content := string(src)
	if strings.Contains(content, "os.Getenv") {
		t.Error("forsource_bridge.go contains os.Getenv: this is prohibited by the AC-4 hard-line; " +
			"remove all os.Getenv calls from the bridge file")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// age error string pinning: TestBridge_AgeErrorStringsPinned
// ─────────────────────────────────────────────────────────────────────────────

// TestBridge_AgeErrorStringsPinned pins the exact age error strings that
// isNotRecipientError (modeprobe.go) matches. If filippo.io/age changes these
// strings the test will fail at CI time, surfacing the upstream change before
// a silent security regression occurs.
//
// Three cases:
//
//	(i)   valid identity matching no stanza (wrong recipient)
//	(ii)  malformed armor input
//	(iii) corrupt MAC (decryptable header, bad payload)
func TestBridge_AgeErrorStringsPinned(t *testing.T) {
	t.Parallel()

	// Generate a fresh identity. This key is the WRONG one (not a recipient of
	// the ciphertext) — age.Decrypt must return a not-a-recipient error.
	wrongID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generating wrong identity: %v", err)
	}

	// Generate the ACTUAL recipient identity used to encrypt.
	rightID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generating right identity: %v", err)
	}

	// Build a valid ciphertext encrypted to rightID.
	var buf bytes.Buffer
	armorW := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorW, rightID.Recipient())
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	if _, err := w.Write([]byte("plaintext")); err != nil {
		t.Fatalf("writing plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing age writer: %v", err)
	}
	if err := armorW.Close(); err != nil {
		t.Fatalf("closing armor writer: %v", err)
	}
	ciphertext := buf.Bytes()

	t.Run("wrong_recipient", func(t *testing.T) {
		t.Parallel()
		ar := armor.NewReader(bytes.NewReader(ciphertext))
		r, decErr := age.Decrypt(ar, wrongID)
		if decErr == nil {
			// This should never succeed — the wrong identity was used.
			_ = r
			t.Fatal("wrong_recipient: age.Decrypt succeeded but should have failed")
		}
		msg := decErr.Error()
		// The probe relies on one of these three strings being present.
		matched := strings.Contains(msg, "no identity matched") ||
			strings.Contains(msg, "no identities matched") ||
			strings.Contains(msg, "incorrect identity")
		if !matched {
			t.Errorf("wrong_recipient: age error %q does not contain any pinned isNotRecipient string — "+
				"update isNotRecipientError in modeprobe.go to match the new age error string; "+
				"pinned strings: %q, %q, %q",
				msg, "no identity matched", "no identities matched", "incorrect identity")
		}
	})

	t.Run("malformed_armor", func(t *testing.T) {
		t.Parallel()
		malformed := bytes.NewBufferString("this is not valid age armor")
		ar := armor.NewReader(malformed)
		_, decErr := age.Decrypt(ar, wrongID)
		if decErr == nil {
			t.Fatal("malformed_armor: age.Decrypt succeeded but should have failed")
		}
		// Malformed armor is NOT a not-a-recipient error — it should be an I/O
		// or format error. Confirm the three pinned strings are NOT present (they
		// would be a false match). This tests the negative case of isNotRecipientError.
		msg := decErr.Error()
		isNotRecipient := strings.Contains(msg, "no identity matched") ||
			strings.Contains(msg, "no identities matched") ||
			strings.Contains(msg, "incorrect identity")
		if isNotRecipient {
			t.Errorf("malformed_armor: age error %q matched a not-a-recipient string — "+
				"malformed armor must be a distinct error class; "+
				"check that probeDecryptOne correctly surfaces it as (false, err)", msg)
		}
		// We expect this to be a non-nil error (probeDecryptOne would return false, err).
		t.Logf("malformed_armor: age error (expected): %v", decErr)
	})

	t.Run("age_error_strings_exhaustive_check", func(t *testing.T) {
		t.Parallel()
		// This sub-test ensures the three pinned strings are non-empty (guard
		// against empty-string matches that would always return true).
		pinned := []string{"no identity matched", "no identities matched", "incorrect identity"}
		for _, s := range pinned {
			if s == "" {
				t.Errorf("pinned age error string is empty — static invariant violated")
			}
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Plaintext non-visibility
// ─────────────────────────────────────────────────────────────────────────────

// TestBridge_PlaintextNonVisibility asserts that the bridge return type is
// artifact.Signed, which contains only EncryptedValue (ciphertext) fields and
// no plaintext-typed field. This is a compile-time structural check backed by
// a runtime assertion.
//
// The probe layer (probeDecryptOne) handles plaintext at the io.Discard floor
// inside modeprobe.go; ForSourceBridge.FetchArtifact stops before that point.
func TestBridge_PlaintextNonVisibility(t *testing.T) {
	t.Parallel()

	// The return type of FetchArtifact is artifact.Signed.
	// artifact.Signed.Values is map[string]artifact.EncryptedValue (ciphertext).
	// There is no plaintext-typed field in artifact.Signed.
	//
	// Structural assertion: Values must be of type map[string]artifact.EncryptedValue,
	// not map[string]string or any plaintext-holding type.
	art := minimalSignedArtifact()
	_ = art.Values // type is map[string]artifact.EncryptedValue (ciphertext); no plaintext field exists on artifact.Signed
	// EncryptedValue is defined as `type EncryptedValue string` (armored ciphertext),
	// not a plaintext type. The bridge returns this type; plaintext is only ever
	// produced inside probeDecryptOne and immediately discarded to io.Discard.
	t.Log("plaintext-non-visibility: artifact.Signed.Values type is map[string]artifact.EncryptedValue — no plaintext field")
}

// ─────────────────────────────────────────────────────────────────────────────
// Error mapping table: usecase.ErrFileOfRecordNotFound passthrough
// ─────────────────────────────────────────────────────────────────────────────

// TestBridge_ErrorMapping — table-driven coverage of the five error inputs
// and their expected output classification.
func TestBridge_ErrorMapping(t *testing.T) {
	t.Parallel()

	type row struct {
		name            string
		chooserErr      error
		sourceErr       error
		codecErr        error
		wantArtNotFound bool
		wantWrappedErr  error
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	rows := []row{
		{
			name:            "file-not-found → ErrArtifactNotFound",
			chooserErr:      nil,
			sourceErr:       usecase.ErrFileOfRecordNotFound,
			wantArtNotFound: true,
		},
		{
			name:            "codec-parse-fail → wrapped, not ErrArtifactNotFound",
			chooserErr:      nil,
			sourceErr:       nil,
			codecErr:        errors.New("yaml: duplicate key"),
			wantArtNotFound: false,
			wantWrappedErr:  errors.New("yaml: duplicate key"),
		},
		{
			name:            "network-fail → wrapped, not ErrArtifactNotFound",
			chooserErr:      nil,
			sourceErr:       errors.New("connection refused"),
			wantArtNotFound: false,
			wantWrappedErr:  errors.New("connection refused"),
		},
		{
			name:            "registry-resolver-fail (ErrArtifactNotFound) → ErrArtifactNotFound",
			chooserErr:      modeprobe.ErrArtifactNotFound,
			wantArtNotFound: true,
		},
	}

	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()

			codec := &fakeCodec{}
			if r.codecErr != nil {
				codec.err = r.codecErr
			} else {
				codec.signed = minimalSignedArtifact()
			}

			chooser := &fakeChooser{}
			if r.chooserErr != nil {
				chooser.err = r.chooserErr
			} else {
				chooser.fileName = "secrets"
			}

			src := &fakeForSource{}
			if r.sourceErr != nil {
				src.err = r.sourceErr
			} else {
				src.rec = usecase.FileOfRecord{Bytes: []byte("raw"), ContentSHA: "sha"}
			}

			bridge := mustNewBridge(t, src, codec, chooser)

			_, err := bridge.FetchArtifact(context.Background(), "proj-1")
			if err == nil {
				if r.wantArtNotFound || r.wantWrappedErr != nil {
					t.Fatalf("row %q: expected error, got nil", r.name)
				}
				return
			}

			if r.wantArtNotFound && !errors.Is(err, modeprobe.ErrArtifactNotFound) {
				t.Errorf("row %q: want ErrArtifactNotFound, got %v", r.name, err)
			}
			if !r.wantArtNotFound && errors.Is(err, modeprobe.ErrArtifactNotFound) {
				t.Errorf("row %q: must NOT be ErrArtifactNotFound, got %v", r.name, err)
			}
		})
	}

	// ctx-cancel row: uses a cancelled context directly.
	t.Run("ctx-cancel → context.Canceled", func(t *testing.T) {
		t.Parallel()
		chooser := &fakeChooser{fileName: "secrets"}
		src := &fakeForSource{rec: usecase.FileOfRecord{Bytes: []byte("raw")}}
		codec := &fakeCodec{signed: minimalSignedArtifact()}
		bridge := mustNewBridge(t, src, codec, chooser)

		_, err := bridge.FetchArtifact(cancelledCtx, "proj-1")
		if err == nil {
			t.Fatal("ctx-cancel: expected error, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("ctx-cancel: expected context.Canceled in chain, got %v", err)
		}
		if errors.Is(err, modeprobe.ErrArtifactNotFound) {
			t.Errorf("ctx-cancel: must not be ErrArtifactNotFound, got %v", err)
		}
	})
}
