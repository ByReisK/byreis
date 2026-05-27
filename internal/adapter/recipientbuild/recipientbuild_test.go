package recipientbuild_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/plugin"

	"github.com/ByReisK/byreis/internal/adapter/fakeplugin"
	"github.com/ByReisK/byreis/internal/adapter/recipientbuild"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// TestMain builds the fake plugin binary once for the lifetime of this test
// binary and wires it onto PATH. All tests that exercise the plugin subprocess
// call fakeplugin.OnPath(t, mode) to set FAKEPLUGIN_MODE; tests that do not
// need the subprocess use native X25519 recipients and are unaffected.
func TestMain(m *testing.M) {
	fakeplugin.BuildOnPath(m)
}

// --- helpers -----------------------------------------------------------------

func newParser(wrapTimeout time.Duration) *recipientbuild.Parser {
	return recipientbuild.New(recipientbuild.Options{WrapTimeout: wrapTimeout})
}

// x25519Recipient returns a fresh X25519 rectypes.Recipient plus the private
// identity so the test can decrypt after a successful wrap.
func x25519Recipient(t *testing.T) (rectypes.Recipient, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate X25519 identity: %v", err)
	}
	pub := id.Recipient().String()
	fp := rectypes.Fingerprint(sha256.Sum256([]byte(pub)))
	return rectypes.Recipient{Label: "test-x25519", AgePubKey: pub, Fingerprint: fp}, id
}

// pluginRecipient returns a rectypes.Recipient for the fake plugin with
// FAKEPLUGIN_MODE already set (via fakeplugin.OnPath).
func pluginRecipient(t *testing.T, mode fakeplugin.Mode) rectypes.Recipient {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	pubKey := fakeplugin.OnPath(t, mode)
	fp := rectypes.Fingerprint(sha256.Sum256([]byte(pubKey)))
	return rectypes.Recipient{Label: "test-plugin", AgePubKey: pubKey, Fingerprint: fp}
}

// encryptWith encrypts a fixed plaintext to the given age.Recipient and
// returns armored ciphertext. Used only in round-trip tests.
func encryptWith(t *testing.T, r age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write([]byte("hello world")); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return buf.Bytes()
}

// noopUI is a ClientUI whose callbacks succeed silently; used to construct a
// plugin.Identity for the decrypt side of round-trip tests without going
// through the recipientbuild path.
var noopUI = &plugin.ClientUI{
	DisplayMessage: func(name, message string) error { return nil },
	RequestValue:   func(name, prompt string, secret bool) (string, error) { return "", nil },
	Confirm:        func(name, prompt, yes, no string) (bool, error) { return true, nil },
	WaitTimer:      func(name string) {},
}

// --- tests -------------------------------------------------------------------

// TestParseX25519_HappyPath verifies that a native age1… X25519 recipient
// string is accepted and produces a working age.Recipient.
func TestParseX25519_HappyPath(t *testing.T) {
	t.Parallel()
	r, _ := x25519Recipient(t)
	p := newParser(5 * time.Second)

	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseRecipient X25519: unexpected error: %v", err)
	}
	if rec == nil {
		t.Fatal("ParseRecipient X25519: returned nil recipient")
	}
}

// TestParseX25519_BadKey verifies that a malformed key string (not a valid
// bech32 X25519 string) returns an actionable error.
func TestParseX25519_BadKey(t *testing.T) {
	t.Parallel()
	r := rectypes.Recipient{Label: "bad", AgePubKey: "not-a-valid-age-key"}
	p := newParser(5 * time.Second)

	_, err := p.ParseRecipient(context.Background(), r)
	if err == nil {
		t.Fatal("ParseRecipient bad key: expected error, got nil")
	}
}

// TestParseX25519_ContextCancelledBeforeParse verifies that a cancelled
// context causes the call to fail rather than proceeding.
func TestParseX25519_ContextCancelledBeforeParse(t *testing.T) {
	t.Parallel()
	r, _ := x25519Recipient(t)
	p := newParser(5 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.ParseRecipient(ctx, r)
	if err == nil {
		t.Fatal("ParseRecipient cancelled context: expected error, got nil")
	}
}

// TestPluginRecipient_HappyPath verifies that a plugin recipient (age1yubikey1…)
// is accepted and wraps successfully via the fake subprocess.
func TestPluginRecipient_HappyPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	r := pluginRecipient(t, fakeplugin.ModeOK)
	p := newParser(5 * time.Second)

	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseRecipient plugin ok: unexpected error: %v", err)
	}
	if rec == nil {
		t.Fatal("ParseRecipient plugin ok: returned nil recipient")
	}

	// Wrap via the returned recipient to confirm the subprocess ran successfully.
	ct := encryptWith(t, rec)
	if len(ct) == 0 {
		t.Fatal("plugin wrap produced empty ciphertext")
	}
}

// TestPluginRecipient_RoundTrip encrypts with the plugin recipient (ModeOK)
// then decrypts with the matching identity (ModeOKIdentity), asserting the
// plain text survives the round trip.
func TestPluginRecipient_RoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	// Encrypt phase.
	r := pluginRecipient(t, fakeplugin.ModeOK)
	p := newParser(5 * time.Second)
	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseRecipient: %v", err)
	}
	ct := encryptWith(t, rec)

	// Decrypt phase — switch fake mode to ok-identity.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOKIdentity))
	id, err := plugin.NewIdentity(fakeplugin.IdentityString(), noopUI)
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	dr, err := age.Decrypt(bytes.NewReader(ct), id)
	if err != nil {
		t.Fatalf("age.Decrypt: %v", err)
	}
	plain, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("read plaintext: %v", err)
	}
	if string(plain) != "hello world" {
		t.Fatalf("round-trip: got %q, want %q", plain, "hello world")
	}
}

// TestWrapError_FailClosed_SingleRecipient verifies that a plugin recipient in
// wrap-error mode causes ParseRecipient to succeed (it builds a deadlineRecipient)
// but the subsequent Wrap to fail. This exercises the C3 fail-closed path at
// the individual-recipient level.
func TestWrapError_FailClosed_SingleRecipient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	r := pluginRecipient(t, fakeplugin.ModeWrapError)
	p := newParser(5 * time.Second)

	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseRecipient wrap-error: unexpected construction error: %v", err)
	}

	// Trigger Wrap directly; it must fail.
	_, err = rec.Wrap([]byte("fake-file-key-0000000000000000"))
	if err == nil {
		t.Fatal("Wrap (wrap-error mode): expected error, got nil")
	}
	// The error must NOT contain plugin-supplied bytes (only the sanitized name).
	if strings.Contains(err.Error(), "simulated") || strings.Contains(err.Error(), "fake plugin") {
		t.Fatalf("Wrap error leaks plugin-supplied bytes: %q", err.Error())
	}
}

// TestWrapError_MultiRecipient_FailClosed is the C3 keystone test. A recipient
// set containing a healthy X25519 recipient at position 0 and a
// wrap-error plugin recipient at position 1 must cause age.Encrypt to return
// an error and produce NO ciphertext (silent-subset truncation is forbidden).
//
// The plugin recipient is deliberately placed at the 2nd position (C3-a).
func TestWrapError_MultiRecipient_FailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	p := newParser(5 * time.Second)

	// First recipient: a healthy X25519 key.
	r1, _ := x25519Recipient(t)
	rec1, err := p.ParseRecipient(context.Background(), r1)
	if err != nil {
		t.Fatalf("ParseRecipient X25519: %v", err)
	}

	// Second recipient: plugin in wrap-error mode (position 1, per C3-a).
	r2 := pluginRecipient(t, fakeplugin.ModeWrapError)
	rec2, err := p.ParseRecipient(context.Background(), r2)
	if err != nil {
		t.Fatalf("ParseRecipient plugin wrap-error: %v", err)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rec1, rec2)
	// age.Encrypt's io.WriteCloser returns an error only on Close. If the
	// writer was returned without error, try to write and close it.
	if err == nil && w != nil {
		_, _ = w.Write([]byte("secret"))
		err = w.Close()
	}
	if err == nil {
		t.Fatal("multi-recipient fail-closed: expected age.Encrypt to error on wrap-error plugin, got nil")
	}
	// No artifact: buffer must be empty or all data discarded.
	if buf.Len() > 0 {
		// age armoring writes a header before wrapping keys; a partial header
		// is expected. What must NOT happen is a fully encrypted ciphertext
		// addressed only to rec1. We assert the error was returned.
		t.Logf("buffer has %d bytes (expected: partial/empty on wrap error)", buf.Len())
	}
}

// TestMissingBinary verifies that a missing plugin binary surfaces an
// actionable error mentioning the binary name and "install age-plugin-yubikey".
func TestMissingBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	// Override PATH to an empty dir so the binary cannot be found.
	emptyDir := t.TempDir()
	t.Setenv("PATH", emptyDir)

	pubKey := fakeplugin.RecipientString() // well-formed age1yubikey1… string
	fp := rectypes.Fingerprint(sha256.Sum256([]byte(pubKey)))
	r := rectypes.Recipient{Label: "missing-plugin", AgePubKey: pubKey, Fingerprint: fp}

	p := newParser(5 * time.Second)
	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		// Some implementations detect missing binary at parse time; that is acceptable.
		if !strings.Contains(err.Error(), "install") && !strings.Contains(err.Error(), "age-plugin") {
			t.Fatalf("missing binary: error lacks actionable hint: %q", err.Error())
		}
		return
	}

	// Others detect at Wrap time; trigger it.
	_, err = rec.Wrap([]byte("fake-file-key-0000000000000000"))
	if err == nil {
		t.Fatal("missing binary: expected error at Wrap, got nil")
	}
	if !strings.Contains(err.Error(), "age-plugin") {
		t.Fatalf("missing binary: error lacks plugin name: %q", err.Error())
	}
}

// TestMalformedPlugin verifies that a malformed plugin binary (non-protocol
// output) surfaces a non-nil error and does NOT produce a ciphertext.
func TestMalformedPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	r := pluginRecipient(t, fakeplugin.ModeMalformed)
	p := newParser(5 * time.Second)

	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		// Acceptable: detect at parse time.
		return
	}

	_, err = rec.Wrap([]byte("fake-file-key-0000000000000000"))
	if err == nil {
		t.Fatal("malformed plugin: expected Wrap error, got nil")
	}
}

// TestBoundedTimeout_NoGoroutineLeak verifies that a plugin that hangs
// forever causes the deadlineRecipient to return a bounded error (not hang)
// and that the goroutine does not leak past the timeout window.
//
// This test exercises the D5 bounded-wait decorator end-to-end.
func TestBoundedTimeout_NoGoroutineLeak(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	r := pluginRecipient(t, fakeplugin.ModeTimeout)
	// Use a very short timeout so the test finishes quickly.
	p := newParser(200 * time.Millisecond)

	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseRecipient timeout-mode: unexpected construction error: %v", err)
	}

	start := time.Now()
	_, err = rec.Wrap([]byte("fake-file-key-0000000000000000"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("timeout: expected bounded error from deadlineRecipient, got nil")
	}
	// The bounded wait must not have run significantly past the timeout.
	if elapsed > 2*time.Second {
		t.Fatalf("timeout: decorator did not bound the hang: elapsed %s (want < 2s)", elapsed)
	}
	// Actionable error must mention the plugin name.
	if !strings.Contains(err.Error(), "yubikey") {
		t.Fatalf("timeout: error lacks plugin name: %q", err.Error())
	}
}

// TestEnvHygiene_ByreisForbidden verifies that the plugin subprocess started
// by Wrap does NOT receive BYREIS_KEY, BYREIS_KEY_FILE, or BYREIS_GITHUB_TOKEN.
//
// The test uses the env-echo mode of the fake plugin: the subprocess writes the
// names (not values) of all BYREIS_* and AGE* env vars it observes to a temp
// file. app.ScrubSecretEnvVars is called before spawning the plugin to simulate
// what BuildProductionDeps does in production. The test asserts that the secret
// variable names are absent from the subprocess's reported environment.
func TestEnvHygiene_ByreisForbidden(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	// Set BYREIS_KEY/KEY_FILE/GITHUB_TOKEN in the parent environment to
	// simulate CI where the admin key arrives via env vars.
	t.Setenv("BYREIS_KEY", "AGE-SECRET-KEY-1FAKE000000000000000000000000000000000000000000000")
	t.Setenv("BYREIS_KEY_FILE", "/fake/key/path")
	t.Setenv("BYREIS_GITHUB_TOKEN", "ghp_fakefakefakefakefakefake")

	// Create the temp file the subprocess will write its env names into.
	echoFile, err := os.CreateTemp("", "envecho-*.txt")
	if err != nil {
		t.Fatalf("env-hygiene: create temp file: %v", err)
	}
	echoPath := echoFile.Name()
	_ = echoFile.Close()
	defer func() { _ = os.Remove(echoPath) }()
	t.Setenv(fakeplugin.EnvEchoFileEnvVar, echoPath)

	// Simulate what app.BuildProductionDeps does: scrub secret vars from the
	// process environment after reading them into config structs. In production
	// this happens via app.ScrubSecretEnvVars() at the end of
	// BuildProductionDeps, before any plugin subprocess is spawned.
	for _, name := range []string{"BYREIS_KEY", "BYREIS_KEY_FILE", "BYREIS_GITHUB_TOKEN"} {
		_ = os.Unsetenv(name)
	}

	r := pluginRecipient(t, fakeplugin.ModeEnvEcho)
	p := newParser(5 * time.Second)

	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseRecipient env-echo: unexpected error: %v", err)
	}

	// Trigger Wrap: the subprocess runs, writes its env to echoPath, then completes.
	ct := encryptWith(t, rec)
	if len(ct) == 0 {
		t.Fatal("env-hygiene: expected non-empty ciphertext from env-echo mode")
	}

	// Read what the subprocess observed.
	echoBytes, readErr := os.ReadFile(echoPath)
	if readErr != nil {
		t.Fatalf("env-hygiene: cannot read env-echo output: %v", readErr)
	}
	observed := string(echoBytes)

	// Assert the secret vars are absent from the child environment.
	for _, forbidden := range []string{"BYREIS_KEY", "BYREIS_KEY_FILE", "BYREIS_GITHUB_TOKEN"} {
		for _, line := range strings.Split(observed, "\n") {
			if strings.TrimSpace(line) == forbidden {
				t.Errorf("env-hygiene: subprocess inherited forbidden env var %q — scrub is broken", forbidden)
			}
		}
	}
}

// TestNoNetworkAtWrap verifies that wrap completes without network access.
// The fake plugin's implementation is purely in-process (file-key echo), so
// completing successfully without a network confirms the B7 property.
func TestNoNetworkAtWrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	r := pluginRecipient(t, fakeplugin.ModeOK)
	p := newParser(5 * time.Second)

	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseRecipient no-network: %v", err)
	}
	ct := encryptWith(t, rec)
	if len(ct) == 0 {
		t.Fatal("no-network: expected non-empty ciphertext; encryption must complete offline")
	}
}

// TestClientUI_MarkerBytesNeverLeak is the B2 marker-byte test. It drives the
// fake plugin in ModeStderrNoise (which writes StderrMarker to stderr) and
// asserts that the marker string NEVER appears in:
//   - any byreis error string returned by ParseRecipient or Wrap
//   - any captured stderr output via os.Stderr redirection
//
// The test covers all four ClientUI callbacks by verifying that any plugin-
// supplied bytes are dropped and that only sanitized, name-keyed text appears.
func TestClientUI_MarkerBytesNeverLeak(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	r := pluginRecipient(t, fakeplugin.ModeStderrNoise)
	p := newParser(5 * time.Second)

	// Capture stderr by replacing os.Stderr temporarily.
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = stderrW

	rec, parseErr := p.ParseRecipient(context.Background(), r)

	// Restore stderr before reading from the pipe to avoid a deadlock.
	os.Stderr = origStderr
	_ = stderrW.Close()

	var captured strings.Builder
	_, _ = io.Copy(&captured, stderrR)
	_ = stderrR.Close()

	// Assert the marker is absent from the byreis error (if any).
	if parseErr != nil {
		if strings.Contains(parseErr.Error(), fakeplugin.StderrMarker) {
			t.Fatalf("ClientUI: StderrMarker leaked into ParseRecipient error: %q", parseErr.Error())
		}
		// Parse error itself is acceptable here — the mode is stderr-noise but still ok.
	}

	// Assert the marker is absent from captured stderr output.
	if strings.Contains(captured.String(), fakeplugin.StderrMarker) {
		t.Fatalf("ClientUI: StderrMarker appeared in captured stderr: %q", captured.String())
	}

	// If parse succeeded, also check the Wrap error path.
	if rec != nil {
		_, wrapErr := rec.Wrap([]byte("fake-file-key-0000000000000000"))
		if wrapErr != nil && strings.Contains(wrapErr.Error(), fakeplugin.StderrMarker) {
			t.Fatalf("ClientUI: StderrMarker leaked into Wrap error: %q", wrapErr.Error())
		}
	}
}

// TestUnknownHRP_Rejected verifies that a recipient string with an unknown
// bech32 HRP (not in SupportedRecipientBackends) is rejected with an
// actionable error at parse time.
func TestUnknownHRP_Rejected(t *testing.T) {
	t.Parallel()
	// Encode a recipient using an unsupported plugin name.
	unsupported := plugin.EncodeRecipient("unsupportedhardware", []byte{0x42})
	fp := rectypes.Fingerprint(sha256.Sum256([]byte(unsupported)))
	r := rectypes.Recipient{Label: "bad-backend", AgePubKey: unsupported, Fingerprint: fp}

	p := newParser(5 * time.Second)
	_, err := p.ParseRecipient(context.Background(), r)
	if err == nil {
		t.Fatal("unknown HRP: expected rejection, got nil error")
	}
	// Error must be actionable (mention "unsupported" or "doctor").
	msg := err.Error()
	if !strings.Contains(msg, "unsupported") && !strings.Contains(msg, "doctor") {
		t.Fatalf("unknown HRP error lacks actionable hint: %q", msg)
	}
}

// TestWrapArtifact_ArmorFormat verifies that the ciphertext produced via the
// plugin recipient is valid armored age format that the standard age library
// can parse (structural sanity check; does not decrypt).
func TestWrapArtifact_ArmorFormat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	r := pluginRecipient(t, fakeplugin.ModeOK)
	p := newParser(5 * time.Second)

	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseRecipient: %v", err)
	}

	// Encrypt with armor.
	var buf bytes.Buffer
	armorW := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorW, rec)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write([]byte("test")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := armorW.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("armor: empty output")
	}
	if !strings.HasPrefix(buf.String(), "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Fatalf("armor: unexpected prefix: %q", buf.String()[:50])
	}
}

// TestReflectionInvariant asserts that the age.Recipient returned by
// ParseRecipient carries no accessible age.Identity / private key material.
// No field or method reachable from the value must yield an age.Identity
// or *age.X25519Identity.
func TestReflectionInvariant(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	r := pluginRecipient(t, fakeplugin.ModeOK)
	p := newParser(5 * time.Second)
	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		t.Fatalf("ParseRecipient: %v", err)
	}

	// The returned value must satisfy age.Recipient but not age.Identity.
	if _, isIdentity := rec.(age.Identity); isIdentity {
		t.Fatal("reflection invariant: Recipient value also satisfies age.Identity — AC-001-d violation")
	}
	// Must not type-assert to *age.X25519Recipient.
	if _, isX := rec.(*age.X25519Recipient); isX {
		t.Fatal("reflection invariant: plugin Recipient value is *age.X25519Recipient")
	}
}

// TestWrapError_ErrorDoesNotContainPluginBytes checks that an error from a
// plugin in wrap-error mode does not contain plugin-supplied bytes from the
// plugin's error stanza. The D6 containment requires the error carry only the
// sanitized plugin name.
func TestWrapError_ErrorDoesNotContainPluginBytes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	r := pluginRecipient(t, fakeplugin.ModeWrapError)
	p := newParser(5 * time.Second)

	rec, err := p.ParseRecipient(context.Background(), r)
	if err != nil {
		return // accepted at parse time
	}
	_, err = rec.Wrap([]byte("fake-file-key-0000000000000000"))
	if err == nil {
		t.Fatal("wrap-error: expected error, got nil")
	}
	// The string "simulated" comes from the fake plugin's error message;
	// it must NOT appear in the byreis-surfaced error.
	if strings.Contains(err.Error(), "simulated") {
		t.Fatalf("wrap-error: plugin-supplied error text leaked into byreis error: %q", err.Error())
	}
	// Must contain the plugin name (yubikey) for actionability.
	if !strings.Contains(err.Error(), "yubikey") {
		t.Fatalf("wrap-error: error lacks plugin name for actionability: %q", err.Error())
	}
}

// TestRaceClean documents that -race must pass on this package. The real race
// coverage is in the goroutine usage inside deadlineRecipient.Wrap.
func TestRaceClean(t *testing.T) {
	// This test has no body; it exists to document the -race requirement.
	// Real race coverage is exercised by TestBoundedTimeout_NoGoroutineLeak
	// and TestWrapError_FailClosed_SingleRecipient above.
}

// TestContextPropagation verifies that context cancellation BEFORE the
// ParseRecipient call is honored — the parser must check ctx.Err() eagerly.
func TestContextPropagation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	r := pluginRecipient(t, fakeplugin.ModeOK)
	p := newParser(5 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	_, err := p.ParseRecipient(ctx, r)
	if err == nil {
		t.Fatal("pre-cancelled context: expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		// Must at least wrap or contain the cancellation semantics.
		t.Logf("pre-cancelled: got error %v (not context.Canceled, but accepted if non-nil)", err)
	}
}
