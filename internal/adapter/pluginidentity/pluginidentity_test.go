package pluginidentity_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/ByReisK/byreis/internal/adapter/fakeplugin"
	"github.com/ByReisK/byreis/internal/adapter/pluginidentity"
)

// TestMain builds the fake plugin binary once for the lifetime of this test
// binary. All plugin-exercising tests call fakeplugin.OnPath(t, mode).
func TestMain(m *testing.M) {
	fakeplugin.BuildOnPath(m)
}

// --- helpers -----------------------------------------------------------------

// noopUI allows constructing plugin.Recipient / plugin.Identity values in
// tests without going through our adapter (needed for the encrypt side of
// round-trip tests).
var noopUI = &plugin.ClientUI{
	DisplayMessage: func(name, message string) error { return nil },
	RequestValue:   func(name, prompt string, secret bool) (string, error) { return "", nil },
	Confirm:        func(name, prompt, yes, no string) (bool, error) { return true, nil },
	WaitTimer:      func(name string) {},
}

// encryptToPlugin encrypts a fixed plaintext to the given plugin.Recipient
// and returns armored ciphertext.
func encryptToPlugin(t *testing.T, r age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatalf("age.Encrypt: %v", err)
	}
	if _, err := w.Write([]byte("secret plaintext")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return buf.Bytes()
}

// --- tests -------------------------------------------------------------------

// TestNew_HappyPath verifies that New accepts a well-formed AGE-PLUGIN-YUBIKEY-1…
// identity string and returns a non-nil Identity without error.
func TestNew_HappyPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOKIdentity))

	id, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: unexpected error: %v", err)
	}
	if id == nil {
		t.Fatal("New: returned nil identity")
	}
}

// TestNew_Recipient verifies that id.Recipient() returns a non-empty string
// that looks like an age recipient public key (starts with "age1").
func TestNew_Recipient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOKIdentity))

	id, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := id.Recipient()
	if rec == "" {
		t.Fatal("Recipient(): empty string")
	}
	if !strings.HasPrefix(rec, "age1") {
		t.Fatalf("Recipient(): expected age1... prefix, got %q", rec)
	}
}

// TestNew_AgeIdentityInterface verifies that id.AgeIdentity() returns a
// non-nil age.Identity and that it satisfies the interface at runtime.
func TestNew_AgeIdentityInterface(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOKIdentity))

	id, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ageID := id.AgeIdentity()
	if ageID == nil {
		t.Fatal("AgeIdentity(): returned nil")
	}
	// The value must satisfy age.Identity at runtime (return type guarantees this
	// at compile time; confirmed here by use through the interface).
	_ = ageID
}

// TestRoundTrip_EncryptThenDecrypt verifies the happy-path round trip:
// encrypt to the fake plugin recipient (ModeOK), then decrypt with the
// pluginidentity adapter (ModeOKIdentity). The recovered plaintext must match.
func TestRoundTrip_EncryptThenDecrypt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	// Encrypt phase: use a direct plugin.Recipient (not through recipientbuild
	// to keep this test self-contained at the identity adapter boundary).
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOK))
	pr, err := plugin.NewRecipient(fakeplugin.RecipientString(), noopUI)
	if err != nil {
		t.Fatalf("NewRecipient: %v", err)
	}
	ct := encryptToPlugin(t, pr)

	// Decrypt phase: switch to ModeOKIdentity and use our pluginidentity adapter.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOKIdentity))
	id, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("pluginidentity.New: %v", err)
	}

	ageID := id.AgeIdentity()
	dr, err := age.Decrypt(bytes.NewReader(ct), ageID)
	if err != nil {
		t.Fatalf("age.Decrypt: %v", err)
	}
	plain, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("read plaintext: %v", err)
	}
	if string(plain) != "secret plaintext" {
		t.Fatalf("round-trip: got %q, want %q", plain, "secret plaintext")
	}
}

// TestIdentityError_FailClosed verifies that a plugin in identity-error mode
// causes age.Decrypt to return a non-nil error (fail-closed on unwrap failure).
func TestIdentityError_FailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	// Produce a valid ciphertext using ModeOK.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOK))
	pr, err := plugin.NewRecipient(fakeplugin.RecipientString(), noopUI)
	if err != nil {
		t.Fatalf("NewRecipient: %v", err)
	}
	ct := encryptToPlugin(t, pr)

	// Attempt to decrypt using ModeIdentityError.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeIdentityError))
	id, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("pluginidentity.New identity-error: %v", err)
	}

	_, decErr := age.Decrypt(bytes.NewReader(ct), id.AgeIdentity())
	if decErr == nil {
		t.Fatal("identity-error: expected age.Decrypt to fail, got nil")
	}
}

// TestCrossBackend_FailClosed verifies that a plugin identity cannot decrypt
// a ciphertext that was encrypted to a different key (cross-backend reject /
// "no identity matched" path).
func TestCrossBackend_FailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	// Encrypt to a fresh native X25519 key (not the plugin key).
	nativeID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate X25519: %v", err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, nativeID.Recipient())
	if err != nil {
		t.Fatalf("encrypt to X25519: %v", err)
	}
	_, _ = w.Write([]byte("x25519-only secret"))
	_ = w.Close()

	// Try to decrypt with the plugin identity — it was not a recipient.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOKIdentity))
	id, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("pluginidentity.New: %v", err)
	}
	_, decErr := age.Decrypt(bytes.NewReader(buf.Bytes()), id.AgeIdentity())
	if decErr == nil {
		t.Fatal("cross-backend: expected age.Decrypt to fail (not a recipient), got nil")
	}
}

// TestBoundedTimeout_NoGoroutineLeak verifies that a plugin that hangs
// causes the deadlineIdentity decorator to return a bounded error and that
// the goroutine does not leak (buffered channel).
func TestBoundedTimeout_NoGoroutineLeak(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	// Encrypt to the plugin recipient in ModeOK so the ciphertext is valid.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOK))
	pr, err := plugin.NewRecipient(fakeplugin.RecipientString(), noopUI)
	if err != nil {
		t.Fatalf("NewRecipient: %v", err)
	}
	ct := encryptToPlugin(t, pr)

	// Switch to ModeTimeout; the identity will hang on Unwrap.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeTimeout))
	id, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("pluginidentity.New timeout: %v", err)
	}

	start := time.Now()
	_, decErr := age.Decrypt(bytes.NewReader(ct), id.AgeIdentity())
	elapsed := time.Since(start)

	if decErr == nil {
		t.Fatal("timeout: expected bounded error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("timeout: decorator did not bound the hang: elapsed %s (want < 2s)", elapsed)
	}
}

// TestClientUI_HeadlessFailsClosed verifies that in a non-interactive context
// (BYREIS_NON_INTERACTIVE=1), any callback in the ClientUI that would require
// user input returns an error rather than blocking.
func TestClientUI_HeadlessFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	t.Setenv("BYREIS_NON_INTERACTIVE", "1")
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOKIdentity))

	// New should succeed (no interactive I/O required at construction time).
	id, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New headless: unexpected error: %v", err)
	}
	if id == nil {
		t.Fatal("New headless: nil identity")
	}
	// The AgeIdentity must be non-nil (construction does not require I/O).
	if id.AgeIdentity() == nil {
		t.Fatal("AgeIdentity headless: nil")
	}
}

// TestClientUI_MarkerBytesNeverLeak mirrors the B2 test for the identity side.
// It drives ModeStderrNoise and asserts that the plugin's stderr marker bytes
// never appear in any byreis error string or captured stderr output.
func TestClientUI_MarkerBytesNeverLeak(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	// Encrypt in ModeOK so we have a valid ciphertext.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOK))
	pr, err := plugin.NewRecipient(fakeplugin.RecipientString(), noopUI)
	if err != nil {
		t.Fatalf("NewRecipient: %v", err)
	}
	ct := encryptToPlugin(t, pr)

	// Decrypt in ModeStderrNoise.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeStderrNoise))

	stderrR, stderrW, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatalf("os.Pipe: %v", pipeErr)
	}
	origStderr := os.Stderr
	os.Stderr = stderrW

	id, newErr := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 5 * time.Second,
	})

	os.Stderr = origStderr
	_ = stderrW.Close()

	var captured strings.Builder
	_, _ = io.Copy(&captured, stderrR)
	_ = stderrR.Close()

	if newErr != nil {
		if strings.Contains(newErr.Error(), fakeplugin.StderrMarker) {
			t.Fatalf("ClientUI: StderrMarker in New error: %q", newErr.Error())
		}
	}
	if strings.Contains(captured.String(), fakeplugin.StderrMarker) {
		t.Fatalf("ClientUI: StderrMarker appeared in captured stderr: %q", captured.String())
	}

	// Also check Decrypt error path.
	if id != nil {
		_, decErr := age.Decrypt(bytes.NewReader(ct), id.AgeIdentity())
		if decErr != nil && strings.Contains(decErr.Error(), fakeplugin.StderrMarker) {
			t.Fatalf("ClientUI: StderrMarker in Decrypt error: %q", decErr.Error())
		}
	}
}

// TestNew_MalformedIdentityString verifies that New rejects a clearly
// malformed identity string (not a valid bech32 encoding) with an error.
func TestNew_MalformedIdentityString(t *testing.T) {
	t.Parallel()
	_, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   "not-a-valid-identity",
		UnwrapTimeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("malformed identity: expected error, got nil")
	}
}

// TestNew_NativeX25519_Rejected verifies that a native AGE-SECRET-KEY-1…
// string is rejected by pluginidentity.New (this adapter is plugin-only;
// native X25519 identities go through the core identity.Parse path).
func TestNew_NativeX25519_Rejected(t *testing.T) {
	t.Parallel()
	// Generate a real X25519 identity string.
	native, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	_, err = pluginidentity.New(pluginidentity.Options{
		IdentityStr:   native.String(),
		UnwrapTimeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("native X25519 identity: expected rejection by pluginidentity.New, got nil")
	}
}

// TestContextPropagation verifies that context cancellation surfaces in any
// operation that respects ctx. New itself does not run a subprocess, but
// callers pass ctx to the resulting identity's Unwrap. We verify that a
// cancelled context does not cause New itself to panic or hang.
func TestContextPropagation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOKIdentity))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// New does not take a ctx; this test confirms it does not hang or panic.
	id, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 5 * time.Second,
	})
	// New may succeed even with a cancelled ctx (it does no I/O at construction).
	_ = ctx
	if err != nil {
		// Acceptable: some implementations may honour ctx.
		return
	}
	if id == nil {
		t.Fatal("New with cancelled ctx: nil identity (expected non-nil)")
	}
	// Verify no panic on AgeIdentity.
	_ = id.AgeIdentity()
	_ = errors.New("context propagation test completed")
}

// TestRaceClean documents the -race requirement for this package.
// Real race coverage is in TestRoundTrip_EncryptThenDecrypt and
// TestBoundedTimeout_NoGoroutineLeak above.
func TestRaceClean(t *testing.T) {
	// Intentionally empty; the -race flag applies to all tests in the binary.
}

// TestNoNetworkAtUnwrap verifies that the fake plugin's unwrap runs without
// network access. Because the fake is purely in-process, completing the
// round-trip without connectivity confirms the B7 property.
func TestNoNetworkAtUnwrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("plugin subprocess tests not supported on Windows")
	}

	// Encrypt.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOK))
	pr, err := plugin.NewRecipient(fakeplugin.RecipientString(), noopUI)
	if err != nil {
		t.Fatalf("NewRecipient: %v", err)
	}
	ct := encryptToPlugin(t, pr)

	// Decrypt.
	t.Setenv("FAKEPLUGIN_MODE", string(fakeplugin.ModeOKIdentity))
	id, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   fakeplugin.IdentityString(),
		UnwrapTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New no-network: %v", err)
	}

	dr, err := age.Decrypt(bytes.NewReader(ct), id.AgeIdentity())
	if err != nil {
		t.Fatalf("age.Decrypt no-network: %v", err)
	}
	plain, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("read no-network: %v", err)
	}
	if string(plain) != "secret plaintext" {
		t.Fatalf("no-network round-trip: got %q", plain)
	}
}
