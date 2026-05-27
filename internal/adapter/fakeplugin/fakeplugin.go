// Package fakeplugin provides test infrastructure for the age-plugin adapter
// surface in byreis. It builds a protocol-faithful fake age plugin binary
// (speaking the C2SP recipient-v1 and identity-v1 stdio state machines) and
// places it on PATH so tests can exercise real os/exec subprocess wrap and
// unwrap without requiring any hardware token.
//
// The binary is NEVER compiled into the shipped byreis binary. It lives
// under internal/adapter/fakeplugin and is only built by test code.
//
// Typical use in TestMain:
//
//	func TestMain(m *testing.M) {
//	    fakeplugin.BuildOnPath(m)
//	}
//
// Individual tests drive a specific mode:
//
//	recipientStr := fakeplugin.OnPath(t, fakeplugin.ModeOK)
//	// recipientStr is a well-formed age1yubikey1... string
//
// The "missing" mode is handled externally: instead of calling OnPath, simply
// do not call it. The absence of the binary on PATH produces a
// plugin.NotFoundError from the age library, which the adapter must surface
// with an actionable hint.
package fakeplugin

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"filippo.io/age/plugin"
)

// Mode selects the fake plugin's behaviour for a test. It is passed via the
// FAKEPLUGIN_MODE environment variable to the subprocess.
type Mode string

const (
	// ModeOK is a well-behaved recipient-v1 plugin: accept add-recipient +
	// wrap-file-key, emit a deterministic recipient-stanza, write "done".
	ModeOK Mode = "ok"

	// ModeOKIdentity is a well-behaved identity-v1 plugin: accept add-identity
	// + recipient-stanza, emit the file key, write "done". It also handles
	// recipient-v1 so an artifact encrypted in ModeOK can be decrypted by
	// ModeOKIdentity.
	ModeOKIdentity Mode = "ok-identity"

	// ModeWrapError causes the plugin to emit an error stanza after receiving
	// wrap-file-key, then exit 3. Tests assert no artifact is written
	// (multi-recipient fail-closed).
	ModeWrapError Mode = "wrap-error"

	// ModeIdentityError causes the plugin to emit an error stanza instead of a
	// file-key stanza during identity-v1. Tests assert the decrypt call fails.
	ModeIdentityError Mode = "identity-error"

	// ModeMalformed causes the plugin to write non-protocol garbage to stdout
	// and exit. The age library's stanza reader will fail and the adapter must
	// surface an error (fail-closed).
	ModeMalformed Mode = "malformed"

	// ModeTimeout causes the plugin to block forever after reading from stdin.
	// The adapter's bounded-wait decorator (deadlineRecipient / deadlineIdentity)
	// must terminate and return an actionable bounded error.
	ModeTimeout Mode = "timeout"

	// ModeStderrNoise causes the plugin to write StderrMarker to stderr before
	// behaving like ModeOK. Tests assert the marker never appears in captured
	// byreis stdout/stderr/log output (ClientUI containment).
	ModeStderrNoise Mode = "stderr-noise"

	// ModeEnvEcho causes the plugin to write a newline-separated list of all
	// environment variable names (without values) that start with "BYREIS_" or
	// "AGE" to the file path given by FAKEPLUGIN_ENVECHO_FILE, then behave
	// like ModeOK. Tests assert that secret BYREIS_* names are absent from
	// that file, proving the composition root scrubbed them before the subprocess
	// was spawned.
	ModeEnvEcho Mode = "env-echo"
)

// PluginName is the age plugin name used by the fake. The binary is placed on
// PATH as "age-plugin-yubikey" and recipient strings carry the HRP "age1yubikey".
// This aligns with the "yubikey" entry in validator.SupportedRecipientBackends.
const PluginName = "yubikey"

// StderrMarker is the exact byte sequence the fake writes to stderr in
// ModeStderrNoise. Tests assert this string never appears in any byreis
// output, log, or error string.
const StderrMarker = "FAKEPLUGIN_STDERR_NOISE_MARKER_7f3a9e"

// EnvEchoFileEnvVar is the name of the environment variable that ModeEnvEcho
// reads to determine where to write the env-echo output file. The value must
// be set by the test (via t.Setenv) before spawning the plugin subprocess.
const EnvEchoFileEnvVar = "FAKEPLUGIN_ENVECHO_FILE"

// binaryName is the filename placed on PATH.
const binaryName = "age-plugin-" + PluginName

// builtBinaryDir holds the directory where BuildOnPath placed the binary.
// It is set once by BuildOnPath (called from TestMain) and read by OnPath.
var builtBinaryDir string

// BuildOnPath builds the fake plugin binary and installs it into a temporary
// directory, then prepends that directory to PATH for the lifetime of the test
// binary. It must be called from TestMain; it calls m.Run() internally and
// passes the exit code to os.Exit.
//
// Pattern:
//
//	func TestMain(m *testing.M) {
//	    fakeplugin.BuildOnPath(m)
//	}
func BuildOnPath(m *testing.M) {
	if runtime.GOOS == "windows" {
		// Windows plugin support is a known gap in filippo.io/age/plugin.
		// Skip build; tests that require the fake will skip themselves.
		os.Exit(m.Run())
	}

	dir, err := os.MkdirTemp("", "fakeplugin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "fakeplugin: failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := buildBinary(dir); err != nil {
		fmt.Fprintf(os.Stderr, "fakeplugin: failed to build plugin binary: %v\n", err)
		os.Exit(1)
	}

	builtBinaryDir = dir
	origPATH := os.Getenv("PATH")
	if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+origPATH); err != nil {
		fmt.Fprintf(os.Stderr, "fakeplugin: failed to set PATH: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// OnPath sets the FAKEPLUGIN_MODE environment variable to mode for the test t
// (via t.Setenv, which restores the original value on test cleanup) and returns
// the well-formed age plugin recipient string for PluginName.
//
// If BuildOnPath was not called (e.g. the test binary was not built with
// TestMain using fakeplugin.BuildOnPath), OnPath calls t.Skip with an
// informative message.
//
// The returned recipient string is a bech32-encoded "age1yubikey1..." value
// that plugin.NewRecipient will accept.
func OnPath(t *testing.T, mode Mode) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fakeplugin: age plugin subprocess tests not supported on Windows")
	}
	if builtBinaryDir == "" {
		t.Skip("fakeplugin: binary not built; call fakeplugin.BuildOnPath(m) in TestMain")
	}
	t.Setenv("FAKEPLUGIN_MODE", string(mode))
	return RecipientString()
}

// RecipientString returns the well-formed bech32 recipient string for the fake
// plugin (age1yubikey1...). The payload encodes a fixed 1-byte test marker so
// the string is non-trivial but deterministic.
func RecipientString() string {
	// Encode a fixed 1-byte payload. The value is arbitrary; it must be
	// non-empty so bech32 produces a non-trivial checksum.
	s := plugin.EncodeRecipient(PluginName, []byte{0x42})
	return s
}

// IdentityString returns the well-formed AGE-PLUGIN-YUBIKEY-1... identity
// string for the fake plugin. Pair with RecipientString() for round-trip tests.
func IdentityString() string {
	s := plugin.EncodeIdentity(PluginName, []byte{0x42})
	return s
}

// buildBinary compiles the fake plugin main package into dir/age-plugin-yubikey.
func buildBinary(dir string) error {
	// Determine the source path of the main package by locating this file at
	// runtime. This is robust to the module being checked out under any path.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return fmt.Errorf("fakeplugin: could not determine source file location")
	}
	// thisFile is .../internal/adapter/fakeplugin/fakeplugin.go
	// mainPkg is   .../internal/adapter/fakeplugin/main
	mainSrcDir := filepath.Join(filepath.Dir(thisFile), "main")

	out := filepath.Join(dir, binaryName)
	// A build-only context with a generous timeout; the context is not
	// threaded into the child (go build ignores -context), so we use
	// CommandContext purely for the deadline, not for cancellation semantics.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, mainSrcDir) //nolint:gosec // controlled argv: go build with a fixed source path
	cmd.Stdout = os.Stderr                                                // build output goes to test stderr for diagnostics
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go build %s: %w", mainSrcDir, err)
	}
	return nil
}
