// Command age-plugin-fakebyreis is a test-only age plugin binary that speaks
// the recipient-v1 and identity-v1 stdio state machines defined by the
// C2SP age-plugin protocol. It is driven by the FAKEPLUGIN_MODE environment
// variable and exercises every failure path that the recipientbuild and
// pluginidentity adapter tests need to cover without requiring real hardware.
//
// This binary is built by fakeplugin.BuildOnPath / fakeplugin.OnPath in
// TestMain and is NEVER compiled into the shipped byreis binary.
//
// Modes (set via FAKEPLUGIN_MODE):
//
//	ok             — well-behaved recipient-v1: wraps the file key and returns
//	                 a deterministic recipient-stanza. (happy wrap path)
//	ok-identity    — well-behaved identity-v1: unwraps the stanza and returns
//	                 the file key. (happy unwrap path)
//	wrap-error     — emits a protocol-level error stanza after receiving
//	                 wrap-file-key, then exits 3. (per-recipient failure / fail-closed)
//	identity-error — emits a protocol-level error stanza instead of file-key.
//	                 (unwrap failure)
//	malformed      — writes non-protocol garbage to stdout, then exits.
//	                 (adapter must error; fail-closed)
//	timeout        — blocks forever after reading from stdin.
//	                 (adapter's bounded-wait decorator must terminate it)
//	stderr-noise   — writes a marker byte sequence to stderr, then behaves
//	                 like "ok". (those bytes must never appear in logs/errors)
//
// The "missing" mode is modelled externally by simply not placing the binary
// on PATH; no code path inside this binary handles it.
//
// Recipient string: age1yubikey1<bech32-data>
// Identity string:  AGE-PLUGIN-YUBIKEY-1<bech32-data>
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// pluginName is the name registered with the age plugin framework. It matches
// the "yubikey" discriminator from validator.SupportedRecipientBackends and
// means the binary is found as "age-plugin-yubikey" on PATH.
const pluginName = "yubikey"

// stanzaType is the type tag used inside every recipient-stanza body written
// by the "ok" and "stderr-noise" modes. Keeping it fixed makes test assertions
// deterministic.
const stanzaType = "fakebyreis"

// StderrMarker is written verbatim to stderr in "stderr-noise" mode so tests
// can assert that this exact sequence never appears in byreis log/error output.
// Exported from main only conceptually — callers reference it via
// fakeplugin.StderrMarker in the helper package.
const stderrMarker = "FAKEPLUGIN_STDERR_NOISE_MARKER_7f3a9e"

func main() {
	mode := os.Getenv("FAKEPLUGIN_MODE")

	switch mode {
	case "timeout":
		// Block forever after receiving any input: the adapter's bounded-wait
		// decorator must detect the hang and return a bounded error.
		time.Sleep(365 * 24 * time.Hour)
		os.Exit(0)
	case "malformed":
		// Emit non-protocol garbage to stdout; the age library's stanza reader
		// will fail to parse it and the adapter must surface an error.
		_, _ = fmt.Fprintln(os.Stdout, "THIS IS NOT A VALID AGE PLUGIN STANZA @#$%^&*()")
		_, _ = fmt.Fprintln(os.Stdout, "MORE GARBAGE")
		os.Exit(1)
	case "env-echo":
		// Write names of all BYREIS_* and AGE* environment variables (without
		// their values) to the file whose path is in FAKEPLUGIN_ENVECHO_FILE,
		// then fall through to behave like "ok".
		if f := os.Getenv("FAKEPLUGIN_ENVECHO_FILE"); f != "" {
			writeEnvEcho(f)
		}
	}

	p, err := plugin.New(pluginName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "age-plugin-yubikey: failed to create plugin: %v\n", err)
		os.Exit(1)
	}

	switch mode {
	case "ok", "env-echo":
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			return &okRecipient{}, nil
		})

	case "ok-identity":
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			return &okRecipient{}, nil
		})
		p.HandleIdentity(func(data []byte) (age.Identity, error) {
			return &okIdentity{}, nil
		})

	case "wrap-error":
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			return &errorRecipient{}, nil
		})

	case "identity-error":
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			return &okRecipient{}, nil
		})
		p.HandleIdentity(func(data []byte) (age.Identity, error) {
			return &errorIdentity{}, nil
		})

	case "stderr-noise":
		// Write the marker to stderr before behaving normally. The test asserts
		// this sequence never appears in captured byreis stdout/stderr/log output.
		fmt.Fprint(os.Stderr, stderrMarker)
		p.HandleRecipient(func(data []byte) (age.Recipient, error) {
			return &okRecipient{}, nil
		})
		p.HandleIdentity(func(data []byte) (age.Identity, error) {
			return &okIdentity{}, nil
		})

	default:
		fmt.Fprintf(os.Stderr, "age-plugin-yubikey: unknown FAKEPLUGIN_MODE %q\n", mode)
		os.Exit(1)
	}

	os.Exit(p.Main())
}

// okRecipient wraps the file key into a deterministic stanza so tests can
// assert the stanza type without depending on any real crypto.
type okRecipient struct{}

func (r *okRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{
		Type: stanzaType,
		Body: fileKey, // echo the file key back verbatim (test-only shortcut)
	}}, nil
}

// okIdentity unwraps the first stanza whose Type matches stanzaType and
// returns its Body as the file key. This pairs with okRecipient.Wrap above.
type okIdentity struct{}

func (i *okIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		if s.Type == stanzaType {
			return s.Body, nil
		}
	}
	return nil, age.ErrIncorrectIdentity
}

// errorRecipient always returns an error from Wrap, driving the wrap-error
// protocol path (plugin emits an error stanza; caller must fail closed).
type errorRecipient struct{}

func (r *errorRecipient) Wrap(_ []byte) ([]*age.Stanza, error) {
	return nil, errors.New("simulated wrap failure from fake plugin")
}

// errorIdentity always returns an error from Unwrap, driving the
// identity-error protocol path.
type errorIdentity struct{}

func (i *errorIdentity) Unwrap(_ []*age.Stanza) ([]byte, error) {
	return nil, errors.New("simulated identity unwrap failure from fake plugin")
}

// writeEnvEcho writes the names (not values) of all environment variables
// whose names start with "BYREIS_" or "AGE" to the given file path, one name
// per line. This lets tests assert which secret variables, if any, were
// inherited from the parent byreis process.
func writeEnvEcho(path string) {
	f, err := os.Create(path) //nolint:gosec // path is test-supplied via env var; trusted in test context only
	if err != nil {
		fmt.Fprintf(os.Stderr, "age-plugin-yubikey env-echo: cannot create %s: %v\n", path, err)
		return
	}
	defer func() { _ = f.Close() }()
	for _, kv := range os.Environ() {
		name := kv
		if idx := strings.IndexByte(kv, '='); idx >= 0 {
			name = kv[:idx]
		}
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "BYREIS_") || strings.HasPrefix(upper, "AGE") {
			_, _ = fmt.Fprintln(f, name)
		}
	}
}
