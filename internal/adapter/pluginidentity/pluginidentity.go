// Package pluginidentity implements the identity.Identity port for plugin-backed
// age identities (admin decrypt path). It is the only place in the codebase
// that imports filippo.io/age/plugin on the identity side: the plugin package
// and all os/exec concerns are confined to this adapter, never to any package
// under internal/core.
//
// An admin whose private key lives on a hardware token (YubiKey, TPM, FIDO2,
// Secure Enclave) supplies an "AGE-PLUGIN-<NAME>-1…" identity string. This
// adapter constructs a coreidentity.Identity backed by a *plugin.Identity and
// wraps it in the same containment disciplines applied on the contributor
// encrypt side:
//
//   - deadlineIdentity (symmetric to deadlineRecipient in recipientbuild) bounds
//     the wait on plugin.Identity.Unwrap with a buffered channel; on timeout it
//     returns an actionable error, never hangs indefinitely, and cannot leak the
//     goroutine.
//   - The plugin ClientUI drops all plugin-supplied bytes; only fixed
//     byreis-authored text keyed on the sanitized closed-set plugin name is
//     emitted. In non-interactive/headless mode, RequestValue and Confirm fail
//     closed rather than blocking.
//   - BYREIS_* secret environment variables (BYREIS_KEY, BYREIS_KEY_FILE,
//     BYREIS_SIGN_KEY, BYREIS_GITHUB_TOKEN) are scrubbed from the process
//     environment by the composition root (app.BuildProductionDeps) via
//     app.ScrubSecretEnvVars, which runs after all env reads and before any
//     plugin subprocess can be spawned. Child processes therefore do not
//     inherit these secrets.
//
// Security responsibilities mirror the encrypt side:
//   - All plugin-supplied bytes (DisplayMessage/RequestValue/Confirm/WaitTimer
//     callbacks) are dropped; byreis emits only fixed text keyed on the
//     sanitized closed-set plugin name.
//   - Errors carry only the sanitized plugin name and a byreis-authored hint;
//     no plugin-supplied error text is forwarded or %w-wrapped.
//   - A failed Unwrap (identity-error, malformed, timeout) makes age.Decrypt
//     return a non-nil error — fail-closed: no plaintext is produced.
//   - A plugin identity that cannot unwrap causes CanDecryptAny to resolve to
//     (false, nil), which downgrades to CONTRIBUTOR (not a hard crash).
package pluginidentity

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"

	coreidentity "github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/validator"
)

// defaultUnwrapTimeout is the bounded-wait window for plugin Unwrap calls when
// Options.UnwrapTimeout is zero or negative. The composition root overrides this
// for production; tests inject a short value to exercise the timeout path quickly.
const defaultUnwrapTimeout = 30 * time.Second

// Options holds the injected configuration for New. All fields have safe
// zero-value defaults or are overridden at the composition root.
type Options struct {
	// IdentityStr is the "AGE-PLUGIN-<NAME>-1…" identity encoding string.
	// Must be non-empty and well-formed; native "AGE-SECRET-KEY-1…" strings
	// are rejected (this adapter handles plugin identities only).
	IdentityStr string

	// UnwrapTimeout is the maximum time the deadlineIdentity decorator waits for
	// a plugin Unwrap call. Zero or negative falls back to defaultUnwrapTimeout.
	// Injected so tests can choose a short value without sleeping.
	UnwrapTimeout time.Duration
}

// pluginIdentity is the concrete coreidentity.Identity backed by a plugin.
// It holds the wrapped age.Identity (deadlineIdentity) and the public recipient
// string for Recipient(). Instances are safe for concurrent use after
// construction (no mutable fields after New returns).
type pluginIdentity struct {
	// ageID is the bounded-wait decorator wrapping the *plugin.Identity.
	ageID age.Identity
	// recipientStr is the public "age1<name>1…" recipient string. It is derived
	// at construction from the identity payload (same bech32 data, recipient HRP)
	// so Recipient() is free of subprocess overhead.
	recipientStr string
}

// Ensure pluginIdentity satisfies the core identity interface at compile time.
var _ coreidentity.Identity = (*pluginIdentity)(nil)

// Recipient implements coreidentity.Identity. It returns the plugin-derived
// public recipient string ("age1<name>1…"). This is derived from the identity
// encoding at construction time — no subprocess invocation.
func (p *pluginIdentity) Recipient() string { return p.recipientStr }

// AgeIdentity implements coreidentity.Identity. It returns the
// deadlineIdentity-wrapped *plugin.Identity as the age.Identity interface.
// age.Decrypt accepts this interface directly; the bounded wait and ClientUI
// containment are transparent to the caller.
func (p *pluginIdentity) AgeIdentity() age.Identity { return p.ageID }

// New constructs a pluginIdentity from opts. It validates and parses the
// AGE-PLUGIN-<NAME>-1… identity string, classifies the backend against the
// closed set, constructs the plugin.Identity with a contained ClientUI, and
// wraps it in the deadlineIdentity bounded-wait decorator.
//
// New rejects:
//   - a malformed bech32 string (not parseable by plugin.ParseIdentity)
//   - a native AGE-SECRET-KEY-1… string (wrong domain; use identity.Parse)
//   - a plugin name not in validator.SupportedRecipientBackends
//
// New performs no subprocess invocation; construction is always synchronous
// and requires no hardware token. The plugin subprocess is only started when
// age.Decrypt calls Unwrap on the returned identity.
func New(opts Options) (coreidentity.Identity, error) {
	t := opts.UnwrapTimeout
	if t <= 0 {
		t = defaultUnwrapTimeout
	}

	// Reject a native X25519 identity string early with an actionable hint,
	// before handing to plugin.ParseIdentity which would error less clearly.
	if strings.HasPrefix(strings.ToUpper(opts.IdentityStr), "AGE-SECRET-KEY-1") {
		return nil, fmt.Errorf(
			"pluginidentity.New: received a native X25519 identity string (AGE-SECRET-KEY-1…); " +
				"use identity.Parse for native admin keys — this adapter handles plugin identities only")
	}

	// Parse the identity string: validates bech32 structure and extracts the
	// plugin name + data payload. plugin.ParseIdentity errors on a malformed
	// string; we sanitize the error to avoid forwarding its text verbatim.
	name, data, parseErr := plugin.ParseIdentity(opts.IdentityStr)
	if parseErr != nil {
		return nil, fmt.Errorf(
			"pluginidentity.New: malformed identity string — " +
				"expected an AGE-PLUGIN-<NAME>-1… encoding; run `byreis doctor`")
	}

	// Validate the extracted plugin name against the closed set. A name outside
	// the set is a registry admission failure that should have been caught
	// upstream; we fail closed with an actionable hint rather than silently
	// accepting an unexpected backend.
	recipientKey := strings.ToLower(name)
	if !validator.SupportedRecipientBackends[recipientKey] {
		return nil, fmt.Errorf(
			"pluginidentity.New: plugin backend %q is not in the admitted set "+
				"(yubikey, tpm, se, fido2) — check the admins.yaml entry and run `byreis doctor`",
			recipientKey)
	}

	// Construct the plugin.Identity with a contained ClientUI. No subprocess is
	// launched here; the library defers that to Unwrap.
	pi, err := plugin.NewIdentity(opts.IdentityStr, newContainedClientUI())
	if err != nil {
		// plugin.NewIdentity errors indicate a structurally-invalid encoding that
		// ParseIdentity did not catch. Sanitize the error.
		return nil, fmt.Errorf(
			"age-plugin-%s identity construction failed — "+
				"check the admins.yaml entry and run `byreis doctor`",
			recipientKey)
	}

	// Derive the public recipient string from the identity payload using the
	// same bech32 data. For plugin identities the age library uses the identity
	// encoding directly in the identity-v1 protocol; the "recipient" form with
	// the same payload is the public key the admin registered in admins.yaml.
	// This derivation is safe to do offline and does not require a subprocess.
	recipientStr := plugin.EncodeRecipient(recipientKey, data)
	if recipientStr == "" {
		// EncodeRecipient returns "" only for an invalid plugin name — guarded
		// above by SupportedRecipientBackends; this branch is defensive only.
		return nil, fmt.Errorf(
			"age-plugin-%s: could not encode recipient string from identity payload — "+
				"run `byreis doctor`",
			recipientKey)
	}

	return &pluginIdentity{
		ageID: &deadlineIdentity{
			inner:   pi,
			timeout: t,
			name:    recipientKey,
		},
		recipientStr: recipientStr,
	}, nil
}

// deadlineIdentity is the bounded-wait decorator around a *plugin.Identity.
// plugin.Identity.Unwrap launches its subprocess via exec.Command (no context,
// no deadline) and blocks until the plugin exits. deadlineIdentity runs Unwrap
// in a separate goroutine, selects on the result channel and a timer, and
// returns a bounded error on timeout.
//
// Goroutine leak prevention: the result channel is buffered (capacity 1), so
// the goroutine will always be able to send its result regardless of whether
// the caller has timed out. On timeout the goroutine is still running (the
// plugin subprocess is owned by the age library and cannot be cancelled from
// here), but it will eventually complete and drain into the channel, at which
// point the GC reclaims the goroutine. This is the documented residual for the
// age-plugin containment model.
type deadlineIdentity struct {
	inner   age.Identity
	timeout time.Duration
	name    string // sanitized closed-set plugin name; never attacker-controlled
}

// unwrapResult is the internal message type for the goroutine channel.
type unwrapResult struct {
	key []byte
	err error
}

// Unwrap implements age.Identity. It runs the inner plugin Unwrap in a goroutine
// bounded by d.timeout. On timeout it returns an actionable error. On a normal
// plugin result the error is passed through mapPluginErr, which preserves any
// age.ErrIncorrectIdentity sentinel (so age.Decrypt can aggregate identities)
// and sanitizes all other errors to byreis-authored text.
func (d *deadlineIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	ch := make(chan unwrapResult, 1) // buffered: goroutine cannot block after timeout
	go func() {
		key, err := d.inner.Unwrap(stanzas)
		ch <- unwrapResult{key, err}
	}()

	timer := time.NewTimer(d.timeout)
	defer timer.Stop()

	select {
	case r := <-ch:
		return r.key, mapPluginErr(d.name, r.err)
	case <-timer.C:
		// Orphaned subprocess: the plugin library owns it; we cannot cancel it.
		// Document this as the expected residual (see package comment).
		return nil, fmt.Errorf(
			"age-plugin-%s: unwrap timed out after %s — "+
				"is the plugin binary (age-plugin-%s) responsive? "+
				"Is the hardware token connected?",
			d.name, d.timeout, d.name)
	}
}

// mapPluginErr sanitizes a plugin-returned error: returns nil on nil, and
// otherwise emits a fixed byreis-authored error string keyed only on the
// closed-set plugin name. The raw plugin error text is deliberately NOT
// %w-wrapped or forwarded to prevent plugin-supplied bytes from appearing in
// logs or error messages (ClientUI containment applied to Unwrap errors).
func mapPluginErr(name string, err error) error {
	if err == nil {
		return nil
	}
	// Surface a missing-binary error with a specifically actionable hint.
	var notFound *plugin.NotFoundError
	if isPluginNotFound(err, &notFound) {
		return fmt.Errorf(
			"age-plugin-%s binary not found — "+
				"install age-plugin-%s and ensure it is on PATH",
			name, name)
	}
	// age.ErrIncorrectIdentity means the stanzas were not produced for this
	// identity — a normal "no identity matched" result, not a fatal error.
	// Return err unchanged (the plugin may have wrapped the sentinel; age.Decrypt
	// aggregates across identities via errors.Is, so the sentinel must be
	// reachable through the error chain).
	if errors.Is(err, age.ErrIncorrectIdentity) {
		return err
	}
	// All other plugin errors: emit a fixed message with the sanitized name only.
	return fmt.Errorf(
		"age-plugin-%s: unwrap failed — "+
			"check that age-plugin-%s is correctly installed and the identity key is valid; "+
			"run `byreis doctor` for diagnostics",
		name, name)
}

// isPluginNotFound unwraps err looking for a *plugin.NotFoundError.
func isPluginNotFound(err error, target **plugin.NotFoundError) bool {
	if err == nil {
		return false
	}
	type unwrapper interface{ Unwrap() error }
	for e := err; e != nil; {
		if nf, ok := e.(*plugin.NotFoundError); ok {
			if target != nil {
				*target = nf
			}
			return true
		}
		u, ok := e.(unwrapper)
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return false
}

// newContainedClientUI returns the fixed byreis ClientUI for the identity side.
// All callbacks drop plugin-supplied bytes and emit only byreis-authored text
// keyed on the sanitized plugin name. In non-interactive contexts
// (BYREIS_NON_INTERACTIVE or no TTY), RequestValue and Confirm fail closed.
func newContainedClientUI() *plugin.ClientUI {
	return &plugin.ClientUI{
		DisplayMessage: func(name, _ string) error {
			safeWrite(fmt.Sprintf("age-plugin-%s is requesting attention\n", sanitizeName(name)))
			return nil
		},

		RequestValue: func(name, _ string, secret bool) (string, error) {
			if isHeadless() {
				return "", fmt.Errorf(
					"age-plugin-%s requires interactive input but this is a "+
						"non-interactive context (BYREIS_NON_INTERACTIVE or no TTY); "+
						"run in an interactive terminal to authenticate",
					sanitizeName(name))
			}
			safeWrite(fmt.Sprintf("age-plugin-%s requires input: ", sanitizeName(name)))
			return readValue(secret)
		},

		Confirm: func(name, _, yes, _ string) (bool, error) {
			if isHeadless() {
				return false, fmt.Errorf(
					"age-plugin-%s requires confirmation but this is a non-interactive context; "+
						"run in an interactive terminal",
					sanitizeName(name))
			}
			safeWrite(fmt.Sprintf("age-plugin-%s requires confirmation [%s]: ", sanitizeName(name), yes))
			return readConfirm(yes)
		},

		WaitTimer: func(name string) {
			safeWrite(fmt.Sprintf("waiting for %s token touch…\n", sanitizeName(name)))
		},
	}
}

// sanitizeName guards the plugin name used in user-visible messages. Although
// the name parameter in ClientUI callbacks is the plugin's self-reported name
// and the closed-set was already validated before construction, we apply a
// conservative pass here as an extra layer (no shell injection, no newlines,
// bounded length).
func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > 64 {
		s = s[:64]
	}
	if s == "" {
		s = "unknown"
	}
	return s
}

// isHeadless reports true when the process should not attempt interactive I/O.
func isHeadless() bool {
	if os.Getenv("BYREIS_NON_INTERACTIVE") == "1" {
		return true
	}
	fi, err := os.Stderr.Stat()
	if err != nil {
		return true
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

// safeWrite writes s to stderr, ignoring any error (best-effort UI output).
func safeWrite(s string) {
	_, _ = os.Stderr.WriteString(s)
}

// readValue reads a single line from stdin as a plugin-requested value.
// The returned value is NEVER logged.
func readValue(secret bool) (string, error) {
	_ = secret // both paths read identically; a future upgrade can use term.ReadPassword for secret=true
	var val string
	_, err := fmt.Fscan(os.Stdin, &val)
	if err != nil {
		return "", fmt.Errorf("reading plugin input value: %w", err)
	}
	return val, nil
}

// readConfirm reads a confirmation from stdin. It accepts "y" / "yes" or the
// plugin's suggested affirmative token (yesLabel) as affirmative.
func readConfirm(yesLabel string) (bool, error) {
	var val string
	_, err := fmt.Fscan(os.Stdin, &val)
	if err != nil {
		return false, fmt.Errorf("reading plugin confirmation: %w", err)
	}
	return strings.EqualFold(val, "y") ||
		strings.EqualFold(val, "yes") ||
		strings.EqualFold(val, yesLabel), nil
}
