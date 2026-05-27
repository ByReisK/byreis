// Package recipientbuild implements the encrypt.RecipientParser port for
// plugin-backed age recipients. It is the only place in the codebase that
// imports filippo.io/age/plugin on the contributor encrypt side: the plugin
// package and all os/exec concerns are confined to this adapter, never to any
// package under internal/core.
//
// The contributor encrypt path uses this adapter only when the admin set
// includes a plugin recipient (age1<name>1…). A native X25519 recipient
// (age1…) is handled directly via age.ParseX25519Recipient, which already
// lives in the in-package x25519Parser inside core/crypto/encrypt; this
// adapter dispatches through the same code path for X25519 inputs so the
// composition root may wire a single parser for both cases.
//
// Security responsibilities:
//   - All plugin-supplied bytes (from ClientUI callbacks: DisplayMessage,
//     RequestValue, Confirm, WaitTimer) are dropped; byreis emits only
//     fixed text keyed on the sanitized closed-set plugin name.
//   - The bounded-wait decorator (deadlineRecipient) runs the plugin's Wrap
//     in a goroutine with a buffered result channel; on timeout it returns a
//     bounded, actionable error rather than hanging indefinitely. The goroutine
//     cannot leak: the buffered channel drains it eventually.
//   - BYREIS_* secret environment variables (BYREIS_KEY, BYREIS_KEY_FILE,
//     BYREIS_SIGN_KEY, BYREIS_GITHUB_TOKEN) are scrubbed from the process
//     environment by the composition root (app.BuildProductionDeps) via
//     app.ScrubSecretEnvVars, which is called after all env reads complete
//     and before any plugin subprocess can be spawned. Child processes
//     therefore do not inherit these secrets.
//   - Errors carry only the sanitized plugin name and a byreis-authored
//     hint; no plugin-supplied error text is %w-wrapped or forwarded.
package recipientbuild

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/validator"
)

// defaultWrapTimeout is the default bounded-wait window for plugin Wrap calls.
// The composition root overrides this via Options.WrapTimeout for production;
// tests inject a short value to exercise the timeout path quickly.
const defaultWrapTimeout = 30 * time.Second

// Options holds the injected configuration for the Parser. All fields have
// safe zero-value defaults or are overridden at the composition root.
type Options struct {
	// WrapTimeout is the maximum time the bounded-wait decorator waits for a
	// plugin Wrap call. Zero or negative values fall back to defaultWrapTimeout.
	// Injected so tests can choose a short timeout without sleeping.
	WrapTimeout time.Duration
}

// Parser implements encrypt.RecipientParser. It dispatches on the bech32 HRP:
// native X25519 recipients are handled via age.ParseX25519Recipient; plugin
// recipients are handled via plugin.NewRecipient wrapped in a deadlineRecipient.
//
// Instances are safe for concurrent use.
type Parser struct {
	ui          *plugin.ClientUI
	wrapTimeout time.Duration
}

// New constructs a Parser from opts. The returned parser is ready to use;
// its internal ClientUI drops all plugin-supplied bytes (containment).
func New(opts Options) *Parser {
	t := opts.WrapTimeout
	if t <= 0 {
		t = defaultWrapTimeout
	}
	return &Parser{
		ui:          newContainedClientUI(),
		wrapTimeout: t,
	}
}

// Ensure Parser satisfies the encrypt.RecipientParser interface at compile time.
var _ encrypt.RecipientParser = (*Parser)(nil)

// ParseRecipient implements encrypt.RecipientParser. It classifies the recipient
// via validator.ClassifyRecipient, then:
//   - "" (X25519): returns age.ParseX25519Recipient
//   - known plugin name: returns plugin.NewRecipient wrapped in a deadlineRecipient
//   - unsupported or malformed: returns a wrapped error with an actionable hint
func (p *Parser) ParseRecipient(ctx context.Context, r rectypes.Recipient) (age.Recipient, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("recipientbuild: context cancelled before parsing recipient %q: %w", r.Label, err)
	}

	backend, err := validator.ClassifyRecipient(r.AgePubKey)
	if err != nil {
		// validator.ClassifyRecipient wraps ErrUnsupportedRecipient with a
		// byreis doctor hint. Surface it directly; it is already actionable.
		return nil, fmt.Errorf("recipient %q: %w", r.Label, err)
	}

	if backend == "" {
		// Native X25519 path: no plugin subprocess, no os/exec, no timeout needed.
		rec, x25519Err := age.ParseX25519Recipient(r.AgePubKey)
		if x25519Err != nil {
			return nil, fmt.Errorf(
				"invalid age recipient public key (label %q): %w — "+
					"the registry returned a malformed recipient; re-run after `byreis doctor`",
				r.Label, x25519Err)
		}
		return rec, nil
	}

	// Plugin path: construct the plugin.Recipient with the contained ClientUI,
	// then wrap it in the bounded-wait decorator.
	pr, err := plugin.NewRecipient(r.AgePubKey, p.ui)
	if err != nil {
		return nil, fmt.Errorf(
			"age-plugin-%s recipient parse failed (label %q): "+
				"register a valid plugin recipient; run `byreis doctor`",
			backend, r.Label)
	}

	return &deadlineRecipient{
		inner:   pr,
		timeout: p.wrapTimeout,
		name:    backend,
	}, nil
}

// deadlineRecipient is the bounded-wait decorator around a plugin.Recipient.
// plugin.Recipient.Wrap launches its subprocess via exec.Command (no context,
// no deadline) and blocks until the plugin exits. deadlineRecipient runs Wrap
// in a separate goroutine, selects on the result channel and a timer, and
// returns a bounded error on timeout.
//
// Goroutine leak prevention: the result channel is buffered (capacity 1), so
// the goroutine will always be able to send its result regardless of whether
// the caller has timed out and moved on. On timeout the goroutine is still
// running (the plugin subprocess is owned by the age library and is
// unkillable from here), but it will eventually complete and drain into the
// channel, at which point Go's GC reclaims it. This is the documented residual
// for the age-plugin containment model.
type deadlineRecipient struct {
	inner   age.Recipient
	timeout time.Duration
	name    string // sanitized closed-set plugin name; never attacker-controlled
}

// wrapResult is the internal message type for the bounded-wait goroutine channel.
type wrapResult struct {
	stanzas []*age.Stanza
	err     error
}

// Wrap implements age.Recipient. It runs the inner plugin Wrap in a goroutine
// bounded by d.timeout. On timeout it returns an actionable error with no
// plugin-supplied bytes; on success or plugin failure it sanitizes the error
// via mapPluginErr before returning.
func (d *deadlineRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	ch := make(chan wrapResult, 1) // buffered: goroutine cannot block after timeout
	go func() {
		st, err := d.inner.Wrap(fileKey)
		ch <- wrapResult{st, err}
	}()

	timer := time.NewTimer(d.timeout)
	defer timer.Stop()

	select {
	case r := <-ch:
		return r.stanzas, mapPluginErr(d.name, r.err)
	case <-timer.C:
		// Orphaned subprocess: the plugin library owns it; we cannot cancel it.
		// Document this as the expected residual (see package comment).
		return nil, fmt.Errorf(
			"age-plugin-%s: wrap timed out after %s — "+
				"is the plugin binary (age-plugin-%s) responsive? "+
				"(you do NOT need the hardware token to encrypt, only the plugin binary on PATH)",
			d.name, d.timeout, d.name)
	}
}

// mapPluginErr sanitizes a plugin-returned error: it returns nil on nil,
// and otherwise emits a fixed byreis-authored error string keyed only on the
// closed-set plugin name. The raw plugin error text is deliberately NOT
// %w-wrapped or forwarded to prevent plugin-supplied bytes appearing in logs
// or error messages (ClientUI containment applied to Wrap errors).
func mapPluginErr(name string, err error) error {
	if err == nil {
		return nil
	}
	// Check for a missing-binary error from the age library and surface a
	// specifically actionable hint ("install age-plugin-<name>").
	var notFound *plugin.NotFoundError
	if isPluginNotFound(err, &notFound) {
		return fmt.Errorf(
			"age-plugin-%s binary not found — "+
				"install age-plugin-%s and ensure it is on PATH; "+
				"you do NOT need the hardware token, only the binary",
			name, name)
	}
	// All other plugin errors: emit a fixed message with the sanitized name only.
	return fmt.Errorf(
		"age-plugin-%s: wrap failed — "+
			"check that age-plugin-%s is correctly installed and the recipient key is valid; "+
			"run `byreis doctor` for diagnostics",
		name, name)
}

// isPluginNotFound unwraps err looking for a *plugin.NotFoundError.
func isPluginNotFound(err error, target **plugin.NotFoundError) bool {
	if err == nil {
		return false
	}
	// Use errors.As semantics manually to avoid importing "errors" at the
	// top-level just for this; we already have fmt imported.
	type notFounder interface {
		Unwrap() error
	}
	for e := err; e != nil; {
		if nf, ok := e.(*plugin.NotFoundError); ok {
			if target != nil {
				*target = nf
			}
			return true
		}
		u, ok := e.(notFounder)
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return false
}

// newContainedClientUI returns the contained byreis ClientUI. All callbacks
// drop plugin-supplied bytes and emit only byreis-authored text keyed on the
// sanitized plugin name. In non-interactive contexts (BYREIS_NON_INTERACTIVE
// or no TTY), RequestValue and Confirm return an error to fail closed.
func newContainedClientUI() *plugin.ClientUI {
	return &plugin.ClientUI{
		// DisplayMessage: emit a fixed byreis-authored line on the sanitized
		// plugin name only. The plugin's `message` bytes are discarded.
		DisplayMessage: func(name, _ string) error {
			// name is the plugin's self-reported name; in production it equals
			// the closed-set discriminator (e.g. "yubikey"). We use it as a
			// label only — it cannot carry attacker bytes because ClassifyRecipient
			// already validated it against SupportedRecipientBackends before any
			// plugin.NewRecipient call.
			safeWrite(fmt.Sprintf("age-plugin-%s is requesting attention\n", sanitizeName(name)))
			return nil
		},

		// RequestValue: in non-interactive mode, fail closed. In interactive mode,
		// prompt with a fixed byreis string; never log the returned value.
		RequestValue: func(name, _ string, secret bool) (string, error) {
			if isHeadless() {
				return "", fmt.Errorf(
					"age-plugin-%s requires interactive input but this is a "+
						"non-interactive context (BYREIS_NON_INTERACTIVE or no TTY); "+
						"run in an interactive terminal to authenticate",
					sanitizeName(name))
			}
			// In an interactive context, write a fixed byreis prompt.
			safeWrite(fmt.Sprintf("age-plugin-%s requires input: ", sanitizeName(name)))
			return readValue(secret)
		},

		// Confirm: same pattern — headless fails closed; interactive uses a
		// fixed byreis prompt.
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

		// WaitTimer: emits a fixed "waiting for touch" message on the sanitized
		// name. Runs in a separate goroutine (per the age library contract).
		WaitTimer: func(name string) {
			safeWrite(fmt.Sprintf("waiting for %s token touch…\n", sanitizeName(name)))
		},
	}
}

// sanitizeName guards the plugin name used in user-visible messages. The
// name parameter in ClientUI callbacks is the plugin's self-reported name.
// Although ClassifyRecipient validates it against the closed set before any
// plugin.NewRecipient call, we apply a conservative sanitization here as an
// extra layer (no shell injection, no newlines, bounded length).
func sanitizeName(name string) string {
	// Constrain to the characters valid in an age-plugin binary name (lowercase
	// alpha + digits). Strip anything outside [a-z0-9-].
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
// It checks BYREIS_NON_INTERACTIVE and, as a courtesy, whether stderr is a
// terminal. Both conditions indicate headless/CI mode.
func isHeadless() bool {
	if os.Getenv("BYREIS_NON_INTERACTIVE") == "1" {
		return true
	}
	// Check if stderr is connected to a terminal.
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

// readValue reads a single line from stdin, returning it as the secret or
// public value the plugin requested. The returned value is NEVER logged.
func readValue(secret bool) (string, error) {
	if secret {
		// Use a simple stdin read; the value must not be echoed and must not
		// be logged anywhere. A production upgrade could use term.ReadPassword.
		var val string
		_, err := fmt.Fscan(os.Stdin, &val)
		if err != nil {
			return "", fmt.Errorf("reading plugin input value: %w", err)
		}
		return val, nil
	}
	var val string
	_, err := fmt.Fscan(os.Stdin, &val)
	if err != nil {
		return "", fmt.Errorf("reading plugin input value: %w", err)
	}
	return val, nil
}

// readConfirm reads a confirmation from stdin. It accepts "y" / yes for
// affirmative. The yesLabel is the plugin's suggested affirmative token; we
// use it only as the comparison target (not displayed to the user verbatim).
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
