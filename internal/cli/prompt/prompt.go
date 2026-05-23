// Package prompt implements the submit.Prompter port for the CLI. It abstracts
// TTY detection and secret value collection so the core submit use-case never
// reads a real terminal or stdin directly.
//
// Placement: internal/cli/prompt (CLI adapter, peer to cli/render). The CLI
// legitimately owns TTY I/O; this adapter may import golang.org/x/term.
// It must NOT import internal/adapter (no adapter-imports-adapter edge) and
// must NOT be imported by any internal/core package.
//
// Security contract:
//   - Secret values are read with echo disabled (term.ReadPassword) so they
//     never appear in the terminal or shell history.
//   - No entered value is ever embedded in an error, log line, or prompt label.
//   - On a TTY, a second no-echo entry is required for confirmation; the two
//     values must match or the submission is refused before anything is sent.
//   - On piped stdin, a single read is performed (no re-prompt).
//   - The IrreversibleAcknowledged flag is set from an explicit y/N affirmation
//     on a TTY; it is implied true for piped input (the operator controls the
//     source and is presumed to have reviewed the input before piping).
package prompt

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// Prompter is the production CLI Prompter. It implements submit.Prompter using
// golang.org/x/term for no-echo TTY reads and bufio for piped stdin. All
// fields are set by New or NewWithDeps for test injection.
type Prompter struct {
	// stdin is the reader for piped/non-TTY input.
	stdin io.Reader
	// out is the writer for prompt labels and error hints.
	out io.Writer
	// ttyFd is the file descriptor used for TTY detection and ReadPassword.
	// -1 means "use os.Stdin.Fd() at call time".
	ttyFd int
}

// New returns the default production Prompter reading from os.Stdin and
// writing prompts to os.Stderr. This is the instance wired in
// BuildProductionDeps.
func New() *Prompter {
	return &Prompter{
		stdin: os.Stdin,
		out:   os.Stderr,
		ttyFd: -1, // resolved from os.Stdin at CollectValue time
	}
}

// NewWithDeps constructs a Prompter with injected stdin/out/ttyFd. Used in
// tests to avoid real TTY reads.
func NewWithDeps(stdin io.Reader, out io.Writer, ttyFd int) *Prompter {
	return &Prompter{stdin: stdin, out: out, ttyFd: ttyFd}
}

// CollectValue implements submit.Prompter. It detects whether stdin is a TTY
// and takes the appropriate collection path:
//
//   - TTY: no-echo ReadPassword for the value, second no-echo ReadPassword for
//     confirm, explicit y/N irreversibility affirmation. Interactive=true.
//   - Non-TTY (piped): single line read from stdin, trim trailing newline.
//     Interactive=false, IrreversibleAcknowledged=true (operator controls source).
func (p *Prompter) CollectValue(ctx context.Context, key string, action submit.SubmitAction) (submit.ValueEntry, error) {
	if err := ctx.Err(); err != nil {
		return submit.ValueEntry{}, fmt.Errorf("prompt cancelled: %w", err)
	}

	fd := p.ttyFd
	if fd == -1 {
		fd = int(os.Stdin.Fd())
	}

	if term.IsTerminal(fd) {
		return p.collectTTY(ctx, fd, key, action)
	}
	return p.collectPiped(ctx)
}

// collectTTY reads the value (and confirm + ack) from a real TTY using
// no-echo ReadPassword. Neither value is ever echoed or embedded in an error.
func (p *Prompter) collectTTY(ctx context.Context, fd int, key string, action submit.SubmitAction) (submit.ValueEntry, error) {
	actionLabel := "Adding"
	if action == submit.ActionReplace {
		actionLabel = "Replacing"
	}

	// Prompt label: key name and action only — no value, never echoed.
	_, _ = fmt.Fprintf(p.out, "%s key %q — enter value (hidden): ", actionLabel, key)
	valueBytes, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(p.out) // newline after hidden input
	if err != nil {
		return submit.ValueEntry{}, fmt.Errorf(
			"reading secret value failed: %w — ensure you are running on a supported terminal", err)
	}
	if err := ctx.Err(); err != nil {
		zeroBytes(valueBytes)
		return submit.ValueEntry{}, fmt.Errorf("prompt cancelled after value entry: %w", err)
	}

	_, _ = fmt.Fprintf(p.out, "Confirm value for key %q (hidden): ", key)
	confirmBytes, cErr := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(p.out)
	if cErr != nil {
		zeroBytes(valueBytes)
		return submit.ValueEntry{}, fmt.Errorf(
			"reading confirmation value failed: %w", cErr)
	}
	if err := ctx.Err(); err != nil {
		zeroBytes(valueBytes)
		zeroBytes(confirmBytes)
		return submit.ValueEntry{}, fmt.Errorf("prompt cancelled after confirm entry: %w", err)
	}

	// Irreversibility acknowledgement — must come BEFORE any side effect.
	_, _ = fmt.Fprintln(p.out,
		"\nThis submission is irreversible — once submitted, you cannot decrypt",
		"or read back this value. Only an admin with a private key can access it.")
	_, _ = fmt.Fprint(p.out, "Continue? [y/N]: ")
	scanner := bufio.NewScanner(p.stdin)
	scanner.Scan()
	ackLine := strings.TrimSpace(scanner.Text())
	acked := strings.EqualFold(ackLine, "y") || strings.EqualFold(ackLine, "yes")

	entry := submit.ValueEntry{
		Value:                    string(valueBytes),
		Interactive:              true,
		Confirm:                  string(confirmBytes),
		IrreversibleAcknowledged: acked,
	}
	// Do not zero valueBytes/confirmBytes before returning: they are now
	// owned by the ValueEntry (the use-case will use them immediately and
	// is responsible for not persisting them).
	return entry, nil
}

// collectPiped reads a single line from stdin for non-TTY (pipe/redirect) use.
// IrreversibleAcknowledged is true: the operator controls the source and is
// presumed to have reviewed the input before piping.
func (p *Prompter) collectPiped(_ context.Context) (submit.ValueEntry, error) {
	scanner := bufio.NewScanner(p.stdin)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return submit.ValueEntry{}, fmt.Errorf(
			"reading secret value from stdin failed: %w — "+
				"pipe a single-line value or run interactively with a TTY", err)
	}
	line := scanner.Text() // already stripped of trailing \n by Scanner
	return submit.ValueEntry{
		Value:                    line,
		Interactive:              false,
		Confirm:                  "",
		IrreversibleAcknowledged: true,
	}, nil
}

// zeroBytes overwrites a byte slice with zeros, minimising the window during
// which secret material is in memory. Called after a ReadPassword result is
// no longer needed.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Compile-time assertion that Prompter satisfies submit.Prompter.
var _ submit.Prompter = (*Prompter)(nil)
