package prompt

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ConfirmPrompter implements usecase.ConfirmPrompter for the CLI init flow.
// It displays the registry signer fingerprint and reads back a typed
// confirmation from the operator.  In non-interactive sessions (piped stdin)
// it returns an error directing the operator to use --accept-signer instead.
type ConfirmPrompter struct {
	stdin io.Reader
	out   io.Writer
}

// NewConfirmPrompter returns the default production ConfirmPrompter reading
// from os.Stdin and writing prompts to os.Stderr.
func NewConfirmPrompter() *ConfirmPrompter {
	return &ConfirmPrompter{stdin: os.Stdin, out: os.Stderr}
}

// NewConfirmPrompterWithDeps constructs a ConfirmPrompter with injected
// stdin/out.  Used in tests to avoid real TTY reads.
func NewConfirmPrompterWithDeps(stdin io.Reader, out io.Writer) *ConfirmPrompter {
	return &ConfirmPrompter{stdin: stdin, out: out}
}

// ConfirmSignerFingerprint implements usecase.ConfirmPrompter.  It displays
// the fingerprint and asks the operator to type it back verbatim.  The
// comparison is case-insensitive to reduce transcription friction.  Returns
// nil when the operator confirms, an error when they decline or input does not
// match.
func (c *ConfirmPrompter) ConfirmSignerFingerprint(ctx context.Context, fingerprint string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("confirm prompter cancelled: %w", err)
	}

	_, _ = fmt.Fprintf(c.out,
		"\nRegistry signer fingerprint:\n  %s\n\n"+
			"Verify this fingerprint out of band (e.g. from the registry maintainer "+
			"or the signed release notes) before accepting.\n\n"+
			"Type the fingerprint to accept, or press Enter to abort: ",
		fingerprint)

	scanner := bufio.NewScanner(c.stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf(
				"reading confirmation input failed: %w — "+
					"use --accept-signer <fingerprint> for non-interactive use", err)
		}
		// EOF (piped empty input or ctrl-D): treat as abort.
		return fmt.Errorf(
			"no input received — use --accept-signer <fingerprint> for non-interactive use")
	}

	entered := strings.TrimSpace(scanner.Text())
	if strings.EqualFold(entered, fingerprint) {
		return nil
	}
	if entered == "" {
		return fmt.Errorf(
			"signer fingerprint confirmation aborted — "+
				"pass --accept-signer %s to confirm non-interactively", fingerprint)
	}
	return fmt.Errorf(
		"signer fingerprint mismatch: entered %q does not match %q — "+
			"verify the fingerprint and retry, or pass --accept-signer <fingerprint>",
		entered, fingerprint)
}

// Compile-time assertion.
var _ usecase.ConfirmPrompter = (*ConfirmPrompter)(nil)
