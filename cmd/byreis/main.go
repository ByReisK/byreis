// Command byreis is the entry point for the byreis CLI.
// It wires the cobra root, builds adapters, injects them into core, and sets
// the process exit code. No business logic lives here.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/tui"
)

func main() {
	ctx := context.Background()

	deps, err := app.BuildProductionDeps(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: byreis: %v\n", err)
		os.Exit(int(cli.ExitCodeOf(err)))
	}

	// Wire the TUI submit sentinel so the submit RunE can distinguish a
	// contributor cancellation (non-zero exit, no message) from a submit
	// failure (non-zero exit + error text) once RunTUISubmit is enabled.
	// RunTUISubmit itself is wired here when the SubmitterFactory is
	// available; it is left nil until the submit adapter wiring is complete.
	deps.ErrTUISubmitAborted = tui.ErrSubmitAborted

	root := cli.NewRootCmdWithDeps(deps)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(cli.ExitCodeOf(err))
	}
}
