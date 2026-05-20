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
)

func main() {
	ctx := context.Background()

	deps, err := app.BuildProductionDeps(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: byreis: %v\n", err)
		os.Exit(int(cli.ExitCodeOf(err)))
	}

	root := cli.NewRootCmdWithDeps(deps)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(cli.ExitCodeOf(err))
	}
}
