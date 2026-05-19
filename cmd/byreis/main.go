// Command byreis is the entry point for the byreis CLI.
// It wires the cobra root, builds adapters, injects them into core, and sets
// the process exit code. No business logic lives here.
package main

import (
	"fmt"
	"os"

	"github.com/ByReisK/byreis/internal/cli"
)

func main() {
	root := cli.NewRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
