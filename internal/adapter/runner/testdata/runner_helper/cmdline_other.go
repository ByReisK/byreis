//go:build !linux

// On non-Linux platforms (macOS, Windows) /proc does not exist. We use
// os.Args which is the standard way to read the process argv. This is
// sufficient for the argv-clean assertion on those platforms.
package main

import (
	"os"
	"strings"
)

// readCmdline returns the process argv via os.Args on non-Linux platforms.
func readCmdline() string {
	return strings.Join(os.Args, "\n")
}
