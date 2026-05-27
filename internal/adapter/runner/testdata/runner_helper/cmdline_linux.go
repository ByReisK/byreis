// This file is compiled only on Linux. On Linux, /proc/self/cmdline contains
// the NUL-delimited raw argument bytes as the kernel holds them — the same
// bytes that ps(1) and other inspection tools see. Reading it proves that
// secrets are absent from the kernel-visible argument vector, not just from
// Go's os.Args (which is parsed from the same source, but testing both sources
// closes the argument that a crafted exec could smuggle bytes into the raw
// cmdline that os.Args does not expose).
package main

import (
	"os"
	"strings"
)

// readCmdline returns a string representation of the current process's argv
// as seen by the Linux kernel (/proc/self/cmdline, NUL-separated).
func readCmdline() string {
	raw, err := os.ReadFile("/proc/self/cmdline") //nolint:gosec // G304: known path, test helper reads its own /proc entry
	if err != nil {
		// Fall back to os.Args if /proc is unavailable in this environment.
		return strings.Join(os.Args, "\n")
	}
	// Replace NUL delimiters with newlines for easy string-contains assertions.
	for i, b := range raw {
		if b == 0 {
			raw[i] = '\n'
		}
	}
	return string(raw)
}
