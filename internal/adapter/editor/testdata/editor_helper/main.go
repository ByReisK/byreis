// editor_helper is a test-only binary that simulates various editor behaviours.
// It is compiled by the editor adapter tests and never shipped in production.
//
// Usage: editor_helper <directive> [sidecar-path] [file-path]
//
// Directives:
//
//	exit0        — exits 0 without modifying the target file.
//	exit1        — exits 1 without modifying the target file.
//	slow         — sleeps until stdin is closed or the process is killed (ctx-cancel test).
//	truncate     — truncates the target file to zero bytes, then exits 0.
//	append-K=V   — appends "K=V\n" to the target file, then exits 0.
//	inspect      — writes "mode=<octal>" to sidecar, then exits 0.
//	inspect-dir  — writes "dirmode=<octal>" (of the target file's parent) to sidecar, then exits 0.
//	report-argv  — writes all argv to sidecar, then exits 0.
//	report-env   — writes all environment variables to sidecar, then exits 0.
//	report-dir   — writes the target file's parent directory path to sidecar, then exits 0.
//	plant-symlink — reads sidecar for a link target path, replaces the target file with
//	                a symlink pointing there, then exits 0.
//
// The last positional argument is always the target file path (the temp file
// created by the editor adapter). The sidecar path (if used) is passed as the
// second argument; some directives write inspection results there so the test
// can read them back without parsing the temp file.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() { //nolint:cyclop // test helper intentionally has many directive branches
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "editor_helper: missing directive")
		os.Exit(2)
	}
	directive := os.Args[1]

	// The last argument is the target file path (the editor adapter always
	// passes ONLY the temp file path as the final argv element).
	targetFile := ""
	if len(os.Args) >= 3 {
		targetFile = os.Args[len(os.Args)-1]
	}

	// Sidecar path (second arg when present, before the target file).
	// Conventions:
	//   - directives that use a sidecar receive it as argv[2] and the target as argv[3].
	//   - directives that do NOT use a sidecar receive only the target as argv[2].
	//   Note: NewWithCommandAndSidecar passes [directive, sidecar, targetFile].
	//         NewWithCommand passes [directive, targetFile].
	sidecar := ""
	if len(os.Args) == 4 {
		// argv: helper directive sidecar targetFile
		sidecar = os.Args[2]
		targetFile = os.Args[3]
	} else if len(os.Args) == 3 {
		// argv: helper directive targetFile
		targetFile = os.Args[2]
	}

	switch {
	case directive == "exit0":
		os.Exit(0)

	case directive == "exit1":
		os.Exit(1)

	case directive == "slow":
		// Sleep until killed (for ctx-cancel tests).
		time.Sleep(30 * time.Second)
		os.Exit(0)

	case directive == "truncate":
		if targetFile == "" {
			fmt.Fprintln(os.Stderr, "editor_helper truncate: no target file")
			os.Exit(2)
		}
		if err := os.Truncate(targetFile, 0); err != nil {
			fmt.Fprintf(os.Stderr, "editor_helper truncate: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case strings.HasPrefix(directive, "append-"):
		if targetFile == "" {
			fmt.Fprintln(os.Stderr, "editor_helper append: no target file")
			os.Exit(2)
		}
		suffix := strings.TrimPrefix(directive, "append-")
		f, err := os.OpenFile(targetFile, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test helper writes to the temp file given by the adapter
		if err != nil {
			fmt.Fprintf(os.Stderr, "editor_helper append: open: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = f.Close() }()
		if _, err := fmt.Fprintf(f, "\n%s\n", suffix); err != nil {
			fmt.Fprintf(os.Stderr, "editor_helper append: write: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case directive == "inspect":
		if targetFile == "" || sidecar == "" {
			fmt.Fprintln(os.Stderr, "editor_helper inspect: need target and sidecar")
			os.Exit(2)
		}
		info, err := os.Lstat(targetFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "editor_helper inspect: lstat: %v\n", err)
			os.Exit(1)
		}
		modeStr := fmt.Sprintf("mode=%04o", info.Mode().Perm())
		if err := os.WriteFile(sidecar, []byte(modeStr), 0o600); err != nil { //nolint:gosec // test helper writes inspection result
			fmt.Fprintf(os.Stderr, "editor_helper inspect: write sidecar: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case directive == "inspect-dir":
		if targetFile == "" || sidecar == "" {
			fmt.Fprintln(os.Stderr, "editor_helper inspect-dir: need target and sidecar")
			os.Exit(2)
		}
		dirPath := filepath.Dir(targetFile)
		info, err := os.Lstat(dirPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "editor_helper inspect-dir: lstat dir: %v\n", err)
			os.Exit(1)
		}
		modeStr := fmt.Sprintf("dirmode=%04o", info.Mode().Perm())
		if err := os.WriteFile(sidecar, []byte(modeStr), 0o600); err != nil { //nolint:gosec // test helper writes inspection result
			fmt.Fprintf(os.Stderr, "editor_helper inspect-dir: write sidecar: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case directive == "report-argv":
		if sidecar == "" {
			fmt.Fprintln(os.Stderr, "editor_helper report-argv: need sidecar")
			os.Exit(2)
		}
		dump := strings.Join(os.Args, "\n")
		if err := os.WriteFile(sidecar, []byte(dump), 0o600); err != nil { //nolint:gosec // test helper writes report
			fmt.Fprintf(os.Stderr, "editor_helper report-argv: write sidecar: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case directive == "report-env":
		if sidecar == "" {
			fmt.Fprintln(os.Stderr, "editor_helper report-env: need sidecar")
			os.Exit(2)
		}
		dump := strings.Join(os.Environ(), "\n")
		if err := os.WriteFile(sidecar, []byte(dump), 0o600); err != nil { //nolint:gosec // test helper writes report
			fmt.Fprintf(os.Stderr, "editor_helper report-env: write sidecar: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case directive == "report-dir":
		if targetFile == "" {
			fmt.Fprintln(os.Stderr, "editor_helper report-dir: no target file")
			os.Exit(2)
		}
		dirPath := filepath.Dir(targetFile)
		if sidecar != "" {
			if err := os.WriteFile(sidecar, []byte(dirPath), 0o600); err != nil { //nolint:gosec // test helper writes report
				fmt.Fprintf(os.Stderr, "editor_helper report-dir: write sidecar: %v\n", err)
				os.Exit(1)
			}
		}
		os.Exit(0)

	case directive == "plant-symlink":
		// Reads the sidecar for the symlink target, removes the target file,
		// then creates a symlink at that path pointing to the sidecar content.
		if targetFile == "" || sidecar == "" {
			fmt.Fprintln(os.Stderr, "editor_helper plant-symlink: need target and sidecar")
			os.Exit(2)
		}
		linkTarget, err := os.ReadFile(sidecar) //nolint:gosec // test helper reads sidecar for symlink target
		if err != nil {
			fmt.Fprintf(os.Stderr, "editor_helper plant-symlink: read sidecar: %v\n", err)
			os.Exit(1)
		}
		target := strings.TrimSpace(string(linkTarget))
		// Remove the real temp file.
		if err := os.Remove(targetFile); err != nil {
			fmt.Fprintf(os.Stderr, "editor_helper plant-symlink: remove target: %v\n", err)
			os.Exit(1)
		}
		// Plant a symlink at the temp file path.
		if err := os.Symlink(target, targetFile); err != nil {
			fmt.Fprintf(os.Stderr, "editor_helper plant-symlink: symlink: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "editor_helper: unknown directive %q\n", directive)
		os.Exit(2)
	}
}
