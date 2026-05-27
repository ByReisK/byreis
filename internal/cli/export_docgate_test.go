//go:build docgate

// v0.7 export doc-gate row — release-blocking.
//
// This file discharges the v0.7 export documentation obligation: the public
// docs (README.md command table + docs/guide.md admin workflow) MUST state, in
// load-bearing prose, three things about `byreis export`:
//
//	(1) export is ADMIN-ONLY and decrypts with the admin private key — a keyless
//	    contributor cannot run it (denied at the permission matrix).
//	(2) a SOPS export format is deliberately unsupported, with the reason cited
//	    (native age recipient model, no shared symmetric data key, supporting it
//	    would defeat asymmetric access); the env/dotenv format is the clean
//	    migration escape hatch.
//	(3) the default TTY refusal is an accidental-dump speed-bump, NOT a security
//	    boundary — once the operator pipes or redirects, the plaintext is theirs
//	    to protect. The docs must not imply TTY refusal is a containment control.
//
// Each load-bearing statement is pinned as an INDEPENDENT verbatim substring
// fixture and asserted against the shipped doc bytes after hard-wrap
// normalisation (whitespace runs collapsed to a single space). The fixtures are
// NOT derived from the doc files; a typo or a silent weakening edit on EITHER
// side fails the gate by design.
//
// Placement: package cli_test, file in internal/cli/. The CI docgate job
// (.github/workflows/ci.yml) and the release docgate job
// (.github/workflows/release.yml) both run, UNFILTERED:
//
//	go test -v -race -tags docgate -timeout=120s ./internal/core/usecase/rotate/ ./internal/cli/
//
// so every docgate-tagged test in internal/cli/ auto-gates with no -run filter.
// A red result here blocks the release via the release job's
// needs: [shipgate, docgate] (no manual override). This is release-blocking by
// construction.
//
// Build constraint: //go:build docgate ONLY — the established non-default
// sibling lane; never compiled into a shipped binary.
//
// Determinism: no network, no clock, no keychain, no git host, no ~/.config.
// The only I/O is a read of README.md and docs/guide.md resolved from the
// module root. A gate that cannot locate the module root or a file fails
// loudly, never silently passes.

package cli_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Doc paths relative to the module root.
const (
	exportDocGateREADMERelPath = "README.md"
	exportDocGateGuideRelPath  = "docs/guide.md"
)

// The load-bearing v0.7 export documentation statements, pinned as INDEPENDENT
// verbatim fixtures. Each MUST appear byte-for-byte (after hard-wrap
// normalisation) in the named shipped doc. Markdown `**bold**` and `inline
// code` markers sit between words and survive whitespace normalisation, so each
// fixture stays inside one styling span.
const (
	// (1) admin-only + decrypts with the admin private key + contributor denied.
	exportDocAdminOnly        = "`byreis export` is an admin-only command."
	exportDocDecryptsAdminKey = "it decrypts the secrets file with the admin private key, so a keyless " +
		"contributor cannot run it"

	// (2) --sops deliberately unsupported, reason cited, env/dotenv is the relief valve.
	exportDocNoSopsFlag    = "`byreis export` does not and will not support a `--sops` output format."
	exportDocNoSopsADRCite = "byreis uses a native age recipient model (see ADR-0001 and ADR-0003)"
	exportDocNoSopsReason  = "A SOPS-style export would have to reintroduce a shared symmetric data key on the " +
		"consumer side, which would defeat the asymmetric-access guarantee."
	exportDocSopsEscapeHatch = "`byreis export --format env|dotenv` is the supported, clean escape hatch into plaintext."

	// (3) TTY refusal is a speed-bump, NOT a security boundary; piped plaintext is the operator's to protect.
	exportDocTTYSpeedBump = "This TTY refusal is a convenience speed-bump against an accidental dump, not a " +
		"security boundary."
	exportDocTTYBoundaryIsKey  = "The security boundary is the admin private key."
	exportDocTTYPlaintextYours = "the plaintext is yours to protect"

	// README command-table row for export (admin-only).
	exportDocREADMETableRow = "`export` | admin |"
)

// exportDocGuideFixtures pairs each verbatim docs/guide.md statement with a
// short human label used in failure messages.
var exportDocGuideFixtures = []struct {
	label string
	want  string
}{
	{"admin-only", exportDocAdminOnly},
	{"decrypts-with-admin-key-contributor-denied", exportDocDecryptsAdminKey},
	{"sops-deliberately-unsupported", exportDocNoSopsFlag},
	{"sops-adr-0001-0003-cite", exportDocNoSopsADRCite},
	{"sops-would-defeat-asymmetry", exportDocNoSopsReason},
	{"env-dotenv-is-migration-escape-hatch", exportDocSopsEscapeHatch},
	{"tty-refusal-is-speed-bump-not-boundary", exportDocTTYSpeedBump},
	{"security-boundary-is-the-admin-key", exportDocTTYBoundaryIsKey},
	{"piped-plaintext-is-operators-to-protect", exportDocTTYPlaintextYours},
}

// TestDocGate_ExportGuide_AdminOnlyNoSopsTTYSpeedBump is the v0.7 release-
// blocking assertion: docs/guide.md exists and contains every load-bearing
// export documentation statement byte-for-byte (after hard-wrap normalisation).
// A missing or weakened statement is a release-blocker: the public docs would
// misstate who can run export (asymmetric-access surface), drop the
// asymmetry-preserving reason for refusing `--sops`, or imply the TTY refusal
// is a containment control rather than the admin key.
func TestDocGate_ExportGuide_AdminOnlyNoSopsTTYSpeedBump(t *testing.T) {
	t.Parallel()

	raw := readExportDoc(t, exportDocGateGuideRelPath)
	normalised := normaliseExportDoc(raw)

	for _, fx := range exportDocGuideFixtures {
		if !bytes.Contains(normalised, []byte(fx.want)) {
			t.Fatalf("v0.7 EXPORT DOC GATE: %s does not contain the verbatim "+
				"statement %q.\n"+
				"This is release-blocking: the export docs would misstate the "+
				"asymmetric-access surface (who can run export), drop the reason the "+
				"SOPS format is refused, or imply the TTY refusal is a security "+
				"boundary rather than a speed-bump.\n\n"+
				"want (substring, after hard-wrap normalisation):\n%q\n\n"+
				"got (normalised doc):\n%s",
				exportDocGateGuideRelPath, fx.label, fx.want, string(normalised))
		}
	}

	t.Logf("v0.7 EXPORT DOC GATE: PASS — all %d verbatim export statements present in %s",
		len(exportDocGuideFixtures), exportDocGateGuideRelPath)
}

// TestDocGate_ExportREADME_AdminOnlyCommandRow asserts the README command table
// lists `export` as an admin-only command. The README command table is the
// first place an operator looks for the mode of a verb; an export row that
// omitted the admin mode (or omitted the verb entirely) would misrepresent the
// asymmetric-access surface.
func TestDocGate_ExportREADME_AdminOnlyCommandRow(t *testing.T) {
	t.Parallel()

	raw := readExportDoc(t, exportDocGateREADMERelPath)
	normalised := normaliseExportDoc(raw)

	if !bytes.Contains(normalised, []byte(exportDocREADMETableRow)) {
		t.Fatalf("v0.7 EXPORT DOC GATE: %s command table does not contain the "+
			"admin-only export row %q.\n"+
			"This is release-blocking: the README command table must list export as "+
			"an admin command so operators do not believe a contributor can run it.\n\n"+
			"want (substring, after hard-wrap normalisation):\n%q\n\n"+
			"got (normalised README):\n%s",
			exportDocGateREADMERelPath, exportDocREADMETableRow, exportDocREADMETableRow, string(normalised))
	}

	t.Logf("v0.7 EXPORT DOC GATE: PASS — %s lists export as an admin-only command",
		exportDocGateREADMERelPath)
}

// readExportDoc resolves a doc path relative to the module root and returns its
// bytes. A failure to locate the module root or the file is a hard test failure
// — a gate that cannot run must fail loudly, never silently pass.
func readExportDoc(t *testing.T, relPath string) []byte {
	t.Helper()

	root, err := findExportDocModuleRoot()
	if err != nil {
		t.Fatalf("v0.7 EXPORT DOC GATE FAIL: cannot find module root: %v.\n"+
			"The export doc gate needs the module root to locate %s.", err, relPath)
	}
	abs := filepath.Join(root, relPath)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		t.Fatalf("v0.7 EXPORT DOC GATE FAIL: %s not found at %s: %v.\n"+
			"The export documentation must be published; a missing file is a "+
			"release-blocker.", relPath, abs, statErr)
	}
	if info.IsDir() {
		t.Fatalf("v0.7 EXPORT DOC GATE FAIL: expected %s to be a file, got a directory", abs)
	}
	raw, readErr := os.ReadFile(abs) //nolint:gosec // G304: path computed from module root, not user input
	if readErr != nil {
		t.Fatalf("v0.7 EXPORT DOC GATE FAIL: cannot read %s: %v", abs, readErr)
	}
	if len(raw) < 500 {
		t.Fatalf("v0.7 EXPORT DOC GATE FAIL: %s is only %d bytes (<500); the export "+
			"documentation must live in a real, non-stub document.", abs, len(raw))
	}
	return raw
}

// normaliseExportDoc collapses every whitespace run to a single space, so a
// hard-wrapped Markdown paragraph matches a single-line verbatim fixture.
func normaliseExportDoc(b []byte) []byte {
	fields := bytes.Fields(b) // splits on any whitespace run, drops empties
	return bytes.Join(fields, []byte(" "))
}

// findExportDocModuleRoot walks up from the test working directory until it
// finds the directory containing go.mod.
func findExportDocModuleRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errExportDocModuleRootNotFound
		}
		dir = parent
	}
}

var errExportDocModuleRootNotFound = errors.New("go.mod not found in any ancestor directory")
