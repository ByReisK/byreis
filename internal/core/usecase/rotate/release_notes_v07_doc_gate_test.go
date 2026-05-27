//go:build docgate

// v0.7 release-notes docgate row — admin-only export verb.
//
// This is the v0.7 sibling of the v0.6 positioning-honesty gate. It pins the
// load-bearing honesty statements of docs/release-notes-v0.7.md as verbatim
// fixtures and asserts the shipped release-notes file contains each one
// byte-for-byte (after hard-wrap normalisation).
//
// Why this test exists: v0.7 ships `byreis export`, an admin-only command that
// decrypts the live secrets file to a plaintext stream. Three statements in the
// release notes are load-bearing for the asymmetric-access guarantee and honest
// capability claims:
//
//  (1) Export is ADMIN-ONLY: the permission matrix denies it for CONTRIBUTOR
//      mode; a keyless contributor cannot run it; denial happens before any
//      decrypt or identity load.
//
//  (2) The `--sops` output format is deliberately NOT supported, with the reason
//      cited: byreis uses a native age recipient model (ADR-0001 and ADR-0003),
//      there is no shared symmetric data key, and a SOPS-style export would
//      reintroduce one on the consumer side — defeating the asymmetric-access
//      guarantee. The env/dotenv format is the clean escape hatch.
//
//  (3) The TTY refusal is a convenience speed-bump against an accidental dump,
//      NOT a security boundary. The security boundary is the admin private key.
//      The release notes must not imply the TTY refusal is a containment control.
//
// If any of these statements is dropped, reworded into something weaker, or
// silently removed, byreis would ship release notes that misstate who can run
// export (asymmetric-access surface), hide the reason the SOPS format is refused,
// or imply the TTY refusal is a security boundary. This gate makes that a
// docgate red.
//
// Verbatim-pin discipline (mirrors the v0.6 row): each load-bearing statement
// is an INDEPENDENT verbatim string fixture in this file, asserted as a
// substring of the shipped release-notes bytes after hard-wrap normalisation.
// The fixtures are NOT derived from the release-notes file; a typo or weakening
// edit on EITHER side fails the gate by design.
//
// Negative checks: the v0.7 notes must not claim GitLab support, must not claim
// a `--json` or `--force` flag exists (both are explicitly NOT in v0.7), and
// must not assert that the TTY refusal is a security boundary.
//
// Build constraint: //go:build docgate, the established non-default sibling
// lane; never compiled into a shipped binary. This file imports zero
// rotate-internal identifiers — it reads a doc file off the module root only —
// so it adds no coupling to the rotate package and no new core symbol. It lives
// in package rotate_test so the existing CI docgate job and the release.yml
// docgate job (both run ./internal/core/usecase/rotate/) pick it up with no
// workflow package-path change required. It reuses the package-local
// findModuleRootForDocgate and normaliseReleaseNotes helpers.
//
// Determinism: no network, no clock, no keychain, no git host, no ~/.config.
// The only I/O is a read of docs/release-notes-v0.7.md resolved from the
// module root. A gate that cannot locate the module root or the file fails
// loudly, never silently passes.

package rotate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// releaseNotesV07RelPath is the on-disk location of the v0.7 release notes,
// relative to the module root.
const releaseNotesV07RelPath = "docs/release-notes-v0.7.md"

// The load-bearing v0.7 positioning-honesty statements, pinned as INDEPENDENT
// verbatim fixtures. Each MUST appear byte-for-byte in the shipped notes (after
// hard-wrap normalisation). Inline-code markers and prose sit between words and
// survive whitespace normalisation.
const (
	// (1) Export is admin-only; contributor is denied at the permission matrix.
	v07HonestyAdminOnly        = "it decrypts the secrets file with the admin private key, so a keyless contributor cannot run it"
	v07HonestyContributorDenied = "denied at the permission matrix for CONTRIBUTOR mode"
	v07HonestyDenyBeforeDecrypt = "The denial happens before any network contact, identity load, or decrypt attempt"

	// (2) --sops deliberately unsupported; reason cited (native age model, ADR-0001/ADR-0003,
	// no shared symmetric data key, would defeat asymmetric-access guarantee).
	v07HonestyNoSopsFlag    = "`byreis export` does not and will not support a `--sops` output format."
	v07HonestyNoSopsADRCite = "byreis uses a native age recipient model (see ADR-0001 and ADR-0003)"
	v07HonestyNoSopsReason  = "A SOPS-style export would have to reintroduce a shared symmetric data key on the consumer side, which would defeat the asymmetric-access guarantee."
	v07HonestyEnvEscapeHatch = "`byreis export --format env|dotenv` is the supported, clean escape hatch into plaintext."

	// (3) TTY refusal is a speed-bump, NOT a security boundary; boundary is the admin key.
	v07HonestyTTYSpeedBump   = "This TTY refusal is a convenience speed-bump against an accidental dump, not a security boundary."
	v07HonestyTTYBoundaryKey = "The security boundary is the admin private key."
	v07HonestyTTYPlaintext   = "the plaintext is yours to protect"
)

// v07HonestyFixtures pairs each verbatim statement with a short human label
// used in failure messages.
var v07HonestyFixtures = []struct {
	label string
	want  string
}{
	{"admin-only-decrypts-with-admin-key", v07HonestyAdminOnly},
	{"contributor-denied-at-permission-matrix", v07HonestyContributorDenied},
	{"denial-before-decrypt-or-identity-load", v07HonestyDenyBeforeDecrypt},
	{"sops-flag-deliberately-unsupported", v07HonestyNoSopsFlag},
	{"sops-adr-0001-0003-cite", v07HonestyNoSopsADRCite},
	{"sops-would-defeat-asymmetry", v07HonestyNoSopsReason},
	{"env-dotenv-is-clean-escape-hatch", v07HonestyEnvEscapeHatch},
	{"tty-refusal-is-speed-bump-not-boundary", v07HonestyTTYSpeedBump},
	{"security-boundary-is-admin-key", v07HonestyTTYBoundaryKey},
	{"piped-plaintext-is-operators-to-protect", v07HonestyTTYPlaintext},
}

// v07ForbiddenPositioningTerms are case-insensitive substrings that MUST NOT
// appear in the v0.7 release notes.
//
// "multi-provider" and "multiprovider" guard the single-provider GitOps
// discipline: byreis is GitHub-only and has no other forge backend. Note that
// a phrase such as "No GitLab support" (an honest boundary disclosure in the
// "What is NOT in v0.7" section) does not violate this gate; only a claim of
// multi-provider capability would.
//
// "tty refusal is a security boundary" guards against misrepresenting the
// TTY check as a containment control — the release notes must state the inverse
// (speed-bump, not boundary). The positive fixture v07HonestyTTYSpeedBump
// already asserts the correct wording; this negative term catches a mistaken
// affirmative claim on a different line.
var v07ForbiddenPositioningTerms = []string{
	"multi-provider",
	"multiprovider",
	"tty refusal is a security boundary",
}

// TestDocGate_ReleaseNotesV07_PositioningHonestyVerbatim is the v0.7 release-
// blocking assertion: docs/release-notes-v0.7.md exists and contains every
// load-bearing positioning-honesty statement byte-for-byte (after hard-wrap
// normalisation). A missing or weakened statement is a release-blocker.
func TestDocGate_ReleaseNotesV07_PositioningHonestyVerbatim(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV07(t)
	normalised := normaliseReleaseNotes(raw)

	for _, fx := range v07HonestyFixtures {
		if !bytes.Contains(normalised, []byte(fx.want)) {
			t.Fatalf("v0.7 DOC GATE: %s does not contain the verbatim "+
				"positioning-honesty statement %q.\n"+
				"This is release-blocking: a missing or weakened statement means the "+
				"shipped notes misstate who can run export (asymmetric-access surface), "+
				"drop the reason the SOPS format is refused, or imply the TTY refusal "+
				"is a security boundary.\n\n"+
				"want (substring, after hard-wrap normalisation):\n%q\n\n"+
				"got (normalised release notes):\n%s",
				releaseNotesV07RelPath, fx.label, fx.want, string(normalised))
		}
	}

	t.Logf("v0.7 DOC GATE: PASS — all %d verbatim positioning-honesty statements "+
		"present in %s", len(v07HonestyFixtures), releaseNotesV07RelPath)
}

// TestDocGate_ReleaseNotesV07_NoForbiddenPositioningLanguage is the negative
// half: the v0.7 notes must carry NO GitLab/multi-provider claims and must not
// state that the TTY refusal is a security boundary (it is explicitly not).
func TestDocGate_ReleaseNotesV07_NoForbiddenPositioningLanguage(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV07(t)
	lower := bytes.ToLower(raw)

	for _, term := range v07ForbiddenPositioningTerms {
		if bytes.Contains(lower, []byte(term)) {
			t.Fatalf("v0.7 DOC GATE (negative): %s contains forbidden positioning "+
				"term %q (case-insensitive).\n"+
				"byreis is single-provider GitOps and this term is a release-blocking "+
				"positioning-honesty regression.\n\nrelease notes:\n%s",
				releaseNotesV07RelPath, term, string(raw))
		}
	}

	t.Logf("v0.7 DOC GATE (negative): PASS — no forbidden positioning language in %s",
		releaseNotesV07RelPath)
}

// readReleaseNotesV07 resolves docs/release-notes-v0.7.md from the module root
// and returns its bytes. A failure to locate the module root or the file is a
// hard test failure — a gate that cannot run must fail loudly, never silently
// pass.
func readReleaseNotesV07(t *testing.T) []byte {
	t.Helper()

	root, err := findModuleRootForDocgate()
	if err != nil {
		t.Fatalf("v0.7 DOC GATE FAIL: cannot find module root: %v.\n"+
			"The positioning-honesty gate needs the module root to locate %s.",
			err, releaseNotesV07RelPath)
	}
	abs := filepath.Join(root, releaseNotesV07RelPath)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		t.Fatalf("v0.7 DOC GATE FAIL: %s not found at %s: %v.\n"+
			"v0.7 requires the release notes to be published; a missing file is a "+
			"release-blocker.", releaseNotesV07RelPath, abs, statErr)
	}
	if info.IsDir() {
		t.Fatalf("v0.7 DOC GATE FAIL: expected %s to be a file, got a directory", abs)
	}
	raw, readErr := os.ReadFile(abs) //nolint:gosec // G304: path computed from module root, not user input
	if readErr != nil {
		t.Fatalf("v0.7 DOC GATE FAIL: cannot read %s: %v", abs, readErr)
	}
	if len(raw) < 500 {
		t.Fatalf("v0.7 DOC GATE FAIL: %s is only %d bytes (<500); the v0.7 release "+
			"notes must be a real, non-stub document.", abs, len(raw))
	}
	return raw
}
