//go:build docgate

// v0.8 release-notes docgate row — admin-only run verb.
//
// This is the v0.8 sibling of the v0.7 admin-only-export gate. It pins the
// load-bearing honesty statements of docs/release-notes-v0.8.md as verbatim
// fixtures and asserts the shipped release-notes file contains each one
// byte-for-byte (after hard-wrap normalisation).
//
// Why this test exists: v0.8 ships `byreis run`, an admin-only command that
// decrypts the live secrets file and injects every value into a child process's
// environment. The following statements in the release notes are load-bearing
// for the asymmetric-access guarantee and for honest capability/residual-risk
// claims:
//
//  (1) run is ADMIN-ONLY: it decrypts with the admin private key; a keyless
//      contributor is denied at the permission matrix before any decrypt or
//      child spawn.
//
//  (2) secrets are injected into the child's ENVIRONMENT only — never the argv
//      (argv is world-readable via `ps`); secrets never touch disk via byreis.
//
//  (3) `exec`, not a shell: byreis execs the post-`--` argv directly and does
//      NOT interpret `$VAR` / run a shell; `byreis run -- sh -c '...'` is the
//      user-owned escape hatch.
//
//  (4) HONEST residual-exposure disclosure, each item named concretely: the
//      child + descendants inherit the env (/proc/<pid>/environ, same-uid); a
//      sub-child can re-expose an inherited secret via its OWN argv (ps); a
//      core dump / crash reporter can capture the env. byreis promises only that
//      byreis itself leaks nothing.
//
//  (5) env-override behavior: a byreis-injected variable OVERRIDES an inherited
//      parent-env variable of the same name (injected-wins).
//
// If any of these is dropped, reworded into something weaker, or silently
// removed, byreis would ship release notes that misstate who can run the verb,
// imply secrets land in argv or on disk, imply byreis interprets a shell, or
// hide a concrete residual exposure. This gate makes that a docgate red.
//
// Negative checks: the v0.8 notes must not claim GitLab support and must not
// claim byreis interprets a shell or `$VAR` (it does not — exec(argv) only).
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
// The only I/O is a read of docs/release-notes-v0.8.md resolved from the
// module root. A gate that cannot locate the module root or the file fails
// loudly, never silently passes.

package rotate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// releaseNotesV08RelPath is the on-disk location of the v0.8 release notes,
// relative to the module root.
const releaseNotesV08RelPath = "docs/release-notes-v0.8.md"

// The load-bearing v0.8 honesty statements, pinned as INDEPENDENT verbatim
// fixtures. Each MUST appear byte-for-byte in the shipped notes (after hard-wrap
// normalisation). Inline-code markers and prose sit between words and survive
// whitespace normalisation.
const (
	// (1) run is admin-only; decrypts with the admin key; contributor denied before spawn.
	v08HonestyAdminOnly = "`byreis run -- <cmd>` is an admin-only command — it decrypts with the admin private " +
		"key, so a keyless contributor is denied at the permission matrix before any decrypt " +
		"or child spawn."
	v08HonestyDenyBeforeDecrypt = "The denial happens before any network contact, identity load, or decrypt attempt"

	// (2) env-only, never argv; argv world-readable via ps; never touches disk.
	v08HonestyEnvOnlyNeverArgv = "byreis injects every decrypted value into the child process's environment only — " +
		"never the argv."
	v08HonestyArgvPsReadable = "A process's argv is world-readable via `ps`, so a secret placed there would leak " +
		"to every user on the host."
	v08HonestyNeverTouchesDisk = "The secrets never touch disk via byreis and exist only for the child's lifetime."

	// (3) exec, not a shell; no $VAR interpretation; sh -c is the user-owned escape hatch.
	v08HonestyExecNotShell = "byreis execs the command after `--` directly — it does NOT interpret `$VAR`, run a " +
		"shell, or expand globs, pipes, or redirects."
	v08HonestyShellEscapeHatch = "If you want shell behavior, run `byreis run -- sh -c '...'` (which you then own)."

	// (4) honest residual-exposure disclosure — each item named concretely.
	v08HonestyByreisItselfLeaksNothing = "byreis promises only that byreis itself leaks nothing and that secrets " +
		"never hit disk via byreis"
	v08HonestyResidualProcEnviron = "The child and all its descendants inherit the environment, making an injected " +
		"secret readable via `/proc/<pid>/environ` by same-uid processes for as long as the " +
		"child or a descendant is alive."
	v08HonestyResidualSubChildArgv = "A sub-child that puts an inherited secret into its OWN argv re-exposes that " +
		"value via `ps`."
	v08HonestyResidualCoreDump = "A child core dump or crash reporter can capture the environment, including the " +
		"injected secrets."

	// (5) env-override behavior: injected-wins over inherited.
	v08HonestyInjectedWins = "A byreis-injected variable overrides an inherited parent-environment variable of the " +
		"same name — injected-wins."
)

// v08HonestyFixtures pairs each verbatim statement with a short human label used
// in failure messages.
var v08HonestyFixtures = []struct {
	label string
	want  string
}{
	{"admin-only-decrypts-with-admin-key-denied-before-spawn", v08HonestyAdminOnly},
	{"denial-before-decrypt-or-identity-load", v08HonestyDenyBeforeDecrypt},
	{"env-only-never-argv", v08HonestyEnvOnlyNeverArgv},
	{"argv-world-readable-via-ps", v08HonestyArgvPsReadable},
	{"secrets-never-touch-disk-child-lifetime-only", v08HonestyNeverTouchesDisk},
	{"exec-not-shell-no-var-interpretation", v08HonestyExecNotShell},
	{"sh-c-is-user-owned-shell-escape-hatch", v08HonestyShellEscapeHatch},
	{"byreis-itself-leaks-nothing-never-disk", v08HonestyByreisItselfLeaksNothing},
	{"residual-proc-pid-environ-same-uid", v08HonestyResidualProcEnviron},
	{"residual-sub-child-own-argv-via-ps", v08HonestyResidualSubChildArgv},
	{"residual-core-dump-crash-reporter", v08HonestyResidualCoreDump},
	{"env-override-injected-wins", v08HonestyInjectedWins},
}

// v08ForbiddenPositioningTerms are case-insensitive substrings that MUST NOT
// appear in the v0.8 release notes.
//
// "multi-provider" and "multiprovider" guard the single-provider GitOps
// discipline: byreis is GitHub-only and has no other forge backend. A phrase
// such as "No GitLab support" (an honest boundary disclosure in the "What is
// NOT in v0.8" section) does not violate this gate; only a claim of
// multi-provider capability would.
//
// "interprets a shell" and "shell interpretation by byreis" guard against
// misrepresenting `run` as a shell — the notes must state the inverse (byreis
// execs argv directly and does NOT interpret a shell). The positive fixture
// v08HonestyExecNotShell already asserts the correct wording; these negative
// terms catch a mistaken affirmative claim on a different line.
var v08ForbiddenPositioningTerms = []string{
	"multi-provider",
	"multiprovider",
	"byreis interprets a shell",
	"shell interpretation by byreis",
}

// TestDocGate_ReleaseNotesV08_RunHonestyVerbatim is the v0.8 release-blocking
// assertion: docs/release-notes-v0.8.md exists and contains every load-bearing
// honesty statement byte-for-byte (after hard-wrap normalisation). A missing or
// weakened statement is a release-blocker.
func TestDocGate_ReleaseNotesV08_RunHonestyVerbatim(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV08(t)
	normalised := normaliseReleaseNotes(raw)

	for _, fx := range v08HonestyFixtures {
		if !bytes.Contains(normalised, []byte(fx.want)) {
			t.Fatalf("v0.8 DOC GATE: %s does not contain the verbatim "+
				"honesty statement %q.\n"+
				"This is release-blocking: a missing or weakened statement means the "+
				"shipped notes misstate who can run the verb (asymmetric-access surface), "+
				"imply secrets land in argv or on disk, imply byreis interprets a shell, "+
				"or drop a concrete residual exposure (/proc/<pid>/environ, sub-child "+
				"argv, core dump).\n\n"+
				"want (substring, after hard-wrap normalisation):\n%q\n\n"+
				"got (normalised release notes):\n%s",
				releaseNotesV08RelPath, fx.label, fx.want, string(normalised))
		}
	}

	t.Logf("v0.8 DOC GATE: PASS — all %d verbatim honesty statements present in %s",
		len(v08HonestyFixtures), releaseNotesV08RelPath)
}

// TestDocGate_ReleaseNotesV08_NoForbiddenPositioningLanguage is the negative
// half: the v0.8 notes must carry NO GitLab/multi-provider claims and must not
// state that byreis interprets a shell (it does not — exec(argv) only).
func TestDocGate_ReleaseNotesV08_NoForbiddenPositioningLanguage(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV08(t)
	lower := bytes.ToLower(raw)

	for _, term := range v08ForbiddenPositioningTerms {
		if bytes.Contains(lower, []byte(term)) {
			t.Fatalf("v0.8 DOC GATE (negative): %s contains forbidden positioning "+
				"term %q (case-insensitive).\n"+
				"byreis is single-provider GitOps and execs argv directly (no shell "+
				"interpretation); this term is a release-blocking positioning-honesty "+
				"regression.\n\nrelease notes:\n%s",
				releaseNotesV08RelPath, term, string(raw))
		}
	}

	t.Logf("v0.8 DOC GATE (negative): PASS — no forbidden positioning language in %s",
		releaseNotesV08RelPath)
}

// readReleaseNotesV08 resolves docs/release-notes-v0.8.md from the module root
// and returns its bytes. A failure to locate the module root or the file is a
// hard test failure — a gate that cannot run must fail loudly, never silently
// pass.
func readReleaseNotesV08(t *testing.T) []byte {
	t.Helper()

	root, err := findModuleRootForDocgate()
	if err != nil {
		t.Fatalf("v0.8 DOC GATE FAIL: cannot find module root: %v.\n"+
			"The run honesty gate needs the module root to locate %s.",
			err, releaseNotesV08RelPath)
	}
	abs := filepath.Join(root, releaseNotesV08RelPath)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		t.Fatalf("v0.8 DOC GATE FAIL: %s not found at %s: %v.\n"+
			"v0.8 requires the release notes to be published; a missing file is a "+
			"release-blocker.", releaseNotesV08RelPath, abs, statErr)
	}
	if info.IsDir() {
		t.Fatalf("v0.8 DOC GATE FAIL: expected %s to be a file, got a directory", abs)
	}
	raw, readErr := os.ReadFile(abs) //nolint:gosec // G304: path computed from module root, not user input
	if readErr != nil {
		t.Fatalf("v0.8 DOC GATE FAIL: cannot read %s: %v", abs, readErr)
	}
	if len(raw) < 500 {
		t.Fatalf("v0.8 DOC GATE FAIL: %s is only %d bytes (<500); the v0.8 release "+
			"notes must be a real, non-stub document.", abs, len(raw))
	}
	return raw
}
