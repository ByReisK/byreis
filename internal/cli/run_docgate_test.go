//go:build docgate

// v0.8 run doc-gate row — release-blocking.
//
// This file discharges the v0.8 `byreis run` documentation obligation: the
// public docs (README.md command table + docs/guide.md admin workflow) MUST
// state, in load-bearing prose, the claims that make `run` honest about its
// asymmetric-access surface and its residual exposure:
//
//	(1) run is ADMIN-ONLY: it decrypts with the admin private key, so a keyless
//	    contributor is denied at the permission matrix before any decrypt or
//	    child spawn.
//	(2) secrets are injected into the child's ENVIRONMENT only — never the argv
//	    (argv is world-readable via `ps`); secrets never touch disk via byreis
//	    and exist only for the child's lifetime.
//	(3) `exec`, not a shell: byreis execs the post-`--` argv directly and does
//	    NOT interpret `$VAR` or run a shell; for a shell, `byreis run -- sh -c
//	    '...'`.
//	(4) HONEST residual-exposure disclosure (named concretely, not "there may be
//	    risks"): the child + descendants inherit the env (readable via
//	    /proc/<pid>/environ by same-uid processes); a sub-child can re-expose an
//	    inherited secret via its OWN argv (ps); a core dump / crash reporter can
//	    capture the env; a SIGKILL of byreis itself reparents the child, which
//	    keeps the injected secrets until it exits. byreis promises only that
//	    byreis itself leaks nothing.
//	(5) env-override behavior: a byreis-injected variable OVERRIDES an inherited
//	    parent-env variable of the same name (injected-wins).
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
// sibling lane; never compiled into a shipped binary. It reuses the package-
// local readExportDoc / normaliseExportDoc helpers (same internal/cli docgate
// lane), so it adds no new I/O machinery.
//
// Determinism: no network, no clock, no keychain, no git host, no ~/.config.
// The only I/O is a read of README.md and docs/guide.md resolved from the
// module root. A gate that cannot locate the module root or a file fails
// loudly, never silently passes.

package cli_test

import (
	"bytes"
	"testing"
)

// The load-bearing v0.8 `run` documentation statements, pinned as INDEPENDENT
// verbatim fixtures. Each MUST appear byte-for-byte (after hard-wrap
// normalisation) in docs/guide.md.
const (
	// (1) admin-only + decrypts with the admin key + contributor denied at the matrix.
	runDocAdminOnlyDeniedAtMatrix = "`byreis run -- <cmd>` is an admin-only command; it decrypts with the admin " +
		"private key, so a keyless contributor is denied at the permission matrix before " +
		"any decrypt or child spawn."

	// (2) environment-only injection, never argv; never touches disk; child-lifetime only.
	runDocEnvOnlyNeverArgv = "byreis injects every decrypted value into the child process's environment only — " +
		"never the argv"
	runDocArgvPsReadable   = "a process's argv is world-readable via `ps`"
	runDocNeverTouchesDisk = "The secrets never touch disk via byreis and exist only for the child's lifetime"

	// (3) exec, not a shell; no $VAR interpretation; sh -c is the user-owned escape hatch.
	runDocExecNotShell = "byreis execs the command after `--` directly — it does NOT interpret `$VAR`, run " +
		"a shell"
	runDocShellEscapeHatch = "If you want shell behavior, run `byreis run -- sh -c '...'` (which you then own)."

	// (4) honest residual-exposure disclosure — each item named concretely.
	runDocResidualProcEnviron = "Any same-uid process can read an injected secret via `/proc/<pid>/environ` for as " +
		"long as the child (or a descendant) is alive."
	runDocResidualSubChildArgv = "If a process started by the child copies an inherited secret into its OWN argv, " +
		"that value becomes readable via `ps`"
	runDocResidualCoreDump = "A child that crashes may write a core dump, or a crash reporter may capture its " +
		"memory, and either can include the injected secrets."
	runDocResidualSigkillReparent = "If the byreis process is force-killed (SIGKILL), the child it spawned is " +
		"reparented (to init) and keeps the injected secrets in its environment until it exits — byreis cannot " +
		"forward a signal it never receives."
	runDocByreisItselfLeaksNothing = "byreis promises only that byreis itself leaks nothing and that secrets never " +
		"hit disk via byreis"

	// (5) env-override behavior: injected-wins over inherited.
	runDocInjectedWins = "A byreis-injected variable overrides an inherited parent-environment variable of the " +
		"same name — injected-wins."

	// (6) inherited stdio, no pty.
	runDocInheritStdioNoPty = "byreis inherits the child's stdin, stdout, and stderr directly — it allocates no " +
		"pty and never captures or filters the child's output."

	// README command-table row for run (admin-only).
	runDocREADMETableRow = "`run` | admin |"
)

// runDocGuideFixtures pairs each verbatim docs/guide.md statement with a short
// human label used in failure messages.
var runDocGuideFixtures = []struct {
	label string
	want  string
}{
	{"admin-only-decrypts-with-admin-key-denied-at-matrix", runDocAdminOnlyDeniedAtMatrix},
	{"env-only-never-argv", runDocEnvOnlyNeverArgv},
	{"argv-world-readable-via-ps", runDocArgvPsReadable},
	{"secrets-never-touch-disk-child-lifetime-only", runDocNeverTouchesDisk},
	{"exec-not-shell-no-var-interpretation", runDocExecNotShell},
	{"sh-c-is-user-owned-shell-escape-hatch", runDocShellEscapeHatch},
	{"residual-proc-pid-environ-same-uid", runDocResidualProcEnviron},
	{"residual-sub-child-own-argv-via-ps", runDocResidualSubChildArgv},
	{"residual-core-dump-crash-reporter", runDocResidualCoreDump},
	{"residual-sigkill-byreis-reparents-child-keeps-secrets", runDocResidualSigkillReparent},
	{"byreis-itself-leaks-nothing-never-disk", runDocByreisItselfLeaksNothing},
	{"env-override-injected-wins", runDocInjectedWins},
	{"inherited-stdio-no-pty", runDocInheritStdioNoPty},
}

// TestDocGate_RunGuide_AdminOnlyEnvOnlyExecNotShellResidualExposure is the v0.8
// release-blocking assertion: docs/guide.md exists and contains every
// load-bearing `run` documentation statement byte-for-byte (after hard-wrap
// normalisation). A missing or weakened statement is a release-blocker: the
// public docs would misstate who can run the verb (asymmetric-access surface),
// imply secrets land in argv or on disk, imply byreis interprets a shell, or
// drop one of the concrete residual exposures the operator must account for.
func TestDocGate_RunGuide_AdminOnlyEnvOnlyExecNotShellResidualExposure(t *testing.T) {
	t.Parallel()

	raw := readExportDoc(t, exportDocGateGuideRelPath)
	normalised := normaliseExportDoc(raw)

	for _, fx := range runDocGuideFixtures {
		if !bytes.Contains(normalised, []byte(fx.want)) {
			t.Fatalf("v0.8 RUN DOC GATE: %s does not contain the verbatim "+
				"statement %q.\n"+
				"This is release-blocking: the run docs would misstate the "+
				"asymmetric-access surface (who can run the verb), imply secrets land "+
				"in argv or on disk, imply byreis interprets a shell, or drop a concrete "+
				"residual exposure (/proc/<pid>/environ, sub-child argv, core dump, SIGKILL reparent).\n\n"+
				"want (substring, after hard-wrap normalisation):\n%q\n\n"+
				"got (normalised doc):\n%s",
				exportDocGateGuideRelPath, fx.label, fx.want, string(normalised))
		}
	}

	t.Logf("v0.8 RUN DOC GATE: PASS — all %d verbatim run statements present in %s",
		len(runDocGuideFixtures), exportDocGateGuideRelPath)
}

// TestDocGate_RunREADME_AdminOnlyCommandRow asserts the README command table
// lists `run` as an admin-only command. The README command table is the first
// place an operator looks for the mode of a verb; a run row that omitted the
// admin mode (or omitted the verb entirely) would misrepresent the
// asymmetric-access surface.
func TestDocGate_RunREADME_AdminOnlyCommandRow(t *testing.T) {
	t.Parallel()

	raw := readExportDoc(t, exportDocGateREADMERelPath)
	normalised := normaliseExportDoc(raw)

	if !bytes.Contains(normalised, []byte(runDocREADMETableRow)) {
		t.Fatalf("v0.8 RUN DOC GATE: %s command table does not contain the "+
			"admin-only run row %q.\n"+
			"This is release-blocking: the README command table must list run as an "+
			"admin command so operators do not believe a contributor can run it.\n\n"+
			"want (substring, after hard-wrap normalisation):\n%q\n\n"+
			"got (normalised README):\n%s",
			exportDocGateREADMERelPath, runDocREADMETableRow, runDocREADMETableRow, string(normalised))
	}

	t.Logf("v0.8 RUN DOC GATE: PASS — %s lists run as an admin-only command",
		exportDocGateREADMERelPath)
}
