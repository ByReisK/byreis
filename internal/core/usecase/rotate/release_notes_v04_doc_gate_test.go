//go:build docgate

// v0.4 positioning-honesty docgate row (REQ-V04-002 mandatory disclosure +
// the merge-audit scope correction). This is the v0.4 sibling of the v0.3
// V-9 row: it pins the load-bearing honesty statements of
// docs/release-notes-v0.4.md as verbatim []byte fixtures and asserts the
// shipped release-notes file contains each one byte-for-byte.
//
// Why this test exists: v0.4 makes specific honesty disclosures release-
// blocking, not prose niceties. REQ-V04-002 requires the release notes to
// disclose the AUGMENT decision (the review TUI opens the submission queue by
// default and access-request triage is one keystroke away, not removed). The
// threat-modeler S3 PRE-ack finding (the merge-audit AC-003-C descope)
// requires the notes to state honestly that merge-audit is
// HEAD-signature/monotonic-counter/CAS protected and is NOT per-line
// tamper-detection. The notes must also carry the two-variable
// BYREIS_PROJECT / BYREIS_PROJECT_REPO contract + migration note, and the
// reject PR-close-only scope.
//
// If any of these honesty statements is dropped, reworded into something
// weaker, or silently removed, byreis would ship release notes that overstate
// the TUI scope, overstate the merge-audit guarantee, or hide the project-var
// breaking change. This gate makes that a docgate red.
//
// Verbatim-pin discipline (mirrors the v0.3 row and the R4 forward-secrecy
// ring): each load-bearing statement is an INDEPENDENT verbatim string fixture
// in this file, asserted as a substring of the shipped release-notes bytes
// after hard-wrap normalisation. The fixtures are NOT derived from the
// release-notes file; a typo or weakening edit on EITHER side fails the gate by
// design. A negative check additionally asserts the notes contain NO
// GitLab/multi-provider language (single-provider GitOps discipline) and no
// "tamper-detect" overclaim about merge-audit.
//
// Build constraint: //go:build docgate, the established non-default sibling
// lane; never compiled into a shipped binary. This file imports zero
// rotate-internal identifiers — it reads a doc file off the module root only —
// so it adds no coupling to the rotate package and no new core symbol. It lives
// in package rotate_test so the EXISTING CI docgate job and the release.yml
// docgate job (both run ./internal/core/usecase/rotate/) pick it up with NO
// workflow package-path change required. It reuses the package-local
// findModuleRootForDocgate and normaliseReleaseNotes helpers.
//
// Determinism: no network, no clock, no keychain, no git host, no ~/.config.
// The only I/O is a read of docs/release-notes-v0.4.md resolved from the module
// root. A gate that cannot locate the module root or the file fails loudly
// (never silently passes).

package rotate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// releaseNotesV04RelPath is the on-disk location of the v0.4 release notes,
// relative to the module root.
const releaseNotesV04RelPath = "docs/release-notes-v0.4.md"

// The load-bearing v0.4 positioning-honesty statements, pinned as INDEPENDENT
// verbatim fixtures. Each MUST appear byte-for-byte in the shipped notes (after
// hard-wrap normalisation). Markdown `**bold**` markers sit between words and
// survive whitespace normalisation, so each fixture stays inside one styling
// span (either a bolded lead phrase with its markers, or an unbolded clause).
const (
	// (1) REQ-V04-002 AUGMENT disclosure: the submission queue is the default
	// review screen; access-request triage is preserved one keystroke away.
	v04HonestyQueueDefaultToggleA = "**The review TUI opens the submission-PR queue by default; press `a` to toggle to " +
		"access-request triage.**"
	v04HonestyTriagePreservedNotRemoved = "the v0.3 access-request-triage path is preserved, not removed"

	// (2) reject is PR-close-only and never touches key material.
	v04HonestyRejectPRCloseOnly = "**`reject` is PR-close-only and never touches key material.**"

	// (3) merge-audit scope correction (AC-003-C descope, threat-modeler
	// T-V04-003-1): HEAD-signature/monotonic-counter/CAS protected, NOT per-line
	// tamper-detection.
	v04HonestyMergeAuditProtection = "**Merge-audit is HEAD-signature, monotonic-counter, and CAS protected — not " +
		"per-line tamper-detection.**"
	v04HonestyMergeAuditFollowUp    = "per-line read-side integrity is a tracked follow-up"
	v04HonestyMergeAuditNotDetected = "is therefore **not** detected by byreis"

	// (4) GitHub-only / no GitLab.
	v04HonestyGitHubOnly = "**byreis is GitHub-only.**"

	// (5) no export --sops / no SOPS interop.
	v04HonestyNoExportSops = "**There is no `export --sops` and no SOPS-symmetric interoperation.**"

	// (6) the two-variable project contract.
	v04HonestyProjectIsSlashFree = "**`BYREIS_PROJECT`** is now the **slash-free logical project id**"
	v04HonestyProjectRepoIsSlug  = "**`BYREIS_PROJECT_REPO`** is the **`owner/repo` slug**"

	// (7) the migration note exists.
	v04HonestyMigrationSplit = "split it: put the `owner/repo` slug in **`BYREIS_PROJECT_REPO`** and put the " +
		"slash-free logical id in **`BYREIS_PROJECT`**"

	// (8) asymmetric-access guarantee restated for v0.4.
	v04HonestyAsymmetryUnchanged = "no v0.4 surface gives a non-key-holder a route to a plaintext value"
)

// v04HonestyFixtures pairs each verbatim statement with a short human label
// used in failure messages.
var v04HonestyFixtures = []struct {
	label string
	want  string
}{
	{"REQ-V04-002 queue-default-toggle-a", v04HonestyQueueDefaultToggleA},
	{"REQ-V04-002 triage-preserved-not-removed", v04HonestyTriagePreservedNotRemoved},
	{"reject-PR-close-only", v04HonestyRejectPRCloseOnly},
	{"merge-audit-protection-not-per-line (AC-003-C)", v04HonestyMergeAuditProtection},
	{"merge-audit-follow-up (AC-003-C)", v04HonestyMergeAuditFollowUp},
	{"merge-audit-keyless-writer-not-detected (AC-003-C)", v04HonestyMergeAuditNotDetected},
	{"github-only", v04HonestyGitHubOnly},
	{"no-export-sops", v04HonestyNoExportSops},
	{"BYREIS_PROJECT-slash-free", v04HonestyProjectIsSlashFree},
	{"BYREIS_PROJECT_REPO-slug", v04HonestyProjectRepoIsSlug},
	{"migration-split-note", v04HonestyMigrationSplit},
	{"asymmetry-unchanged", v04HonestyAsymmetryUnchanged},
}

// v04ForbiddenPositioningTerms are case-insensitive substrings that MUST NOT
// appear in the v0.4 release notes. byreis is single-provider (GitHub):
// affirmative multi-provider language is a positioning-honesty regression. Note
// "gitlab" is NOT forbidden here (unlike the v0.3 row) because v0.4 honestly
// DISCLOSES "no GitLab provider" as a limitation — the v04HonestyGitHubOnly
// fixture pins that honest statement. The "tamper-detects" forbidden term
// guards against the original AC-003-C overclaim re-entering the notes: the
// corrected language uses "tamper-detection" only inside the explicit negation
// ("not per-line tamper-detection"), which is allowed; the bare affirmative
// verb phrase "tamper-detects" is the regression marker.
var v04ForbiddenPositioningTerms = []string{
	"multi-provider",
	"multiprovider",
	"tamper-detects",
}

// TestDocGate_ReleaseNotesV04_PositioningHonestyVerbatim is the v0.4 release-
// blocking assertion: docs/release-notes-v0.4.md exists and contains every
// load-bearing positioning-honesty statement byte-for-byte (after hard-wrap
// normalisation). A missing or weakened statement is a release-blocker.
func TestDocGate_ReleaseNotesV04_PositioningHonestyVerbatim(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV04(t)
	normalised := normaliseReleaseNotes(raw)

	for _, fx := range v04HonestyFixtures {
		if !bytes.Contains(normalised, []byte(fx.want)) {
			t.Fatalf("v0.4 DOC GATE: %s does not contain the verbatim "+
				"positioning-honesty statement %q.\n"+
				"This is release-blocking: a missing or weakened statement means the "+
				"shipped notes overstate the TUI/merge-audit scope or hide the "+
				"BYREIS_PROJECT breaking change.\n\n"+
				"want (substring, after hard-wrap normalisation):\n%q\n\n"+
				"got (normalised release notes):\n%s",
				releaseNotesV04RelPath, fx.label, fx.want, string(normalised))
		}
	}

	t.Logf("v0.4 DOC GATE: PASS — all %d verbatim positioning-honesty statements "+
		"present in %s", len(v04HonestyFixtures), releaseNotesV04RelPath)
}

// TestDocGate_ReleaseNotesV04_NoForbiddenPositioningLanguage is the negative
// half: the v0.4 notes must carry NO GitLab/multi-provider language and NO bare
// "tamper-detects" overclaim about merge-audit (AC-003-C correction).
func TestDocGate_ReleaseNotesV04_NoForbiddenPositioningLanguage(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV04(t)
	lower := bytes.ToLower(raw)

	for _, term := range v04ForbiddenPositioningTerms {
		if bytes.Contains(lower, []byte(term)) {
			t.Fatalf("v0.4 DOC GATE (negative): %s contains forbidden positioning "+
				"term %q (case-insensitive).\n"+
				"byreis is single-provider GitOps and merge-audit does NOT do per-line "+
				"tamper-detection; this term is a release-blocking positioning-honesty "+
				"regression.\n\nrelease notes:\n%s",
				releaseNotesV04RelPath, term, string(raw))
		}
	}

	t.Logf("v0.4 DOC GATE (negative): PASS — no forbidden positioning language in %s",
		releaseNotesV04RelPath)
}

// readReleaseNotesV04 resolves docs/release-notes-v0.4.md from the module root
// and returns its bytes. A failure to locate the module root or the file is a
// hard test failure — a gate that cannot run must fail loudly, never silently
// pass.
func readReleaseNotesV04(t *testing.T) []byte {
	t.Helper()

	root, err := findModuleRootForDocgate()
	if err != nil {
		t.Fatalf("v0.4 DOC GATE FAIL: cannot find module root: %v.\n"+
			"The positioning-honesty gate needs the module root to locate %s.",
			err, releaseNotesV04RelPath)
	}
	abs := filepath.Join(root, releaseNotesV04RelPath)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		t.Fatalf("v0.4 DOC GATE FAIL: %s not found at %s: %v.\n"+
			"v0.4 requires the release notes to be published; a missing file is a "+
			"release-blocker.", releaseNotesV04RelPath, abs, statErr)
	}
	if info.IsDir() {
		t.Fatalf("v0.4 DOC GATE FAIL: expected %s to be a file, got a directory", abs)
	}
	raw, readErr := os.ReadFile(abs) //nolint:gosec // G304: path computed from module root, not user input
	if readErr != nil {
		t.Fatalf("v0.4 DOC GATE FAIL: cannot read %s: %v", abs, readErr)
	}
	if len(raw) < 500 {
		t.Fatalf("v0.4 DOC GATE FAIL: %s is only %d bytes (<500); the v0.4 release "+
			"notes must be a real, non-stub document.", abs, len(raw))
	}
	return raw
}
