//go:build docgate

// V-9 (REQ-V03-011, MUST, release-gate doc) — v0.3 positioning-honesty docgate
// row. This is the last MUST of v0.3 and the sibling lane to the R4 forward-
// secrecy verbatim ring: it pins the load-bearing honesty statements of
// docs/release-notes-v0.3.md as verbatim []byte fixtures and asserts the
// shipped release-notes file contains each one byte-for-byte.
//
// Why this test exists: REQ-V03-011 makes the v0.3 positioning a release-
// blocking obligation, not a prose nicety. The release notes must honestly
// disclose, in shipped text, that:
//
//   (1) the TUI covers submit + review ONLY (rotation/decrypt/key-mgmt/audit
//       stay CLI),
//   (2) the CLI remains the source of truth + the CI-native interface,
//   (3) the TUI review is access-request triage + single-PR detail, NOT a
//       browsable submission-PR queue (deferred to v0.4) — the binding
//       DISCLOSURE-V5-REQ003 from principal-go,
//   (4) the behavioral delta: on a TTY, submit/review now launch the TUI by
//       default (#16),
//   (5) Windows is the CLI path only (#17, SHOULD).
//
// If any of these honesty statements is dropped, reworded into something
// weaker, or silently removed, byreis would ship release notes that overstate
// what the TUI does or understate the asymmetric/CLI-source-of-truth posture —
// a positioning-honesty regression. This gate makes that a docgate red.
//
// Verbatim-pin discipline (mirrors the R4 forward-secrecy ring): each load-
// bearing statement is an INDEPENDENT verbatim []byte/string fixture in this
// file, asserted as a substring of the shipped release-notes bytes. The
// fixtures are NOT derived from the release-notes file (no os.ReadFile of the
// doc to seed the fixture); a typo or weakening edit on EITHER side fails the
// gate by design. A negative check additionally asserts the notes contain NO
// GitLab/multi-provider language (disclosed-limitations discipline; the moat
// is single-provider GitOps + asymmetric write-only).
//
// Build constraint: //go:build docgate. The docgate tag is the established
// non-default sibling lane; never compiled into a shipped binary. This file
// imports zero rotate-internal identifiers — it reads a doc file off the
// module root only — so it adds no coupling to the rotate package and no new
// core symbol. It lives in package rotate_test so the EXISTING CI docgate job
// and the release.yml docgate job (both run ./internal/core/usecase/rotate/)
// pick it up with NO workflow package-path change required.
//
// Determinism: no network, no clock, no keychain, no git host, no ~/.config.
// The only I/O is a read of docs/release-notes-v0.3.md resolved from the
// module root via the package-local findModuleRootForDocgate helper. A gate
// that cannot locate the module root or the file fails loudly (never silently
// passes).

package rotate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// releaseNotesV03RelPath is the on-disk location of the v0.3 release notes,
// relative to the module root.
const releaseNotesV03RelPath = "docs/release-notes-v0.3.md"

// The five load-bearing v0.3 positioning-honesty statements, pinned as
// INDEPENDENT verbatim fixtures. Each MUST appear byte-for-byte in the shipped
// release-notes file. Do NOT replace these with substrings read from the file:
// the cross-check exists precisely so a weakening edit to the prose fails the
// gate. Hard line-wraps in the shipped Markdown are normalised away before
// matching (see normaliseReleaseNotes) so the fixtures can be written as single
// logical sentences without tracking the doc's column wrapping.
// Markdown styling note: the honesty section renders each statement as
// `- **<lead phrase>.** <rest>`. The `**` bold markers sit BETWEEN words, so a
// fixture must not straddle a `**` boundary (the markers survive whitespace
// normalisation). Each fixture below is therefore pinned to a contiguous run
// of prose that lives entirely within one styling span — either the bolded
// lead phrase (markers included verbatim) or a clause from the unbolded body.
const (
	// (1) TUI covers submit + review only; the other flows stay CLI. The lead
	// phrase is bold; the CLI-only follow-on is unbolded — pin both, each
	// within its own span.
	v03HonestyTUICoversSubmitReviewOnly       = "**The TUI covers `submit` and `review` only.**"
	v03HonestyTUICoversSubmitReviewOnlyDetail = "Rotation, decryption, key management, and audit remain CLI-only commands."

	// (2) CLI is the source of truth + the CI-native interface (bold lead).
	v03HonestyCLISourceOfTruth = "**The CLI remains the source of truth and the CI-native interface.**"

	// (3) DISCLOSURE-V5-REQ003 — review is triage + single-PR detail, NOT a
	// browsable submission-PR queue; the queue is deferred to v0.4.
	v03HonestyNotASubmissionQueue = "**TUI review is access-request triage plus single-PR detail, not a browsable " +
		"submission-PR queue.**"
	v03HonestySubmissionQueueDeferred = "A browsable submission-PR queue needs new core surface and is deferred to v0.4."

	// (4) behavioral delta (#16): TTY now launches the TUI by default
	// (unbolded body clause).
	v03HonestyBehavioralDelta = "on an interactive terminal, `byreis submit` and `byreis review` launch the " +
		"TUI by default. This is a deliberate behavior change."

	// (5) Windows = CLI path only (#17) (bold lead).
	v03HonestyWindowsCLIOnly = "**Windows is the CLI path only.**"
)

// v03HonestyFixtures pairs each verbatim statement with a short human label
// used in failure messages. Slice order is the disclosure order in the notes.
var v03HonestyFixtures = []struct {
	label string
	want  string
}{
	{"TUI-covers-submit+review-only", v03HonestyTUICoversSubmitReviewOnly},
	{"TUI-covers-submit+review-only (CLI-only detail)", v03HonestyTUICoversSubmitReviewOnlyDetail},
	{"CLI-source-of-truth", v03HonestyCLISourceOfTruth},
	{"not-a-submission-PR-queue (DISCLOSURE-V5-REQ003)", v03HonestyNotASubmissionQueue},
	{"submission-PR-queue-deferred-to-v0.4 (DISCLOSURE-V5-REQ003)", v03HonestySubmissionQueueDeferred},
	{"behavioral-delta TTY-launches-TUI (#16)", v03HonestyBehavioralDelta},
	{"Windows-CLI-only (#17)", v03HonestyWindowsCLIOnly},
}

// v03ForbiddenPositioningTerms are case-insensitive substrings that MUST NOT
// appear in the v0.3 release notes. byreis is deliberately single-provider
// (GitHub) GitOps; any GitLab / multi-provider language would be a positioning-
// honesty regression (REQ-V03-011 "no GitLab/multi-provider language").
var v03ForbiddenPositioningTerms = []string{
	"gitlab",
	"multi-provider",
	"multiprovider",
}

// TestDocGate_ReleaseNotesV03_PositioningHonestyVerbatim is the V-9 REQ-V03-011
// release-blocking assertion: docs/release-notes-v0.3.md exists and contains
// every load-bearing positioning-honesty statement byte-for-byte (after hard-
// wrap normalisation). A missing or weakened statement is a release-blocker.
func TestDocGate_ReleaseNotesV03_PositioningHonestyVerbatim(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV03(t)
	normalised := normaliseReleaseNotes(raw)

	for _, fx := range v03HonestyFixtures {
		if !bytes.Contains(normalised, []byte(fx.want)) {
			t.Fatalf("V-9 REQ-V03-011: %s does not contain the verbatim "+
				"positioning-honesty statement %q.\n"+
				"This is release-blocking: REQ-V03-011 requires the v0.3 release "+
				"notes to honestly state this. A missing or weakened statement "+
				"means the shipped notes overstate the TUI scope or understate the "+
				"CLI/asymmetric posture.\n\n"+
				"want (substring, after hard-wrap normalisation):\n%q\n\n"+
				"got (normalised release notes):\n%s",
				releaseNotesV03RelPath, fx.label, fx.want, string(normalised))
		}
	}

	t.Logf("V-9 REQ-V03-011: PASS — all %d verbatim positioning-honesty "+
		"statements present in %s", len(v03HonestyFixtures), releaseNotesV03RelPath)
}

// TestDocGate_ReleaseNotesV03_NoGitLabOrMultiProviderLanguage is the negative
// half of REQ-V03-011: the v0.3 notes must carry NO GitLab / multi-provider
// language. byreis's wedge is single-provider GitOps + asymmetric write-only;
// multi-provider language would dilute the honest positioning and is a
// release-blocker.
func TestDocGate_ReleaseNotesV03_NoGitLabOrMultiProviderLanguage(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV03(t)
	lower := bytes.ToLower(raw)

	for _, term := range v03ForbiddenPositioningTerms {
		if bytes.Contains(lower, []byte(term)) {
			t.Fatalf("V-9 REQ-V03-011 (negative): %s contains forbidden positioning "+
				"term %q (case-insensitive).\n"+
				"byreis is single-provider GitOps; GitLab/multi-provider language is "+
				"a release-blocking positioning-honesty regression.\n\n"+
				"release notes:\n%s",
				releaseNotesV03RelPath, term, string(raw))
		}
	}

	t.Logf("V-9 REQ-V03-011 (negative): PASS — no GitLab/multi-provider language in %s",
		releaseNotesV03RelPath)
}

// readReleaseNotesV03 resolves docs/release-notes-v0.3.md from the module root
// and returns its bytes. A failure to locate the module root or the file is a
// hard test failure — a gate that cannot run must fail loudly, never silently
// pass.
func readReleaseNotesV03(t *testing.T) []byte {
	t.Helper()

	root, err := findModuleRootForDocgate()
	if err != nil {
		t.Fatalf("V-9 DOC GATE FAIL: cannot find module root: %v.\n"+
			"The positioning-honesty gate needs the module root to locate %s.",
			err, releaseNotesV03RelPath)
	}
	abs := filepath.Join(root, releaseNotesV03RelPath)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		t.Fatalf("V-9 DOC GATE FAIL: %s not found at %s: %v.\n"+
			"REQ-V03-011 requires the v0.3 release notes to be published; a missing "+
			"file is a release-blocker.", releaseNotesV03RelPath, abs, statErr)
	}
	if info.IsDir() {
		t.Fatalf("V-9 DOC GATE FAIL: expected %s to be a file, got a directory", abs)
	}
	raw, readErr := os.ReadFile(abs) //nolint:gosec // G304: path computed from module root, not user input
	if readErr != nil {
		t.Fatalf("V-9 DOC GATE FAIL: cannot read %s: %v", abs, readErr)
	}
	if len(raw) < 500 {
		t.Fatalf("V-9 DOC GATE FAIL: %s is only %d bytes (<500); the v0.3 release "+
			"notes must be a real, non-stub document.", abs, len(raw))
	}
	return raw
}

// normaliseReleaseNotes collapses Markdown hard-wrapping so a verbatim fixture
// written as a single logical sentence matches prose that the shipped file
// wraps across lines. It replaces every run of whitespace (including newlines)
// with a single space. This is the same idea as the R4 forward-secrecy row's
// hyphen-newline soft-wrap normalisation, generalised to word-wrapped Markdown:
// the test pins the WORDS and their order, not the column at which the doc
// happens to wrap. Two-space-or-more and tab runs collapse identically.
func normaliseReleaseNotes(b []byte) []byte {
	fields := bytes.Fields(b) // splits on any whitespace run, drops empties
	return bytes.Join(fields, []byte(" "))
}
