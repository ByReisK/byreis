//go:build docgate

// v0.6 positioning-honesty docgate row — contributor audit verify and
// counter-monotonicity closure.
//
// This is the v0.6 sibling of the v0.5 positioning-honesty gate. It pins the
// load-bearing honesty statements of docs/release-notes-v0.6.md as verbatim
// fixtures and asserts the shipped release-notes file contains each one
// byte-for-byte (after hard-wrap normalisation).
//
// Why this test exists: v0.6 ships two headline features that together close
// the gap between what the v0.5 audit-binding verifier claimed and what it
// could actually prove:
//
//   (1) Contributor-accessible audit verification: `byreis audit verify` is
//       now permitted in all modes (Contributor, Admin, Super). The v0.5
//       admin-only restriction is retired. The compliance story is now honest:
//       any party with read access can independently verify the audit trail.
//
//   (2) Counter-monotonicity closure: the pre-binding prefix residual disclosed
//       in v0.5 (ADR-0019 errata E2) is closed. A counter break → TAMPERED
//       even when the content hash matches, on both cold and warm
//       (checkpoint-seam) paths.
//
// Eight disclosures are load-bearing for v0.6:
//
//   (1) Audit verification is now available to contributors (admin-only RETIRED).
//   (2) The v0.5 counter-monotonicity residual is closed — cold and warm paths.
//   (3) Reject events are host-local only; the verifier cannot bind them.
//   (4) Pre-binding (legacy) lines are shown as "legacy", never "verified".
//   (5) Intra-commit reorder is below per-commit binding granularity (residual).
//   (6) Trust root is the pinned TrustAnchorKey; a principal with the anchor
//       key can author internally consistent history (the trust root is the
//       anchor, by design).
//   (7) The verifier is read-only and zero-decrypt.
//   (8) Verification fails closed under resource pressure.
//
// If any of these statements is dropped, reworded into something weaker, or
// silently removed, byreis would ship release notes that overstate the
// tamper-detection scope, re-assert a retired restriction, or hide a residual
// boundary. This gate makes that a docgate red.
//
// Crucially: the v0.5 "admin-only" claim is NOT re-asserted here. The v0.6
// fixture set asserts the inverse — that verification is now available to
// contributors. Any test that re-asserts the v0.5 admin-only wording against
// the v0.6 file would be wrong; this gate only pins the v0.6 file.
//
// Verbatim-pin discipline (mirrors the v0.5 row): each load-bearing statement
// is an INDEPENDENT verbatim string fixture in this file, asserted as a
// substring of the shipped release-notes bytes after hard-wrap normalisation.
// The fixtures are NOT derived from the release-notes file; a typo or weakening
// edit on EITHER side fails the gate by design.
//
// Negative checks: no false GitLab/multi-provider claim, no re-assertion of the
// retired v0.5 "admin-only" wording.
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
// The only I/O is a read of docs/release-notes-v0.6.md resolved from the
// module root. A gate that cannot locate the module root or the file fails
// loudly, never silently passes.

package rotate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// releaseNotesV06RelPath is the on-disk location of the v0.6 release notes,
// relative to the module root.
const releaseNotesV06RelPath = "docs/release-notes-v0.6.md"

// The load-bearing v0.6 positioning-honesty statements, pinned as INDEPENDENT
// verbatim fixtures. Each MUST appear byte-for-byte in the shipped notes (after
// hard-wrap normalisation). Markdown `**bold**` markers sit between words and
// survive whitespace normalisation, so each fixture stays inside one styling
// span (either a bolded lead phrase with its markers, or an unbolded clause).
const (
	// (1) Audit verification is now available to contributors; admin-only RETIRED.
	v06HonestyContribAvailable = "**Audit verification is now available to contributors.**"
	v06HonestyContribAllModes  = "`byreis audit verify` is permitted in all modes (Contributor, Admin, Super)."
	v06HonestyAdminOnlyRetired = "The v0.5 admin-only restriction is superseded by this release."

	// (2) Counter-monotonicity residual from v0.5 is now closed.
	v06HonestyCounterClosed      = "**The counter-monotonicity residual disclosed in v0.5 is now closed.**"
	v06HonestyCounterColdAndWarm = "A counter break → TAMPERED, regardless of content-hash outcome."

	// (3) Reject events are host-local and not covered by the verifier.
	v06HonestyRejectNotCovered = "**Decline and reject events are not covered by the audit-binding verifier.**"
	v06HonestyRejectHostLocal  = "Reject events are recorded host-locally at the time of rejection and are not " +
		"written to the registry audit channel."

	// (4) Pre-binding (legacy) lines are unverified, not tampered.
	v06HonestyLegacyNotVerified = "They are never displayed as `verified` and never as `TAMPERED`."

	// (5) Intra-commit reorder is below per-commit granularity (residual).
	v06HonestyIntraCommitReorder = "**Reordering two lines introduced by the same single commit is below the " +
		"per-commit binding granularity and is not detected.**"

	// (6) Trust root is the pinned TrustAnchorKey; an anchor-key-holding principal
	// can author internally consistent history (by design).
	v06HonestyTrustAnchor       = "**The verifier is only as strong as the pinned trust anchor.**"
	v06HonestyByreisSignerLabel = "The `byreis-signer` commit footer is an attested label that identifies the " +
		"signing tool; it is not an independent trust key."
	v06HonestyAnchorKeyResidual = "the trust root is the anchor, by design."

	// (7) The verifier is read-only and zero-decrypt.
	v06HonestyReadOnly    = "**The verifier is read-only and zero-decrypt.**"
	v06HonestyNoPlaintext = "No v0.6 surface gives a non-key-holder a route to a plaintext value."

	// (8) Verification fails closed under resource pressure.
	v06HonestyFailClosed        = "**Verification fails closed under resource pressure.**"
	v06HonestyNoPartialVerified = "There is no partial-verified-as-clean result and no silent truncation."

	// Asymmetric-access guarantee restated for v0.6.
	v06HonestyAsymmetryUnchanged = "no v0.6 surface gives a non-key-holder a route to a plaintext value"

	// GitHub-only scope.
	v06HonestyGitHubOnly = "**GitHub-only.**"
)

// v06HonestyFixtures pairs each verbatim statement with a short human label
// used in failure messages.
var v06HonestyFixtures = []struct {
	label string
	want  string
}{
	{"contrib-audit-verify-all-modes", v06HonestyContribAvailable},
	{"contrib-all-modes-enumerated", v06HonestyContribAllModes},
	{"v0.5-admin-only-retired", v06HonestyAdminOnlyRetired},
	{"counter-monotonicity-residual-closed", v06HonestyCounterClosed},
	{"counter-tampered-regardless-of-content-hash", v06HonestyCounterColdAndWarm},
	{"reject-not-covered (host-local only)", v06HonestyRejectNotCovered},
	{"reject-host-local-not-written-to-channel", v06HonestyRejectHostLocal},
	{"legacy-never-tampered", v06HonestyLegacyNotVerified},
	{"intra-commit-reorder-residual", v06HonestyIntraCommitReorder},
	{"trust-anchor-only-as-strong-as-pinned-key", v06HonestyTrustAnchor},
	{"byreis-signer-is-label-not-key", v06HonestyByreisSignerLabel},
	{"anchor-key-residual-by-design", v06HonestyAnchorKeyResidual},
	{"verifier-read-only-zero-decrypt", v06HonestyReadOnly},
	{"no-plaintext-route-for-non-key-holder", v06HonestyNoPlaintext},
	{"fail-closed-under-resource-pressure", v06HonestyFailClosed},
	{"no-partial-verified-as-clean", v06HonestyNoPartialVerified},
	{"asymmetry-unchanged", v06HonestyAsymmetryUnchanged},
	{"github-only-scope", v06HonestyGitHubOnly},
}

// v06ForbiddenPositioningTerms are case-insensitive substrings that MUST NOT
// appear in the v0.6 release notes.
//
// "multi-provider" and "multiprovider" guard the single-provider GitOps
// discipline: byreis is GitHub-only and has no other forge backend.
//
// "audit-binding verifier is admin-only in v0.6" guards against re-asserting
// the retired v0.5 admin-only restriction in the v0.6 notes. The v0.6 notes
// must state the INVERSE (verification is now available to contributors); any
// re-assertion of the old wording is a positioning-honesty regression.
var v06ForbiddenPositioningTerms = []string{
	"multi-provider",
	"multiprovider",
	"audit-binding verifier is admin-only in v0.6",
}

// TestDocGate_ReleaseNotesV06_PositioningHonestyVerbatim is the v0.6 release-
// blocking assertion: docs/release-notes-v0.6.md exists and contains every
// load-bearing positioning-honesty statement byte-for-byte (after hard-wrap
// normalisation). A missing or weakened statement is a release-blocker.
func TestDocGate_ReleaseNotesV06_PositioningHonestyVerbatim(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV06(t)
	normalised := normaliseReleaseNotes(raw)

	for _, fx := range v06HonestyFixtures {
		if !bytes.Contains(normalised, []byte(fx.want)) {
			t.Fatalf("v0.6 DOC GATE: %s does not contain the verbatim "+
				"positioning-honesty statement %q.\n"+
				"This is release-blocking: a missing or weakened statement means the "+
				"shipped notes overstate the audit-binding verifier scope or hide a "+
				"residual boundary of a security feature.\n\n"+
				"want (substring, after hard-wrap normalisation):\n%q\n\n"+
				"got (normalised release notes):\n%s",
				releaseNotesV06RelPath, fx.label, fx.want, string(normalised))
		}
	}

	t.Logf("v0.6 DOC GATE: PASS — all %d verbatim positioning-honesty statements "+
		"present in %s", len(v06HonestyFixtures), releaseNotesV06RelPath)
}

// TestDocGate_ReleaseNotesV06_NoForbiddenPositioningLanguage is the negative
// half: the v0.6 notes must carry NO multi-provider, GitLab, or retired admin-
// only language. byreis is single-provider (GitHub); multi-provider language
// or a re-assertion of the now-retired v0.5 admin-only claim are both
// positioning-honesty regressions.
func TestDocGate_ReleaseNotesV06_NoForbiddenPositioningLanguage(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV06(t)
	lower := bytes.ToLower(raw)

	for _, term := range v06ForbiddenPositioningTerms {
		if bytes.Contains(lower, []byte(term)) {
			t.Fatalf("v0.6 DOC GATE (negative): %s contains forbidden positioning "+
				"term %q (case-insensitive).\n"+
				"byreis is single-provider GitOps and this term is a release-blocking "+
				"positioning-honesty regression.\n\nrelease notes:\n%s",
				releaseNotesV06RelPath, term, string(raw))
		}
	}

	t.Logf("v0.6 DOC GATE (negative): PASS — no forbidden positioning language in %s",
		releaseNotesV06RelPath)
}

// readReleaseNotesV06 resolves docs/release-notes-v0.6.md from the module root
// and returns its bytes. A failure to locate the module root or the file is a
// hard test failure — a gate that cannot run must fail loudly, never silently
// pass.
func readReleaseNotesV06(t *testing.T) []byte {
	t.Helper()

	root, err := findModuleRootForDocgate()
	if err != nil {
		t.Fatalf("v0.6 DOC GATE FAIL: cannot find module root: %v.\n"+
			"The positioning-honesty gate needs the module root to locate %s.",
			err, releaseNotesV06RelPath)
	}
	abs := filepath.Join(root, releaseNotesV06RelPath)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		t.Fatalf("v0.6 DOC GATE FAIL: %s not found at %s: %v.\n"+
			"v0.6 requires the release notes to be published; a missing file is a "+
			"release-blocker.", releaseNotesV06RelPath, abs, statErr)
	}
	if info.IsDir() {
		t.Fatalf("v0.6 DOC GATE FAIL: expected %s to be a file, got a directory", abs)
	}
	raw, readErr := os.ReadFile(abs) //nolint:gosec // G304: path computed from module root, not user input
	if readErr != nil {
		t.Fatalf("v0.6 DOC GATE FAIL: cannot read %s: %v", abs, readErr)
	}
	if len(raw) < 500 {
		t.Fatalf("v0.6 DOC GATE FAIL: %s is only %d bytes (<500); the v0.6 release "+
			"notes must be a real, non-stub document.", abs, len(raw))
	}
	return raw
}
