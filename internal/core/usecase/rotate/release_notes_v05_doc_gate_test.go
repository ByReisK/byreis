//go:build docgate

// v0.5 positioning-honesty docgate row — per-line audit-binding verifier.
//
// This is the v0.5 sibling of the v0.4 positioning-honesty gate. It pins the
// load-bearing honesty statements of docs/release-notes-v0.5.md as verbatim
// fixtures and asserts the shipped release-notes file contains each one
// byte-for-byte (after hard-wrap normalisation).
//
// Why this test exists: v0.5 ships admin audit show --verify, which makes a
// concrete tamper-detection claim. That claim is only acceptable if the release
// notes honestly bound what the verifier does and does not cover. Seven
// disclosures are load-bearing:
//
//   (1) Reject events are host-local only; the verifier cannot bind them.
//   (2) Pre-binding (legacy) lines are shown as "legacy", never "verified".
//   (3) Intra-commit reorder is below per-commit binding granularity (residual).
//   (4) Trust is anchored to the single pinned TrustAnchorKey; byreis-signer
//       is a label, not an independent key.
//   (5) --verify is admin-only in v0.5; contributor verify is a follow-up.
//   (6) Verification fails closed under resource pressure; availability is
//       not guaranteed against a hostile registry.
//   (7) Pre-binding prefix residual: an anchor-key-holding admin could fabricate
//       a legacy-classified line; it does not affect the counter anti-rollback layer.
//
// If any of these statements is dropped, reworded into something weaker, or
// silently removed, byreis would ship release notes that overstate the
// tamper-detection scope or hide the residual boundaries of a security feature.
// This gate makes that a docgate red.
//
// Verbatim-pin discipline (mirrors the v0.4 row and the R4 forward-secrecy ring):
// each load-bearing statement is an INDEPENDENT verbatim string fixture in this
// file, asserted as a substring of the shipped release-notes bytes after hard-wrap
// normalisation. The fixtures are NOT derived from the release-notes file; a typo
// or weakening edit on EITHER side fails the gate by design.
//
// A negative check asserts the notes contain no false GitLab/multi-provider claim
// and no claim that contributor-side verify is shipped in v0.5.
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
// The only I/O is a read of docs/release-notes-v0.5.md resolved from the
// module root. A gate that cannot locate the module root or the file fails
// loudly, never silently passes.

package rotate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// releaseNotesV05RelPath is the on-disk location of the v0.5 release notes,
// relative to the module root.
const releaseNotesV05RelPath = "docs/release-notes-v0.5.md"

// The load-bearing v0.5 positioning-honesty statements, pinned as INDEPENDENT
// verbatim fixtures. Each MUST appear byte-for-byte in the shipped notes (after
// hard-wrap normalisation). Markdown `**bold**` markers sit between words and
// survive whitespace normalisation, so each fixture stays inside one styling
// span (either a bolded lead phrase with its markers, or an unbolded clause).
const (
	// (1) Reject events are host-local and not covered by the verifier.
	v05HonestyRejectNotCovered = "**Decline and reject events are not covered by the audit-binding verifier.**"
	v05HonestyRejectHostLocal  = "Reject events are recorded host-locally at the time of rejection and are not " +
		"written to the registry audit channel."

	// (2) Pre-binding (legacy) lines are unverified, not tampered.
	v05HonestyLegacyNotVerified = "**Audit lines written before this release are shown as `legacy`, not `verified`.**"
	v05HonestyLegacyNeverTamper = "They are never displayed as `verified` and never as `TAMPERED`"

	// (3) Intra-commit reorder is below per-commit granularity (residual).
	v05HonestyIntraCommitReorder = "**Reordering two lines introduced by the same single commit is below the " +
		"per-commit binding granularity and is not detected.**"

	// (4) Trust root is the pinned TrustAnchorKey; byreis-signer is a label only.
	v05HonestyTrustAnchor      = "**The verifier is only as strong as the pinned trust anchor.**"
	v05HonestyByreisSignerLabel = "The `byreis-signer` commit footer is an attested label that identifies the " +
		"signing tool; it is not an independent trust key."

	// (5) --verify is admin-only in v0.5; contributor verify is a follow-up.
	v05HonestyAdminOnly      = "**The audit-binding verifier is admin-only in v0.5.**"
	v05HonestyContribFollowUp = "Contributor-side audit verification is not in this release and is a planned follow-up"

	// (6) Verification fails closed under resource pressure; no partial result.
	v05HonestyFailClosed        = "**Verification fails closed under resource pressure.**"
	v05HonestyNoPartialVerified = "There is no partial-verified-as-clean result and no silent truncation."

	// (7) Pre-binding prefix residual: anchor-key-holding admin could fabricate
	// a legacy-classified line; counter anti-rollback is orthogonal and unaffected.
	v05HonestyLegacyResidual      = "**Pre-binding legacy lines carry a residual that cannot be closed without " +
		"rewriting history.**"
	v05HonestyResidualAdminOnly   = "is exploitable only by a maximally-trusted principal"
	v05HonestyCounterUnaffected   = "It does not affect the monotonic-counter anti-rollback layer that protects " +
		"secret artifacts."

	// Asymmetric-access guarantee restated for v0.5.
	v05HonestyAsymmetryUnchanged = "no v0.5 surface gives a non-key-holder a route to a plaintext value"

	// (S3) Actor attribution is anchor-attested + current-admin-scoped; removed/rotated
	// admins display "-"; attribution only on binding-verified path; JSONL actor field untrusted.
	v05HonestyActorAnchorAttested   = "derived from the anchor-attested signer identity recorded in the signed introducing"
	v05HonestyActorJSONLUntrusted   = "The in-line JSONL `actor` field is never used for display."
	v05HonestyActorRemovedDash      = "An action by a since-removed or rotated admin displays `-`."
	v05HonestyActorBindingOnly      = "Only entries whose binding status is `verified` receive an actor attribution."
	v05HonestyActorForgeImpossible  = "A registry-writer who controlled only the JSONL bytes (but not a registered " +
		"signing key) cannot cause a forged name to appear in the actor column."
)

// v05HonestyFixtures pairs each verbatim statement with a short human label
// used in failure messages.
var v05HonestyFixtures = []struct {
	label string
	want  string
}{
	{"reject-not-covered (host-local only)", v05HonestyRejectNotCovered},
	{"reject-host-local-not-written-to-channel", v05HonestyRejectHostLocal},
	{"legacy-shown-as-legacy-not-verified", v05HonestyLegacyNotVerified},
	{"legacy-never-tampered", v05HonestyLegacyNeverTamper},
	{"intra-commit-reorder-residual", v05HonestyIntraCommitReorder},
	{"trust-anchor-only-as-strong-as-pinned-key", v05HonestyTrustAnchor},
	{"byreis-signer-is-label-not-key", v05HonestyByreisSignerLabel},
	{"admin-only-in-v0.5", v05HonestyAdminOnly},
	{"contributor-verify-is-follow-up", v05HonestyContribFollowUp},
	{"fail-closed-under-resource-pressure", v05HonestyFailClosed},
	{"no-partial-verified-as-clean", v05HonestyNoPartialVerified},
	{"legacy-prefix-residual", v05HonestyLegacyResidual},
	{"residual-exploitable-only-by-maximally-trusted", v05HonestyResidualAdminOnly},
	{"counter-anti-rollback-unaffected", v05HonestyCounterUnaffected},
	{"asymmetry-unchanged", v05HonestyAsymmetryUnchanged},
	// S3 actor-identity attribution disclosures.
	{"actor-attribution-anchor-attested", v05HonestyActorAnchorAttested},
	{"actor-jsonl-field-untrusted-for-display", v05HonestyActorJSONLUntrusted},
	{"actor-removed-admin-displays-dash", v05HonestyActorRemovedDash},
	{"actor-attribution-binding-verified-only", v05HonestyActorBindingOnly},
	{"actor-forge-impossible-without-signing-key", v05HonestyActorForgeImpossible},
}

// v05ForbiddenPositioningTerms are case-insensitive substrings that MUST NOT
// appear in the v0.5 release notes.
//
// "multi-provider" and "multiprovider" guard the single-provider GitOps discipline:
// byreis is GitHub-only and has no other forge backend.
//
// "contributor.*verify" is not a simple substring check — it is checked via the
// explicit negative fixture below rather than a forbidden-term scan, because the
// notes legitimately say contributor verify is a "planned follow-up" (which is the
// honest statement). The forbidden term here ensures no affirmative shipped-in-v0.5
// claim slips in.
var v05ForbiddenPositioningTerms = []string{
	"multi-provider",
	"multiprovider",
}

// TestDocGate_ReleaseNotesV05_PositioningHonestyVerbatim is the v0.5 release-
// blocking assertion: docs/release-notes-v0.5.md exists and contains every
// load-bearing positioning-honesty statement byte-for-byte (after hard-wrap
// normalisation). A missing or weakened statement is a release-blocker.
func TestDocGate_ReleaseNotesV05_PositioningHonestyVerbatim(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV05(t)
	normalised := normaliseReleaseNotes(raw)

	for _, fx := range v05HonestyFixtures {
		if !bytes.Contains(normalised, []byte(fx.want)) {
			t.Fatalf("v0.5 DOC GATE: %s does not contain the verbatim "+
				"positioning-honesty statement %q.\n"+
				"This is release-blocking: a missing or weakened statement means the "+
				"shipped notes overstate the audit-binding verifier scope or hide a "+
				"residual boundary of a security feature.\n\n"+
				"want (substring, after hard-wrap normalisation):\n%q\n\n"+
				"got (normalised release notes):\n%s",
				releaseNotesV05RelPath, fx.label, fx.want, string(normalised))
		}
	}

	t.Logf("v0.5 DOC GATE: PASS — all %d verbatim positioning-honesty statements "+
		"present in %s", len(v05HonestyFixtures), releaseNotesV05RelPath)
}

// TestDocGate_ReleaseNotesV05_NoForbiddenPositioningLanguage is the negative
// half: the v0.5 notes must carry NO multi-provider language. byreis is
// single-provider (GitHub); multi-provider language is a positioning-honesty
// regression.
func TestDocGate_ReleaseNotesV05_NoForbiddenPositioningLanguage(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV05(t)
	lower := bytes.ToLower(raw)

	for _, term := range v05ForbiddenPositioningTerms {
		if bytes.Contains(lower, []byte(term)) {
			t.Fatalf("v0.5 DOC GATE (negative): %s contains forbidden positioning "+
				"term %q (case-insensitive).\n"+
				"byreis is single-provider GitOps and this term is a release-blocking "+
				"positioning-honesty regression.\n\nrelease notes:\n%s",
				releaseNotesV05RelPath, term, string(raw))
		}
	}

	t.Logf("v0.5 DOC GATE (negative): PASS — no forbidden positioning language in %s",
		releaseNotesV05RelPath)
}

// readReleaseNotesV05 resolves docs/release-notes-v0.5.md from the module root
// and returns its bytes. A failure to locate the module root or the file is a
// hard test failure — a gate that cannot run must fail loudly, never silently
// pass.
func readReleaseNotesV05(t *testing.T) []byte {
	t.Helper()

	root, err := findModuleRootForDocgate()
	if err != nil {
		t.Fatalf("v0.5 DOC GATE FAIL: cannot find module root: %v.\n"+
			"The positioning-honesty gate needs the module root to locate %s.",
			err, releaseNotesV05RelPath)
	}
	abs := filepath.Join(root, releaseNotesV05RelPath)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		t.Fatalf("v0.5 DOC GATE FAIL: %s not found at %s: %v.\n"+
			"v0.5 requires the release notes to be published; a missing file is a "+
			"release-blocker.", releaseNotesV05RelPath, abs, statErr)
	}
	if info.IsDir() {
		t.Fatalf("v0.5 DOC GATE FAIL: expected %s to be a file, got a directory", abs)
	}
	raw, readErr := os.ReadFile(abs) //nolint:gosec // G304: path computed from module root, not user input
	if readErr != nil {
		t.Fatalf("v0.5 DOC GATE FAIL: cannot read %s: %v", abs, readErr)
	}
	if len(raw) < 500 {
		t.Fatalf("v0.5 DOC GATE FAIL: %s is only %d bytes (<500); the v0.5 release "+
			"notes must be a real, non-stub document.", abs, len(raw))
	}
	return raw
}
