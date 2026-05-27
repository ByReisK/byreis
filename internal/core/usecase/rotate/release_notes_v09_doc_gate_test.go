//go:build docgate

// v0.9 release-notes docgate row — plugin-backed admin identities.
//
// This is the v0.9 sibling of the v0.8 run-verb gate. It pins the
// load-bearing honesty statements of docs/release-notes-v0.9.md as verbatim
// fixtures and asserts the shipped release-notes file contains each one
// byte-for-byte (after hard-wrap normalisation).
//
// Why this test exists: v0.9 ships plugin-backed admin identities. Two
// statements in the release notes are load-bearing for the asymmetric-access
// guarantee and honest capability/risk claims:
//
//  (1) The CONTRIBUTOR change: contributors submitting to a project with
//      plugin-backed admins need the plugin binary on PATH but do NOT need
//      a YubiKey. The age plugin binary handles the recipient protocol during
//      encryption; the hardware token is only required at the admin's machine
//      during decryption.
//
//  (2) PATH-trust / no-code-signature disclosure: byreis invokes
//      age-plugin-* binaries from PATH and cannot verify their authenticity;
//      a hostile binary earlier on PATH sees the file key on the contributor
//      encrypt path (bigger exposure than admin-only). Install from trusted
//      sources only.
//
// If either of these is dropped, reworded into something weaker, or silently
// removed, byreis would ship release notes that misstate the contributor
// prerequisites (asymmetric-access surface) or hide the supply-chain trust
// assumption that operators must act on. This gate makes that a docgate red.
//
// Negative checks: the v0.9 notes must not claim GitLab support, must not
// claim TPM/FIDO2/Secure-Enclave are certified or tested (they are not; only
// yubikey is certified), and must not claim auto-install or managed plugin
// registry capability exists.
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
// The only I/O is a read of docs/release-notes-v0.9.md resolved from the
// module root. A gate that cannot locate the module root or the file fails
// loudly, never silently passes.

package rotate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// releaseNotesV09RelPath is the on-disk location of the v0.9 release notes,
// relative to the module root.
const releaseNotesV09RelPath = "docs/release-notes-v0.9.md"

// The load-bearing v0.9 honesty statements, pinned as INDEPENDENT verbatim
// fixtures. Each MUST appear byte-for-byte in the shipped notes (after
// hard-wrap normalisation). Inline-code markers and prose sit between words
// and survive whitespace normalisation.
const (
	// (1) Contributor change: binary needed, token NOT needed.
	// This is the "contributors need the binary, not the token" framing
	// required by the v0.9 spec. Pinned verbatim so a weakening edit
	// (e.g. "might not need" or "usually need") fails the gate.
	v09HonestyContributorBinaryNotToken = "contributors submitting to a project with plugin-backed admins need " +
		"`age-plugin-yubikey` on PATH but do NOT need a YubiKey"

	// Contributor encrypt path: the plugin binary handles the recipient protocol;
	// the YubiKey hardware is required only at the admin's machine during decryption.
	v09HonestyContributorPluginHandlesEncrypt = "The plugin binary handles the age recipient protocol on the " +
		"contributor's machine during encryption; the YubiKey hardware is only needed at the admin's machine " +
		"during decryption."

	// (2) PATH-trust / no-code-signature disclosure (B1 threat-modeler condition).
	// Pinned verbatim: byreis invokes age-plugin-* from PATH and cannot verify
	// authenticity; a hostile binary sees the file key — install from trusted
	// sources only.
	v09HonestyPATHTrust = "byreis invokes `age-plugin-*` binaries from your PATH and cannot verify their " +
		"authenticity; a hostile binary earlier on PATH sees the file key — install plugins from trusted " +
		"sources only."

	// Contributor path is explicitly named as the bigger exposure surface.
	v09HonestyContributorPathExposure = "This applies on the contributor encrypt path as well as the admin decrypt path"

	// One certified plugin only — yubikey.
	v09HonestyOneCertified = "Only `age-plugin-yubikey` is certified and tested."

	// Mixed fleet works: no re-key required when adding a plugin admin.
	v09HonestyMixedFleet = "Mixed X25519 + plugin fleets are the expected migration path."

	// Orphaned-subprocess residual disclosure.
	v09HonestyOrphanedSubprocess = "The underlying plugin subprocess may continue to run briefly after the timeout; " +
		"it is a best-effort reap, not a guaranteed kill."

	// Linux pcscd requirement.
	v09HonestyLinuxPcscd = "On Linux, `age-plugin-yubikey` requires `pcscd` (the PC/SC smart card daemon) to be " +
		"running when the YubiKey is touched during decryption."

	// Total-blockage edge case: documented, not hidden.
	v09HonestyTotalBlockage = "If every admin in a project has a plugin identity and a contributor does not have " +
		"the corresponding plugin binary installed, every `byreis submit` will fail with a binary-not-found error."

	// Drop-in upgrade: no format change.
	v09HonestyDropIn = "No secrets-format change, no registry-schema change, no environment variable change."
)

// v09HonestyFixtures pairs each verbatim statement with a short human label
// used in failure messages.
var v09HonestyFixtures = []struct {
	label string
	want  string
}{
	{"contributor-binary-not-token", v09HonestyContributorBinaryNotToken},
	{"contributor-plugin-handles-encrypt-hardware-admin-only", v09HonestyContributorPluginHandlesEncrypt},
	{"path-trust-no-code-sig-install-trusted-sources", v09HonestyPATHTrust},
	{"contributor-path-is-bigger-exposure", v09HonestyContributorPathExposure},
	{"one-certified-plugin-yubikey-only", v09HonestyOneCertified},
	{"mixed-fleet-expected-migration-path", v09HonestyMixedFleet},
	{"orphaned-subprocess-best-effort-reap-not-guaranteed-kill", v09HonestyOrphanedSubprocess},
	{"linux-pcscd-required-for-admin-decrypt", v09HonestyLinuxPcscd},
	{"total-blockage-edge-case-documented", v09HonestyTotalBlockage},
	{"drop-in-no-format-change", v09HonestyDropIn},
}

// v09ForbiddenPositioningTerms are case-insensitive substrings that MUST NOT
// appear in the v0.9 release notes.
//
// "multi-provider" and "multiprovider" guard the single-provider GitOps
// discipline: byreis is GitHub-only in v0.9. A phrase such as
// "No GitLab support" (an honest boundary disclosure) does not violate this
// gate; only a claim of multi-provider capability would.
//
// "tpm is certified", "fido2 is certified", and "se is certified" guard against
// affirmative certification claims for backends that are admitted-by-format only
// in v0.9. The correct wording ("admitted by format but are NOT certified or
// tested") does not contain any of these forbidden phrases.
//
// "byreis downloads plugins" and "byreis installs plugins" guard against a
// claim of auto-install capability that is explicitly OUT of v0.9. The honest
// "byreis does not download or manage plugin binaries" does not match.
var v09ForbiddenPositioningTerms = []string{
	"multi-provider",
	"multiprovider",
	"tpm is certified",
	"fido2 is certified",
	"se is certified",
	"secure enclave is certified",
	"byreis downloads plugins",
	"byreis installs plugins",
}

// TestDocGate_ReleaseNotesV09_PluginHonestyVerbatim is the v0.9 release-
// blocking assertion: docs/release-notes-v0.9.md exists and contains every
// load-bearing honesty statement byte-for-byte (after hard-wrap normalisation).
// A missing or weakened statement is a release-blocker.
func TestDocGate_ReleaseNotesV09_PluginHonestyVerbatim(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV09(t)
	normalised := normaliseReleaseNotes(raw)

	for _, fx := range v09HonestyFixtures {
		if !bytes.Contains(normalised, []byte(fx.want)) {
			t.Fatalf("v0.9 DOC GATE: %s does not contain the verbatim "+
				"honesty statement %q.\n"+
				"This is release-blocking: a missing or weakened statement means the "+
				"shipped notes misstate the contributor prerequisites (asymmetric-access "+
				"surface), hide the PATH-trust / supply-chain assumption operators must "+
				"act on, or drop another concrete residual risk.\n\n"+
				"want (substring, after hard-wrap normalisation):\n%q\n\n"+
				"got (normalised release notes):\n%s",
				releaseNotesV09RelPath, fx.label, fx.want, string(normalised))
		}
	}

	t.Logf("v0.9 DOC GATE: PASS — all %d verbatim honesty statements present in %s",
		len(v09HonestyFixtures), releaseNotesV09RelPath)
}

// TestDocGate_ReleaseNotesV09_NoForbiddenPositioningLanguage is the negative
// half: the v0.9 notes must carry NO GitLab/multi-provider claims, no claim
// that auto-install or a managed plugin registry is supported, and no
// affirmative certification claim for TPM/FIDO2/Secure Enclave.
func TestDocGate_ReleaseNotesV09_NoForbiddenPositioningLanguage(t *testing.T) {
	t.Parallel()

	raw := readReleaseNotesV09(t)
	lower := bytes.ToLower(raw)

	for _, term := range v09ForbiddenPositioningTerms {
		if bytes.Contains(lower, []byte(term)) {
			t.Fatalf("v0.9 DOC GATE (negative): %s contains forbidden positioning "+
				"term %q (case-insensitive).\n"+
				"byreis is single-provider GitOps and this release does not include "+
				"auto-install, managed plugin registry, or multi-provider support. "+
				"This term is a release-blocking positioning-honesty regression.\n\n"+
				"release notes:\n%s",
				releaseNotesV09RelPath, term, string(raw))
		}
	}

	t.Logf("v0.9 DOC GATE (negative): PASS — no forbidden positioning language in %s",
		releaseNotesV09RelPath)
}

// readReleaseNotesV09 resolves docs/release-notes-v0.9.md from the module root
// and returns its bytes. A failure to locate the module root or the file is a
// hard test failure — a gate that cannot run must fail loudly, never silently
// pass.
func readReleaseNotesV09(t *testing.T) []byte {
	t.Helper()

	root, err := findModuleRootForDocgate()
	if err != nil {
		t.Fatalf("v0.9 DOC GATE FAIL: cannot find module root: %v.\n"+
			"The plugin-identity honesty gate needs the module root to locate %s.",
			err, releaseNotesV09RelPath)
	}
	abs := filepath.Join(root, releaseNotesV09RelPath)
	info, statErr := os.Stat(abs)
	if statErr != nil {
		t.Fatalf("v0.9 DOC GATE FAIL: %s not found at %s: %v.\n"+
			"v0.9 requires the release notes to be published; a missing file is a "+
			"release-blocker.", releaseNotesV09RelPath, abs, statErr)
	}
	if info.IsDir() {
		t.Fatalf("v0.9 DOC GATE FAIL: expected %s to be a file, got a directory", abs)
	}
	raw, readErr := os.ReadFile(abs) //nolint:gosec // G304: path computed from module root, not user input
	if readErr != nil {
		t.Fatalf("v0.9 DOC GATE FAIL: cannot read %s: %v", abs, readErr)
	}
	if len(raw) < 500 {
		t.Fatalf("v0.9 DOC GATE FAIL: %s is only %d bytes (<500); the v0.9 release "+
			"notes must be a real, non-stub document.", abs, len(raw))
	}
	return raw
}
