//go:build docgate

// v0.9 plugin-identity doc-gate row — release-blocking.
//
// This file discharges the v0.9 plugin-identity documentation obligation: the
// public docs (README.md status line + docs/guide.md plugin section) MUST
// state, in load-bearing prose, the claims that make the plugin-identity
// feature honest about its asymmetric-access surface and its supply-chain risk:
//
//  (1) CONTRIBUTOR prerequisite: contributors submitting to a project with
//      plugin-backed admins need the plugin binary on PATH but do NOT need a
//      YubiKey. The binary handles the age recipient protocol during encryption;
//      the hardware token is required only at the admin's machine during
//      decryption.
//
//  (2) PATH-trust / no-code-signature disclosure: byreis invokes age-plugin-*
//      from PATH and cannot verify their authenticity; a hostile binary earlier
//      on PATH sees the file key; install from trusted sources only. This applies
//      on the contributor path (the bigger exposure surface) as well as the admin
//      path.
//
//  (3) Linux pcscd prerequisite: on Linux, age-plugin-yubikey requires pcscd to
//      be running when the YubiKey is touched during decryption.
//
//  (4) Missing-binary fail-closed: if the plugin binary is absent when a
//      contributor runs byreis submit, the command fails immediately with an
//      error naming the missing binary and an install hint.
//
//  (5) Version-skew gap: re-enrolling a token slot produces a new recipient
//      string; the old registry entry becomes stale and must be updated manually.
//      byreis doctor does not auto-detect this.
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

// The load-bearing v0.9 plugin-identity documentation statements, pinned as
// INDEPENDENT verbatim fixtures. Each MUST appear byte-for-byte (after
// hard-wrap normalisation) in docs/guide.md unless noted otherwise.
const (
	// (1) Contributor prerequisite: binary on PATH, not the token.
	// This is the "contributors need the binary, not the token" verbatim
	// framing required by the v0.9 spec (AC-011-a). Pinned so a weakening
	// edit (e.g. "might not need") fails the gate. The sentence starts with a
	// capital C (start of a paragraph), so the fixture matches the guide prose.
	pluginDocContributorBinaryNotToken = "Contributors submitting to a project with plugin-backed admins need " +
		"`age-plugin-yubikey` on PATH but do NOT need a YubiKey"

	// The plugin binary handles the age recipient protocol on the contributor's
	// machine during encryption; the YubiKey is required only at the admin's
	// machine during decryption.
	pluginDocContributorPluginRole = "The plugin binary handles the age recipient protocol on the " +
		"contributor's machine during encryption; the YubiKey hardware is needed only at the admin's " +
		"machine during decryption."

	// (2) PATH-trust / no-code-signature disclosure (B1 threat-modeler condition).
	// Pinned verbatim: byreis invokes age-plugin-* from PATH, cannot verify
	// authenticity, a hostile binary sees the file key — install from trusted
	// sources only.
	pluginDocPATHTrust = "byreis invokes `age-plugin-*` binaries from your PATH and cannot verify their " +
		"authenticity; a hostile binary earlier on PATH sees the file key — install plugins from trusted " +
		"sources only."

	// The contributor encrypt path is named as a concern (larger exposure surface
	// than admin-only, because the contributor runs without hardware).
	pluginDocContributorPathExposure = "This applies on the contributor encrypt path as well as the admin decrypt path"

	// (3) Linux pcscd prerequisite.
	pluginDocLinuxPcscd = "On Linux, `age-plugin-yubikey` requires the `pcscd` smart card daemon to be running " +
		"when the YubiKey is touched during decryption."

	// The contributor path is explicitly not affected by pcscd.
	pluginDocLinuxPcscdContributorUnaffected = "The contributor path does NOT touch the YubiKey and is not affected by `pcscd`."

	// (4) Missing-binary fail-closed: error names the missing binary + install hint.
	pluginDocMissingBinaryFailClosed = "If the binary is absent when a contributor runs `byreis submit`, the command " +
		"fails immediately with an error naming the missing binary and an install hint, before any secret value " +
		"is collected."

	// (5) Version-skew gap: re-enroll changes the recipient string; registry
	// entry becomes stale; byreis doctor does not auto-detect this.
	pluginDocVersionSkew = "`byreis doctor` does not automatically detect this skew."

	// README status-line reference: v0.9 plugin feature and contributor binary prerequisite.
	pluginDocREADMEStatusLine = "contributors submitting to a plugin-admin project need `age-plugin-yubikey` on " +
		"PATH but do NOT need a YubiKey"
)

// pluginDocGuideFixtures pairs each verbatim docs/guide.md statement with a
// short human label used in failure messages.
var pluginDocGuideFixtures = []struct {
	label string
	want  string
}{
	{"contributor-binary-not-token-verbatim", pluginDocContributorBinaryNotToken},
	{"contributor-plugin-handles-encrypt-hardware-admin-only", pluginDocContributorPluginRole},
	{"path-trust-no-code-sig-install-trusted-sources", pluginDocPATHTrust},
	{"contributor-encrypt-path-is-bigger-exposure", pluginDocContributorPathExposure},
	{"linux-pcscd-required-for-admin-decrypt", pluginDocLinuxPcscd},
	{"contributor-path-not-affected-by-pcscd", pluginDocLinuxPcscdContributorUnaffected},
	{"missing-binary-fail-closed-names-binary-install-hint", pluginDocMissingBinaryFailClosed},
	{"version-skew-doctor-does-not-auto-detect", pluginDocVersionSkew},
}

// TestDocGate_PluginIdentityGuide_ContributorBinaryPATHTrustLinuxPcscd is the
// v0.9 release-blocking assertion: docs/guide.md contains every load-bearing
// plugin-identity documentation statement byte-for-byte (after hard-wrap
// normalisation). A missing or weakened statement is a release-blocker: the
// public docs would misstate the contributor prerequisites (asymmetric-access
// surface), hide the PATH-trust / supply-chain assumption operators must act
// on, or drop the Linux pcscd requirement.
func TestDocGate_PluginIdentityGuide_ContributorBinaryPATHTrustLinuxPcscd(t *testing.T) {
	t.Parallel()

	raw := readExportDoc(t, exportDocGateGuideRelPath)
	normalised := normaliseExportDoc(raw)

	for _, fx := range pluginDocGuideFixtures {
		if !bytes.Contains(normalised, []byte(fx.want)) {
			t.Fatalf("v0.9 PLUGIN DOC GATE: %s does not contain the verbatim "+
				"statement %q.\n"+
				"This is release-blocking: the plugin docs would misstate the "+
				"contributor prerequisites (asymmetric-access surface), hide the "+
				"PATH-trust / supply-chain assumption, drop the Linux pcscd "+
				"requirement, or drop the missing-binary fail-closed behavior.\n\n"+
				"want (substring, after hard-wrap normalisation):\n%q\n\n"+
				"got (normalised doc):\n%s",
				exportDocGateGuideRelPath, fx.label, fx.want, string(normalised))
		}
	}

	t.Logf("v0.9 PLUGIN DOC GATE: PASS — all %d verbatim plugin-identity statements "+
		"present in %s", len(pluginDocGuideFixtures), exportDocGateGuideRelPath)
}

// TestDocGate_PluginIdentityREADME_V09StatusLine asserts the README status
// section references v0.9 and the contributor binary prerequisite. The README
// status line is the first place an operator checks whether they are on the
// current release; a status line that does not mention the plugin feature or
// omits the contributor-binary-not-token framing would misrepresent v0.9.
func TestDocGate_PluginIdentityREADME_V09StatusLine(t *testing.T) {
	t.Parallel()

	raw := readExportDoc(t, exportDocGateREADMERelPath)
	normalised := normaliseExportDoc(raw)

	if !bytes.Contains(normalised, []byte(pluginDocREADMEStatusLine)) {
		t.Fatalf("v0.9 PLUGIN DOC GATE: %s does not contain the v0.9 status-line "+
			"plugin framing %q.\n"+
			"This is release-blocking: the README must state the contributor-binary "+
			"prerequisite ('binary not token') so operators know what to install.\n\n"+
			"want (substring, after hard-wrap normalisation):\n%q\n\n"+
			"got (normalised README):\n%s",
			exportDocGateREADMERelPath, pluginDocREADMEStatusLine,
			pluginDocREADMEStatusLine, string(normalised))
	}

	t.Logf("v0.9 PLUGIN DOC GATE: PASS — %s contains the v0.9 plugin status-line framing",
		exportDocGateREADMERelPath)
}
