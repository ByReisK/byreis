//go:build docgate

// V4 (REQ-R-003-DOC R4-constant + BO-V4-3 + BO-V4-5 §V4 ship-gate addendum) —
// docgate suite: forward-secrecy warning verbatim cross-check.
//
// This file is the docgate sibling lane to the V1 default-tag verbatim check.
// The V4 row (BO-V4-3) asserts THREE-WAY byte-for-byte equality between:
//
//   (a) The independent []byte fixture embedded verbatim in this file,
//   (b) the production rotate.ForwardSecrecyWarning constant,
//   (c) the ADR-0016 §D9 normative warning block.
//
// (a) ⇄ (b) is asserted directly here. (a) ⇄ (c) is asserted operationally:
// the fixture below IS the verbatim ADR-0016 §D9 text and is reviewed against
// that text at any change to either side. (b) ⇄ (c) is asserted by the V1
// default-tag test TestForwardSecrecyWarning_VerbatimMatchesADR0016 in
// rotate_test.go — the V4 row composes with it to close the three-way ring.
//
// Per BO-V4-5 this file additionally asserts the fixture contains the literal
// substring "docs/forward-secrecy.md" — so a rename of the shipped runbook
// file at docs/forward-secrecy.md is a docgate red, surfacing the implied
// breakage of the warning's "See <path> for the runbook" sentence before
// release.
//
// Build constraint: //go:build docgate. The docgate tag is a NEW sibling
// lane to shipgate / testhook; it is non-default, never compiled into a
// shipped binary (asserted structurally by shipped_surface_test.go and by
// the CI release-build-clean check in .github/workflows/ci.yml).
//
// Package: rotate_test (external test package). The fixture deliberately
// does NOT use any unexported rotate-internal identifier; the ONLY
// reference to rotate.ForwardSecrecyWarning in this file is the single
// equality-assertion line, marked nolint:forbidigo per the BO-V4-F14
// boundary rule (rule defined in .golangci.yml).

package rotate_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// forwardSecrecyWarningFixture is the verbatim ADR-0016 §D9 warning text,
// embedded here as an independent []byte literal — NOT derived from the
// production constant. The fixture and the constant are independently
// reviewed against the same ADR §D9 source-of-truth text, so a typo in
// either side fails this gate by design (BO-V4-3 three-way equality).
//
// CRITICAL: do NOT replace this []byte literal with a string-import of
// rotate.ForwardSecrecyWarning ("DRY refactor"). The single-source
// equality that move would create defeats the three-way cross-check
// and silently green-lights a regression in the production constant.
// The .golangci.yml forbidigo rule defends this boundary; this comment
// documents WHY the boundary exists.
var forwardSecrecyWarningFixture = []byte("WARNING: forward secrecy over git history is NOT provided by rotation.\n" +
	"\n" +
	"A removed recipient's private key, if retained, can still decrypt the\n" +
	"pre-rotation ciphertext from any retained clone or fork of the project\n" +
	"git history. byreis rotation re-encrypts every CURRENT secrets file to\n" +
	"the new recipient set, but it CANNOT retroactively remove past\n" +
	"ciphertext from past commits. If the removed recipient is a compromised\n" +
	"party, you MUST treat all secret values that were ever encrypted under\n" +
	"the pre-rotation recipient set as compromised and rotate the\n" +
	"underlying values (passwords, tokens, keys) themselves out-of-band.\n" +
	"\n" +
	"This is a property of the `age` cryptographic primitive (Model B) and\n" +
	"of git's append-only history, not a byreis bug. See docs/forward-\n" +
	"secrecy.md for the runbook.")

// TestForwardSecrecyWarning_VerbatimMatch asserts BO-V4-3 (a) ⇄ (b):
// the docgate fixture and the production rotate.ForwardSecrecyWarning
// constant are byte-for-byte equal. A divergence on either side is a
// deliberate review event (re-issue of ADR-0016 §D9 with crypto-auditor
// on the loop).
//
// This is the ONLY line in the file that references
// rotate.ForwardSecrecyWarning as a token — per BO-V4-F14 the rule
// defined in .golangci.yml bans the token everywhere; the one-line
// boundary mark below is the single allowed reference (equality
// assertion only). A future refactor that imports the constant as the
// fixture source would have to either (i) remove the nolint mark
// (which makes the lint rule fire and blocks the PR) or (ii) keep the
// mark but extend its usage (which is a deliberate review event because
// the boundary comment requires "boundary: equality assertion only").
func TestForwardSecrecyWarning_VerbatimMatch(t *testing.T) {
	t.Parallel()

	want := forwardSecrecyWarningFixture
	got := []byte(rotate.ForwardSecrecyWarning) //nolint:forbidigo // boundary: equality assertion only

	if len(got) != len(want) {
		t.Fatalf("docgate fixture / rotate.ForwardSecrecyWarning length mismatch: "+
			"got %d, want %d.\n"+
			"This indicates the production constant has drifted from the verbatim "+
			"ADR-0016 §D9 block. Either (a) the constant was edited without "+
			"updating the ADR + this fixture, OR (b) the fixture has a typo. "+
			"Re-review against ADR-0016 §D9 before changing either side.\n\n"+
			"full got:  %q\n"+
			"full want: %q",
			len(got), len(want), string(got), string(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("docgate fixture / rotate.ForwardSecrecyWarning differ at byte %d: "+
				"got %q, want %q.\n"+
				"This is a deliberate-review-event regression: the production "+
				"constant has drifted from the verbatim ADR-0016 §D9 block. "+
				"Re-review against ADR-0016 §D9.\n\n"+
				"full got:  %q\n"+
				"full want: %q",
				i, string(got[i]), string(want[i]), string(got), string(want))
		}
	}
}

// TestForwardSecrecyWarning_RunbookPathReferenceIntact asserts BO-V4-5:
// the verbatim warning's "See <runbook> for the runbook." sentence is
// intact AND a shipped runbook file actually exists at the referenced
// path. If the runbook is renamed without the warning being updated, the
// released binary would point a compromised-key incident-responder at a
// path that no longer exists — release-blocking on R4a/R4b honesty.
//
// The verbatim ADR-0016 §D9 block hard-wraps the path across one line
// boundary ("docs/forward-\nsecrecy.md"), so the substring check
// normalises hyphen-newline soft-wraps before matching. The reference
// MUST be present in BOTH wrapped and unwrapped forms (the wrapped form
// is what ships in the binary; the unwrapped form is what an operator
// will actually file-system-look-up). Then a filesystem stat asserts
// the runbook file exists at HEAD of the module.
func TestForwardSecrecyWarning_RunbookPathReferenceIntact(t *testing.T) {
	t.Parallel()

	// The runbook path, in the form an operator would type to look it
	// up. The warning text references this path with a hyphen-newline
	// soft-wrap; the check below normalises the wrap before matching.
	const runbookPath = "docs/forward-secrecy.md"

	normalized := bytes.ReplaceAll(forwardSecrecyWarningFixture, []byte("-\n"), []byte("-"))
	if !bytes.Contains(normalized, []byte(runbookPath)) {
		t.Fatalf("docgate fixture does not contain the literal substring %q "+
			"(checked after normalising hyphen-newline soft-wraps).\n"+
			"The verbatim ADR-0016 §D9 warning ends with a reference to this "+
			"runbook path; a missing substring here means either (a) the fixture "+
			"was edited without updating the warning's runbook reference, OR "+
			"(b) the runbook was renamed and the warning's See-line is stale. "+
			"Either is a release-blocker for R4a/R4b honesty.\n\n"+
			"normalized fixture: %q",
			runbookPath, string(normalized))
	}

	// File-system existence check: the warning points operators at a
	// real file. A warning that references a non-existent runbook is a
	// release-blocking honesty regression.
	root, err := findModuleRootForDocgate()
	if err != nil {
		t.Fatalf("RUNBOOK GATE FAIL: cannot find module root: %v", err)
	}
	abs := filepath.Join(root, runbookPath)
	info, err := os.Stat(abs)
	if err != nil {
		t.Fatalf("RUNBOOK GATE FAIL: %s referenced by ForwardSecrecyWarning does "+
			"not exist on disk at %s: %v.\n"+
			"The warning points an operator at this path; a missing file is a "+
			"release-blocker.", runbookPath, abs, err)
	}
	if info.IsDir() {
		t.Fatalf("RUNBOOK GATE FAIL: expected %s to be a file, got a directory", abs)
	}
	if info.Size() < 1000 {
		t.Fatalf("RUNBOOK GATE FAIL: %s exists but is only %d bytes (<1000); "+
			"per BO-V4-5 PRE-impl ack, the runbook must be non-empty and "+
			"meaningfully cover (a) age semantics, (b) git append-only "+
			"history, (c) out-of-band value rotation, (d) the no-forward-"+
			"secrecy honesty.", abs, info.Size())
	}
}

// findModuleRootForDocgate walks up from CWD looking for go.mod. The
// release-wiring test has an identical helper; they are sibling test
// files in the same package and both need to resolve the module root.
// Keeping the helper file-local here avoids cross-file ordering brittleness
// (Go test files in the same package may be compiled in any order; a
// shared helper file would couple two otherwise-orthogonal docgate rows).
func findModuleRootForDocgate() (string, error) {
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
			return "", errDocgateModuleRootNotFound
		}
		dir = parent
	}
}

var errDocgateModuleRootNotFound = errors.New("go.mod not found in any ancestor directory")
