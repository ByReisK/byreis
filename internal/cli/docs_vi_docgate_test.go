//go:build docgate

// VN docs anti-rot gate — release-blocking.
//
// This file enforces the cross-language coverage contract for the multilingual
// MkDocs site: every English doc page that is part of the rendered site MUST
// have a Vietnamese sibling, and a small set of structural anchors (CLI verb
// names, the canonical environment variable names, and the current shipped
// version number) MUST appear in BOTH the EN and VN copies of every page.
//
// The point is not translation correctness — that is a human concern — but to
// catch the easy rot case mechanically: a release-cycle edit that touches the
// EN docs without touching VN, or vice versa, breaks an anchor and fails the
// gate. The author of the change then either updates the VN side, or
// explicitly removes a docs page in BOTH languages.
//
// Coverage:
//
//	(1) Every docs/*.md (excluding *.vi.md and the excluded README.md) must have
//	    a sibling docs/*.vi.md. Missing pairs fail.
//	(2) The version number that appears in the EN guide must appear in the VN
//	    guide (the lede mentions byreis v0.X.Y; a stale lede on either side is
//	    almost always a forgotten translation).
//	(3) For docs that mention CLI verbs or env var names (guide.md,
//	    features.md, getting-started.md, walkthrough.md, security-model.md),
//	    each named anchor that appears in the EN file MUST appear in the VN
//	    file too.
//
// Build constraint: //go:build docgate ONLY. Non-default; never compiled into a
// shipped binary.
package cli_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// docsRoot resolves the absolute path to <repo>/docs from this test file's own
// path, so the test does not depend on the test runner's working directory.
func docsRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed; cannot derive docs root")
	}
	// internal/cli/docs_vi_docgate_test.go → ../../docs
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "docs")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("filepath.Abs(%q): %v", root, err)
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		t.Fatalf("docs root %q is not a directory: err=%v", abs, err)
	}
	return abs
}

// enPages walks docs/ and returns every English page name (basename without
// the .md extension) that is part of the rendered site — i.e. every *.md
// except *.vi.md siblings and the excluded README.md.
func enPages(t *testing.T) []string {
	t.Helper()
	root := docsRoot(t)
	var pages []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".md") {
			return nil
		}
		if strings.HasSuffix(name, ".vi.md") {
			return nil
		}
		if name == "README.md" {
			return nil
		}
		base := strings.TrimSuffix(name, ".md")
		pages = append(pages, base)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %q: %v", root, err)
	}
	sort.Strings(pages)
	return pages
}

// TestDocsVI_EveryENPageHasVNSibling asserts that every English docs page has
// a Vietnamese .vi.md sibling. A new EN page added without a VN sibling — or
// a removed EN page that left its VN sibling behind — fails the gate.
func TestDocsVI_EveryENPageHasVNSibling(t *testing.T) {
	root := docsRoot(t)
	pages := enPages(t)
	if len(pages) == 0 {
		t.Fatalf("no EN doc pages discovered under %q", root)
	}
	var missing []string
	for _, p := range pages {
		viPath := filepath.Join(root, p+".vi.md")
		if _, err := os.Stat(viPath); err != nil {
			missing = append(missing, p+".vi.md")
		}
	}
	if len(missing) > 0 {
		t.Fatalf("VN docs missing sibling(s) for EN page(s): %v\n"+
			"every docs/<page>.md must have a docs/<page>.vi.md sibling so the multilingual site\n"+
			"does not silently fall back to English when the user switches to Vietnamese.\n"+
			"either add the missing translation(s), or delete the corresponding EN page if it is intentionally retired.",
			missing)
	}

	// Inverse: a VN file without an EN sibling is also a rot signal.
	var orphans []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".vi.md") {
			return nil
		}
		base := strings.TrimSuffix(name, ".vi.md")
		enPath := filepath.Join(root, base+".md")
		if _, err := os.Stat(enPath); err != nil {
			orphans = append(orphans, name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk for orphan VN: %v", err)
	}
	if len(orphans) > 0 {
		t.Fatalf("VN docs orphan(s) without an EN sibling: %v\n"+
			"either restore the EN page or delete the orphaned VN translation.",
			orphans)
	}
}

// readPage returns the bytes of a single doc page (EN or VN). It fails the
// test if the file cannot be read.
func readPage(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return string(b)
}

// versionRe finds tokens like "v0.9.2", "v0.9.0", "v0.10.0" in a doc body.
var versionRe = regexp.MustCompile(`v\d+\.\d+\.\d+`)

// TestDocsVI_VersionNumberMatchesAcrossENVN asserts that for every EN page
// that mentions a version number, the EXACT set of version tokens that appears
// in the EN page also appears in the VN sibling. A stale lede on either side
// (the canonical case: "guide.md" updates to v0.10 in EN but VN still says
// v0.9) fails the gate.
func TestDocsVI_VersionNumberMatchesAcrossENVN(t *testing.T) {
	root := docsRoot(t)
	pages := enPages(t)
	for _, p := range pages {
		p := p
		t.Run(p, func(t *testing.T) {
			enPath := filepath.Join(root, p+".md")
			viPath := filepath.Join(root, p+".vi.md")
			enBody := readPage(t, enPath)
			viBody := readPage(t, viPath)
			enVersions := uniqueTokens(versionRe.FindAllString(enBody, -1))
			if len(enVersions) == 0 {
				return // page does not mention a version; nothing to gate.
			}
			for _, v := range enVersions {
				if !strings.Contains(viBody, v) {
					t.Errorf("version token %q present in %s.md is absent from %s.vi.md\n"+
						"the VN doc is almost certainly stale relative to the EN doc;\n"+
						"update the VN file to reference the same shipped version.",
						v, p, p)
				}
			}
		})
	}
}

// uniqueTokens deduplicates a token list while preserving order.
func uniqueTokens(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

// structuralAnchors is the closed set of byreis-specific tokens whose presence
// in BOTH the EN and VN copy of a page is gated. The list is intentionally
// narrow — CLI verb names and env var names — because those are the tokens
// that MUST be preserved across translations per the "technical terms stay in
// English" rule the operator pinned. If a translation drops one of these
// tokens, the operator-facing claim no longer matches the actual shipped CLI
// surface.
//
// Tokens are checked PER PAGE: a token is gated on a VN page only when it
// already appears in the corresponding EN page. So a release notes file that
// never mentions `BYREIS_PROJECT_REPO` does not require the token to appear
// in its VN sibling either.
var structuralAnchors = []string{
	// CLI verbs (the shipped command surface).
	"byreis init",
	"byreis submit",
	"byreis review",
	"byreis admin merge",
	"byreis get",
	"byreis decrypt",
	"byreis export",
	"byreis run",
	"byreis edit",
	"byreis rotate",
	"byreis doctor",
	"byreis audit verify",
	"byreis request-access",
	"byreis admin audit show",
	"byreis admin request reject",
	"byreis admin request list",
	"byreis admin rotation reconcile",

	// Env var names (the shipped configuration surface).
	"BYREIS_REGISTRY",
	"BYREIS_PROJECT",
	"BYREIS_PROJECT_REPO",
	"BYREIS_KEY",
	"BYREIS_KEY_FILE",
	"BYREIS_NON_INTERACTIVE",
	"BYREIS_GITHUB_TOKEN",
	"GH_TOKEN",
	"GITHUB_TOKEN",
}

// TestDocsVI_StructuralAnchorsPreservedAcrossENVN asserts that every CLI verb
// and env var token that appears in an EN page also appears, verbatim, in the
// VN sibling. The check is conditional: a token absent from the EN page is
// not gated on the VN page. This catches the most common translation rot:
// a translator paraphrases away a CLI verb name (which the operator's pin
// forbids) or a stale VN doc that does not name a recently added env var.
func TestDocsVI_StructuralAnchorsPreservedAcrossENVN(t *testing.T) {
	root := docsRoot(t)
	pages := enPages(t)
	for _, p := range pages {
		p := p
		t.Run(p, func(t *testing.T) {
			enPath := filepath.Join(root, p+".md")
			viPath := filepath.Join(root, p+".vi.md")
			enBody := readPage(t, enPath)
			viBody := readPage(t, viPath)
			var missing []string
			for _, anchor := range structuralAnchors {
				if !strings.Contains(enBody, anchor) {
					continue // EN does not name this anchor; nothing to gate.
				}
				if !strings.Contains(viBody, anchor) {
					missing = append(missing, anchor)
				}
			}
			if len(missing) > 0 {
				t.Errorf("VN sibling %s.vi.md is missing structural anchor(s) that appear in %s.md: %v\n"+
					"per the byreis docs policy, CLI verb names and env var names must NOT be translated;\n"+
					"they are the load-bearing operator-facing surface. fix the VN file to include each missing token verbatim.",
					p, p, missing)
			}
		})
	}
}
