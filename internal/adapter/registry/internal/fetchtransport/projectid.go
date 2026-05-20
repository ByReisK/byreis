// Package fetchtransport provides the production FetchTransport implementation
// for the registry adapter. It shells to system git for commit-signature
// verification per the project's signed-commit discipline and uses the
// GitHub API (via the injected runner) for repository access.
//
// This package is an internal/ sub-package of internal/adapter/registry and is
// importable only by code rooted at that adapter path (Go internal/ rule).
//
// No internal/core/** package is imported here; no SDK/transport types leak into
// core. The mapping from subprocess results to domain values (verified bool,
// signerID string) happens entirely in this outer adapter layer.
package fetchtransport

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	// maxProjectIDLen is the maximum allowed length for a project identifier.
	// Bounded to prevent path traversal via over-long identifiers.
	maxProjectIDLen = 128
)

// ValidateProjectID checks that projectID is safe to embed in registry file
// paths. It rejects: empty string, identifiers longer than maxProjectIDLen,
// any path separator ("/"), any dot-dot component (".."), any identifier
// starting with a dot ("."), any identifier containing backslash or null, and
// any identifier containing control characters.
//
// This guard must be applied before composing any registry path for the
// trust-bearing admins.yaml or recipient-binding read. A typed error is
// returned on violation; the caller must not proceed to path composition.
func ValidateProjectID(projectID string) error {
	if projectID == "" {
		return fmt.Errorf(
			"project ID must not be empty — pass --project or set BYREIS_PROJECT")
	}
	if len(projectID) > maxProjectIDLen {
		return fmt.Errorf(
			"project ID is too long (%d bytes, max %d) — check BYREIS_PROJECT",
			len(projectID), maxProjectIDLen)
	}
	if strings.Contains(projectID, "/") {
		return fmt.Errorf(
			"project ID %q contains a path separator ('/') — "+
				"project IDs must be a single path component with no slashes",
			projectID)
	}
	if strings.Contains(projectID, "\\") {
		return fmt.Errorf(
			"project ID %q contains a backslash — "+
				"project IDs must use forward-slash paths only",
			projectID)
	}
	if strings.Contains(projectID, "\x00") {
		return fmt.Errorf(
			"project ID %q contains a null byte — "+
				"project IDs must not contain null bytes",
			projectID)
	}
	if strings.HasPrefix(projectID, ".") {
		return fmt.Errorf(
			"project ID %q starts with '.' — "+
				"project IDs must not start with a dot",
			projectID)
	}
	if projectID == ".." || strings.Contains(projectID, "..") {
		return fmt.Errorf(
			"project ID %q contains a dot-dot component ('..') — "+
				"project IDs must not contain path traversal sequences",
			projectID)
	}
	for _, r := range projectID {
		if unicode.IsControl(r) {
			return fmt.Errorf(
				"project ID %q contains a control character (0x%X) — "+
					"project IDs must contain only printable characters",
				projectID, r)
		}
	}
	return nil
}
