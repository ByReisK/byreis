package fetchtransport

import (
	"fmt"
	"strings"
)

const (
	// maxFileNameLen is the maximum allowed length for a counter-store file name.
	// Bounded separately from maxProjectIDLen to allow per-axis evolution.
	maxFileNameLen = 128
)

// ValidateFileName checks that fileName is safe to embed in registry counter
// store paths. It rejects: empty string, names longer than maxFileNameLen, any
// path separator ("/" or "\"), any NUL byte, any leading dot, any ".."
// substring, and any control characters or whitespace.
//
// This validator is intentionally stricter than ValidateProjectID on the
// whitespace axis (counter file names are caller-controlled identifiers that
// must compose safely into "counters/<projectID>/<fileName>.json"). The caller
// must apply this guard before composing any counter blob path; the git binary
// must never be invoked when validation fails.
func ValidateFileName(fileName string) error {
	if fileName == "" {
		return fmt.Errorf(
			"file name must not be empty — check the fileName argument")
	}
	if len(fileName) > maxFileNameLen {
		return fmt.Errorf(
			"file name is too long (%d bytes, max %d) — check the fileName argument",
			len(fileName), maxFileNameLen)
	}
	if strings.Contains(fileName, "/") {
		return fmt.Errorf(
			"file name %q contains a path separator ('/') — "+
				"file names must be a single path component with no slashes",
			fileName)
	}
	if strings.Contains(fileName, "\\") {
		return fmt.Errorf(
			"file name %q contains a backslash — "+
				"file names must use forward-slash paths only",
			fileName)
	}
	if strings.Contains(fileName, "\x00") {
		return fmt.Errorf(
			"file name %q contains a null byte — "+
				"file names must not contain null bytes",
			fileName)
	}
	if strings.HasPrefix(fileName, ".") {
		return fmt.Errorf(
			"file name %q starts with '.' — "+
				"file names must not start with a dot",
			fileName)
	}
	if strings.Contains(fileName, "..") {
		return fmt.Errorf(
			"file name %q contains a dot-dot sequence ('..') — "+
				"file names must not contain path traversal sequences",
			fileName)
	}
	// Positive whitelist enforcement: only [A-Za-z0-9._-] are allowed.
	// Any other rune — including '+', ':', ';', '=', '@', '#', '%', '&', '$',
	// non-ASCII (e.g. 'é'), control characters, and whitespace — is rejected.
	// This is stricter than a deny-list and closes all unlisted edge cases.
	for _, r := range fileName {
		if !isFileNameRune(r) {
			return fmt.Errorf(
				"file name %q contains a disallowed character %q — "+
					"file names must contain only [A-Za-z0-9._-]",
				fileName, r)
		}
	}
	return nil
}

// isFileNameRune reports whether r is in the allowed rune set for file names:
// uppercase letters A-Z, lowercase letters a-z, digits 0-9, dot '.', underscore
// '_', and hyphen '-'. All other runes are disallowed.
func isFileNameRune(r rune) bool {
	return (r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '.' || r == '_' || r == '-'
}

// CounterBlobPath composes the registry tree path for a counter store file.
// Format: "counters/<projectID>/<fileName>.json". This is the ONLY site in the
// adapter that composes counter blob paths — callers must not build this string
// by hand.
//
// Both projectID and fileName must already have been validated by
// ValidateProjectID and ValidateFileName respectively before this call.
// CounterBlobPath does NOT re-validate; it trusts the caller's prior guards.
func CounterBlobPath(projectID, fileName string) string {
	return "counters/" + projectID + "/" + fileName + ".json"
}
