// Package audit — canonical event-field validator.
//
// ValidateEventFields enforces canonical-typed field-value rules on an
// audit.Event's Details map before it is serialised. Callers on any durable
// audit channel (signed registry commit or host-local audit log) MUST invoke
// this helper before persisting an Event.
//
// The validator rejects:
//   - A non-empty top-level Event.KeyName whose value does not match the strict
//     leaf key-name format ^[a-zA-Z0-9._-]{1,256}$ (no slash, no control bytes,
//     no whitespace) — the key name is contributor-influenced and reaches the
//     durable signed write.
//   - A non-empty top-level Event.Actor that is an age recipient pubkey
//     (^age1<58 bech32 chars>$) — an actor label is a human identity, never a
//     recipient pubkey, so an age1... value indicates a leaked pubkey in the
//     actor slot and is refused before the durable signed write.
//   - Age recipient fields (key contains "pubkey", "recipient", or "age_key")
//     whose values do not match the canonical age1<58 bech32 chars> format.
//   - Project-ID or file-name fields (key contains "project", "file", or
//     "name") whose values do not match ^[a-zA-Z0-9._/-]{1,256}$.
//   - General fields whose values contain a contiguous run of 32 or more
//     characters drawn from the base64 alphabet — a heuristic that guards
//     against accidentally writing secret-like material through the audit
//     channel.
//
// Returns ErrAuditEventInvalidField wrapping the per-field reason on the first
// failure (fail-closed; do not enumerate further to avoid mass-information
// leaks under a poisoned-input attack).
package audit

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrAuditEventInvalidField is returned when an audit.Event.Details entry
// contains a value that fails canonical field validation. The event must be
// refused; callers must never silently drop a validation failure — surface it
// immediately so producers can be fixed.
var ErrAuditEventInvalidField = errors.New(
	"audit: event carries invalid field value — " +
		"verify the audit-event producer constructs canonical-typed Details values",
)

// agePubkeyRE matches a canonical age public key: "age1" followed by exactly
// 58 lower-case bech32 characters (total 62 chars).
var agePubkeyRE = regexp.MustCompile(`^age1[0-9a-z]{58}$`)

// projectIDOrFileNameRE matches canonical project ID and file name values:
// alphanumeric plus . _ / - characters, 1 to 256 characters.
var projectIDOrFileNameRE = regexp.MustCompile(`^[a-zA-Z0-9._\-/]{1,256}$`)

// keyNameRE matches a canonical secret key NAME (never the secret value):
// alphanumeric plus . _ - characters, 1 to 256 characters. Unlike a project or
// file name, a key name MUST NOT contain a slash — a key is a leaf identifier,
// not a path — so this is a deliberately stricter pattern than
// projectIDOrFileNameRE. The trailing position of '-' inside the class keeps it
// a literal hyphen, never a character range. Control bytes, whitespace, and
// path separators are all rejected.
var keyNameRE = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,256}$`)

// shaHexRE matches canonical lowercase hex SHA-style digests: 1 to 128
// hexadecimal characters. Audit-event fields carrying SHAs (commit SHAs,
// content SHAs, blob SHAs, audit-entry SHAs) are typed: only canonical hex
// passes. The 128-char ceiling covers SHA-512 and shorter cryptographic
// hashes the registry might surface; non-hex (or any value outside that set)
// fails-closed at validation rather than slipping through the high-entropy
// heuristic with a false-positive secret-leak alarm.
var shaHexRE = regexp.MustCompile(`^[0-9a-f]{1,128}$`)

// prURLRE matches the canonical "<owner>/<repo>#<number>" PR-reference
// string emitted by the rotation audit-event producer's reversal_target_pr
// and from_request_pr_url fields. This is a strict structural form — no
// query strings, no fragments, no schemes — so a producer that accidentally
// serialised a raw URL or an opaque ID fails validation here.
var prURLRE = regexp.MustCompile(`^[A-Za-z0-9._\-/]{1,256}#[0-9]+$`)

// ValidateEventFields checks that every Details entry in e carries a
// canonical-typed value. It is a pure function with no side effects.
//
// Callers MUST invoke ValidateEventFields before persisting an Event to any
// durable audit channel (signed registry commit or host-local audit log).
//
// Forward-defense: keys matching `from_request_yaml_just*` are explicitly
// denylisted. The contributor-authored free-text justification field from the
// request-access YAML must never enter the permanent audit JSONL — sanitised
// terminal-render is the only operator-facing surface where that bytes live.
// A future code path that accidentally added the field would be caught here.
func ValidateEventFields(e Event) error {
	// Top-level KeyName is a contributor-influenced field (it carries the secret
	// key NAME a submission targets) and reaches the durable signed write, so it
	// is validated here independently of Details. The rule fires only when a key
	// name is present; a leaf key identifier may not contain a slash, control
	// byte, or whitespace.
	if e.KeyName != "" && !keyNameRE.MatchString(e.KeyName) {
		return fmt.Errorf(
			"%w: event KeyName does not match the key-name format (^[a-zA-Z0-9._-]{1,256}$, no slash): %q",
			ErrAuditEventInvalidField, truncate(e.KeyName))
	}

	// Top-level Actor is a human identity label attested by the registry signer
	// record; it is NEVER a recipient pubkey. An age1... value in Actor means a
	// recipient pubkey leaked into the actor slot — refuse it fail-closed so such
	// material can never reach the durable signed write. This is write-side
	// defense-in-depth; the read side never displays an unresolved label as a key.
	if e.Actor != "" && agePubkeyRE.MatchString(e.Actor) {
		return fmt.Errorf(
			"%w: event Actor is an age recipient pubkey, which is never a valid actor label: %q",
			ErrAuditEventInvalidField, truncate(e.Actor))
	}

	for k, v := range e.Details {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "from_request_yaml_just") {
			return fmt.Errorf(
				"%w: details key %q is on the contributor-text denylist (justification bytes never enter the permanent audit log)",
				ErrAuditEventInvalidField, k)
		}
		switch {
		case strings.Contains(lk, "pubkey") || strings.Contains(lk, "recipient") || strings.Contains(lk, "age_key"):
			if !agePubkeyRE.MatchString(v) {
				return fmt.Errorf("%w: details field %q value does not match age pubkey format (^age1[0-9a-z]{58}$): %q",
					ErrAuditEventInvalidField, k, truncate(v))
			}
		case strings.HasSuffix(lk, "_url") || strings.HasSuffix(lk, "_pr") || strings.HasSuffix(lk, "_pr_url"):
			if !prURLRE.MatchString(v) {
				return fmt.Errorf("%w: details field %q value does not match canonical PR ref format (<owner>/<repo>#<number>): %q",
					ErrAuditEventInvalidField, k, truncate(v))
			}
		case strings.Contains(lk, "sha") || strings.Contains(lk, "hash") || strings.Contains(lk, "digest"):
			if !shaHexRE.MatchString(v) {
				return fmt.Errorf("%w: details field %q value does not match canonical hex SHA format (^[0-9a-f]{1,128}$): %q",
					ErrAuditEventInvalidField, k, truncate(v))
			}
		case strings.Contains(lk, "project") || strings.Contains(lk, "file") || strings.Contains(lk, "name"):
			if !projectIDOrFileNameRE.MatchString(v) {
				return fmt.Errorf("%w: details field %q value does not match project/file name format (^[a-zA-Z0-9._/-]{1,256}$): %q",
					ErrAuditEventInvalidField, k, truncate(v))
			}
		default:
			if looksHighEntropyBase64(v) {
				return fmt.Errorf("%w: details field %q value appears to contain high-entropy encoded data (possible secret leakage): len=%d",
					ErrAuditEventInvalidField, k, len(v))
			}
		}
	}
	return nil
}

// looksHighEntropyBase64 returns true when s contains a contiguous run of 32
// or more characters drawn from the base64 alphabet (A-Z, a-z, 0-9, +, /, =).
// This is a heuristic that detects ciphertext or key material accidentally
// written into audit metadata.
func looksHighEntropyBase64(s string) bool {
	const threshold = 32
	run := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '=' {
			run++
			if run >= threshold {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// truncate returns at most 32 chars of s for inclusion in error messages.
func truncate(s string) string {
	if len(s) <= 32 {
		return s
	}
	return s[:32] + "..."
}
