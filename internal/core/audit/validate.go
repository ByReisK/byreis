// Package audit — canonical event-field validator.
//
// ValidateEventFields enforces canonical-typed field-value rules on an
// audit.Event's Details map before it is serialised. Callers on any durable
// audit channel (signed registry commit or host-local audit log) MUST invoke
// this helper before persisting an Event.
//
// The validator rejects:
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

// ValidateEventFields checks that every Details entry in e carries a
// canonical-typed value. It is a pure function with no side effects.
//
// Callers MUST invoke ValidateEventFields before persisting an Event to any
// durable audit channel (signed registry commit or host-local audit log).
func ValidateEventFields(e Event) error {
	for k, v := range e.Details {
		lk := strings.ToLower(k)
		switch {
		case strings.Contains(lk, "pubkey") || strings.Contains(lk, "recipient") || strings.Contains(lk, "age_key"):
			if !agePubkeyRE.MatchString(v) {
				return fmt.Errorf("%w: details field %q value does not match age pubkey format (^age1[0-9a-z]{58}$): %q",
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
