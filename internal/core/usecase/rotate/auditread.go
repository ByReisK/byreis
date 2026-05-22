package rotate

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
)

// acceptedAuditKinds is the read-side accepted event-class set. An entry whose
// kind falls outside this set is not dropped and not an error: it maps to a
// warning-row view (Unknown=true) so a newer client that wrote a future event
// class does not crash an older admin's audit display. The set deliberately
// mirrors the write-side registry sink's accepted kinds; the read path is
// lenient over a write path that stays strict.
var acceptedAuditKinds = map[audit.EventKind]bool{
	audit.EventKindRotation:   true,
	audit.EventKindMerge:      true,
	audit.EventKindCommitBump: true,
}

// removedRecipientIndexRE matches the per-index removed-recipient detail keys
// the rotation audit producer emits. The value of each such key is a raw age
// recipient pubkey, so the keys are NEVER surfaced individually; their count is
// derived into the synthetic removed_recipients_count key instead. The pattern
// is anchored on a numeric suffix so a non-numeric lookalike (e.g.
// removed_recipients_evil) is not counted.
var removedRecipientIndexRE = regexp.MustCompile(`^removed_recipients_[0-9]+$`)

// reversalPendingsClearedRE matches the suffixed reversal-pendings-cleared
// detail family. It is an ANCHORED whole-key regex, never a prefix test: a
// prefix match would be a denylist hole inside the positive allowlist (a key
// such as reversal_pendings_cleared_evil would slip a prefix gate). The value
// of a matched key is a cleared pending's logical file name, which is safe to
// surface.
var reversalPendingsClearedRE = regexp.MustCompile(`^reversal_pendings_cleared_[0-9]+$`)

// safeFixedDetailKeys is the positive allowlist of fixed (non-suffixed) detail
// keys that are safe to surface verbatim. It is a positive allowlist, not a
// denylist subtraction: an unrecognised key is dropped by omission, so a future
// producer that adds a leaky key cannot regress the read surface without an
// explicit edit here.
var safeFixedDetailKeys = map[string]bool{
	"reversal_reason":                     true,
	"reversal_target_pr":                  true,
	"rotation_epoch":                      true,
	"from_request_pr_url":                 true,
	"from_request_pr_head_sha":            true,
	"from_request_yaml_handle":            true,
	"from_request_validated_author_login": true,
}

// ProjectAuditEvent maps a raw audit.Event to the SAFE AuditEntryView display
// projection. It is a pure function with no side effects and no I/O, so the
// security-critical SAFE/DENY partition is testable without the registry
// adapter.
//
// The projection is a closed positive allowlist. The top-level fields Kind,
// OccurredAt, Actor, Project, and Outcome are projected directly; the Details
// map is partitioned so that:
//
//   - Per-index removed-recipient keys (whose values are raw age recipient
//     pubkeys) are NEVER copied. Their count is surfaced as the synthetic
//     decimal key removed_recipients_count, derived from the number of distinct
//     matching keys.
//   - The contributor-authored justification family (keys prefixed
//     from_request_yaml_just) is denied — that free text never reaches the
//     read surface.
//   - The reversal-pendings-cleared family is matched by an anchored whole-key
//     regex (never a prefix), and its file-name values are surfaced.
//   - A fixed set of canonical keys is surfaced verbatim.
//   - Anything else is dropped (fail-closed by omission).
//
// An unrecognised event kind sets Unknown=true; the entry still projects so the
// render layer can show a forward-compat warning row.
func ProjectAuditEvent(e audit.Event) AuditEntryView {
	view := AuditEntryView{
		Kind:        string(e.Kind),
		OccurredAt:  e.OccurredAt.UTC().Format(time.RFC3339),
		Actor:       e.Actor,
		Project:     e.ProjectID,
		Outcome:     e.Outcome,
		SafeDetails: projectSafeDetails(e.Details),
		Unknown:     !acceptedAuditKinds[e.Kind],
	}
	return view
}

// projectSafeDetails applies the SAFE/DENY partition to a decoded Details map
// and returns the allowlisted projection. The partition runs on the resolved
// (post-decode, last-wins) key set, so a shadowed earlier key cannot smuggle a
// denied value into a safe slot. The result is always non-nil so callers can
// range over it unconditionally.
func projectSafeDetails(details map[string]string) map[string]string {
	safe := make(map[string]string, len(details))
	var removedCount int

	for k, v := range details {
		lk := strings.ToLower(k)

		// DENY: the contributor-authored justification family never surfaces.
		if strings.HasPrefix(lk, "from_request_yaml_just") {
			continue
		}

		// COUNT-ONLY: per-index removed-recipient keys carry raw pubkeys; we
		// only count them and never copy the value.
		if removedRecipientIndexRE.MatchString(lk) {
			removedCount++
			continue
		}

		// SAFE suffixed family: anchored whole-key match, never a prefix test.
		if reversalPendingsClearedRE.MatchString(lk) {
			safe[k] = v
			continue
		}

		// SAFE fixed keys: explicit positive allowlist.
		if safeFixedDetailKeys[lk] {
			safe[k] = v
			continue
		}

		// Everything else is dropped (fail-closed by omission).
	}

	if removedCount > 0 {
		safe["removed_recipients_count"] = strconv.Itoa(removedCount)
	}
	return safe
}
