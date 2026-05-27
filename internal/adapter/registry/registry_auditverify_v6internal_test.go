package registry

// Internal-package unit tests for S4: undeterminable staged-file set → fail-closed.
//
// These tests call bindLines directly with a fabricated auditCommitInfo that has
// StagedFilesUndeterminable=true. This is the authoritative behavioral assertion
// for the S4 contract: an undeterminable staged set must produce BindingTampered
// and ErrAuditLogTampered, never a silent splice-skip or a clean pass.
//
// Placed in package registry (not registry_test) because bindLines is unexported.
// No new exported symbols are added here; the TUI ceiling guard is not affected.

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// TestS4_BindLines_UndeterminableStagedSet_FailClosed verifies that bindLines
// marks a line BindingTampered and returns ErrAuditLogTampered when the
// associated introducing commit has StagedFilesUndeterminable=true.
//
// The undeterminable condition arises when git diff-tree exits non-zero or
// errors during the walk phase. Pre-S4, this silently left StagedFiles nil and
// the splice check was skipped. Post-S4, it must fail closed.
func TestS4_BindLines_UndeterminableStagedSet_FailClosed(t *testing.T) {
	t.Parallel()

	const projectID = "s4-internal"
	auditFilePath := "audit/" + projectID + ".jsonl"

	ev := audit.Event{
		Kind:       audit.EventKindMerge,
		OccurredAt: time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
		Actor:      "admin",
		ProjectID:  projectID,
		Outcome:    "ok",
	}
	rawJSON, marshalErr := json.Marshal(ev)
	if marshalErr != nil {
		t.Fatalf("json.Marshal: %v", marshalErr)
	}
	rawLine := append(rawJSON, '\n')
	lineSHA := sha256HexOfLine(rawLine)

	view := rotate.AuditEntryView{
		Kind:    string(ev.Kind),
		Actor:   ev.Actor,
		Project: ev.ProjectID,
		Outcome: ev.Outcome,
	}

	// Commit carries the correct content hash and is anchor-signed, but diff-tree
	// failed so StagedFilesUndeterminable=true.
	ci := auditCommitInfo{
		SHA:                       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AuditEntrySHA:             lineSHA,
		SignedByAnchor:            true,
		StagedFilesUndeterminable: true,
	}

	result, bindErr := bindLines(
		[]rotate.AuditEntryView{view},
		[][]byte{rawLine},
		[]auditCommitInfo{ci},
		projectID,
		auditFilePath,
		nil,
	)

	if bindErr == nil {
		t.Fatal("bindLines: expected ErrAuditLogTampered for undeterminable staged set, got nil — " +
			"undeterminable staged set must fail closed, not silently skip the splice check")
	}
	if !errors.Is(bindErr, coreregistry.ErrAuditLogTampered) {
		t.Errorf("bindLines: want errors.Is(err, ErrAuditLogTampered), got: %v", bindErr)
	}

	if len(result.Entries) != 1 {
		t.Fatalf("bindLines: want 1 entry, got %d", len(result.Entries))
	}
	got := result.Entries[0].BindingStatus
	if got != rotate.BindingTampered {
		t.Errorf("bindLines: entry BindingStatus = %v, want BindingTampered — "+
			"undeterminable staged set must fail closed, not produce BindingMissing or BindingVerified",
			got)
	}
	t.Logf("S4/BindLines/Undeterminable: PASS — BindingTampered + ErrAuditLogTampered: %v", bindErr)
}

// TestS4_BindLines_UndeterminableStagedSet_OverridesMatchingHash verifies that
// an undeterminable staged set produces BindingTampered even when the content
// hash would have passed. The splice dimension is fail-closed independently of
// the content-hash dimension.
func TestS4_BindLines_UndeterminableStagedSet_OverridesMatchingHash(t *testing.T) {
	t.Parallel()

	const projectID = "s4-internal-override"
	auditFilePath := "audit/" + projectID + ".jsonl"

	ev := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 5, 27, 11, 0, 0, 0, time.UTC),
		Actor:      "admin",
		ProjectID:  projectID,
		Outcome:    "ok",
	}
	rawJSON, marshalErr := json.Marshal(ev)
	if marshalErr != nil {
		t.Fatalf("json.Marshal: %v", marshalErr)
	}
	rawLine := append(rawJSON, '\n')
	lineSHA := sha256HexOfLine(rawLine)

	view := rotate.AuditEntryView{
		Kind:    string(ev.Kind),
		Actor:   ev.Actor,
		Project: ev.ProjectID,
		Outcome: ev.Outcome,
	}

	// The content hash is correct (would pass the content-hash check alone),
	// but StagedFilesUndeterminable means the splice dimension cannot be cleared.
	ci := auditCommitInfo{
		SHA:                       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		AuditEntrySHA:             lineSHA,
		SignedByAnchor:            true,
		StagedFilesUndeterminable: true,
	}

	result, bindErr := bindLines(
		[]rotate.AuditEntryView{view},
		[][]byte{rawLine},
		[]auditCommitInfo{ci},
		projectID,
		auditFilePath,
		nil,
	)

	if bindErr == nil {
		t.Fatal("bindLines: expected ErrAuditLogTampered — " +
			"a matching content hash must not override the undeterminable staged-set fail-closed")
	}
	if !errors.Is(bindErr, coreregistry.ErrAuditLogTampered) {
		t.Errorf("want errors.Is(err, ErrAuditLogTampered), got: %v", bindErr)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(result.Entries))
	}
	if result.Entries[0].BindingStatus != rotate.BindingTampered {
		t.Errorf("BindingStatus = %v, want BindingTampered — "+
			"matching content hash must not clear the undeterminable-staged-set fail-closed",
			result.Entries[0].BindingStatus)
	}
	t.Logf("S4/BindLines/OverridesMatchingHash: PASS: %v", bindErr)
}

// TestS4_BindLines_DeterminableEmptyStagedSet_NoTamper verifies that when
// StagedFilesUndeterminable=false and StagedFiles is empty (a commit with an
// empty staged set, which should not happen in a well-formed registry but is
// structurally valid), the splice check is skipped cleanly — the S4 change did
// not accidentally break the determinable-empty-set path.
func TestS4_BindLines_DeterminableEmptyStagedSet_NoTamper(t *testing.T) {
	t.Parallel()

	const projectID = "s4-internal-empty"
	auditFilePath := "audit/" + projectID + ".jsonl"

	ev := audit.Event{
		Kind:       audit.EventKindMerge,
		OccurredAt: time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		Actor:      "admin",
		ProjectID:  projectID,
		Outcome:    "ok",
	}
	rawJSON, marshalErr := json.Marshal(ev)
	if marshalErr != nil {
		t.Fatalf("json.Marshal: %v", marshalErr)
	}
	rawLine := append(rawJSON, '\n')
	lineSHA := sha256HexOfLine(rawLine)

	view := rotate.AuditEntryView{
		Kind:    string(ev.Kind),
		Actor:   ev.Actor,
		Project: ev.ProjectID,
		Outcome: ev.Outcome,
	}

	// StagedFilesUndeterminable=false, StagedFiles=nil (empty/determinable empty).
	// The splice check is entered but len(StagedFiles)==0 so nothing fires.
	ci := auditCommitInfo{
		SHA:                       "cccccccccccccccccccccccccccccccccccccccc",
		AuditEntrySHA:             lineSHA,
		SignedByAnchor:            true,
		StagedFilesUndeterminable: false,
		StagedFiles:               nil, // determinable empty set
	}

	result, bindErr := bindLines(
		[]rotate.AuditEntryView{view},
		[][]byte{rawLine},
		[]auditCommitInfo{ci},
		projectID,
		auditFilePath,
		nil,
	)

	if bindErr != nil {
		t.Errorf("bindLines: unexpected error for determinable empty staged set: %v — "+
			"determinable-empty-set path must not be affected by the S4 change", bindErr)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(result.Entries))
	}
	if result.Entries[0].BindingStatus != rotate.BindingVerified {
		t.Errorf("BindingStatus = %v, want BindingVerified — "+
			"determinable empty staged set must produce a clean binding result",
			result.Entries[0].BindingStatus)
	}
	t.Logf("S4/BindLines/DeterminableEmpty: PASS — BindingVerified with empty staged set (determinable)")
}
