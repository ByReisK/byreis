//go:build shipgate

package registry_test

// V5 rotation-reverser shipgate rows.
//
// Build constraint: //go:build shipgate. Run via:
//
//	go test -tags shipgate -run TestV5Reverser ./internal/adapter/registry/
//
// These rows exercise the RotationReverserAdapter against the recording runner
// (no real network), asserting the load-bearing invariants of the two-phase
// commit protocol's reversal path:
//
//   - V5.RECON.reversal-audit-atomicity-single-commit
//     The single-signed-commit invariant: BOTH the counter-cleared state AND
//     the audit JSONL line are staged in one commit message body. A reader of
//     any post-reconcile registry snapshot sees either both or neither.
//
//   - V5.RECON.reversal-audit-validator-rejects-malformed
//     The pre-marshal validator fires BEFORE any git operation. A malformed
//     audit event must not reach the clone, the counter write, the audit file,
//     or the commit.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/core/audit"
	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// TestV5Reverser_AuditAtomicitySingleCommit is the shipgate row for
// V5.RECON.reversal-audit-atomicity-single-commit.
//
// It proves that the single commit landing both the cleared counter state and
// the audit JSONL line carries the expected canonical structure in its signed
// message body — specifically:
//
//   - "byreis: rotation reversal" header
//   - "project_id:" line
//   - "pending_cleared:" line for each pending
//   - "audit_entry_sha:" line (proof the audit bytes were hashed into the body)
//   - "byreis-signer:" envelope
//   - "byreis-sig:" envelope
//
// Exactly one commit and one push subprocess must be invoked.
func TestV5Reverser_AuditAtomicitySingleCommit(t *testing.T) {
	t.Parallel()

	// ClearPendings requires: clone, rev-parse, add, config×2, commit, push.
	runner := &reverserRunner{
		steps: []reverserStep{
			rrCloneOK(),
			rrRevParseOK(),
			rrGitAddOK(),
			rrGitCfgOK(),
			rrGitCfgOK(),
			rrGitCommitOK(),
			rrGitPushOK(),
		},
	}

	fakeMkdir := func(_, _ string) (string, error) {
		return t.TempDir(), nil
	}

	adapter, err := registry.NewRotationReverserAdapter(registry.RotationReverserDeps{
		RegistryURL:    "https://github.com/myorg/shipgate-registry",
		ProjectRepoURL: "https://github.com/myorg/shipgate-project",
		Signer:         &reverserNopSigner{},
		TokenProvider:  &reverserTokenProvider{token: "sg-tok"},
		Runner:         runner,
		MkdirTemp:      fakeMkdir,
		RemoveAll:      noopRemoveAll,
	})
	if err != nil {
		t.Fatalf("NewRotationReverserAdapter: %v", err)
	}

	pendings := []rotate.PendingObservation{
		{
			LogicalName:       "db-enc",
			PendingCounter:    7,
			TargetArtifactSHA: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			TargetPR:          coregit.PRRef{Project: "myorg/shipgate-project/byreis/rotate-db-sg", Number: 0},
		},
	}

	event := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		ProjectID:  "sg-proj",
		Outcome:    rotate.RotationOutcomeReverted,
		Details: map[string]string{
			"reversal_target_pr":          "myorg/shipgate-project/byreis/rotate-db-sg#0",
			"reversal_reason":             "phase-1-only-classification",
			"reversal_pendings_cleared_0": "db-enc",
		},
	}

	if err := adapter.ClearPendings(context.Background(), "sg-proj", pendings, event); err != nil {
		t.Fatalf("ClearPendings: unexpected error: %v", err)
	}

	// Exactly 7 subprocess calls: clone, rev-parse, add, cfg×2, commit, push.
	if got := runner.callCount(); got != 7 {
		t.Fatalf("runner call count = %d, want 7 (clone+rev-parse+add+cfg×2+commit+push)", got)
	}

	// Locate the commit call (index 5).
	commitCall := runner.callAt(5)
	if commitCall.name != "git" || (len(commitCall.args) < 1 || commitCall.args[0] != "commit") {
		t.Fatalf("call[5] expected 'git commit', got name=%q args=%v", commitCall.name, commitCall.args)
	}

	// Extract the -m value.
	var msg string
	for i, arg := range commitCall.args {
		if arg == "-m" && i+1 < len(commitCall.args) {
			msg = commitCall.args[i+1]
			break
		}
	}
	if msg == "" {
		t.Fatal("commit message is empty or -m flag not found")
	}

	// Shipgate assertions on the signed commit body:
	shipgateAssert := []struct {
		needle string
		label  string
	}{
		{"byreis: rotation reversal", "header"},
		{"project_id: sg-proj", "project_id field"},
		{"pending_cleared: db-enc", "pending_cleared field"},
		{"audit_entry_sha:", "audit_entry_sha field (atomicity proof)"},
		{"registry_parent_sha:", "registry_parent_sha (CAS anchor)"},
		{"byreis-signer:", "signer envelope"},
		{"byreis-sig:", "signature envelope"},
	}
	for _, sa := range shipgateAssert {
		if !strings.Contains(msg, sa.needle) {
			t.Errorf("commit body missing %s (%q): full body = %q", sa.label, sa.needle, msg)
		}
	}

	// Push call (index 6) must carry --force-with-lease.
	pushCall := runner.callAt(6)
	var hasForceLease bool
	for _, arg := range pushCall.args {
		if strings.HasPrefix(arg, "--force-with-lease=") {
			hasForceLease = true
			break
		}
	}
	if !hasForceLease {
		t.Errorf("CAS push missing --force-with-lease; push args = %v", pushCall.args)
	}
}

// TestV5Reverser_ValidatorRejectsMalformed is the shipgate row for
// V5.RECON.reversal-audit-validator-rejects-malformed.
//
// It proves the pre-marshal audit validator fires BEFORE any git subprocess
// (clone, commit, push) when the reversal event's Details map contains a
// disallowed value. The runner has zero configured steps so any invocation
// is detectable as a failure.
func TestV5Reverser_ValidatorRejectsMalformed(t *testing.T) {
	t.Parallel()

	// Zero-step runner: any Run call returns an error, making it detectable.
	runner := &reverserRunner{steps: []reverserStep{}}

	fakeMkdir := func(_, _ string) (string, error) {
		return t.TempDir(), nil
	}

	adapter, err := registry.NewRotationReverserAdapter(registry.RotationReverserDeps{
		RegistryURL:    "https://github.com/myorg/shipgate-registry",
		ProjectRepoURL: "https://github.com/myorg/shipgate-project",
		Signer:         &reverserNopSigner{},
		TokenProvider:  &reverserTokenProvider{token: "sg-tok"},
		Runner:         runner,
		MkdirTemp:      fakeMkdir,
		RemoveAll:      noopRemoveAll,
	})
	if err != nil {
		t.Fatalf("NewRotationReverserAdapter: %v", err)
	}

	// Malformed event: Details value exceeds 512 chars.
	malformed := audit.Event{
		Kind:       audit.EventKindRotation,
		OccurredAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		ProjectID:  "sg-proj",
		Outcome:    rotate.RotationOutcomeReverted,
		Details: map[string]string{
			"reversal_reason": strings.Repeat("z", 600),
		},
	}

	pendings := []rotate.PendingObservation{
		{
			LogicalName:       "db-enc",
			PendingCounter:    1,
			TargetArtifactSHA: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			TargetPR:          coregit.PRRef{Project: "myorg/shipgate-project/byreis/rotate-db-sg", Number: 0},
		},
	}

	clearErr := adapter.ClearPendings(context.Background(), "sg-proj", pendings, malformed)
	if clearErr == nil {
		t.Fatal("ClearPendings: expected validation error, got nil")
	}

	// Error must wrap ErrAuditEventInvalidField.
	if !errors.Is(clearErr, audit.ErrAuditEventInvalidField) {
		t.Errorf("want errors.Is(err, audit.ErrAuditEventInvalidField), got: %v", clearErr)
	}

	// No git subprocess must have been invoked.
	if runner.callCount() != 0 {
		t.Errorf("runner call count = %d; want 0 (validator must fire before git clone)", runner.callCount())
	}
}
