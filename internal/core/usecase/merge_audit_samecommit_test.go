//go:build testhook

package usecase_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// spyAudit records every host-local audit.Event the merge use-case appends.
type spyAudit struct {
	events []audit.Event
}

func (s *spyAudit) Append(_ context.Context, e audit.Event) error {
	s.events = append(s.events, e)
	return nil
}

// auditCapturingCounter is the recordingCounter pattern plus a capture of the
// CommitBumpInput.AuditEntry, so a test can assert the merge audit event rode
// the same-commit channel rather than the host-local logger.
type auditCapturingCounter struct {
	lastAccepted uint64
	pending      *countertypes.PendingBump
	commitCalls  int
	commitEntry  audit.Event
	commitEntryS bool
}

func (c *auditCapturingCounter) CounterAuthority(context.Context, string, string) (countertypes.CounterAuthority, error) {
	return countertypes.NewForTest(countertypes.ForTestWitness(), c.lastAccepted, c.pending), nil
}

func (c *auditCapturingCounter) RecordPendingBump(_ context.Context, in usecase.PendingBumpInput) error {
	c.pending = &countertypes.PendingBump{
		PendingCounter:    in.PendingCounter,
		TargetArtifactSHA: in.TargetArtifactSHA,
		TargetPR:          in.TargetPR,
	}
	return nil
}

func (c *auditCapturingCounter) CommitBump(_ context.Context, in usecase.CommitBumpInput) error {
	c.commitCalls++
	c.commitEntry = in.AuditEntry
	c.commitEntryS = true
	c.lastAccepted = in.PendingCounter
	c.pending = nil
	return nil
}

// realE2EMergeDeps wires a full real-crypto merge that lands successfully. It
// returns the spying host-local audit logger and the audit-capturing counter so
// callers can assert where the merge event was recorded.
func realE2EMergeDeps(t *testing.T) (usecase.MergeDeps, *spyAudit, *auditCapturingCounter, git.PRRef) {
	t.Helper()
	rec, id, _ := mkRecipient(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	ct := ageEncryptOne(t, "the-secret", rec.AgePubKey)
	uns := artifact.Unsigned{
		Values: map[string]artifact.EncryptedValue{"API_KEY": artifact.EncryptedValue(ct)},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1", ProjectID: "p", File: "f", Counter: 0,
			Recipients: []artifact.RecipientEntry{recipientFPEntry(rec)},
		},
	}
	ref := git.PRRef{Project: "p", Number: 7}
	g := &stubGit{
		sub: git.Submission{
			Ref: ref, ArtifactSHA: "PIN",
			ArtifactBytes: mustJSON(t, uns),
			Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml", Key: "API_KEY"}, //nolint:gosec // G101 false positive: "API_KEY" is a key NAME, not a credential value
		},
		merge: git.MergeResult{MergedCommit: "landed", SignedFileCommitted: true, SignedFileCommitSHA: "sf"},
	}
	spy := &spyAudit{}
	ctr := &auditCapturingCounter{lastAccepted: 0}
	deps := usecase.MergeDeps{
		Git: g, Decryptor: realDecryptor(), Encryptor: encrypt.New(encrypt.NewX25519Parser()),
		IDLoader:      &stubIDLoader{id: id},
		ArtifactCodec: &realCodec{},
		Recipients: &stubRecipients{
			set:            []rectypes.Recipient{rec},
			signers:        map[string]ed25519.PublicKey{"admin-1": pub},
			sourceVerified: true,
		},
		Counter:  ctr,
		Signer:   realSigner{id: "admin-1", priv: priv},
		Verifier: realVerifier(),
		Mode:     modeGate{m: mode.ModeAdmin},
		Audit:    spy,
	}
	return deps, spy, ctr, ref
}

// TestMerge_SuccessAuditRidesSameCommitNotHostLocal proves the durable merge
// record is the SINGLE source of truth: on a successful merge the audit event
// is passed through CommitBumpInput.AuditEntry (the same-commit channel) and the
// host-local success emit is REMOVED. The host-local logger must therefore see
// NO merge "ok" event.
func TestMerge_SuccessAuditRidesSameCommitNotHostLocal(t *testing.T) {
	t.Parallel()

	deps, spy, ctr, ref := realE2EMergeDeps(t)
	m, err := usecase.NewMerger(deps)
	if err != nil {
		t.Fatalf("NewMerger: %v", err)
	}
	res, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: ref, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if res.FinalCounter != 1 {
		t.Fatalf("FinalCounter = %d, want 1", res.FinalCounter)
	}

	// No host-local merge "ok" event: the durable registry record is the single
	// source of truth.
	for _, e := range spy.events {
		if e.Kind == audit.EventKindMerge && e.Outcome == "ok" {
			t.Fatalf("host-local logger received a merge ok event %+v — "+
				"the success emit must ride CommitBumpInput.AuditEntry, not the host-local logger", e)
		}
	}

	// The merge event rode the same-commit channel.
	if !ctr.commitEntryS {
		t.Fatalf("CommitBump was never called")
	}
	ae := ctr.commitEntry
	if ae.Kind != audit.EventKindMerge {
		t.Fatalf("CommitBumpInput.AuditEntry.Kind = %q, want %q", ae.Kind, audit.EventKindMerge)
	}
	if ae.Outcome != "ok" {
		t.Fatalf("AuditEntry.Outcome = %q, want ok", ae.Outcome)
	}
	if ae.ProjectID != "p" || ae.FileName != "f" {
		t.Fatalf("AuditEntry project/file = %q/%q, want p/f", ae.ProjectID, ae.FileName)
	}
	if ae.KeyName != "API_KEY" {
		t.Fatalf("AuditEntry.KeyName = %q, want API_KEY", ae.KeyName)
	}
}

// TestMerge_SameCommitAuditCounterEqualsCommittedCounter proves BO-1: the
// counter value carried in the AuditEntry is the SAME value CommitBump advances
// to (one pending counter feeds both), not an independently-computed number.
func TestMerge_SameCommitAuditCounterEqualsCommittedCounter(t *testing.T) {
	t.Parallel()

	deps, _, ctr, ref := realE2EMergeDeps(t)
	m, err := usecase.NewMerger(deps)
	if err != nil {
		t.Fatalf("NewMerger: %v", err)
	}
	if _, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: ref, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if ctr.commitEntry.Details["counter"] != "1" {
		t.Fatalf("AuditEntry counter detail = %q, want 1 (== committed counter)",
			ctr.commitEntry.Details["counter"])
	}
}

// TestMerge_SameCommitAuditEventPassesValidator proves BO-3: the merge audit
// event the use-case constructs PASSES audit.ValidateEventFields (the transport
// calls it before signing), including the now-validated top-level KeyName.
func TestMerge_SameCommitAuditEventPassesValidator(t *testing.T) {
	t.Parallel()

	deps, _, ctr, ref := realE2EMergeDeps(t)
	m, err := usecase.NewMerger(deps)
	if err != nil {
		t.Fatalf("NewMerger: %v", err)
	}
	if _, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: ref, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if err := audit.ValidateEventFields(ctr.commitEntry); err != nil {
		t.Fatalf("merge AuditEntry must pass ValidateEventFields, got: %v", err)
	}
}

// TestMerge_SameCommitAuditActorEmpty proves AC-003-F: actor stays empty
// (deferred) and is NEVER an age1... recipient value.
func TestMerge_SameCommitAuditActorEmpty(t *testing.T) {
	t.Parallel()

	deps, _, ctr, ref := realE2EMergeDeps(t)
	m, err := usecase.NewMerger(deps)
	if err != nil {
		t.Fatalf("NewMerger: %v", err)
	}
	if _, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: ref, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if ctr.commitEntry.Actor != "" {
		t.Fatalf("AuditEntry.Actor = %q, want empty (deferred)", ctr.commitEntry.Actor)
	}
	if strings.HasPrefix(ctr.commitEntry.Actor, "age1") {
		t.Fatalf("AuditEntry.Actor must never be an age recipient value")
	}
}

// TestMerge_FailurePathAlarmStaysHostLocal proves BO-7's complement: the
// post-merge integrity ALARM emit is RETAINED on the host-local logger and is
// distinguishable from a durable merge success (it carries an "error..."
// outcome). The success same-commit emit is gone, but the alarm is not.
func TestMerge_FailurePathAlarmStaysHostLocal(t *testing.T) {
	t.Parallel()

	deps, spy, _, ref := realE2EMergeDeps(t)
	// Force the post-merge of-record verification to fail so the alarm fires.
	deps.Verifier = failingVerifier{err: errors.New("forced post-merge verify failure")}
	m, err := usecase.NewMerger(deps)
	if err != nil {
		t.Fatalf("NewMerger: %v", err)
	}
	_, err = m.Merge(context.Background(), usecase.MergeInput{
		Ref: ref, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if err == nil {
		t.Fatalf("expected post-merge integrity alarm error")
	}

	var foundAlarm bool
	for _, e := range spy.events {
		if e.Kind == audit.EventKindMerge && strings.HasPrefix(e.Outcome, "error") {
			foundAlarm = true
		}
		if e.Kind == audit.EventKindMerge && e.Outcome == "ok" {
			t.Fatalf("host-local logger received a merge ok event during a failed merge: %+v", e)
		}
	}
	if !foundAlarm {
		t.Fatalf("expected a host-local merge alarm event with an error outcome; got %+v", spy.events)
	}
}
