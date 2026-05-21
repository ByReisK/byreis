package rotate_test

// Table-driven + negative tests for the rotation use-case spine, planner,
// reconciler, and the forward-secrecy warning constant.
//
// Every collaborator is an in-memory fake injected at construction: no real
// fs, net, clock, randomness, or keychain. All test rows are mapped 1:1 to
// the §V1 17-row plan in design/V02_WORK_BREAKDOWN.md.
//
// Row IDs (audit-trail anchors permitted in _test.go ONLY):
//   - V1.R001.1 — TestRotate_AdminModeGate_ContributorDeniedNotAttempted
//   - V1.R001.2 — TestRotate_StaleOrUnverifiedRegistry_FailsClosed
//   - V1.R001.3 — TestRotate_DryRun_ExitsWithPlanNoPhase1
//   - V1.R001.4 — TestRotate_PlanFlagsHasRemovals_RequiresConfirmSignalled
//   - V1.R001.5 — TestRotate_NonInteractiveRequiresYes
//   - V1.D2.1  — TestRotate_AdminCannotDecryptExisting_FailsClosedBeforeBranch
//   - V1.D3.1  — TestPlan_AddAndRemoveSamePubkey_ErrFlagConflict
//   - V1.D3.2  — TestPlan_RemoveAbsentRecipient_ErrRemoveAbsent
//   - V1.D3.3  — TestPlan_AddNotAdmin_ErrAddNotAdmin
//   - V1.D3.4  — TestPlan_EmptyResultingRecipientSet_ErrEmpty
//   - V1.R007.1 — TestReconcile_Phase1OnlyClassification
//   - V1.R007.2 — TestReconcile_Phase1OnlyAction_DeletesBranchClearsPendings
//   - V1.R007.3 — TestReconcile_Phase2Midflight_TerminalErrRotationReconcile
//   - V1.R007.4 — TestReconcile_CONTRIBUTOR_DeniedAtVerbWrapper (port-level mode test)
//   - V1.D7.race — TestReconcile_BoundedRetries_OnConcurrentRotation
//   - V1.D9 — TestForwardSecrecyWarning_VerbatimMatchesADR0016
//   - V1.allowlist — see allowlist_test.go (Submit/rotate disjointness)

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ---- fakes (no real fs/net/clock/keychain; no decrypting identity) ----

type fakeClock struct {
	now time.Time
}

func (f fakeClock) Now() time.Time { return f.now }

// recordingPhase1 records whether Execute was called. The V1.R001.3 row
// asserts the call count is 0 in dry-run mode.
type recordingPhase1 struct {
	calls    atomic.Int32
	result   rotate.Phase1Result
	err      error
	captured rotate.RotationPlan
}

func (p *recordingPhase1) Execute(_ context.Context, plan rotate.RotationPlan) (rotate.Phase1Result, error) {
	p.calls.Add(1)
	p.captured = plan
	if p.err != nil {
		return rotate.Phase1Result{}, p.err
	}
	return p.result, nil
}

type recordingPhase2 struct {
	calls  atomic.Int32
	result rotate.Phase2Result
	err    error
}

func (p *recordingPhase2) Execute(_ context.Context, _ rotate.Phase1Result) (rotate.Phase2Result, error) {
	p.calls.Add(1)
	if p.err != nil {
		return rotate.Phase2Result{}, p.err
	}
	return p.result, nil
}

// recordingPlanner wraps the real planner and records call counts so the
// V1.R001.1 / R001.2 tests can assert "planner not called" before any
// mode/sourceVerified gate violation.
type recordingPlanner struct {
	inner rotate.RotationPlanner
	calls atomic.Int32
}

func (r *recordingPlanner) Plan(ctx context.Context, in rotate.PlanInput) (rotate.RotationPlan, error) {
	r.calls.Add(1)
	return r.inner.Plan(ctx, in)
}

// happyPathDeps builds a Rotator with fakes that always succeed and a real
// planner; tests override individual fields as needed.
type happyPathHarness struct {
	clock   fakeClock
	planner *recordingPlanner
	p1      *recordingPhase1
	p2      *recordingPhase2
}

func newHappyPathHarness() happyPathHarness {
	return happyPathHarness{
		clock:   fakeClock{now: time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)},
		planner: &recordingPlanner{inner: rotate.NewPlanner()},
		p1: &recordingPhase1{
			result: rotate.Phase1Result{
				BranchRef:         git.PRRef{Project: "myorg/proj", Number: 1},
				ProjectParentSHA:  "proj-parent",
				RegistryParentSHA: "reg-parent",
				PlannedEpoch:      1,
			},
		},
		p2: &recordingPhase2{
			result: rotate.Phase2Result{
				MergedSHA:         "merged",
				CommitRotationSHA: "commit",
				NewEpoch:          1,
			},
		},
	}
}

func (h happyPathHarness) build(t *testing.T) rotate.Rotator {
	t.Helper()
	r, err := rotate.NewRotator(rotate.RotatorDeps{
		Planner: h.planner,
		Phase1:  h.p1,
		Phase2:  h.p2,
		Clock:   h.clock,
	})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	return r
}

// recipient builds a Recipient with a deterministic, unique AgePubKey.
func recipient(label, pk string) rectypes.Recipient {
	return rectypes.Recipient{Label: label, AgePubKey: pk}
}

// admins returns a standard 3-admin set used across rows.
func admins() []rectypes.Recipient {
	return []rectypes.Recipient{
		recipient("alice", "age1alice"),
		recipient("bob", "age1bob"),
		recipient("carol", "age1carol"),
	}
}

// happyInput builds a base RotationInput with ADMIN mode and a
// SourceVerified registry, sufficient to pass the entry gates.
func happyInput() rotate.RotationInput {
	return rotate.RotationInput{
		ProjectID:             "myorg/proj",
		Mode:                  mode.ModeAdmin,
		SourceVerified:        true,
		RegistryStale:         false,
		PreRotationRecipients: admins(),
		RegisteredAdmins:      admins(),
		AdminCanDecryptAll:    true,
	}
}

// V1.R001.1 — ADMIN-mode gate; CONTRIBUTOR is denied-not-attempted before
// any planner call, any registry fetch, any branch creation.
func TestRotate_AdminModeGate_ContributorDeniedNotAttempted(t *testing.T) {
	h := newHappyPathHarness()
	r := h.build(t)

	in := happyInput()
	in.Mode = mode.ModeContributor

	_, err := r.Rotate(context.Background(), in)
	if err == nil {
		t.Fatal("expected denial for CONTRIBUTOR mode, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("error must wrap mode.ErrPermissionDenied, got %v", err)
	}
	// Denied-not-attempted: no planner / phase-1 / phase-2 call occurred.
	if h.planner.calls.Load() != 0 {
		t.Errorf("planner was called %d times; CONTRIBUTOR must be denied BEFORE planner",
			h.planner.calls.Load())
	}
	if h.p1.calls.Load() != 0 {
		t.Errorf("phase1 was called %d times; must be denied-not-attempted",
			h.p1.calls.Load())
	}
	if h.p2.calls.Load() != 0 {
		t.Errorf("phase2 was called %d times; must be denied-not-attempted",
			h.p2.calls.Load())
	}
}

// V1.R001.2 — stale or unverified registry → ErrRotationRequiresFreshRegistry
// + actionable hint; no planner call, no Phase-1 work.
func TestRotate_StaleOrUnverifiedRegistry_FailsClosed(t *testing.T) {
	cases := []struct {
		name           string
		sourceVerified bool
		stale          bool
	}{
		{"unverified", false, false},
		{"stale", true, true},
		{"both", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHappyPathHarness()
			r := h.build(t)
			in := happyInput()
			in.SourceVerified = tc.sourceVerified
			in.RegistryStale = tc.stale

			_, err := r.Rotate(context.Background(), in)
			if !errors.Is(err, rotate.ErrRotationRequiresFreshRegistry) {
				t.Fatalf("expected ErrRotationRequiresFreshRegistry, got %v", err)
			}
			if h.planner.calls.Load() != 0 {
				t.Errorf("planner called %d; must be denied-not-attempted",
					h.planner.calls.Load())
			}
			if h.p1.calls.Load() != 0 {
				t.Errorf("phase1 called %d; must be denied-not-attempted", h.p1.calls.Load())
			}
			hint := err.Error()
			if !containsSubstr(hint, "byreis registry refresh") {
				t.Errorf("error message must carry an actionable refresh-command hint, got: %s", hint)
			}
		})
	}
}

// V1.R001.3 — --dry-run exits with plan; no Phase1Executor.Execute called.
func TestRotate_DryRun_ExitsWithPlanNoPhase1(t *testing.T) {
	h := newHappyPathHarness()
	r := h.build(t)
	in := happyInput()
	in.DryRun = true
	in.AddPubkeys = []rectypes.Recipient{recipient("dan", "age1dan")}
	// Register dan as an admin so the planner accepts the --add.
	in.RegisteredAdmins = append(in.RegisteredAdmins, recipient("dan", "age1dan"))

	res, err := r.Rotate(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.DryRun {
		t.Error("result.DryRun must be true on dry-run exit")
	}
	if h.planner.calls.Load() != 1 {
		t.Errorf("planner expected to be called once for plan computation; got %d",
			h.planner.calls.Load())
	}
	if h.p1.calls.Load() != 0 {
		t.Errorf("dry-run must NOT call Phase1Executor; got %d", h.p1.calls.Load())
	}
	if h.p2.calls.Load() != 0 {
		t.Errorf("dry-run must NOT call Phase2Executor; got %d", h.p2.calls.Load())
	}
	if len(res.Plan.AddedRecipients) != 1 || res.Plan.AddedRecipients[0].AgePubKey != "age1dan" {
		t.Errorf("plan must show dan as added; got %+v", res.Plan.AddedRecipients)
	}
}

// V1.R001.4 — --remove/--replace interactively: plan signals removals so the
// CLI layer can require typed-fingerprint confirm. The spine itself does not
// implement the TTY confirm (that lives in the CLI render layer per L20);
// here we assert HasRemovals is set so the CLI knows to require the
// fingerprint confirm.
func TestRotate_PlanFlagsHasRemovals_RequiresConfirmSignalled(t *testing.T) {
	h := newHappyPathHarness()
	r := h.build(t)
	in := happyInput()
	in.DryRun = true
	in.RemovePubkeys = []rectypes.Recipient{recipient("bob", "age1bob")}

	res, err := r.Rotate(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Plan.HasRemovals {
		t.Error("plan.HasRemovals must be true when --remove is used; the CLI " +
			"requires typed-fingerprint confirm only when removals are present")
	}
	if len(res.Plan.RemovedRecipients) != 1 || res.Plan.RemovedRecipients[0].AgePubKey != "age1bob" {
		t.Errorf("plan must list bob as removed; got %+v", res.Plan.RemovedRecipients)
	}
}

// V1.R001.5 — --yes skips confirm (the CLI render layer would otherwise
// require an interactive confirm). BYREIS_NON_INTERACTIVE=1 without --yes
// fails closed with ErrNonInteractiveRequiresYes BEFORE any plan-print or
// Phase-1 work.
func TestRotate_NonInteractiveRequiresYes(t *testing.T) {
	t.Run("non-interactive_without_yes_fails_closed", func(t *testing.T) {
		h := newHappyPathHarness()
		r := h.build(t)
		in := happyInput()
		in.NonInteractive = true
		in.Yes = false

		_, err := r.Rotate(context.Background(), in)
		if !errors.Is(err, rotate.ErrNonInteractiveRequiresYes) {
			t.Fatalf("expected ErrNonInteractiveRequiresYes, got %v", err)
		}
		if h.planner.calls.Load() != 0 {
			t.Errorf("planner called %d; non-interactive opt-in gate must be denied-not-attempted",
				h.planner.calls.Load())
		}
		if h.p1.calls.Load() != 0 {
			t.Errorf("phase1 called %d; must be denied-not-attempted", h.p1.calls.Load())
		}
	})

	t.Run("non-interactive_with_yes_proceeds", func(t *testing.T) {
		h := newHappyPathHarness()
		r := h.build(t)
		in := happyInput()
		in.NonInteractive = true
		in.Yes = true
		in.DryRun = true // keep test bounded to plan + return

		res, err := r.Rotate(context.Background(), in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.DryRun {
			t.Error("--yes + dry-run must still exit at dry-run")
		}
	})
}

// V1.D2.1 — admin-not-in-pre-rotation-set → ErrRotationCannotDecryptExisting
// BEFORE branch creation. The spine receives AdminCanDecryptAll=false from
// the caller (the CLI layer attempts the per-file decrypt and signals here);
// the spine fails closed BEFORE Phase-1 runs.
func TestRotate_AdminCannotDecryptExisting_FailsClosedBeforeBranch(t *testing.T) {
	h := newHappyPathHarness()
	r := h.build(t)
	in := happyInput()
	in.AdminCanDecryptAll = false
	in.PreRotationFiles = []rotate.FileSnapshot{
		{LogicalName: "prod", SignedArtifact: artifact.Signed{}, CurrentCounter: 1, CurrentEpoch: 0},
	}

	_, err := r.Rotate(context.Background(), in)
	if !errors.Is(err, rotate.ErrRotationCannotDecryptExisting) {
		t.Fatalf("expected ErrRotationCannotDecryptExisting, got %v", err)
	}
	if h.p1.calls.Load() != 0 {
		t.Errorf("phase1 must NOT be invoked when admin cannot decrypt every file; got %d calls",
			h.p1.calls.Load())
	}
	if h.p2.calls.Load() != 0 {
		t.Errorf("phase2 must NOT be invoked; got %d calls", h.p2.calls.Load())
	}
}

// V1.D3.1 — --add X --remove X within one invocation → ErrRotationFlagConflict.
func TestPlan_AddAndRemoveSamePubkey_ErrFlagConflict(t *testing.T) {
	planner := rotate.NewPlanner()
	dup := recipient("bob", "age1bob")
	_, err := planner.Plan(context.Background(), rotate.PlanInput{
		ProjectID:             "myorg/proj",
		PreRotationRecipients: admins(),
		RegisteredAdmins:      admins(),
		AddPubkeys:            []rectypes.Recipient{dup},
		RemovePubkeys:         []rectypes.Recipient{dup},
	})
	if !errors.Is(err, rotate.ErrRotationFlagConflict) {
		t.Fatalf("expected ErrRotationFlagConflict, got %v", err)
	}
}

// V1.D3.2 — --remove X where X ∉ R → ErrRotationRemoveAbsentRecipient.
func TestPlan_RemoveAbsentRecipient_ErrRemoveAbsent(t *testing.T) {
	planner := rotate.NewPlanner()
	_, err := planner.Plan(context.Background(), rotate.PlanInput{
		ProjectID:             "myorg/proj",
		PreRotationRecipients: admins(),
		RegisteredAdmins:      admins(),
		RemovePubkeys:         []rectypes.Recipient{recipient("ghost", "age1ghost")},
	})
	if !errors.Is(err, rotate.ErrRotationRemoveAbsentRecipient) {
		t.Fatalf("expected ErrRotationRemoveAbsentRecipient, got %v", err)
	}
}

// V1.D3.3 — --add X where X ∉ admins.yaml → ErrRotationAddNotAdmin.
func TestPlan_AddNotAdmin_ErrAddNotAdmin(t *testing.T) {
	planner := rotate.NewPlanner()
	_, err := planner.Plan(context.Background(), rotate.PlanInput{
		ProjectID:             "myorg/proj",
		PreRotationRecipients: admins(),
		RegisteredAdmins:      admins(),
		AddPubkeys:            []rectypes.Recipient{recipient("stranger", "age1stranger")},
	})
	if !errors.Is(err, rotate.ErrRotationAddNotAdmin) {
		t.Fatalf("expected ErrRotationAddNotAdmin, got %v", err)
	}
}

// V1.D3.4 — empty R' → ErrRotationEmptyRecipientSet.
func TestPlan_EmptyResultingRecipientSet_ErrEmpty(t *testing.T) {
	planner := rotate.NewPlanner()
	// Remove every admin in R; no adds; resulting R' is empty.
	in := rotate.PlanInput{
		ProjectID:             "myorg/proj",
		PreRotationRecipients: admins(),
		RegisteredAdmins:      admins(),
	}
	in.RemovePubkeys = append(in.RemovePubkeys, admins()...)
	_, err := planner.Plan(context.Background(), in)
	if !errors.Is(err, rotate.ErrRotationEmptyRecipientSet) {
		t.Fatalf("expected ErrRotationEmptyRecipientSet, got %v", err)
	}
}

// PlannerNoWrites: the spec mandates Plan causes ZERO write side effects.
// The recordingPlanner above sees its inner Plan return data; this row
// asserts that calling Plan does not increment the fake Phase-1/Phase-2 call
// counts. Bound to V1.R001.3 obligations.
func TestPlan_NoSideEffectsOnPlanCall(t *testing.T) {
	h := newHappyPathHarness()
	r := h.build(t)
	in := happyInput()
	in.DryRun = true

	_, err := r.Rotate(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.p1.calls.Load() != 0 || h.p2.calls.Load() != 0 {
		t.Errorf("Plan path must cause ZERO Phase-1/Phase-2 invocations; got p1=%d p2=%d",
			h.p1.calls.Load(), h.p2.calls.Load())
	}
}

// ---- reconciler test fakes ----

type fakeProbe struct {
	mu  atomic.Int32 // call count
	seq []rotate.PartialStateObservation
	err error
}

func (f *fakeProbe) FetchPartialState(_ context.Context, _ string) (rotate.PartialStateObservation, error) {
	idx := f.mu.Add(1) - 1
	if f.err != nil {
		return rotate.PartialStateObservation{}, f.err
	}
	if int(idx) >= len(f.seq) {
		return f.seq[len(f.seq)-1], nil
	}
	return f.seq[idx], nil
}

type fakeReverser struct {
	clearCalls      atomic.Int32
	deleteCalls     atomic.Int32
	clearErrs       []error
	deleteErr       error
	clearedPendings [][]rotate.PendingObservation
}

func (f *fakeReverser) ClearPendings(_ context.Context, _ string, ps []rotate.PendingObservation) error {
	idx := f.clearCalls.Add(1) - 1
	f.clearedPendings = append(f.clearedPendings, ps)
	if int(idx) < len(f.clearErrs) {
		return f.clearErrs[idx]
	}
	return nil
}

func (f *fakeReverser) DeleteRotationBranch(_ context.Context, _ git.PRRef) error {
	f.deleteCalls.Add(1)
	return f.deleteErr
}

func phase1OnlyObs() rotate.PartialStateObservation {
	return rotate.PartialStateObservation{
		PendingsTaggedRotation: []rotate.PendingObservation{
			{
				LogicalName:       "prod",
				PendingCounter:    1,
				TargetArtifactSHA: "sha-prod",
				TargetPR:          git.PRRef{Project: "myorg/proj", Number: 99},
			},
		},
		MatchingPendings:     nil,
		RotationBranchExists: true,
		RotationBranchMerged: false,
		RotationBranchRef:    git.PRRef{Project: "myorg/proj", Number: 99},
	}
}

func phase2MidflightObs() rotate.PartialStateObservation {
	p := rotate.PendingObservation{
		LogicalName:       "prod",
		PendingCounter:    1,
		TargetArtifactSHA: "sha-prod",
		TargetPR:          git.PRRef{Project: "myorg/proj", Number: 99},
	}
	return rotate.PartialStateObservation{
		PendingsTaggedRotation: []rotate.PendingObservation{p},
		MatchingPendings:       []rotate.PendingObservation{p},
		RotationBranchExists:   false,
		RotationBranchMerged:   true,
	}
}

func noPartialObs() rotate.PartialStateObservation {
	return rotate.PartialStateObservation{}
}

// V1.R007.1 — Phase-1-only partial state classified correctly.
func TestReconcile_Phase1OnlyClassification(t *testing.T) {
	probe := &fakeProbe{seq: []rotate.PartialStateObservation{phase1OnlyObs()}}
	rev := &fakeReverser{}
	rec, err := rotate.NewReconciler(rotate.ReconcilerDeps{Probe: probe, Reverser: rev})
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}
	got, err := rec.Classify(context.Background(), "myorg/proj")
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got != rotate.Phase1Only {
		t.Fatalf("classification: want Phase1Only, got %s", got)
	}
	// Classify is read-only; no reverser methods called.
	if rev.clearCalls.Load() != 0 || rev.deleteCalls.Load() != 0 {
		t.Errorf("Classify must NOT write; got clear=%d delete=%d",
			rev.clearCalls.Load(), rev.deleteCalls.Load())
	}
}

// V1.R007.2 — Phase-1-only reconcile deletes unmerged branch + clears
// pendings; no counter advance is introduced.
func TestReconcile_Phase1OnlyAction_DeletesBranchClearsPendings(t *testing.T) {
	obs := phase1OnlyObs()
	probe := &fakeProbe{seq: []rotate.PartialStateObservation{obs}}
	rev := &fakeReverser{}
	rec, _ := rotate.NewReconciler(rotate.ReconcilerDeps{Probe: probe, Reverser: rev})

	res, err := rec.Reconcile(context.Background(), "myorg/proj")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.Classification != rotate.Phase1Only {
		t.Errorf("want Phase1Only, got %s", res.Classification)
	}
	if !res.BranchDeleted {
		t.Error("BranchDeleted must be true after a successful Phase-1-only reverse")
	}
	if res.PendingsCleared != 1 {
		t.Errorf("PendingsCleared: want 1, got %d", res.PendingsCleared)
	}
	if rev.clearCalls.Load() != 1 {
		t.Errorf("ClearPendings calls: want 1, got %d", rev.clearCalls.Load())
	}
	if rev.deleteCalls.Load() != 1 {
		t.Errorf("DeleteRotationBranch calls: want 1, got %d", rev.deleteCalls.Load())
	}
	// The reverser saw exactly the pending the probe observed.
	if len(rev.clearedPendings) != 1 || len(rev.clearedPendings[0]) != 1 ||
		rev.clearedPendings[0][0].LogicalName != "prod" {
		t.Errorf("ClearPendings input: want [prod], got %+v", rev.clearedPendings)
	}
}

// V1.R007.3 — Phase-2-midflight → terminal ErrRotationReconcile; no auto-
// rollback (no reverser methods called).
func TestReconcile_Phase2Midflight_TerminalErrRotationReconcile(t *testing.T) {
	probe := &fakeProbe{seq: []rotate.PartialStateObservation{phase2MidflightObs()}}
	rev := &fakeReverser{}
	rec, _ := rotate.NewReconciler(rotate.ReconcilerDeps{Probe: probe, Reverser: rev})

	res, err := rec.Reconcile(context.Background(), "myorg/proj")
	if !errors.Is(err, rotate.ErrRotationReconcile) {
		t.Fatalf("expected ErrRotationReconcile (terminal), got %v", err)
	}
	if res.Classification != rotate.Phase2Midflight {
		t.Errorf("want Phase2Midflight, got %s", res.Classification)
	}
	if rev.clearCalls.Load() != 0 || rev.deleteCalls.Load() != 0 {
		t.Errorf("Phase-2 midflight must NOT invoke any reverser action; got clear=%d delete=%d",
			rev.clearCalls.Load(), rev.deleteCalls.Load())
	}
	hint := err.Error()
	if !containsSubstr(hint, "docs/rotation-runbook.md") {
		t.Errorf("error message must reference the runbook; got: %s", hint)
	}
}

// V1.R007.4 — CONTRIBUTOR mode is denied at the verb-wrapper level (the
// reconciler port itself is mode-agnostic per V02_PORTS.md separation of
// concerns). Here we assert the spine's verb-wrapper contract: a
// CONTRIBUTOR-mode caller of Rotator.Rotate (the spine that wraps the
// reconciler in practice) is denied before any registry observation.
//
// The actual reconcile CLI verb wrapper lives in V5; this row asserts the
// invariant the wrapper must honour: the rotate spine entry refuses
// CONTRIBUTOR for the rotate verb itself, and the reconcile verb will
// mirror the same shape against the same mode.ErrPermissionDenied sentinel.
func TestReconcile_CONTRIBUTOR_DeniedAtVerbWrapper(t *testing.T) {
	// (a) The rotator-level verb wrapper denies CONTRIBUTOR (the same pattern
	// the V5 reconcile CLI verb will follow).
	h := newHappyPathHarness()
	r := h.build(t)
	in := happyInput()
	in.Mode = mode.ModeContributor

	_, err := r.Rotate(context.Background(), in)
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("verb-wrapper must wrap mode.ErrPermissionDenied for CONTRIBUTOR; got %v", err)
	}

	// (b) The reconciler port itself does NOT check mode (separation of
	// concerns per V02_PORTS.md). Calling Reconcile directly with a probe
	// that returns NoPartialState must succeed; mode is the verb wrapper's
	// concern, not the port's. This asserts the contract that the V5 CLI
	// verb wrapper carries the mode gate, not the port.
	probe := &fakeProbe{seq: []rotate.PartialStateObservation{noPartialObs()}}
	rev := &fakeReverser{}
	rec, _ := rotate.NewReconciler(rotate.ReconcilerDeps{Probe: probe, Reverser: rev})
	if _, err := rec.Reconcile(context.Background(), "myorg/proj"); err != nil {
		t.Fatalf("port-level Reconcile must not check mode; got %v", err)
	}
}

// V1.D7.race — bounded retries (max 3) under concurrent rotation. The probe
// returns Phase-1-only on every call; the reverser rejects the first
// pending-clear (concurrent CommitRotation landed and moved the CAS lease),
// then succeeds on the second. The reconciler retries within budget.
func TestReconcile_BoundedRetries_OnConcurrentRotation(t *testing.T) {
	t.Run("retries_then_succeeds_within_budget", func(t *testing.T) {
		probe := &fakeProbe{seq: []rotate.PartialStateObservation{
			phase1OnlyObs(), // first classification
			phase1OnlyObs(), // re-classification after CAS rejection
		}}
		rev := &fakeReverser{
			clearErrs: []error{errors.New("CAS rejected: registry HEAD moved")},
		}
		rec, _ := rotate.NewReconciler(rotate.ReconcilerDeps{Probe: probe, Reverser: rev})
		res, err := rec.Reconcile(context.Background(), "myorg/proj")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Retries != 1 {
			t.Errorf("Retries: want 1, got %d", res.Retries)
		}
		if !res.BranchDeleted {
			t.Error("BranchDeleted must be true after a successful retry")
		}
	})

	t.Run("exhausts_budget_surfaces_terminal_err", func(t *testing.T) {
		// Probe stays at Phase-1-only across every retry; reverser always
		// rejects the clear → budget exhausted at retries=3.
		probe := &fakeProbe{seq: []rotate.PartialStateObservation{
			phase1OnlyObs(), phase1OnlyObs(), phase1OnlyObs(), phase1OnlyObs(),
		}}
		rev := &fakeReverser{
			clearErrs: []error{
				errors.New("CAS rejected 1"),
				errors.New("CAS rejected 2"),
				errors.New("CAS rejected 3"),
				errors.New("CAS rejected 4"),
			},
		}
		rec, _ := rotate.NewReconciler(rotate.ReconcilerDeps{Probe: probe, Reverser: rev})
		res, err := rec.Reconcile(context.Background(), "myorg/proj")
		if !errors.Is(err, rotate.ErrRotationReconcile) {
			t.Fatalf("expected ErrRotationReconcile after budget exhaustion, got %v", err)
		}
		if res.Retries != 3 {
			t.Errorf("Retries: want 3 (bounded budget), got %d", res.Retries)
		}
	})

	t.Run("counter_reconcile_is_terminal_not_retried", func(t *testing.T) {
		// countertypes.ErrCounterReconcile is a terminal error per ADR-0006;
		// the reconciler must NOT retry on it.
		probe := &fakeProbe{seq: []rotate.PartialStateObservation{phase1OnlyObs()}}
		rev := &fakeReverser{
			clearErrs: []error{countertypes.ErrCounterReconcile},
		}
		rec, _ := rotate.NewReconciler(rotate.ReconcilerDeps{Probe: probe, Reverser: rev})
		res, err := rec.Reconcile(context.Background(), "myorg/proj")
		if !errors.Is(err, countertypes.ErrCounterReconcile) {
			t.Fatalf("counter-reconcile must propagate terminally, got %v", err)
		}
		if res.Retries != 0 {
			t.Errorf("counter-reconcile must NOT trigger retries; got Retries=%d", res.Retries)
		}
	})
}

// V1.D9 — ForwardSecrecyWarning matches the verbatim ADR-0016 D9 block
// byte-for-byte. The fixture is an INDEPENDENT []byte literal (not derived
// from the production constant); both are asserted against the same
// source-of-truth text. A typo in either fails the test by design.
func TestForwardSecrecyWarning_VerbatimMatchesADR0016(t *testing.T) {
	// Independent fixture: this []byte is the verbatim ADR-0016 D9 text.
	// Any divergence between this fixture and the production
	// ForwardSecrecyWarning constant is a deliberate review event.
	want := []byte("WARNING: forward secrecy over git history is NOT provided by rotation.\n" +
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
	got := []byte(rotate.ForwardSecrecyWarning) //nolint:forbidigo // boundary: equality assertion only
	if len(got) != len(want) {
		t.Fatalf("ForwardSecrecyWarning length mismatch: got %d, want %d "+
			"(divergence from ADR-0016 D9 verbatim block)",
			len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ForwardSecrecyWarning differs from ADR-0016 D9 at byte %d: "+
				"got %q, want %q\n"+
				"full got: %q\nfull want: %q",
				i, string(got[i]), string(want[i]), string(got), string(want))
		}
	}
}

// ---- helpers ----

func containsSubstr(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
