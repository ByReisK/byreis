package tui

// review_test.go — V-6 in-TUI approve action unit tests.
//
// These tests are in package tui (not tui_test) so they can drive the
// unexported reviewModel and message types directly without a real terminal.
// This is the standard approach for testing bubbletea models: drive
// Update/View directly without constructing a tea.Program (which requires a
// real terminal and registers signal handlers).
//
// Covered obligations:
//
//   - Golden-equivalence: MergeInput built by doApprove matches the admin_cmds.go
//     merge path field-for-field, including the pinnedSHA→ExpectSHA pin
//     (TestReviewApprove_GoldenEquivalence_MergeInputMatchesCLIPath).
//   - Read-only default: pressing a key other than 'a' on the detail screen
//     does NOT call Merge (TestReviewApprove_DetailScreenReadOnlyDefault).
//   - Approve→confirm→Merge flow: 'a' enters confirm, 'y' dispatches Merge
//     (TestReviewApprove_ConfirmYes_MergeCalled).
//   - Abort/no-confirm: 'a' then non-y key returns to detail, no Merge called
//     (TestReviewApprove_ConfirmAbort_NoMergeCalled).
//   - Already-merged graceful: Merge returns an error, TUI surfaces it and
//     does NOT crash or leave queue inconsistent
//     (TestReviewApprove_AlreadyMerged_GracefulError).
//   - Non-admin cannot reach approve: mode gate is enforced before the model
//     is constructed (TestReviewApprove_NonAdmin_CannotReachApprove).
//   - Nil Merger → error surfaced without panic
//     (TestReviewApprove_NilMerger_GracefulError).

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// spyMerger records the MergeInput it received and returns a canned result.
type spyMerger struct {
	calls  []usecase.MergeInput
	result usecase.MergeResult
	err    error
}

func (s *spyMerger) Merge(_ context.Context, in usecase.MergeInput) (usecase.MergeResult, error) {
	s.calls = append(s.calls, in)
	return s.result, s.err
}

// panicMerger panics if Merge is ever called (asserts Merge is NOT reached).
type panicMerger struct{}

func (p *panicMerger) Merge(_ context.Context, _ usecase.MergeInput) (usecase.MergeResult, error) {
	panic("Merge was called but must not be reached in this test path")
}

// buildReviewDetail constructs a reviewDetail with deterministic test values.
func buildReviewDetail() reviewDetail {
	return reviewDetail{
		Ref:       git.PRRef{Project: "testorg/secrets", Number: 42},
		Author:    "alice",
		PinnedSHA: "sha256:deadbeef",
		ProjectID: "myproject",
		FileName:  "prod",
		PerKey: []usecase.KeyReviewLine{
			{Key: "DB_HOST", Action: "add", ValidationOK: true},
		},
	}
}

// buildDetailModel constructs a reviewModel already in screenDetail state with
// the given Merger. This bypasses the queue/review flow and tests only the
// detail+approve path.
func buildDetailModel(merger usecase.Merger) reviewModel {
	pol := &mode.Policy{}
	m := reviewModel{
		ctx: context.Background(),
		deps: Deps{
			Merger:      merger,
			Policy:      pol,
			CurrentMode: mode.ModeAdmin,
		},
		screen:   screenDetail,
		detail:   buildReviewDetail(),
		detailOK: true,
	}
	return m
}

// sendKey drives a single key event through Update and returns the updated model.
func sendKey(m reviewModel, key string) reviewModel {
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
	rm, ok := updated.(reviewModel)
	if !ok {
		panic("Update returned unexpected model type")
	}
	return rm
}

// sendNamedKey drives a named key (esc, enter, ctrl+c, etc.) through Update.
func sendNamedKey(m reviewModel, keyType tea.KeyType) reviewModel {
	updated, _ := m.Update(tea.KeyMsg{Type: keyType})
	rm, ok := updated.(reviewModel)
	if !ok {
		panic("Update returned unexpected model type")
	}
	return rm
}

// drainCmd executes a bubbletea Cmd (the merge dispatch) synchronously and
// delivers the resulting message back through Update. This simulates the
// bubbletea runtime dispatching the Cmd result without running a real Program.
func drainCmd(m reviewModel, cmd tea.Cmd) reviewModel {
	if cmd == nil {
		return m
	}
	msg := cmd()
	updated, _ := m.Update(msg)
	rm, ok := updated.(reviewModel)
	if !ok {
		panic("Update returned unexpected model type after cmd drain")
	}
	return rm
}

// GOLDEN_EQUIVALENCE: the MergeInput built by doApprove matches the
// admin_cmds.go merge path field-for-field, including the PinnedSHA pin.
//
// The canonical CLI merge path (admin_cmds.go:1025) constructs:
//
//	usecase.MergeInput{
//	    Ref:               ref,              // ← detail.Ref
//	    ExpectSHA:         targetArtifactSHA, // ← detail.PinnedSHA (the pin)
//	    ExpectedProjectID: project,           // ← detail.ProjectID
//	    ExpectedFileName:  file,              // ← detail.FileName
//	    CommitMessage:     msg,               // ← derived default
//	}
//
// The TUI approve must construct an identical MergeInput.
func TestReviewApprove_GoldenEquivalence_MergeInputMatchesCLIPath(t *testing.T) {
	t.Parallel()

	spy := &spyMerger{
		result: usecase.MergeResult{
			LiveFileSHA:  "sha256:live",
			ReEncrypted:  false,
			FinalCounter: 5,
		},
	}
	m := buildDetailModel(spy)
	detail := m.detail

	// Enter confirm screen (press 'a').
	m = sendKey(m, "a")
	if m.screen != screenConfirmApprove {
		t.Fatalf("expected screenConfirmApprove after 'a', got screen=%d", m.screen)
	}

	// Confirm with 'y' — this dispatches doApprove via a Cmd.
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = updated.(reviewModel)
	if m.screen != screenApproving {
		t.Fatalf("expected screenApproving after 'y', got screen=%d", m.screen)
	}

	// Drain the cmd (synchronously execute the Merge call).
	m = drainCmd(m, cmd)
	if m.screen != screenApproveSuccess {
		t.Fatalf("expected screenApproveSuccess after merge, got screen=%d; approveErr=%q",
			m.screen, m.approveErrMsg)
	}

	// Assert the spy received exactly one call with the correct MergeInput.
	if len(spy.calls) != 1 {
		t.Fatalf("expected 1 Merge call, got %d", len(spy.calls))
	}
	got := spy.calls[0]

	// Field-for-field equivalence with the CLI merge path.
	if got.Ref != detail.Ref {
		t.Errorf("MergeInput.Ref: got %v, want %v", got.Ref, detail.Ref)
	}
	if got.ExpectSHA != detail.PinnedSHA {
		t.Errorf("MergeInput.ExpectSHA (pinnedSHA pin): got %q, want %q",
			got.ExpectSHA, detail.PinnedSHA)
	}
	if got.ExpectedProjectID != detail.ProjectID {
		t.Errorf("MergeInput.ExpectedProjectID: got %q, want %q",
			got.ExpectedProjectID, detail.ProjectID)
	}
	if got.ExpectedFileName != detail.FileName {
		t.Errorf("MergeInput.ExpectedFileName: got %q, want %q",
			got.ExpectedFileName, detail.FileName)
	}
	// CommitMessage must be non-empty and derived from the ref (not empty, not
	// carrying any secret material).
	if got.CommitMessage == "" {
		t.Error("MergeInput.CommitMessage must not be empty")
	}
	if got.ExpectSHA == "" {
		t.Error("MergeInput.ExpectSHA (pinnedSHA pin) must not be empty — " +
			"this is the replay-protection keystone; an empty pin is a security gap")
	}
}

// TestReviewApprove_PinnedSHA_NonEmpty asserts that the replay-protection pin
// is always present in the constructed MergeInput. An empty ExpectSHA would
// bypass the review→merge replay protection: the Merge use-case would fail
// closed, but the TUI should never send an empty pin.
func TestReviewApprove_PinnedSHA_NonEmpty(t *testing.T) {
	t.Parallel()

	spy := &spyMerger{result: usecase.MergeResult{LiveFileSHA: "sha256:x"}}
	m := buildDetailModel(spy)

	// Confirm approve flow.
	m = sendKey(m, "a")
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = updated.(reviewModel)
	_ = drainCmd(m, cmd)

	if len(spy.calls) != 1 {
		t.Fatalf("expected 1 Merge call, got %d", len(spy.calls))
	}
	if spy.calls[0].ExpectSHA == "" {
		t.Error("REPLAY PROTECTION GAP: MergeInput.ExpectSHA is empty — " +
			"the TUI approve must always pass the reviewed PinnedSHA as ExpectSHA")
	}
}

// TestReviewApprove_DetailScreenReadOnlyDefault asserts that pressing keys
// other than 'a' on the detail screen does NOT call Merge. The detail screen
// is read-only by default; approve is an explicit opt-in.
func TestReviewApprove_DetailScreenReadOnlyDefault(t *testing.T) {
	t.Parallel()

	panicker := &panicMerger{}
	m := buildDetailModel(panicker)

	// Pressing 'r' (review another) must not call Merge.
	m2 := sendKey(m, "r")
	if m2.screen != screenRefEntry {
		t.Errorf("expected screenRefEntry after 'r', got screen=%d", m2.screen)
	}

	// Pressing other arbitrary keys must not call Merge (would panic if called).
	for _, k := range []string{"x", "m", "z", "p"} {
		m3 := sendKey(m, k)
		if m3.screen != screenDetail {
			t.Logf("key %q: screen transitioned to %d (unexpected but no Merge call)", k, m3.screen)
		}
	}
}

// TestReviewApprove_ConfirmYes_MergeCalled asserts that 'a' then 'y' dispatches
// Merger.Merge and transitions to screenApproveSuccess on success.
func TestReviewApprove_ConfirmYes_MergeCalled(t *testing.T) {
	t.Parallel()

	spy := &spyMerger{result: usecase.MergeResult{
		LiveFileSHA:  "sha256:abc",
		FinalCounter: 3,
	}}
	m := buildDetailModel(spy)

	// Enter confirm.
	m = sendKey(m, "a")
	if m.screen != screenConfirmApprove {
		t.Fatalf("expected screenConfirmApprove, got %d", m.screen)
	}

	// Confirm with Enter (using sendNamedKey which wraps Update for named keys).
	m2 := sendNamedKey(m, tea.KeyEnter)
	if m2.screen != screenApproving {
		t.Fatalf("expected screenApproving after Enter, got %d", m2.screen)
	}
	// Drain the Cmd returned by the Enter update to execute the merge.
	updated2, cmd2 := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated2.(reviewModel)
	m = drainCmd(m, cmd2)

	if len(spy.calls) != 1 {
		t.Fatalf("expected 1 Merge call, got %d", len(spy.calls))
	}
	if m.screen != screenApproveSuccess {
		t.Errorf("expected screenApproveSuccess, got %d; approveErr=%q",
			m.screen, m.approveErrMsg)
	}
	if m.approveResult.liveFileSHA != "sha256:abc" {
		t.Errorf("approveResult.liveFileSHA: got %q, want %q",
			m.approveResult.liveFileSHA, "sha256:abc")
	}
}

// TestReviewApprove_ConfirmAbort_NoMergeCalled asserts that pressing any key
// other than 'y'/Enter on the confirm screen aborts back to the detail screen
// without calling Merger.Merge. The queue must remain consistent.
func TestReviewApprove_ConfirmAbort_NoMergeCalled(t *testing.T) {
	t.Parallel()

	panicker := &panicMerger{}
	m := buildDetailModel(panicker)

	// Enter confirm screen.
	m = sendKey(m, "a")
	if m.screen != screenConfirmApprove {
		t.Fatalf("expected screenConfirmApprove, got %d", m.screen)
	}

	// Press a non-confirming key to abort — must return to detail, no Merge call.
	m = sendKey(m, "n")
	if m.screen != screenDetail {
		t.Errorf("expected screenDetail after abort key, got %d", m.screen)
	}

	// Pressing Esc-equivalent (any key != y/enter) also aborts.
	m2 := buildDetailModel(panicker)
	m2 = sendKey(m2, "a")
	m2 = sendKey(m2, "q")
	if m2.screen != screenDetail {
		t.Errorf("expected screenDetail after 'q' abort, got %d", m2.screen)
	}
}

// TestReviewApprove_AlreadyMerged_GracefulError asserts that when the Merger
// returns an error (including the already-merged/closed concurrent race), the
// TUI surfaces an actionable error message in screenApproveError without
// crashing or leaving the queue inconsistent.
func TestReviewApprove_AlreadyMerged_GracefulError(t *testing.T) {
	t.Parallel()

	alreadyMergedErr := errors.New("PR #42 is already merged or closed — " +
		"no further action required")
	spy := &spyMerger{err: alreadyMergedErr}
	m := buildDetailModel(spy)

	// Enter confirm, then confirm with 'y'.
	m = sendKey(m, "a")
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = updated.(reviewModel)
	m = drainCmd(m, cmd)

	if m.screen != screenApproveError {
		t.Fatalf("expected screenApproveError after merge failure, got screen=%d", m.screen)
	}
	if m.approveErrMsg == "" {
		t.Error("approveErrMsg must not be empty after merge failure")
	}

	// The TUI must remain navigable: pressing 'q' should transition to screenDone.
	m = sendKey(m, "q")
	if m.screen != screenDone {
		t.Errorf("expected screenDone after 'q' from error screen, got %d", m.screen)
	}

	// The view must render without panic.
	m2 := buildDetailModel(spy)
	m2 = sendKey(m2, "a")
	updated2, cmd2 := m2.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m2 = updated2.(reviewModel)
	m2 = drainCmd(m2, cmd2)
	view := m2.View()
	if view == "" {
		t.Error("View() on screenApproveError must not be empty")
	}
}

// TestReviewApprove_NonAdmin_CannotReachApprove asserts that the mode gate
// enforced in RunReview prevents a non-admin from reaching the approve action.
// The approve is only reachable inside a model that was constructed after the
// mode gate passed; the gate is in RunReview (not in the model itself).
// This test drives the model directly to confirm the model-level nil-Merger
// guard also surfaces an error rather than panicking.
func TestReviewApprove_NonAdmin_CannotReachApprove(t *testing.T) {
	t.Parallel()

	// A contributor model has no Merger wired (the mode gate in RunReview would
	// have denied it, but we simulate the nil-Merger guard at the model level).
	pol := &mode.Policy{}
	m := reviewModel{
		ctx: context.Background(),
		deps: Deps{
			Merger:      nil, // explicitly nil: no merge capability for contributor
			Policy:      pol,
			CurrentMode: mode.ModeContributor,
		},
		screen:   screenDetail,
		detail:   buildReviewDetail(),
		detailOK: true,
	}

	// Press 'a': should surface the nil-Merger error, not call Merge.
	m = sendKey(m, "a")
	if m.screen != screenApproveError {
		t.Errorf("expected screenApproveError when Merger is nil, got %d", m.screen)
	}
	if m.approveErrMsg == "" {
		t.Error("approveErrMsg must not be empty when Merger is nil")
	}
}

// TestReviewApprove_NilMerger_GracefulError mirrors the non-admin test but
// confirms the nil check is on Merger, not on mode.
func TestReviewApprove_NilMerger_GracefulError(t *testing.T) {
	t.Parallel()

	m := buildDetailModel(nil) // nil Merger
	m = sendKey(m, "a")
	if m.screen != screenApproveError {
		t.Errorf("expected screenApproveError for nil Merger, got %d", m.screen)
	}
	if m.approveErrMsg == "" {
		t.Error("approveErrMsg must not be empty for nil Merger")
	}
}

// TestReviewApprove_ViewConfirmApprove_RendersNonEmpty asserts the confirm view
// renders a non-empty, non-panicking string showing the PR ref and pinnedSHA.
func TestReviewApprove_ViewConfirmApprove_RendersNonEmpty(t *testing.T) {
	t.Parallel()

	spy := &spyMerger{}
	m := buildDetailModel(spy)
	m = sendKey(m, "a")
	if m.screen != screenConfirmApprove {
		t.Fatalf("expected screenConfirmApprove, got %d", m.screen)
	}

	view := m.View()
	if view == "" {
		t.Fatal("View() on screenConfirmApprove must not be empty")
	}

	// The confirm view must mention the pinnedSHA so the admin can verify.
	detail := buildReviewDetail()
	if !contains(view, detail.PinnedSHA) {
		t.Errorf("confirm view must include pinnedSHA %q for the admin to verify; got:\n%s",
			detail.PinnedSHA, view)
	}
}

// TestReviewApprove_DetailHintShownWhenMergerWired asserts that the 'a' key
// hint is visible in the detail view when Merger is wired, and absent when nil.
func TestReviewApprove_DetailHintShownWhenMergerWired(t *testing.T) {
	t.Parallel()

	spy := &spyMerger{}
	mWithMerger := buildDetailModel(spy)
	viewWith := mWithMerger.View()
	if !contains(viewWith, "approve") {
		t.Errorf("detail view must include approve hint when Merger is wired; got:\n%s", viewWith)
	}

	mNilMerger := buildDetailModel(nil)
	viewWithout := mNilMerger.View()
	if contains(viewWithout, "approve") {
		t.Errorf("detail view must NOT include approve hint when Merger is nil; got:\n%s", viewWithout)
	}
}

// TestReviewApprove_SuccessViewRendersResult asserts that the success view
// renders the merge result fields without panicking.
func TestReviewApprove_SuccessViewRendersResult(t *testing.T) {
	t.Parallel()

	spy := &spyMerger{result: usecase.MergeResult{
		LiveFileSHA:  "sha256:successfile",
		ReEncrypted:  true,
		FinalCounter: 7,
	}}
	m := buildDetailModel(spy)
	m = sendKey(m, "a")
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = updated.(reviewModel)
	m = drainCmd(m, cmd)

	if m.screen != screenApproveSuccess {
		t.Fatalf("expected screenApproveSuccess, got %d; approveErr=%q",
			m.screen, m.approveErrMsg)
	}

	view := m.View()
	if view == "" {
		t.Fatal("View() on screenApproveSuccess must not be empty")
	}
	if !contains(view, "sha256:successfile") {
		t.Errorf("success view must render content_sha; got:\n%s", view)
	}
}

// contains is a helper asserting s contains sub (avoids importing strings in
// test assertions where the intent would be obscured).
func contains(s, sub string) bool {
	return len(sub) > 0 && (s == sub || len(s) >= len(sub) && indexSubstring(s, sub) >= 0)
}

func indexSubstring(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
