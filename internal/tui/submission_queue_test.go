package tui

// submission_queue_test.go — unit tests for the screenSubmissionQueue TUI screen.
//
// These tests are in package tui (not tui_test) so they can drive the unexported
// model types and message types directly without a real terminal, following the
// same pattern as review_test.go.
//
// Covered obligations:
//
//   - AC-002-A (no-plaintext keystone): the queue list view never calls
//     Reviewer.Review or Decryptor.Decrypt; only Enter on an item triggers review
//     (TestSubmissionQueue_ListViewNeverCallsReview).
//   - AC-002-C: Enter on a queue item populates the ref-binding and transitions
//     to screenReviewing directly (TestSubmissionQueue_EnterNavigatesToReview).
//   - AC-002-D: empty queue → the view renders "No pending submissions" and the
//     model stays in the submission-queue screen, not screenError
//     (TestSubmissionQueue_EmptyQueue_NonErrorState).
//   - AC-002-E: Reviewer returns 404/merged error → screenError, no panic, 'r'
//     returns to queue (TestSubmissionQueue_ReviewError_ReturnToQueue).
//   - AC-002-F: truncated=true renders a visible truncation affordance
//     (TestSubmissionQueue_TruncationSignalRendered).
//   - AC-002-I: ListSubmissionsBounded returns an error → queue-error state with
//     a 'byreis doctor' hint (TestSubmissionQueue_LoadError_DoctorHint).
//   - Navigation: ↑/↓ navigation updates selectedIdx correctly
//     (TestSubmissionQueue_ArrowKeyNavigation).
//   - Nil queue source: graceful error without panic
//     (TestSubmissionQueue_NilQueueSource).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ─── fakes ───────────────────────────────────────────────────────────────────

// countingReviewer counts Review calls to assert the list path never calls it.
type countingReviewer struct {
	calls  int
	result usecase.ReviewResult
	err    error
}

func (c *countingReviewer) Review(_ context.Context, in usecase.ReviewInput) (usecase.ReviewResult, error) {
	c.calls++
	c.result.Ref = in.Ref
	return c.result, c.err
}

// fixedSubmissionSource returns canned summaries and truncated flag.
type fixedSubmissionSource struct {
	summaries []rotate.OpenRequestSummary
	truncated bool
	err       error
}

func (f *fixedSubmissionSource) ListSubmissionsBounded(
	_ context.Context,
) ([]rotate.OpenRequestSummary, bool, error) {
	return f.summaries, f.truncated, f.err
}

// buildSummary builds a rotate.OpenRequestSummary for test fixtures.
func buildSummary(number int, author, title, headRef string) rotate.OpenRequestSummary {
	return rotate.OpenRequestSummary{
		PRRef:       coregit.PRRef{Project: "testorg/secrets", Number: number},
		AuthorLogin: author,
		Title:       title,
		CreatedAt:   "2026-01-15T00:00:00Z",
		HeadSHA:     fmt.Sprintf("sha%d", number),
	}
}

// buildSubmissionQueueModel constructs a reviewModel in the submission-queue
// screen (screenSubmissionQueue) with the given dependencies.
func buildSubmissionQueueModel(
	queueSource SubmissionQueueSource,
	reviewer usecase.Reviewer,
) reviewModel {
	pol := &mode.Policy{}
	m := reviewModel{
		ctx: context.Background(),
		deps: Deps{
			Reviewer:              reviewer,
			Policy:                pol,
			CurrentMode:           mode.ModeAdmin,
			SubmissionQueueSource: queueSource,
		},
		screen: screenSubmissionQueue,
	}
	return m
}

// drainSubmissionQueueLoad drives the Init Cmd returned by a submission-queue
// model, delivering the resulting queueSubmissionsLoadedMsg back to the model.
func drainSubmissionQueueLoad(m reviewModel) reviewModel {
	cmd := m.loadSubmissionQueue()
	if cmd == nil {
		return m
	}
	msg := cmd()
	updated, _ := m.Update(msg)
	rm, ok := updated.(reviewModel)
	if !ok {
		panic("Update returned unexpected type after submission queue load")
	}
	return rm
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestSubmissionQueue_ListViewNeverCallsReview asserts that loading the
// submission queue and navigating the list does NOT call Reviewer.Review.
// This is the AC-002-A no-plaintext keystone for the list path.
func TestSubmissionQueue_ListViewNeverCallsReview(t *testing.T) {
	t.Parallel()

	counter := &countingReviewer{}
	source := &fixedSubmissionSource{
		summaries: []rotate.OpenRequestSummary{
			buildSummary(1, "alice", "byreis: add DB_HOST", "byreis/add-DB_HOST-111"),
			buildSummary(2, "bob", "byreis: replace API_KEY", "byreis/replace-API_KEY-222"),
		},
	}
	m := buildSubmissionQueueModel(source, counter)
	m = drainSubmissionQueueLoad(m)

	if counter.calls != 0 {
		t.Errorf(
			"NO-PLAINTEXT VIOLATION: Review was called %d time(s) during queue list "+
				"loading; the list view must NEVER call Review",
			counter.calls)
	}

	// Navigate up and down — still no Review call.
	m = sendKey(m, "j") // down
	m = sendKey(m, "k") // up
	if counter.calls != 0 {
		t.Errorf(
			"NO-PLAINTEXT VIOLATION: Review was called %d time(s) during navigation; "+
				"the list view must NEVER call Review",
			counter.calls)
	}

	// Check the view renders without calling Review.
	_ = m.View()
	if counter.calls != 0 {
		t.Errorf(
			"NO-PLAINTEXT VIOLATION: Review was called %d time(s) during View(); "+
				"the list view must NEVER call Review",
			counter.calls)
	}
}

// TestSubmissionQueue_EnterNavigatesToReview asserts that pressing Enter on a
// highlighted item transitions to screenReviewing with the correct ref binding,
// without requiring manual ref entry.
func TestSubmissionQueue_EnterNavigatesToReview(t *testing.T) {
	t.Parallel()

	source := &fixedSubmissionSource{
		summaries: []rotate.OpenRequestSummary{
			buildSummary(10, "alice", "byreis: add KEY", "byreis/add-KEY-111"),
		},
	}
	counter := &countingReviewer{}
	m := buildSubmissionQueueModel(source, counter)
	m = drainSubmissionQueueLoad(m)

	if m.screen != screenSubmissionQueue {
		t.Fatalf("expected screenSubmissionQueue after load, got %d", m.screen)
	}
	if len(m.submissionSummaries) != 1 {
		t.Fatalf("expected 1 submission summary, got %d", len(m.submissionSummaries))
	}

	// Press Enter — must transition to screenReviewing.
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(reviewModel)

	if m.screen != screenReviewing {
		t.Errorf("expected screenReviewing after Enter on submission queue item, got %d", m.screen)
	}
	// The ref binding must be pre-populated so no manual entry is needed.
	if m.refBinding == "" {
		t.Error("refBinding must be set after Enter on submission queue item (no manual ref entry)")
	}
	// There must be a cmd to drive the Review call.
	if cmd == nil {
		t.Error("cmd must be non-nil after transitioning to screenReviewing from the queue")
	}
}

// TestSubmissionQueue_EmptyQueue_NonErrorState verifies that an empty
// submission queue renders "No pending submissions" and does NOT transition
// to screenError (AC-002-D).
func TestSubmissionQueue_EmptyQueue_NonErrorState(t *testing.T) {
	t.Parallel()

	source := &fixedSubmissionSource{summaries: nil}
	m := buildSubmissionQueueModel(source, nil)
	m = drainSubmissionQueueLoad(m)

	if m.screen == screenError {
		t.Error("empty submission queue must NOT transition to screenError (it is a non-error state)")
	}
	if m.screen != screenSubmissionQueue {
		t.Errorf("expected screenSubmissionQueue for empty result, got %d", m.screen)
	}
	if m.submissionQueueErr != nil {
		t.Errorf("submissionQueueErr must be nil for empty result, got %v", m.submissionQueueErr)
	}

	view := m.View()
	if !strings.Contains(view, "No pending submissions") {
		t.Errorf("view must contain 'No pending submissions' for empty queue; got:\n%s", view)
	}
}

// TestSubmissionQueue_LoadError_DoctorHint verifies that when
// ListSubmissionsBounded returns an error the queue-error state is shown with a
// 'byreis doctor' hint (AC-002-I).
func TestSubmissionQueue_LoadError_DoctorHint(t *testing.T) {
	t.Parallel()

	source := &fixedSubmissionSource{
		err: errors.New("registry unreachable: connection refused"),
	}
	m := buildSubmissionQueueModel(source, nil)
	m = drainSubmissionQueueLoad(m)

	if m.submissionQueueErr == nil {
		t.Fatal("submissionQueueErr must be non-nil when the source returns an error")
	}
	if m.screen == screenError {
		t.Error("a queue-load error must not transition to screenError " +
			"(it should show an inline error in the submission-queue screen)")
	}

	view := m.View()
	if !strings.Contains(view, "byreis doctor") {
		t.Errorf("view must contain 'byreis doctor' hint on load error; got:\n%s", view)
	}
}

// TestSubmissionQueue_TruncationSignalRendered verifies that when
// ListSubmissionsBounded returns truncated=true the view renders a visible
// truncation affordance (AC-002-F).
func TestSubmissionQueue_TruncationSignalRendered(t *testing.T) {
	t.Parallel()

	var summaries []rotate.OpenRequestSummary
	for i := 0; i < 5; i++ {
		summaries = append(summaries, buildSummary(i+1, "alice",
			fmt.Sprintf("byreis: add KEY%d", i+1),
			fmt.Sprintf("byreis/add-KEY%d-111", i+1)))
	}
	source := &fixedSubmissionSource{summaries: summaries, truncated: true}
	m := buildSubmissionQueueModel(source, nil)
	m = drainSubmissionQueueLoad(m)

	if !m.submissionTruncated {
		t.Error("submissionTruncated must be true when source returns truncated=true")
	}
	view := m.View()
	// The truncation affordance must appear as a visible signal.
	if !strings.Contains(view, "more") && !strings.Contains(view, "Showing") &&
		!strings.Contains(view, "truncated") {
		t.Errorf("view must contain a truncation signal when truncated=true; got:\n%s", view)
	}
}

// TestSubmissionQueue_ReviewError_ReturnToQueue verifies that when the Review
// call returns an error for a queue-selected item, the model transitions to
// screenError and pressing 'r' returns to the submission queue (AC-002-E).
func TestSubmissionQueue_ReviewError_ReturnToQueue(t *testing.T) {
	t.Parallel()

	reviewer := &countingReviewer{
		err: fmt.Errorf("PR #10 was merged or 404: %w",
			errors.New("not found")),
	}
	source := &fixedSubmissionSource{
		summaries: []rotate.OpenRequestSummary{
			buildSummary(10, "alice", "byreis: add KEY", "byreis/add-KEY-111"),
		},
	}
	m := buildSubmissionQueueModel(source, reviewer)
	m = drainSubmissionQueueLoad(m)

	// Press Enter to navigate to the detail.
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(reviewModel)

	// The model should now be in screenReviewing; drain the Review cmd.
	m = drainCmd(m, cmd)

	// Review returned an error → should be in screenError.
	if m.screen != screenError {
		t.Fatalf("expected screenError after Review failure from queue, got %d", m.screen)
	}
	if m.errMsg == "" {
		t.Error("errMsg must be non-empty after Review failure")
	}

	// Press 'r' — must return to the submission queue, not the access-request queue.
	m = sendKey(m, "r")
	if m.screen != screenSubmissionQueue {
		t.Errorf("expected screenSubmissionQueue after 'r' from screenError (entered from submission queue), got %d", m.screen)
	}
}

// TestSubmissionQueue_ArrowKeyNavigation verifies that ↑/↓ (k/j) updates
// the selectedIdx within bounds without panicking.
func TestSubmissionQueue_ArrowKeyNavigation(t *testing.T) {
	t.Parallel()

	source := &fixedSubmissionSource{
		summaries: []rotate.OpenRequestSummary{
			buildSummary(1, "a", "byreis: add K1", "byreis/add-K1-1"),
			buildSummary(2, "b", "byreis: add K2", "byreis/add-K2-2"),
			buildSummary(3, "c", "byreis: add K3", "byreis/add-K3-3"),
		},
	}
	m := buildSubmissionQueueModel(source, nil)
	m = drainSubmissionQueueLoad(m)

	// Initial index is 0.
	if m.submissionSelectedIdx != 0 {
		t.Errorf("initial submissionSelectedIdx = %d, want 0", m.submissionSelectedIdx)
	}

	// Move down twice.
	m = sendKey(m, "j")
	if m.submissionSelectedIdx != 1 {
		t.Errorf("after j: submissionSelectedIdx = %d, want 1", m.submissionSelectedIdx)
	}
	m = sendKey(m, "j")
	if m.submissionSelectedIdx != 2 {
		t.Errorf("after j: submissionSelectedIdx = %d, want 2", m.submissionSelectedIdx)
	}
	// Past the last element — must not go below len-1.
	m = sendKey(m, "j")
	if m.submissionSelectedIdx != 2 {
		t.Errorf("after j past end: submissionSelectedIdx = %d, want 2", m.submissionSelectedIdx)
	}

	// Move up.
	m = sendKey(m, "k")
	if m.submissionSelectedIdx != 1 {
		t.Errorf("after k: submissionSelectedIdx = %d, want 1", m.submissionSelectedIdx)
	}
	// Past the first element — must not go below 0.
	m = sendKey(m, "k")
	m = sendKey(m, "k")
	if m.submissionSelectedIdx != 0 {
		t.Errorf("after k past start: submissionSelectedIdx = %d, want 0", m.submissionSelectedIdx)
	}
}

// TestSubmissionQueue_NilQueueSource verifies that a nil SubmissionQueueSource
// results in a graceful queue-error state with a doctor hint (not a panic).
func TestSubmissionQueue_NilQueueSource(t *testing.T) {
	t.Parallel()

	m := buildSubmissionQueueModel(nil, nil)
	m = drainSubmissionQueueLoad(m)

	if m.submissionQueueErr == nil {
		t.Error("submissionQueueErr must be non-nil when SubmissionQueueSource is nil")
	}
	view := m.View()
	if !strings.Contains(view, "byreis doctor") {
		t.Errorf("view must contain 'byreis doctor' hint for nil source; got:\n%s", view)
	}
}

// TestSubmissionQueue_QuitFromQueue verifies that pressing 'q' from the
// submission queue transitions to screenDone without panicking.
func TestSubmissionQueue_QuitFromQueue(t *testing.T) {
	t.Parallel()

	source := &fixedSubmissionSource{
		summaries: []rotate.OpenRequestSummary{
			buildSummary(1, "alice", "byreis: add KEY", "byreis/add-KEY-111"),
		},
	}
	m := buildSubmissionQueueModel(source, nil)
	m = drainSubmissionQueueLoad(m)

	m = sendKey(m, "q")
	if m.screen != screenDone {
		t.Errorf("expected screenDone after 'q', got %d", m.screen)
	}
}

// TestSubmissionQueue_ToggleKey_SubmissionToAccessRequest verifies that pressing
// 'a' from screenSubmissionQueue transitions to screenQueue (access-request
// triage). This is the first direction of the bidirectional toggle required by
// the AUGMENT contract: both screens must be reachable from each other.
func TestSubmissionQueue_ToggleKey_SubmissionToAccessRequest(t *testing.T) {
	t.Parallel()

	source := &fixedSubmissionSource{
		summaries: []rotate.OpenRequestSummary{
			buildSummary(1, "alice", "byreis: add KEY", "byreis/add-KEY-111"),
		},
	}
	m := buildSubmissionQueueModel(source, nil)
	m = drainSubmissionQueueLoad(m)

	if m.screen != screenSubmissionQueue {
		t.Fatalf("expected screenSubmissionQueue after load, got %d", m.screen)
	}

	// Press 'a' — must transition to screenQueue (access-request triage).
	m = sendKey(m, "a")
	if m.screen != screenQueue {
		t.Errorf("expected screenQueue after pressing 'a' from screenSubmissionQueue, got %d", m.screen)
	}
}

// TestSubmissionQueue_ToggleKey_AccessRequestToSubmission verifies that pressing
// 's' from screenQueue transitions back to screenSubmissionQueue. This is the
// return direction of the bidirectional toggle required by the AUGMENT contract.
func TestSubmissionQueue_ToggleKey_AccessRequestToSubmission(t *testing.T) {
	t.Parallel()

	source := &fixedSubmissionSource{
		summaries: []rotate.OpenRequestSummary{
			buildSummary(1, "alice", "byreis: add KEY", "byreis/add-KEY-111"),
		},
	}
	m := buildSubmissionQueueModel(source, nil)
	m = drainSubmissionQueueLoad(m)

	// Navigate to screenQueue via 'a'.
	m = sendKey(m, "a")
	if m.screen != screenQueue {
		t.Fatalf("expected screenQueue after 'a', got %d", m.screen)
	}

	// Press 's' — must return to screenSubmissionQueue.
	m = sendKey(m, "s")
	if m.screen != screenSubmissionQueue {
		t.Errorf("expected screenSubmissionQueue after pressing 's' from screenQueue, got %d", m.screen)
	}
}

// TestSubmissionQueue_ToggleKey_BothDirections_HelpTextNamesRealKey verifies
// that the help text on each screen mentions the actual key used to reach the
// other screen. An affordance that names a non-existent key is a contract
// violation under the AUGMENT spec.
func TestSubmissionQueue_ToggleKey_BothDirections_HelpTextNamesRealKey(t *testing.T) {
	t.Parallel()

	source := &fixedSubmissionSource{
		summaries: []rotate.OpenRequestSummary{
			buildSummary(1, "alice", "byreis: add KEY", "byreis/add-KEY-111"),
		},
	}
	m := buildSubmissionQueueModel(source, nil)
	m = drainSubmissionQueueLoad(m)

	// Submission queue view must mention 'a' as the toggle key to reach
	// access-requests.
	subView := m.View()
	if !strings.Contains(subView, " a ") && !strings.Contains(subView, "• a ") &&
		!strings.Contains(subView, "Press a") && !strings.Contains(subView, "press a") {
		t.Errorf("submission queue help text must name the 'a' toggle key; got:\n%s", subView)
	}

	// Navigate to screenQueue and verify its help text names 's'.
	m = sendKey(m, "a")
	if m.screen != screenQueue {
		t.Fatalf("expected screenQueue after 'a', got %d", m.screen)
	}
	queueView := m.View()
	if !strings.Contains(queueView, " s ") && !strings.Contains(queueView, "• s ") &&
		!strings.Contains(queueView, "Press s") && !strings.Contains(queueView, "press s") {
		t.Errorf("access-request queue help text must name the 's' toggle key; got:\n%s", queueView)
	}
}

// TestSubmissionQueue_ToggleKey_LazyLoadsAccessQueue verifies that toggling to
// screenQueue from screenSubmissionQueue triggers a load of the access-request
// queue when it has not been loaded yet. The returned command must be non-nil.
func TestSubmissionQueue_ToggleKey_LazyLoadsAccessQueue(t *testing.T) {
	t.Parallel()

	source := &fixedSubmissionSource{}
	m := buildSubmissionQueueModel(source, nil)
	m = drainSubmissionQueueLoad(m)

	// summaries is nil at this point (empty source), queueErr is nil too:
	// the access-request queue has never been loaded. Pressing 'a' should
	// emit a loadQueue command.
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	rm := updated.(reviewModel)

	if rm.screen != screenQueue {
		t.Errorf("expected screenQueue after 'a', got %d", rm.screen)
	}
	if cmd == nil {
		t.Error("expected a non-nil cmd to load the access-request queue on first visit")
	}
}

// TestSubmissionQueue_ViewRendersColumns verifies that the queue view renders
// the expected column headers and submission data.
func TestSubmissionQueue_ViewRendersColumns(t *testing.T) {
	t.Parallel()

	source := &fixedSubmissionSource{
		summaries: []rotate.OpenRequestSummary{
			buildSummary(42, "alice", "byreis: add DB_HOST", "byreis/add-DB_HOST-111"),
		},
	}
	m := buildSubmissionQueueModel(source, nil)
	m = drainSubmissionQueueLoad(m)

	view := m.View()
	// The view must render the PR reference.
	if !strings.Contains(view, "#42") {
		t.Errorf("view must contain PR number '42'; got:\n%s", view)
	}
	// The view must sanitize and render the author login.
	if !strings.Contains(view, "alice") {
		t.Errorf("view must contain author 'alice'; got:\n%s", view)
	}
}
