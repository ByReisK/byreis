package tui

// REQ-V05-005 (b): the submission-queue AGE column previously read a real
// time.Now() at render time, making the rendered age non-deterministic and
// untestable. These tests pin the AGE rendering against an INJECTED clock
// (tui.Deps.Clock) so the column is deterministic, matching the codebase's
// injected-clock discipline (no real clock in unit tests).
//
// In package tui (not tui_test) so the unexported reviewModel and the
// viewSubmissionQueue renderer can be driven directly without a terminal,
// following submission_queue_test.go.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// fixedClock is a deterministic injected time source for the AGE column. It
// returns the same instant on every Now() call so the rendered age is stable.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// buildSubmissionQueueModelWithClock constructs a reviewModel already populated
// with the given submission summaries and the injected clock, parked on the
// submission-queue screen. No queue source / reviewer are needed because the
// summaries are set directly and only the view is exercised.
func buildSubmissionQueueModelWithClock(
	summaries []rotate.OpenRequestSummary, clock Clock,
) reviewModel {
	return reviewModel{
		ctx: context.Background(),
		deps: Deps{
			Policy:      &mode.Policy{},
			CurrentMode: mode.ModeAdmin,
			Clock:       clock,
		},
		screen:              screenSubmissionQueue,
		submissionSummaries: summaries,
	}
}

// TestSubmissionQueueAge_DeterministicAgainstInjectedClock pins the rendered
// AGE token for a known CreatedAt against a fixed injected "now". Without the
// injected clock this assertion could not be written (real time.Now() drifts).
func TestSubmissionQueueAge_DeterministicAgainstInjectedClock(t *testing.T) {
	t.Parallel()

	const created = "2026-01-15T00:00:00Z"
	base, err := time.Parse(time.RFC3339, created)
	if err != nil {
		t.Fatalf("parsing the fixture CreatedAt: %v", err)
	}

	tests := []struct {
		name    string
		now     time.Time
		wantAge string
	}{
		{
			name:    "minutes bucket",
			now:     base.Add(42 * time.Minute),
			wantAge: "42m",
		},
		{
			name:    "hours bucket",
			now:     base.Add(5 * time.Hour),
			wantAge: "5h",
		},
		{
			name:    "days bucket",
			now:     base.Add(72 * time.Hour),
			wantAge: "3d",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			summaries := []rotate.OpenRequestSummary{
				buildSummary(7, "alice", "byreis: add DB_HOST", "byreis/add-DB_HOST-7"),
			}
			summaries[0].CreatedAt = created

			m := buildSubmissionQueueModelWithClock(summaries, fixedClock{t: tc.now})
			view := m.viewSubmissionQueue()

			// The AGE column is the last whitespace-padded field of the row; the
			// bucket token (e.g. "42m") must appear verbatim in the rendered view.
			if !strings.Contains(view, tc.wantAge) {
				t.Errorf("AGE column: want token %q in rendered view, not found.\nview:\n%s",
					tc.wantAge, view)
			}
		})
	}
}

// TestFormatPRAge_PureFunctionDeterminism documents that formatPRAge is a pure
// function of (createdAt, now): the model's clock only supplies the now. This
// is the unit the injected clock feeds, and it must bucket correctly and fail
// soft (empty string) on an unparseable timestamp.
func TestFormatPRAge_PureFunctionDeterminism(t *testing.T) {
	t.Parallel()

	const created = "2026-01-15T00:00:00Z"
	base, err := time.Parse(time.RFC3339, created)
	if err != nil {
		t.Fatalf("parsing the fixture CreatedAt: %v", err)
	}

	tests := []struct {
		name      string
		createdAt string
		now       time.Time
		want      string
	}{
		{name: "sub-hour to minutes", createdAt: created, now: base.Add(30 * time.Minute), want: "30m"},
		{name: "exactly one hour rolls to hours", createdAt: created, now: base.Add(time.Hour), want: "1h"},
		{name: "just under a day", createdAt: created, now: base.Add(23 * time.Hour), want: "23h"},
		{name: "exactly one day rolls to days", createdAt: created, now: base.Add(24 * time.Hour), want: "1d"},
		{name: "unparseable timestamp fails soft", createdAt: "not-a-time", now: base, want: ""},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := formatPRAge(tc.createdAt, tc.now); got != tc.want {
				t.Errorf("formatPRAge(%q, now=%s) = %q, want %q",
					tc.createdAt, tc.now.Format(time.RFC3339), got, tc.want)
			}
		})
	}
}
