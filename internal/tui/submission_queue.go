package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ─── screen constants ─────────────────────────────────────────────────────────

const (
	// screenSubmissionQueue is the separate submission-PR triage queue added by
	// the v0.4 queue feature. It lists open submission PRs from the project repo
	// (byreis/add-*, byreis/replace-*, byreis/bulk-*) and lets the admin navigate
	// to the existing no-plaintext detail/approve flow by pressing Enter.
	//
	// This screen AUGMENTS the existing v0.3 access-request queue (screenQueue) —
	// it does not replace it. The two screens are distinct and independently
	// navigable from the same review TUI session.
	screenSubmissionQueue reviewScreen = iota + 100
)

// ─── port ─────────────────────────────────────────────────────────────────────

// SubmissionQueueSource is the narrow read-only port the submission queue screen
// depends on. It is satisfied by the project-repo adapter's
// ProjectSubmissionsReader, injected at the composition root. The TUI never
// constructs a GitHub client; all network access flows through this interface.
//
// The interface is defined here in the tui package (consumer-defined, per the
// Clean Architecture dependency rule) and implemented by the adapter layer. No
// core package import is needed: the return type rotate.OpenRequestSummary is
// already a shared DTO that the review and access-request screens also use.
type SubmissionQueueSource interface {
	ListSubmissionsBounded(ctx context.Context) ([]rotate.OpenRequestSummary, bool, error)
}

// ─── messages ────────────────────────────────────────────────────────────────

// queueSubmissionsLoadedMsg is delivered when ListSubmissionsBounded completes.
// It carries the submission summaries, the truncated signal, and any load error.
// The naming mirrors queueLoadedMsg (access-request queue) to keep the message
// type vocabulary parallel.
type queueSubmissionsLoadedMsg struct {
	summaries []rotate.OpenRequestSummary
	truncated bool
	err       error
}

// ─── model fields (added to reviewModel) ─────────────────────────────────────
//
// The fields below extend reviewModel with submission-queue state. They are
// intentionally separate from the access-request queue fields (summaries,
// truncated, queueErr, selectedIdx) so the two screens do not share mutable
// state and the v0.3 behavior is fully preserved.
//
// The fields are documented inline in the reviewModel struct in review.go;
// the zero values are valid initial states for both screens.

// ─── Deps extension ───────────────────────────────────────────────────────────

// The SubmissionQueueSource field is added to Deps in tui.go (Deps struct). It
// is nil when the composition root cannot construct the project-repo reader
// (e.g. contributor mode, or BYREIS_PROJECT_REPO not set). A nil source causes
// the submission-queue screen to show an inline error with a 'byreis doctor'
// hint, not a panic.

// ─── Cmd builders ────────────────────────────────────────────────────────────

// loadSubmissionQueue fetches the open submission PR list via
// SubmissionQueueSource.ListSubmissionsBounded. A nil source is handled
// gracefully: it returns a fixed error message instead of panicking.
func (m reviewModel) loadSubmissionQueue() tea.Cmd {
	ctx := m.ctx
	deps := m.deps
	return func() tea.Msg {
		if deps.SubmissionQueueSource == nil {
			return queueSubmissionsLoadedMsg{err: fmt.Errorf(
				"submission queue not configured — " +
					"check BYREIS_PROJECT_REPO and BYREIS_GITHUB_TOKEN; run `byreis doctor` for diagnostics")}
		}
		summaries, truncated, err := deps.SubmissionQueueSource.ListSubmissionsBounded(ctx)
		return queueSubmissionsLoadedMsg{summaries: summaries, truncated: truncated, err: err}
	}
}

// ─── state machine ───────────────────────────────────────────────────────────

// updateSubmissionQueue handles messages while the submission-queue screen is
// active. It mirrors updateQueue in shape but manages the separate submission
// state fields and routes Enter to the existing detail review flow rather than
// the access-request triage path.
func (m reviewModel) updateSubmissionQueue(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case queueSubmissionsLoadedMsg:
		if msg.err != nil {
			m.submissionQueueErr = msg.err
		} else {
			m.submissionSummaries = msg.summaries
			m.submissionTruncated = msg.truncated
			m.submissionQueueErr = nil
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.screen = screenDone
			return m, tea.Quit

		case "up", "k":
			if m.submissionSelectedIdx > 0 {
				m.submissionSelectedIdx--
			}
			return m, nil

		case "down", "j":
			if m.submissionSelectedIdx < len(m.submissionSummaries)-1 {
				m.submissionSelectedIdx++
			}
			return m, nil

		case "a":
			// 'a' switches to the access-request triage screen (screenQueue).
			// Trigger a load if the queue has not been loaded yet (summaries is
			// nil, meaning the screen has never been visited this session).
			m.screen = screenQueue
			if m.summaries == nil && m.queueErr == nil {
				return m, m.loadQueue()
			}
			return m, nil

		case "enter":
			// Enter on a submission queue row jumps directly to the detail/review
			// flow. No manual ref entry is required — the ref is derived from the
			// highlighted queue row and the model transitions to screenReviewing.
			if len(m.submissionSummaries) == 0 {
				return m, nil
			}
			idx := m.submissionSelectedIdx
			if idx < 0 || idx >= len(m.submissionSummaries) {
				return m, nil
			}
			s := m.submissionSummaries[idx]
			ref := fmt.Sprintf("%s#%d", s.PRRef.Project, s.PRRef.Number)
			m.refBinding = ref
			m.screen = screenReviewing
			// The 'r' key from screenError will return to screenSubmissionQueue
			// because m.enteredFromSubmissionQueue is true.
			m.enteredFromSubmissionQueue = true
			return m, m.doReview(ref)
		}
	}
	return m, nil
}

// ─── view ─────────────────────────────────────────────────────────────────────

// viewSubmissionQueue renders the submission-PR triage queue screen.
// All contributor-authored fields (Title, AuthorLogin) pass through
// render.SanitizeForTerminal before display.
func (m reviewModel) viewSubmissionQueue() string {
	var sb strings.Builder

	sb.WriteString(reviewHeaderStyle())
	sb.WriteString("\n")

	label := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("6")).
		Render("SUBMISSION QUEUE  (pending secret submissions)")
	sb.WriteString(label)
	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
		Render("Submission PRs from contributors. Enter to review.  " +
			"Press a to switch to the access-request triage screen."))
	sb.WriteString("\n\n")

	if m.submissionQueueErr != nil {
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("1")).
			Render("Could not load submissions: " + sanitizeErr(m.submissionQueueErr)))
		sb.WriteString("\n")
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
			Render("Run `byreis doctor` to diagnose connectivity and configuration issues."))
		sb.WriteString("\n\n")
	} else if len(m.submissionSummaries) == 0 {
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
			Render("No pending submissions."))
		sb.WriteString("\n\n")
	} else {
		// Column header.
		_, _ = fmt.Fprintf(&sb, "%-40s  %-30s  %-12s  %-20s  %-12s\n",
			"PR", "TITLE (KEY/ACTION)", "AUTHOR", "CREATED", "AGE")
		sb.WriteString(strings.Repeat("-", 118))
		sb.WriteString("\n")

		now := time.Now()
		for i, s := range m.submissionSummaries {
			prStr := fmt.Sprintf("%s#%d", s.PRRef.Project, s.PRRef.Number)
			// Key/action columns are derived from the PR title by convention. The
			// title is contributor-authored and must be sanitized before rendering.
			titleCol := render.SanitizeForTerminal(s.Title)
			if runeLen := len([]rune(titleCol)); runeLen > 30 {
				titleCol = string([]rune(titleCol)[:27]) + "..."
			}
			author := render.SanitizeForTerminal(s.AuthorLogin)
			created := render.SanitizeForTerminal(s.CreatedAt)
			ageStr := formatPRAge(s.CreatedAt, now)

			row := fmt.Sprintf("%-40s  %-30s  %-12s  %-20s  %-12s",
				prStr, titleCol, author, created[:min(len(created), 10)], ageStr)
			if i == m.submissionSelectedIdx {
				row = lipgloss.NewStyle().
					Bold(true).
					Foreground(lipgloss.Color("6")).
					Render("> " + row)
			} else {
				row = "  " + row
			}
			sb.WriteString(row)
			sb.WriteString("\n")
		}

		if m.submissionTruncated {
			sb.WriteString("\n")
			sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("3")).
				Render(fmt.Sprintf(
					"Showing %d of many — more pending submissions exist beyond this list.",
					len(m.submissionSummaries))))
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
		Render("↑/↓ navigate  •  Enter review selected  •  a access-requests  •  q / Esc quit"))
	sb.WriteString("\n")

	return sb.String()
}

// formatPRAge returns a human-readable age string for a PR given its RFC3339
// CreatedAt timestamp and the current time. On parse failure it returns an
// empty string rather than an error (display field, non-critical).
func formatPRAge(createdAt string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return ""
	}
	d := now.Sub(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
