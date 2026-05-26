package tui

import (
	"context"
	"fmt"
	"io"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// reviewScreen tracks which screen of the review TUI is active.
type reviewScreen int

const (
	// screenQueue is the triage queue showing open access-request PRs.
	// It is the initial screen; selecting an entry surfaces the PR ref and
	// a hint about the next step (rotate --from-request / rotate --add --from-request).
	// It does NOT enter the submission detail flow.
	screenQueue reviewScreen = iota

	// screenRefEntry is the ref-input screen. The admin types a PR ref in
	// project#number form; submitting it triggers a Review call.
	screenRefEntry

	// screenReviewing is the transient state while Review is executing.
	screenReviewing

	// screenDetail is the read-only detail view rendered after a successful Review.
	screenDetail

	// screenError is shown after a Review failure. The admin can press Esc/q to
	// return to the queue.
	screenError

	// screenDone is the terminal state reached after the admin quits from any screen.
	screenDone

	// screenConfirmApprove is the explicit opt-in confirm step shown before the
	// irreversible merge. The detail screen stays read-only by default; the admin
	// must press 'a' to enter this screen, then confirm or abort.
	screenConfirmApprove

	// screenApproving is the transient state while Merger.Merge is executing.
	screenApproving

	// screenApproveError is shown when the Merge call returns an error (including
	// the already-merged/closed race case). The admin can press Esc/q to return
	// to the queue or 'r' to review another submission.
	screenApproveError

	// screenApproveSuccess is the terminal acknowledgment shown after a
	// successful Merge. The admin presses q/Esc to quit.
	screenApproveSuccess
)

// reviewDetail is the no-plaintext projection of a ReviewResult. It carries
// ONLY the fields needed for display and for the in-TUI approve action: ref,
// author, justification, secrets path, per-key review lines, sorted key names,
// the pinned SHA, and the artifact-embedded logical project ID and file name
// (needed to construct the MergeInput without introducing new core symbols).
//
// The enforcement mechanism is structural absence: reviewDetail has no
// Plaintext field, so the Review call site cannot copy a decrypted value into
// it by accident. ReviewResult.Plaintext (the decrypted values) is never read
// or stored here. The closure-local ReviewResult is GC-reclaimed after doReview
// returns. A TUI-side zeroize is neither possible nor meaningful for Go
// immutable strings; the only effective scrub site is the crypto/identity
// layer. The no_plaintext_guard AST test mechanically enforces that no TUI
// view ever references .Plaintext.
type reviewDetail struct {
	Ref           git.PRRef
	Author        string
	Justification string
	SecretsPath   string
	PerKey        []usecase.KeyReviewLine
	KeyNames      []string
	PinnedSHA     string
	// ProjectID and FileName are the artifact-embedded logical identifiers
	// required to construct MergeInput.ExpectedProjectID and
	// MergeInput.ExpectedFileName for the in-TUI approve action. They are
	// not secret: they are the same values the admin would pass to
	// `byreis admin merge --project <ProjectID> --file <FileName>`.
	ProjectID string
	FileName  string
}

// reviewDetailMsg is the bubbletea message delivered when a Review call completes
// successfully. It carries only the extracted reviewDetail, never a ReviewResult
// or any map[string]string of decrypted values.
type reviewDetailMsg struct {
	detail reviewDetail
}

// reviewErrMsg is delivered when a Review call fails.
type reviewErrMsg struct {
	err error
}

// queueLoadedMsg is delivered when ListOpenRequestsBounded completes.
type queueLoadedMsg struct {
	summaries []rotate.OpenRequestSummary
	truncated bool
	err       error
}

// mergeApproveMsg is delivered when the Merger.Merge call completes
// successfully. It carries the live file SHA for the acknowledgment view.
type mergeApproveMsg struct {
	liveFileSHA string
	reEncrypted bool
	counter     uint64
}

// mergeErrMsg is delivered when the Merger.Merge call returns an error.
// The error message is pre-sanitized and carries an actionable hint.
type mergeErrMsg struct {
	err error
}

// reviewModel is the bubbletea model for the admin review TUI. It manages the
// access-request triage queue (v0.3, preserved), the submission-PR queue (v0.4
// augmentation), and the submission detail flow connected by the ref-entry form.
//
// Design constraints:
//   - reviewDetail has NO Plaintext field. The review call site copies only
//     display-safe fields out of ReviewResult; it never reads or stores
//     ReviewResult.Plaintext (the decrypted values). The closure-local result
//     is GC-reclaimed after return. The no_plaintext_guard AST test enforces
//     that no TUI view ever references .Plaintext.
//   - All contributor-authored strings are sanitized via render.SanitizeForTerminal
//     before rendering. Justification is additionally collapsed via collapseLineBreaks.
//   - The mode gate is enforced in RunReview before constructing this model.
//   - The access-request queue (screenQueue) and the submission queue
//     (screenSubmissionQueue) are SEPARATE screens with separate state. The v0.3
//     access-request behavior is fully preserved; the v0.4 submission queue
//     augments it on a distinct screen.
type reviewModel struct {
	ctx  context.Context
	deps Deps

	screen reviewScreen

	// Access-request queue state (screenQueue — v0.3 preserved).
	summaries []rotate.OpenRequestSummary
	truncated bool
	queueErr  error
	// selectedIdx is the index of the currently highlighted access-request row.
	selectedIdx int
	// selectedRef is the PRRef of the highlighted access-request entry (display only).
	selectedRef string

	// Submission-queue state (screenSubmissionQueue — v0.4 augmentation).
	// These fields are entirely separate from the access-request queue fields so
	// the two screens do not share mutable state.
	submissionSummaries   []rotate.OpenRequestSummary
	submissionTruncated   bool
	submissionQueueErr    error
	submissionSelectedIdx int
	// enteredFromSubmissionQueue records that the current review/detail/error
	// flow was initiated from the submission queue. When true, the 'r' shortcut
	// returns to screenSubmissionQueue instead of opening the ref-entry form.
	enteredFromSubmissionQueue bool

	// Ref-entry form for the detail screen.
	refForm    *huh.Form
	refBinding string // bound by huh

	// Detail state populated after a successful Review.
	detail   reviewDetail
	detailOK bool

	// Error message from a failed Review or queue fetch.
	errMsg string

	// approveResult carries the merge acknowledgment data after a successful
	// Merger.Merge call (screenApproveSuccess state).
	approveResult mergeApproveMsg
	// approveErrMsg carries the sanitized error string from a failed merge
	// (screenApproveError state).
	approveErrMsg string
}

// newReviewModel constructs the review model. prRef, when non-empty, causes the
// model to skip both queues entirely and jump directly to reviewing the named
// submission. For the typical TUI launch (bare `review` at a TTY without --pr),
// prRef is empty.
//
// Screen selection when prRef is empty:
//   - If a SubmissionQueueSource is configured in deps, start on the submission
//     queue (screenSubmissionQueue) — the v0.4 headline screen.
//   - Otherwise fall back to the access-request triage queue (screenQueue) to
//     preserve the v0.3 behavior for unconfigured submission sources.
func newReviewModel(ctx context.Context, deps Deps, prRef string) reviewModel {
	m := reviewModel{
		ctx:  ctx,
		deps: deps,
	}
	if prRef != "" {
		m.refBinding = prRef
		m.screen = screenReviewing
	} else if deps.SubmissionQueueSource != nil {
		m.screen = screenSubmissionQueue
	} else {
		m.screen = screenQueue
	}
	return m
}

// Init starts the appropriate initial command based on the opening screen.
// For screenSubmissionQueue it loads the submission list; for screenQueue it
// loads the access-request list; for screenReviewing it starts the Review call.
func (m reviewModel) Init() tea.Cmd {
	switch m.screen {
	case screenSubmissionQueue:
		return m.loadSubmissionQueue()
	case screenQueue:
		return m.loadQueue()
	case screenReviewing:
		return m.doReview(m.refBinding)
	default:
		return nil
	}
}

// loadQueue fetches the open access-request PR list via ListOpenRequestsBounded.
func (m reviewModel) loadQueue() tea.Cmd {
	ctx := m.ctx
	deps := m.deps
	return func() tea.Msg {
		if deps.RequestAccessReader == nil {
			return queueLoadedMsg{err: fmt.Errorf(
				"access-request reader not configured — " +
					"check BYREIS_GITHUB_TOKEN and BYREIS_REGISTRY; run `byreis doctor` for diagnostics")}
		}
		summaries, truncated, err := deps.RequestAccessReader.ListOpenRequestsBounded(ctx)
		return queueLoadedMsg{summaries: summaries, truncated: truncated, err: err}
	}
}

// doReview calls Reviewer.Review with the given PR ref and extracts the
// display-safe fields into a reviewDetail. It never reads or stores
// ReviewResult.Plaintext (the decrypted values); the closure-local result is
// GC-reclaimed after return. No decrypted value ever leaves this closure.
func (m reviewModel) doReview(prRef string) tea.Cmd {
	ctx := m.ctx
	deps := m.deps
	return func() tea.Msg {
		if deps.Reviewer == nil {
			return reviewErrMsg{err: fmt.Errorf(
				"review adapters not configured — " +
					"run `byreis init` or check your BYREIS_* environment variables")}
		}

		ref, parseErr := parseReviewRef(prRef)
		if parseErr != nil {
			return reviewErrMsg{err: parseErr}
		}

		res, err := deps.Reviewer.Review(ctx, usecase.ReviewInput{
			Ref: ref,
		})
		// reviewDetail has no Plaintext field: structural absence is the primary
		// and sufficient enforcement. No decrypted value is ever copied into the
		// detail struct or the bubbletea message. The ReviewResult local (res)
		// exits scope when this closure returns; the GC reclaims it.
		// The AST guard mechanically enforces that no .Plaintext selector
		// appears anywhere in the TUI source.

		if err != nil {
			return reviewErrMsg{err: fmt.Errorf(
				"reviewing %s: %w — "+
					"check your admin key and registry reachability; run `byreis doctor` for diagnostics",
				prRef, err)}
		}

		// Extract ONLY the display-safe fields. Plaintext is deliberately absent.
		// ProjectID and FileName come from the artifact-embedded Byreis header
		// (res.ProjectID / res.FileName); they are needed to construct MergeInput
		// for the in-TUI approve action without new core symbols.
		detail := reviewDetail{
			Ref:           res.Ref,
			Author:        res.Author,
			Justification: res.Justification,
			SecretsPath:   res.SecretsPath,
			PerKey:        res.PerKey,
			KeyNames:      res.KeyNames,
			PinnedSHA:     res.PinnedSHA,
			ProjectID:     res.ProjectID,
			FileName:      res.FileName,
		}
		return reviewDetailMsg{detail: detail}
	}
}

// parseReviewRef parses a "project#number" string into a git.PRRef for use in
// the review TUI. It applies the same structural validation as the CLI-layer
// parsePRRef (length cap, control-character rejection, hash-separator check)
// but is a standalone helper in the tui package so no import of cli is needed.
func parseReviewRef(prRef string) (git.PRRef, error) {
	if prRef == "" {
		return git.PRRef{}, fmt.Errorf(
			"PR ref is required — enter it in the form project#number (e.g. myorg/my-app-secrets#42)")
	}
	if len(prRef) > 200 {
		return git.PRRef{}, fmt.Errorf(
			"PR ref is too long (max 200 characters) — " +
				"use the form project#number (e.g. myorg/my-app-secrets#42)")
	}
	for _, b := range []byte(prRef) {
		if b < 0x20 || b == 0x7F {
			return git.PRRef{}, fmt.Errorf(
				"PR ref contains a control character — " +
					"use plain printable ASCII: project#number")
		}
	}
	hashIdx := strings.LastIndex(prRef, "#")
	if hashIdx <= 0 {
		return git.PRRef{}, fmt.Errorf(
			"PR ref %q is missing the '#N' PR number suffix — "+
				"use the form project#number (e.g. myorg/my-app-secrets#42)",
			prRef)
	}
	project := prRef[:hashIdx]
	numStr := prRef[hashIdx+1:]

	if len(numStr) == 0 || len(numStr) > 10 {
		return git.PRRef{}, fmt.Errorf(
			"PR ref %q has an invalid number segment — "+
				"use the form project#number (e.g. myorg/my-app-secrets#42)",
			prRef)
	}
	var num int
	for _, c := range numStr {
		if c < '0' || c > '9' {
			return git.PRRef{}, fmt.Errorf(
				"PR ref %q has a non-numeric number segment — "+
					"use the form project#number (e.g. myorg/my-app-secrets#42)",
				prRef)
		}
		num = num*10 + int(c-'0')
	}
	if num <= 0 {
		return git.PRRef{}, fmt.Errorf(
			"PR ref %q has a zero or negative PR number — "+
				"PR numbers must be positive integers",
			prRef)
	}
	return git.PRRef{Project: project, Number: num}, nil
}

// Update drives the reviewModel state machine.
func (m reviewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.screen {

	case screenSubmissionQueue:
		return m.updateSubmissionQueue(msg)

	case screenQueue:
		return m.updateQueue(msg)

	case screenRefEntry:
		return m.updateRefEntry(msg)

	case screenReviewing:
		switch msg := msg.(type) {
		case reviewDetailMsg:
			m.detail = msg.detail
			m.detailOK = true
			m.screen = screenDetail
			return m, nil
		case reviewErrMsg:
			m.errMsg = sanitizeErr(msg.err)
			m.screen = screenError
			return m, nil
		}
		return m, nil

	case screenDetail:
		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "q", "esc", "ctrl+c":
				m.screen = screenDone
				return m, tea.Quit
			case "r":
				m.detail = reviewDetail{}
				m.detailOK = false
				m.errMsg = ""
				m.refBinding = ""
				m.refForm = buildRefForm(&m.refBinding)
				m.screen = screenRefEntry
				return m, m.refForm.Init()
			case "a":
				// 'a' enters the confirm-before-approve screen. The detail view
				// is read-only by default; approve is an explicit opt-in that
				// triggers a confirm step before the irreversible merge.
				// Merger nil check: approve is unreachable if no Merger is wired.
				if m.deps.Merger == nil {
					m.approveErrMsg = "approve not available: merge adapters not configured — " +
						"run `byreis doctor` to verify your admin mode and registry-write credential"
					m.screen = screenApproveError
					return m, nil
				}
				m.screen = screenConfirmApprove
				return m, nil
			}
		}
		return m, nil

	case screenError:
		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "q", "esc", "ctrl+c":
				m.screen = screenDone
				return m, tea.Quit
			case "r":
				m.detail = reviewDetail{}
				m.detailOK = false
				m.errMsg = ""
				m.refBinding = ""
				// Return to the submission queue when the error was triggered from
				// there; otherwise fall back to the ref-entry form.
				if m.enteredFromSubmissionQueue {
					m.enteredFromSubmissionQueue = false
					m.screen = screenSubmissionQueue
					return m, m.loadSubmissionQueue()
				}
				m.refForm = buildRefForm(&m.refBinding)
				m.screen = screenRefEntry
				return m, m.refForm.Init()
			}
		}
		return m, nil

	case screenConfirmApprove:
		return m.updateConfirmApprove(msg)

	case screenApproving:
		switch msg := msg.(type) {
		case mergeApproveMsg:
			m.approveResult = msg
			m.screen = screenApproveSuccess
			return m, nil
		case mergeErrMsg:
			m.approveErrMsg = sanitizeErr(msg.err)
			m.screen = screenApproveError
			return m, nil
		}
		return m, nil

	case screenApproveError, screenApproveSuccess:
		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "q", "esc", "ctrl+c":
				m.screen = screenDone
				return m, tea.Quit
			case "r":
				m.detail = reviewDetail{}
				m.detailOK = false
				m.errMsg = ""
				m.approveErrMsg = ""
				m.refBinding = ""
				m.refForm = buildRefForm(&m.refBinding)
				m.screen = screenRefEntry
				return m, m.refForm.Init()
			}
		}
		return m, nil

	case screenDone:
		return m, tea.Quit
	}

	return m, nil
}

// updateQueue handles messages while the queue screen is active.
func (m reviewModel) updateQueue(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case queueLoadedMsg:
		if msg.err != nil {
			m.queueErr = msg.err
		} else {
			m.summaries = msg.summaries
			m.truncated = msg.truncated
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.screen = screenDone
			return m, tea.Quit

		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
			m.updateSelectedRef()
			return m, nil

		case "down", "j":
			if m.selectedIdx < len(m.summaries)-1 {
				m.selectedIdx++
			}
			m.updateSelectedRef()
			return m, nil

		case "r":
			// 'r' from queue: open the ref-entry screen to review a submission.
			m.refBinding = ""
			m.refForm = buildRefForm(&m.refBinding)
			m.screen = screenRefEntry
			return m, m.refForm.Init()

		case "s":
			// 's' switches to the submission queue screen. Trigger a load if the
			// submission summaries have not been loaded yet this session.
			m.screen = screenSubmissionQueue
			if m.submissionSummaries == nil && m.submissionQueueErr == nil {
				return m, m.loadSubmissionQueue()
			}
			return m, nil

		case "enter":
			// Enter on a queue row surfaces the ref and a next-step hint.
			// It does NOT auto-enter Review (the queue lists access-requests, not submissions).
			m.updateSelectedRef()
			return m, nil
		}
	}
	return m, nil
}

// updateSelectedRef sets selectedRef to the PRRef string of the currently
// highlighted queue entry, or "" when the queue is empty.
func (m *reviewModel) updateSelectedRef() {
	if len(m.summaries) == 0 || m.selectedIdx < 0 || m.selectedIdx >= len(m.summaries) {
		m.selectedRef = ""
		return
	}
	s := m.summaries[m.selectedIdx]
	m.selectedRef = fmt.Sprintf("%s#%d", s.PRRef.Project, s.PRRef.Number)
}

// updateRefEntry handles messages while the ref-entry form is active.
func (m reviewModel) updateRefEntry(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.refForm == nil {
		return m, nil
	}
	form, cmd := m.refForm.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		m.refForm = f
	}
	if m.refForm.State == huh.StateAborted {
		// Return to queue on Esc/Ctrl-C.
		m.refBinding = ""
		m.screen = screenQueue
		return m, m.loadQueue()
	}
	if m.refForm.State == huh.StateCompleted {
		ref := strings.TrimSpace(m.refBinding)
		m.screen = screenReviewing
		return m, m.doReview(ref)
	}
	return m, cmd
}

// updateConfirmApprove handles key events on the confirm-before-approve screen.
// 'y' / Enter confirms and dispatches the merge; any other key aborts back to
// the detail screen (the detail is read-only by default; the abort path must
// leave the queue consistent and not call Merger.Merge).
func (m reviewModel) updateConfirmApprove(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "y", "enter":
		m.screen = screenApproving
		return m, m.doApprove()
	default:
		// Any other key (including Esc/q) aborts back to detail without calling Merge.
		m.screen = screenDetail
		return m, nil
	}
}

// doApprove dispatches a Merger.Merge call using the MergeInput constructed
// from the reviewed detail. Field-for-field equivalence with the admin_cmds.go
// merge path:
//
//   - MergeInput.Ref               ← detail.Ref
//   - MergeInput.ExpectSHA         ← detail.PinnedSHA  (the replay-protection pin)
//   - MergeInput.ExpectedProjectID ← detail.ProjectID
//   - MergeInput.ExpectedFileName  ← detail.FileName
//   - MergeInput.CommitMessage     ← derived (same default as CLI merge path)
//
// The PinnedSHA is the load-bearing replay-protection keystone:
// if the PR branch is re-pushed between review and approve, the Merge use-case
// compares the on-PR artifact SHA against ExpectSHA and fails closed, preventing
// the admin from approving a different artifact than the one reviewed.
//
// doApprove never decrypts or displays values; it merges the reviewed PR.
// The no_plaintext_guard AST test confirms no .Plaintext selector appears here.
func (m reviewModel) doApprove() tea.Cmd {
	ctx := m.ctx
	deps := m.deps
	detail := m.detail
	return func() tea.Msg {
		commitMsg := fmt.Sprintf("byreis: merge submission %s#%d",
			detail.Ref.Project, detail.Ref.Number)
		res, err := deps.Merger.Merge(ctx, usecase.MergeInput{
			Ref:               detail.Ref,
			ExpectSHA:         detail.PinnedSHA,
			ExpectedProjectID: detail.ProjectID,
			ExpectedFileName:  detail.FileName,
			CommitMessage:     commitMsg,
		})
		if err != nil {
			return mergeErrMsg{err: fmt.Errorf(
				"merging %s#%d: %w — "+
					"check your admin key and registry-write credential; "+
					"run `byreis doctor` for diagnostics",
				detail.Ref.Project, detail.Ref.Number, err)}
		}
		return mergeApproveMsg{
			liveFileSHA: res.LiveFileSHA,
			reEncrypted: res.ReEncrypted,
			counter:     res.FinalCounter,
		}
	}
}

// View renders the current review model state.
func (m reviewModel) View() string {
	switch m.screen {
	case screenSubmissionQueue:
		return m.viewSubmissionQueue()
	case screenQueue:
		return m.viewQueue()
	case screenRefEntry:
		return m.viewRefEntry()
	case screenReviewing:
		return reviewHeaderStyle() + "\n" +
			lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
				Render("Fetching submission…") + "\n"
	case screenDetail:
		return m.viewDetail()
	case screenError:
		return reviewHeaderStyle() + "\n" +
			lipgloss.NewStyle().Foreground(lipgloss.Color("1")).
				Render("Error: "+m.errMsg) + "\n\n" +
			lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
				Render("Press r to review another submission  •  q / Esc to quit") + "\n"
	case screenConfirmApprove:
		return m.viewConfirmApprove()
	case screenApproving:
		return reviewHeaderStyle() + "\n" +
			lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
				Render("Merging…") + "\n"
	case screenApproveError:
		return reviewHeaderStyle() + "\n" +
			lipgloss.NewStyle().Foreground(lipgloss.Color("1")).
				Render("Merge error: "+m.approveErrMsg) + "\n\n" +
			lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
				Render("Press r to review another submission  •  q / Esc to quit") + "\n"
	case screenApproveSuccess:
		return m.viewApproveSuccess()
	case screenDone:
		return ""
	}
	return ""
}

// viewQueue renders the triage queue screen.
func (m reviewModel) viewQueue() string {
	var sb strings.Builder

	sb.WriteString(reviewHeaderStyle())
	sb.WriteString("\n")

	// Prominent label: these are access-requests, not submissions.
	label := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("3")).
		Render("ACCESS-REQUEST TRIAGE QUEUE  (not submission PRs)")
	sb.WriteString(label)
	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
		Render("Contributor access-request PRs. Press r to review a submission directly.  " +
			"Press s to switch to the submission queue screen."))
	sb.WriteString("\n\n")

	if m.queueErr != nil {
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("1")).
			Render("Could not load queue: " + sanitizeErr(m.queueErr)))
		sb.WriteString("\n\n")
	} else if len(m.summaries) == 0 {
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
			Render("No open access requests."))
		sb.WriteString("\n\n")
	} else {
		// Column header.
		_, _ = fmt.Fprintf(&sb, "%-40s  %-20s  %-25s\n",
			"PR", "AUTHOR", "CREATED")
		sb.WriteString(strings.Repeat("-", 90))
		sb.WriteString("\n")

		for i, s := range m.summaries {
			prStr := fmt.Sprintf("%s#%d", s.PRRef.Project, s.PRRef.Number)
			author := render.SanitizeForTerminal(s.AuthorLogin)
			createdAt := render.SanitizeForTerminal(s.CreatedAt)
			row := fmt.Sprintf("%-40s  %-20s  %-25s", prStr, author, createdAt)
			if i == m.selectedIdx {
				row = lipgloss.NewStyle().
					Bold(true).
					Foreground(lipgloss.Color("62")).
					Render("> " + row)
			} else {
				row = "  " + row
			}
			sb.WriteString(row)
			sb.WriteString("\n")
		}

		if m.truncated {
			sb.WriteString("\n")
			sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("3")).
				Render(fmt.Sprintf("Showing %d of many — more access requests exist beyond this list.", len(m.summaries))))
			sb.WriteString("\n")
		}

		// Show selected row hint when an entry is highlighted.
		if m.selectedRef != "" {
			sb.WriteString("\n")
			hint := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
				Render("Selected: " + m.selectedRef +
					"  →  merge with: byreis rotate --add --from-request " + m.selectedRef)
			sb.WriteString(hint)
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
		Render("↑/↓ navigate  •  Enter select  •  r review a submission  •  s submissions  •  q / Esc quit"))
	sb.WriteString("\n")

	return sb.String()
}

// viewRefEntry renders the ref-entry screen.
func (m reviewModel) viewRefEntry() string {
	if m.refForm == nil {
		return ""
	}
	return reviewHeaderStyle() + "\n" + m.refForm.View()
}

// viewDetail renders the submission detail screen. All contributor-authored
// strings are sanitized. Plaintext is never rendered.
func (m reviewModel) viewDetail() string {
	d := m.detail
	var sb strings.Builder

	sb.WriteString(reviewHeaderStyle())
	sb.WriteString("\n")

	// PR header line.
	prLine := fmt.Sprintf("PR #%d  •  %s",
		d.Ref.Number,
		lipgloss.NewStyle().Foreground(lipgloss.Color("62")).
			Render(render.SanitizeForTerminal(d.Author)))
	sb.WriteString(lipgloss.NewStyle().Bold(true).Render(prLine))
	sb.WriteString("\n")

	if d.Justification != "" {
		just := render.SanitizeForTerminal(collapseReviewLineBreaks(d.Justification))
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
			Render("Justification: " + just))
		sb.WriteString("\n")
	}

	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
		Render("Secrets path:  " + render.SanitizeForTerminal(d.SecretsPath)))
	sb.WriteString("\n\n")

	// Per-key table.
	_, _ = fmt.Fprintf(&sb, "%-10s  %-40s  %s\n", "ACTION", "KEY", "VALIDATION")
	sb.WriteString(strings.Repeat("-", 70))
	sb.WriteString("\n")

	for _, kl := range d.PerKey {
		action := render.SanitizeForTerminal(kl.Action)
		keyName := render.SanitizeForTerminal(kl.Key)
		if len(keyName) > 40 {
			keyName = keyName[:37] + "..."
		}
		actionLabel := action
		if action == "replace" {
			actionLabel = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("1")).
				Render("REPLACE")
		}
		valStatus := lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("ok")
		if !kl.ValidationOK {
			msg := render.SanitizeForTerminal(kl.ValidationMsg)
			valStatus = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).
				Render("FAIL: " + msg)
		}
		_, _ = fmt.Fprintf(&sb, "%-10s  %-40s  %s\n", actionLabel, keyName, valStatus)
	}

	sb.WriteString("\n")
	_, _ = fmt.Fprintf(&sb, "pinned_sha: %s\n", d.PinnedSHA)
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
		Render(fmt.Sprintf("To merge:   byreis merge --pr %s#%d --expect %s",
			d.Ref.Project, d.Ref.Number, d.PinnedSHA)))
	sb.WriteString("\n\n")

	hintParts := []string{"r review another", "q / Esc quit"}
	if m.deps.Merger != nil {
		hintParts = append([]string{"a approve (merge)"}, hintParts...)
	}
	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
		Render(strings.Join(hintParts, "  •  ")))
	sb.WriteString("\n")

	return sb.String()
}

// viewConfirmApprove renders the explicit confirm screen shown before the
// irreversible merge. The admin must press 'y' or Enter to proceed; any other
// key returns to the detail screen without calling Merge.
func (m reviewModel) viewConfirmApprove() string {
	d := m.detail
	var sb strings.Builder

	sb.WriteString(reviewHeaderStyle())
	sb.WriteString("\n")

	warning := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("1")).
		Render("CONFIRM MERGE — this action is irreversible")
	sb.WriteString(warning)
	sb.WriteString("\n\n")

	_, _ = fmt.Fprintf(&sb, "PR:         %s#%d\n", d.Ref.Project, d.Ref.Number)
	_, _ = fmt.Fprintf(&sb, "pinned_sha: %s\n", d.PinnedSHA)
	_, _ = fmt.Fprintf(&sb, "project:    %s\n", render.SanitizeForTerminal(d.ProjectID))
	_, _ = fmt.Fprintf(&sb, "file:       %s\n", render.SanitizeForTerminal(d.FileName))
	sb.WriteString("\n")

	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
		Render("Press y / Enter to merge  •  any other key to cancel"))
	sb.WriteString("\n")

	return sb.String()
}

// viewApproveSuccess renders the merge acknowledgment screen shown after a
// successful Merger.Merge call.
func (m reviewModel) viewApproveSuccess() string {
	var sb strings.Builder

	sb.WriteString(reviewHeaderStyle())
	sb.WriteString("\n")

	ok := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("2")).
		Render("Merge complete")
	sb.WriteString(ok)
	sb.WriteString("\n\n")

	res := m.approveResult
	_, _ = fmt.Fprintf(&sb, "content_sha:  %s\n", res.liveFileSHA)
	_, _ = fmt.Fprintf(&sb, "re_encrypted: %v\n", res.reEncrypted)
	_, _ = fmt.Fprintf(&sb, "counter:      %d\n", res.counter)
	sb.WriteString("\n")

	sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
		Render("r review another  •  q / Esc quit"))
	sb.WriteString("\n")

	return sb.String()
}

// reviewHeaderStyle returns the branded header for the review TUI screens.
func reviewHeaderStyle() string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("62")).
		Render("byreis review")
}

// buildRefForm builds the huh form that collects the PR ref string. The ref is
// a structural value (project#number) and is not secret; it is displayed as
// plain text. The admin types it; it is sanitized structurally by parseReviewRef
// before it is used.
func buildRefForm(binding *string) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Submission PR reference").
				Description("Enter the PR ref to review in project#number form (e.g. myorg/my-app-secrets#42)").
				Value(binding),
		),
	)
}

// collapseReviewLineBreaks replaces newline, carriage return, and tab characters
// with a single space. This is the TUI-local counterpart to the cli-layer helper
// applied to the justification field; it is replicated here so the tui package
// does not import internal/cli (which would create a cli↛tui cycle).
func collapseReviewLineBreaks(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
}

// ErrReviewAborted is returned by RunReview when the admin quits the TUI before
// a review completes. It is exposed so the caller can distinguish a deliberate
// quit (non-zero exit, no message) from a review failure.
var ErrReviewAborted = fmt.Errorf("review cancelled — no submission was reviewed")

// RunReview launches the interactive review TUI. It is the entry point from the
// review RunE fork when ShouldLaunchTUI returns true.
//
// prRef may be empty (the model opens on the queue + ref-entry flow) or
// non-empty (a pre-supplied ref, jumps directly to reviewing). Either way the
// mode gate must have already been enforced by the RunE caller before RunReview
// is called.
//
// The context ctx carries the caller's deadline and cancellation. All I/O
// operations (queue fetch, Review call) use this context, so cancellation is
// honored end-to-end.
//
// RunReview returns nil on a clean quit after a completed review (or after the
// admin presses q without reviewing anything). It returns ErrReviewAborted when
// the program exits in the initial or intermediate states without having
// completed a Review. It returns a wrapped error for TUI program failures.
func RunReview(ctx context.Context, deps Deps, out io.Writer, prRef string) error {
	if deps.Policy == nil {
		return fmt.Errorf(
			"review TUI cannot start: mode policy not configured — run `byreis doctor` to check your setup")
	}

	// Enforce mode gate: review is ADMIN-only.
	if err := deps.Policy.Allow(deps.CurrentMode, mode.CommandReview); err != nil {
		return fmt.Errorf("review requires ADMIN mode: %w", err)
	}

	m := newReviewModel(ctx, deps, prRef)

	opts := []tea.ProgramOption{
		tea.WithContext(ctx),
	}
	if out != nil {
		opts = append(opts, tea.WithOutput(out))
	}

	p := tea.NewProgram(m, opts...)
	finalModel, runErr := p.Run()
	if runErr != nil {
		return fmt.Errorf("TUI review program error: %w — check your terminal configuration", runErr)
	}

	rm, ok := finalModel.(reviewModel)
	if !ok {
		return fmt.Errorf("TUI review: unexpected final model type — internal error")
	}

	// A clean quit after having viewed a detail, or after a successful merge,
	// is success (the admin completed the flow they entered the TUI for).
	if rm.screen == screenDone && (rm.detailOK || rm.approveResult.liveFileSHA != "") {
		return nil
	}
	// Any other terminal state is treated as a deliberate quit without completing.
	return ErrReviewAborted
}
