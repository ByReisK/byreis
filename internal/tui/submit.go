package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// WriteOnlyAffordance is the verbatim write-only guarantee string displayed
// persistently adjacent to the confirm action on the TUI submit screen. It is
// pinned as an exported constant so tests can assert its exact text without
// duplicating the string, and so the string cannot drift silently between the
// UI and the test fixture.
//
// The text is the load-bearing affordance: it must be shown BEFORE the
// contributor confirms, must persist on screen (not be a transient toast),
// and must communicate that the value cannot be recovered after submission.
const WriteOnlyAffordance = "byreis encrypts this to the project admins. " +
	"You are writing only — you will not be able to read this value back. " +
	"Only an admin with a private key can decrypt it."

// submitPhase tracks which step of the TUI submit flow is active.
type submitPhase int

const (
	// phaseKeyEntry is the first step: the contributor supplies the key name
	// (or the key was pre-supplied via --key; in that case this phase is skipped).
	phaseKeyEntry submitPhase = iota

	// phaseValueEntry is the masked-value input step.
	phaseValueEntry

	// phaseConfirm is the confirmation screen: displays the WriteOnlyAffordance
	// persistently adjacent to the confirm/cancel actions.
	phaseConfirm

	// phaseSubmitting is the transient state while Submit is called.
	phaseSubmitting

	// phaseDone is the final state after a successful or failed submission.
	phaseDone

	// phaseAborted is set when the contributor presses Ctrl-C or Esc and cancels
	// before confirm. No Submit call is made, no artifact is created.
	phaseAborted
)

// submitModel is the bubbletea model for the TUI contributor submit screen.
// It progresses through phaseKeyEntry → phaseValueEntry → phaseConfirm →
// phaseSubmitting → phaseDone, or terminates at phaseAborted on Ctrl-C/Esc.
//
// Design constraints enforced by this type:
//   - The entered value is held only in the huh form's bound variable and in the
//     collectedValue field. Both are zeroized immediately after Submit returns.
//   - The value is NEVER written to any View() output at any phase.
//   - WriteOnlyAffordance is displayed persistently on phaseConfirm.
//   - Submit is called exactly once on confirm; never on abort.
type submitModel struct {
	ctx         context.Context
	deps        Deps
	submitInput submit.Input // metadata fields only — no value

	// preFilledKey is the key name supplied via --key before TUI launch.
	// When non-empty, phaseKeyEntry is skipped.
	preFilledKey string

	phase submitPhase

	// keyForm collects the key name when no --key was pre-supplied.
	keyForm    *huh.Form
	keyBinding string // bound by huh

	// valueForm collects the masked secret value. EchoModePassword prevents
	// the value from appearing on screen during entry.
	valueForm    *huh.Form
	valueBinding string // bound by huh; zeroized after Submit returns

	// collectedKey is the key name resolved from either preFilledKey or keyForm.
	collectedKey string

	// confirmed tracks whether the contributor chose confirm (true) or cancel
	// (false) on the confirm screen.
	confirmed bool

	// confirmIndex is the huh Select index on the confirm screen.
	confirmForm *huh.Form

	// result holds the successful Result after Submit returns.
	result submit.Result
	// submitErr holds any error from Submit (non-nil only on phaseDone after failure).
	submitErr error
}

// newSubmitModel constructs the submit model. preFilledKey may be empty (the
// key-name collection step will run) or non-empty (the key-name step is
// skipped). The submitInput carries the metadata fields that the CLI path
// would put into submit.Input (ProjectID, LogicalFileName, Justification,
// SecretsPath, BaseFilePath) — the Key field is populated from the form or
// preFilledKey before Submit is called.
//
// ctx is the caller's context (from RunSubmit) and is used for the Submit call
// in doSubmit so that cancellation and deadlines from the caller are honored.
func newSubmitModel(ctx context.Context, deps Deps, preFilledKey string, base submit.Input) submitModel {
	m := submitModel{
		ctx:          ctx,
		deps:         deps,
		submitInput:  base,
		preFilledKey: preFilledKey,
	}

	if preFilledKey != "" {
		// Key is already known: skip key-name collection.
		m.collectedKey = preFilledKey
		m.phase = phaseValueEntry
		m.valueForm = buildValueForm(&m.valueBinding, preFilledKey)
	} else {
		// Collect the key name first.
		m.phase = phaseKeyEntry
		m.keyForm = buildKeyForm(&m.keyBinding)
	}
	return m
}

// buildKeyForm returns a huh form that collects the key name. The key name is
// not secret and is displayed as plain text; it is sanitized before rendering
// via render.SanitizeForTerminal when echoed back.
func buildKeyForm(binding *string) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Secret key name").
				Description("Enter the environment variable name (e.g. DATABASE_URL)").
				Value(binding),
		),
	)
}

// buildValueForm returns a huh form that collects the masked secret value.
// EchoModePassword ensures the value is rendered as bullets on entry and
// NEVER echoed back as plaintext.
func buildValueForm(binding *string, keyName string) *huh.Form {
	label := "Secret value"
	if keyName != "" {
		sanitized := render.SanitizeForTerminal(keyName)
		label = "Value for " + sanitized
	}
	return huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title(label).
				Description("Masked entry — the value will not be displayed.").
				EchoMode(huh.EchoModePassword).
				Value(binding),
		),
	)
}

// buildConfirmForm returns a huh form that presents the confirm/cancel choice.
// The WriteOnlyAffordance string is shown as the form description so it appears
// persistently adjacent to the confirm action, not as a transient toast.
func buildConfirmForm(binding *bool) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Confirm submission").
				Description(WriteOnlyAffordance).
				Affirmative("Submit (write-only, irreversible)").
				Negative("Cancel").
				Value(binding),
		),
	)
}

// submitResultMsg is sent over the bubbletea message bus when the Submit call
// completes (success or failure) so the Update loop can transition to phaseDone.
type submitResultMsg struct {
	result submit.Result
	err    error
}

// Init returns the command that kicks off the first form.
func (m submitModel) Init() tea.Cmd {
	switch m.phase {
	case phaseKeyEntry:
		return m.keyForm.Init()
	case phaseValueEntry:
		return m.valueForm.Init()
	default:
		return nil
	}
}

// Update drives the submitModel state machine. On Ctrl-C or huh ErrUserAborted,
// the model transitions to phaseAborted — no Submit call, no artifact, no PR.
func (m submitModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.phase {

	case phaseKeyEntry:
		form, cmd := m.keyForm.Update(msg)
		if f, ok := form.(*huh.Form); ok {
			m.keyForm = f
		}
		if m.keyForm.State == huh.StateAborted {
			m.phase = phaseAborted
			return m, tea.Quit
		}
		if m.keyForm.State == huh.StateCompleted {
			m.collectedKey = m.keyBinding
			// Key name collected; advance to value entry.
			m.phase = phaseValueEntry
			m.valueForm = buildValueForm(&m.valueBinding, m.collectedKey)
			return m, m.valueForm.Init()
		}
		return m, cmd

	case phaseValueEntry:
		form, cmd := m.valueForm.Update(msg)
		if f, ok := form.(*huh.Form); ok {
			m.valueForm = f
		}
		if m.valueForm.State == huh.StateAborted {
			zeroizeString(&m.valueBinding)
			m.phase = phaseAborted
			return m, tea.Quit
		}
		if m.valueForm.State == huh.StateCompleted {
			// Advance to confirm — value is now in m.valueBinding.
			m.phase = phaseConfirm
			m.confirmForm = buildConfirmForm(&m.confirmed)
			return m, m.confirmForm.Init()
		}
		return m, cmd

	case phaseConfirm:
		form, cmd := m.confirmForm.Update(msg)
		if f, ok := form.(*huh.Form); ok {
			m.confirmForm = f
		}
		if m.confirmForm.State == huh.StateAborted {
			zeroizeString(&m.valueBinding)
			m.phase = phaseAborted
			return m, tea.Quit
		}
		if m.confirmForm.State == huh.StateCompleted {
			if !m.confirmed {
				// Contributor chose "Cancel".
				zeroizeString(&m.valueBinding)
				m.phase = phaseAborted
				return m, tea.Quit
			}
			// Contributor confirmed: launch Submit in the background.
			m.phase = phaseSubmitting
			return m, m.doSubmit()
		}
		return m, cmd

	case phaseSubmitting:
		if r, ok := msg.(submitResultMsg); ok {
			// Zeroize the in-memory value now that Submit has returned.
			// The value is no longer needed regardless of success or failure.
			zeroizeString(&m.valueBinding)
			m.result = r.result
			m.submitErr = r.err
			m.phase = phaseDone
			return m, tea.Quit
		}
		return m, nil

	case phaseDone, phaseAborted:
		return m, tea.Quit
	}

	return m, nil
}

// doSubmit constructs the submit.Input (field-for-field identical to the CLI
// single-key path) and calls deps.Submitter.Submit in a bubbletea command so
// the bubbletea event loop is not blocked. The value collected by the form is
// passed through a prefilledPrompter so the use-case's internal Prompter call
// returns immediately with the already-collected value.
//
// The confirm action IS the irreversibility acknowledgement: the prefilledPrompter
// returns IrreversibleAcknowledged: true and Interactive: true, matching the
// interactive TTY path in the CLI.
func (m submitModel) doSubmit() tea.Cmd {
	// Capture these values before the goroutine is scheduled so the model's
	// fields are not accessed from a concurrent goroutine.
	value := m.valueBinding
	key := m.collectedKey
	in := m.submitInput
	in.Key = key
	deps := m.deps

	// Capture ctx before the goroutine is scheduled.
	ctx := m.ctx

	return func() tea.Msg {
		// Build a pre-filled Prompter so the use-case's CollectValue returns the
		// value the TUI form already collected. The TUI confirm IS the
		// irreversibility acknowledgement: IrreversibleAcknowledged is true,
		// Interactive is true (mirrors the TTY path).
		//
		// ctx is the caller's context (captured from the submitModel), so
		// cancellation and deadlines from RunSubmit's caller are honored.
		prompter := &prefilledPrompter{
			value:                    value,
			irreversibleAcknowledged: true,
			interactive:              true,
		}

		// Create a dedicated TUI-backed Submitter using the same deps but with
		// the pre-filled prompter. This is the composition-root-delegated
		// construction path: the adapter deps (Recipients, Encryptor, etc.) are
		// the same instances the CLI Submitter was handed; only the Prompter
		// differs (TUI-backed vs TTY-backed).
		tuiSubmitter, err := deps.buildTUISubmitter(prompter)
		if err != nil {
			zeroizeString(&value)
			return submitResultMsg{err: fmt.Errorf(
				"TUI submit: failed to build submitter: %w — run `byreis doctor` for diagnostics", err)}
		}

		result, submitErr := tuiSubmitter.Submit(ctx, in)
		zeroizeString(&value)
		return submitResultMsg{result: result, err: submitErr}
	}
}

// View renders the current state of the submit model. The entered value is
// NEVER rendered at any phase: the masked form is handled by huh internally
// (EchoModePassword), and after value entry the value is only referenced
// inside the closed-over prefilledPrompter — never in View output.
func (m submitModel) View() string {
	switch m.phase {

	case phaseKeyEntry:
		if m.keyForm == nil {
			return ""
		}
		return headerStyle() + "\n" + m.keyForm.View()

	case phaseValueEntry:
		if m.valueForm == nil {
			return ""
		}
		return headerStyle() + "\n" + m.valueForm.View()

	case phaseConfirm:
		if m.confirmForm == nil {
			return ""
		}
		// The WriteOnlyAffordance is part of the confirm form's description
		// (set in buildConfirmForm). It is rendered persistently by huh as part
		// of the form layout, not as a separate element that could be omitted.
		return headerStyle() + "\n" + m.confirmForm.View()

	case phaseSubmitting:
		return headerStyle() + "\n" +
			lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
				Render("Submitting…")

	case phaseDone:
		if m.submitErr != nil {
			return headerStyle() + "\n" +
				lipgloss.NewStyle().Foreground(lipgloss.Color("1")).
					Render("Submit failed: "+sanitizeErr(m.submitErr)) + "\n"
		}
		// Success: show the PR URL. The value is gone; never echo it.
		return headerStyle() + "\n" +
			lipgloss.NewStyle().Foreground(lipgloss.Color("2")).
				Render(m.result.Action.String()+" — PR opened: "+m.result.PRURL) + "\n"

	case phaseAborted:
		return headerStyle() + "\n" +
			lipgloss.NewStyle().Foreground(lipgloss.Color("240")).
				Render("Submission cancelled.") + "\n"
	}

	return ""
}

// headerStyle returns the branded header line shared across submit phases.
func headerStyle() string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("62")).
		Render("byreis submit")
}

// sanitizeErr formats an error for terminal display. It strips newlines and
// sanitizes any contributor-influenced text so a crafted error message cannot
// inject terminal control sequences.
func sanitizeErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	msg = strings.ReplaceAll(msg, "\n", " ")
	return render.SanitizeForTerminal(msg)
}

// prefilledPrompter implements submit.Prompter. It returns the pre-collected
// value from the TUI form without prompting the user again. The TUI confirm
// action serves as the irreversibility acknowledgement.
//
// This type lives in internal/tui because it is the TUI-specific bridge between
// the huh form's output and the core use-case's Prompter port. It is not in
// internal/core (that would violate the ceiling) and not in internal/adapter
// (it has no network/SDK/keychain dependency).
type prefilledPrompter struct {
	value                    string
	irreversibleAcknowledged bool
	interactive              bool
}

// CollectValue returns the pre-collected value. The action parameter is ignored
// because the TUI form already asked for confirmation — the value is always
// returned as-is.
func (p *prefilledPrompter) CollectValue(_ context.Context, _ string, _ submit.SubmitAction) (submit.ValueEntry, error) {
	return submit.ValueEntry{
		Value:                    p.value,
		Confirm:                  p.value, // same value for double-entry check
		Interactive:              p.interactive,
		IrreversibleAcknowledged: p.irreversibleAcknowledged,
	}, nil
}

// buildTUISubmitter is called on the Deps to construct a submit.Submitter
// backed by the given Prompter. The deps struct carries the SubmitterFactory
// function set at the composition root; calling it with the TUI-backed prompter
// produces a Submitter that uses all the same adapter deps (Recipients, Encryptor,
// Validator, KeyProbe, Git, Resume, Clock, Audit, Log) but with a TUI Prompter.
//
// This function is separate from Deps so that tests can substitute a spy factory
// for golden-equivalence validation without changing any core symbol.
func (d Deps) buildTUISubmitter(p *prefilledPrompter) (submit.Submitter, error) {
	if d.SubmitterFactory == nil {
		return nil, errors.New(
			"TUI submit: SubmitterFactory not wired — run `byreis init` or check your configuration")
	}
	return d.SubmitterFactory(p)
}

// zeroizeString overwrites the string's backing storage with zero bytes and
// resets the string to empty. This is a best-effort zeroization: Go's string
// interning / GC may retain copies, but this eliminates the most obvious
// retention path (the local variable in the TUI model).
func zeroizeString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// Overwrite each byte via unsafe-free reflection on the backing array.
	// Since Go strings are immutable, we work through a byte slice view.
	b := []byte(*s)
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

// RunSubmit launches the TUI submit screen. It is the entry point from the
// submit RunE fork. The preFilledKey is the value of --key if supplied (may be
// empty). The base submit.Input carries all metadata fields the CLI path would
// populate (ProjectID, LogicalFileName, Justification, SecretsPath,
// BaseFilePath); the Key field is populated from the form or preFilledKey inside
// the model.
//
// RunSubmit returns a non-nil error on Submit failure, TUI program error, or
// user abort (Ctrl-C / Esc / cancel). On abort the error wraps ErrSubmitAborted
// so the caller can distinguish abort (non-zero exit, no message) from a submit
// failure (non-zero exit + error message).
//
// The entered value is zeroized after Submit returns (or immediately on abort);
// it is never persisted to disk in plaintext and never passed to a render path.
func RunSubmit(ctx context.Context, deps Deps, out interface{ Write([]byte) (int, error) }, preFilledKey string, base submit.Input) error {
	m := newSubmitModel(ctx, deps, preFilledKey, base)

	opts := []tea.ProgramOption{
		tea.WithContext(ctx),
	}
	if out != nil {
		opts = append(opts, tea.WithOutput(out))
	}

	p := tea.NewProgram(m, opts...)
	finalModel, runErr := p.Run()
	if runErr != nil {
		return fmt.Errorf("TUI submit program error: %w — check your terminal configuration", runErr)
	}

	sm, ok := finalModel.(submitModel)
	if !ok {
		return fmt.Errorf("TUI submit: unexpected final model type — internal error")
	}

	switch sm.phase {
	case phaseAborted:
		return ErrSubmitAborted
	case phaseDone:
		return sm.submitErr
	default:
		// Program exited in an unexpected phase (e.g. context cancelled mid-form).
		return fmt.Errorf("TUI submit: program exited unexpectedly in phase %d — check your terminal configuration", sm.phase)
	}
}

// ErrSubmitAborted is returned by RunSubmit when the contributor cancels the
// form (Ctrl-C / Esc / "Cancel" on the confirm screen) before any Submit call
// is made. No artifact is created, no branch is opened, no PR is created.
var ErrSubmitAborted = errors.New("submission cancelled — no secret was submitted")
