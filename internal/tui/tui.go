// Package tui is the interactive TUI shell for byreis.
//
// It is a peer to internal/cli, bound by the same adapter-import ban (the
// depguard adapter-wired-at-cmd rule): internal/tui must not import
// internal/adapter, must not construct SDK clients, and must not perform
// error-to-exit-code mapping against adapter sentinels.
// The TUI consumes core use-case ports through the injected Deps struct, which
// is populated at cmd/byreis/main.go alongside cli.Deps.
//
// Allowed imports: bubbletea, lipgloss, huh (confined here by the
// ui-frameworks-tui-only depguard rule); internal/core use-case ports and
// their DTOs; internal/cli/render (shared presentation utilities — sanitizer
// and Renderer, not business logic); internal/core/mode (Command and Mode
// constants and Policy, read-only).
// No internal/adapter import. No SDK client construction.
//
// Architecture constraints enforced by depguard and the ceiling gate:
//   - bubbletea, lipgloss, and huh are confined to this package tree (the
//     ui-frameworks-tui-only depguard rule).
//   - internal/core is never modified by TUI work; the exported-symbol baseline
//     is frozen at 393 and enforced by make test-tui-core-ceiling.
//   - Zero new internal/core exported symbols are permitted from TUI work;
//     any addition fails the ceiling gate and escalates to principal-go.
package tui

import (
	"context"
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// SubmitterFactory is a function that constructs a submit.Submitter using the
// same underlying adapter deps as the CLI's Submitter but with the supplied
// Prompter. The TUI submit screen calls this factory with a prefilledPrompter
// (backed by the huh form's collected value) so the core use-case's
// CollectValue call returns the TUI-collected value without re-prompting.
//
// The factory function is set by the composition root (cmd/byreis/main.go) and
// reuses the same Recipients, Encryptor, Validator, KeyProbe, Git, Resume,
// Clock, Audit, and Log adapters as the CLI's Submitter. Only the Prompter
// differs. This is intentional: the TUI is a UI shell, not a second adapter
// wiring layer — it drives the same adapters through a different interaction model.
type SubmitterFactory func(prompter submit.Prompter) (submit.Submitter, error)

// Deps carries the narrow set of core ports the TUI needs. It is a strict
// subset of cli.Deps fields — all consumer-defined core ports, never adapter
// types. The TUI calls the same constructed port instances handed to the CLI:
// one wiring path, one set of behaviors, no parallel adapter construction.
//
// The mode gate runs first in every privileged TUI screen:
// deps.Policy.Allow(deps.CurrentMode, <existing Command>) mirrors the CLI
// "mode gate FIRST" rule so denied-not-attempted is preserved — privileged
// screens are never reachable by a contributor-mode caller.
type Deps struct {
	// Submitter is the contributor Submit use-case. Same instance as cli.Deps.
	// When nil the submit screen is unreachable; the program exits with an error.
	Submitter submit.Submitter

	// Reviewer is the admin Review use-case. Same instance as cli.Deps.
	// When nil the review queue screen is unreachable.
	Reviewer usecase.Reviewer

	// Merger is the admin Merge use-case. Same instance as cli.Deps.
	// Used by the in-TUI approve flow. When nil approve is disabled
	// (the action returns an error).
	Merger usecase.Merger

	// Rejecter is the admin Reject use-case. Same instance as cli.Deps.
	// Used by the in-TUI decline (reject) flow. When nil the 'd' key
	// affordance is omitted from the detail view and pressing 'd' is a no-op,
	// mirroring the nil-Merger pattern for approve.
	Rejecter usecase.RequestRejecter

	// RequestAccessReader is the narrow read-only port used to fetch
	// contributor request-access PR metadata. Same instance as cli.Deps.
	RequestAccessReader rotate.RequestAccessReader

	// RequestAccessOpener is the narrow write-side port for the contributor
	// request-access verb. Same instance as cli.Deps.
	RequestAccessOpener rotate.RequestAccessOpener

	// Policy is the mode permission gate. Must be non-nil; a nil Policy causes
	// Run to return an error before constructing the bubbletea program.
	Policy *mode.Policy

	// CurrentMode is the cryptographically-derived mode resolved at startup.
	// Used together with Policy for screen-level permission checks.
	CurrentMode mode.Mode

	// Renderer is the shared presentation utility injected by the composition
	// root. The TUI writes to the bubbletea program's output channel via this
	// Renderer, not directly to os.Stdout, so the bubbletea frame is never
	// corrupted by bare os.Stdout writes.
	//
	// Never call render.New() inside the TUI package (enforced by the
	// render_guard_test.go AST test in this package): render.New binds bare
	// os.Stdout and would bypass the bubbletea output model.
	Renderer *render.Renderer

	// SubmitterFactory constructs a submit.Submitter backed by the given
	// Prompter. The factory is set by the composition root and reuses all
	// the same adapter deps as the CLI's Submitter; only the Prompter differs.
	// When nil the TUI submit screen returns an error (adapters not configured).
	SubmitterFactory SubmitterFactory

	// SubmissionQueueSource is the narrow read-only port that lists open
	// submission PRs on the project repo. When non-nil the review TUI opens
	// on the submission queue screen (screenSubmissionQueue); when nil it falls
	// back to the v0.3 access-request queue screen. The source is constructed
	// at the composition root from BYREIS_PROJECT_REPO and the GitHub token;
	// it is nil in contributor mode or when project-repo config is absent.
	//
	// This is an adapter-layer interface defined here in the tui package
	// (consumer-defined per the Clean Architecture dependency rule). No core
	// package symbol is added: the return type rotate.OpenRequestSummary is
	// the existing shared DTO already used by the access-request queue.
	SubmissionQueueSource SubmissionQueueSource
}

// Run launches the interactive TUI program for non-submit verbs (review queue,
// etc.). It is retained as the entry point for the review and other TUI screens
// that are added in subsequent build slices. Run must only be called after
// ShouldLaunchTUI returns true; the caller is responsible for that check.
//
// For the submit verb use RunSubmit (defined in submit.go), which handles the
// pre-filled-key argument and the masked-value form lifecycle.
//
// The context ctx carries the caller's deadline and cancellation signal.
// Run honors cancellation: if ctx is cancelled before the program finishes,
// Run returns ctx.Err() wrapped with an actionable hint.
func Run(ctx context.Context, deps Deps, out io.Writer) error {
	if deps.Policy == nil {
		return fmt.Errorf(
			"TUI cannot start: mode policy not configured — run `byreis doctor` to check your setup")
	}

	// Construct the bubbletea program only when Run is called. This is the
	// "never constructed" invariant: if ShouldLaunchTUI returned false, Run is
	// never called, and therefore tea.NewProgram is never called, therefore no
	// signal handlers, no alt-screen escape, and no input reader are registered.
	m := newShellModel(deps)

	opts := []tea.ProgramOption{
		tea.WithContext(ctx),
	}
	if out != nil {
		opts = append(opts, tea.WithOutput(out))
	}

	p := tea.NewProgram(m, opts...)
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI program error: %w — check your terminal configuration", err)
	}
	return nil
}

// shellModel is the placeholder bubbletea model for non-submit TUI paths
// (review queue, etc.). It renders a brief informational message and exits
// after the first render cycle. The real review screens are added in
// subsequent build slices.
//
// The submit screen uses submitModel (defined in submit.go), not this model.
// Run is retained for non-submit entry points; submit uses RunSubmit.
type shellModel struct {
	deps Deps
	done bool
}

// newShellModel constructs the placeholder shell model for non-submit paths.
func newShellModel(deps Deps) shellModel {
	return shellModel{deps: deps}
}

// Init returns no initial command: the placeholder shell has nothing to set up.
func (m shellModel) Init() tea.Cmd {
	return tea.Quit
}

// Update handles incoming messages. The placeholder shell quits immediately.
func (m shellModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg.(type) {
	case tea.QuitMsg:
		m.done = true
		return m, nil
	}
	return m, tea.Quit
}

// View renders the current state. The header style uses lipgloss for the
// brand accent so the framework import is exercised at compile time, confirming
// the dependency is wired correctly even before the real screens land.
func (m shellModel) View() string {
	if m.done {
		return ""
	}
	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("62")).
		Render("byreis")

	return header + " — interactive mode (review screens landing in upcoming slices)\n"
}
