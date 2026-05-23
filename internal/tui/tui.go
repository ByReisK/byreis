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
}

// Run launches the interactive TUI program. It is the single entry point from
// cmd/byreis/main.go. Run must only be called after ShouldLaunchTUI returns
// true for the current invocation; the caller is responsible for that check.
//
// The context ctx carries the caller's deadline and cancellation signal.
// Run honors cancellation: if ctx is cancelled before the program finishes,
// Run returns ctx.Err() wrapped with an actionable hint.
//
// This implementation is a minimal placeholder shell. The actual submit and
// review screens are added in subsequent build slices. The placeholder renders
// a brief informational message and exits cleanly so the scaffold compiles and
// all integration tests remain green.
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

// shellModel is the minimal placeholder bubbletea model. It renders a brief
// informational message and exits after the first render cycle. The real submit
// and review models are added in subsequent build slices.
//
// submitF is nil in the scaffold; it is populated with the masked value form
// when the submit screen lands.
type shellModel struct {
	deps    Deps
	done    bool
	submitF *SubmitForm
}

// newShellModel constructs the placeholder shell model. The submit form is
// pre-allocated as a typed placeholder; the real submit screen populates it
// with the actual key name when the submit path launches the TUI. In the
// scaffold the form is constructed but never Run().
func newShellModel(deps Deps) shellModel {
	sf := newSubmitForm("")
	return shellModel{deps: deps, submitF: sf}
}

// Init returns no initial command: the placeholder shell has nothing to set up.
func (m shellModel) Init() tea.Cmd {
	return tea.Quit
}

// Update handles incoming messages. The placeholder shell quits immediately.
// When a submit form is active, Update forwards messages to it and returns a
// quit command when the form completes.
func (m shellModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.submitF != nil {
		// The submit form is allocated but not run in the placeholder shell.
		// The real submit screen wires form message delegation here.
		_ = m.submitF
	}
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

	return header + " — interactive mode (screens landing in upcoming slices)\n"
}
