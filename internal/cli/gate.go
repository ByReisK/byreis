package cli

import (
	"os"

	"github.com/ByReisK/byreis/internal/core/mode"
)

// ShouldLaunchTUI reports whether the interactive TUI program should be
// launched for the given invocation. It returns true iff ALL of the following
// hold:
//
//   - cmd is one of the TUI-eligible verbs ("submit" or "review")
//   - the --json flag is NOT set
//   - env["TERM"] is not "dumb"
//   - stdin and stdout are both TTYs (per the injected isTTY probe)
//   - BYREIS_NON_INTERACTIVE is not set in env and --non-interactive is not set
//   - FlagsFullySpecify returns false for the command (the flag set does not
//     make the TUI unnecessary)
//
// The mode gate for privileged commands (review) must run separately, before
// calling ShouldLaunchTUI. A contributor reaching bare "review" is denied by
// the permission matrix before this function is consulted; the policy parameter
// is used here only to cheaply short-circuit eligibility without re-running the
// full gate (returns false when Policy.Allow returns an error for the command).
//
// The function is pure given its inputs and never reads from os.Stdin,
// os.Stdout, os.Getenv, or any real clock. All input is injected so the
// function is fully table-testable without a real terminal.
//
// ShouldLaunchTUI is defined here as the foundation for the RunE fork point.
// It must not be called from RunE in this slice; the wiring is done when the
// real submit and review screens exist.
func ShouldLaunchTUI(
	cmd string,
	flagJSON bool,
	env map[string]string,
	isTTYStdin bool,
	isTTYStdout bool,
	policy *mode.Policy,
	currentMode mode.Mode,
	flagKey string,
	flagFile string,
	flagPR string,
	flagNonInteractive bool,
) bool {
	// Guard 1: only "submit" and "review" are TUI-eligible in v0.3.
	switch cmd {
	case "submit", "review":
		// eligible — continue
	default:
		return false
	}

	// Guard 2: --json suppresses the TUI on every path.
	if flagJSON {
		return false
	}

	// Guard 3: TERM=dumb means a non-ANSI terminal — no TUI.
	if env["TERM"] == "dumb" {
		return false
	}

	// Guard 4: both stdin and stdout must be TTYs.
	if !isTTYStdin || !isTTYStdout {
		return false
	}

	// Guard 5: BYREIS_NON_INTERACTIVE env or --non-interactive flag suppresses
	// the TUI unconditionally.
	if nonInteractiveEnv(env) || flagNonInteractive {
		return false
	}

	// Guard 6: mode eligibility — review is admin-only. A contributor reaching
	// bare "review" must never get a half-launched TUI; the permission matrix
	// handles the hard deny in RunE, but we short-circuit here too so the gate
	// is independently safe when run before RunE's mode check.
	//
	// Fail closed: a nil Policy for a privileged command is treated as a deny.
	// The mode gate in RunE is the authoritative hard deny; this guard provides
	// an independent safe default so a misconfigured or absent Policy never
	// results in a half-launched TUI for a privileged command.
	if cmd == "review" {
		if policy == nil {
			return false
		}
		if err := policy.Allow(currentMode, mode.CommandReview); err != nil {
			return false
		}
	}

	// Guard 7: FlagsFullySpecify — if the flags make the TUI unnecessary (the
	// headless path covers this case), suppress the TUI.
	if FlagsFullySpecify(cmd, env, flagKey, flagFile, flagPR, isTTYStdin, flagNonInteractive) {
		return false
	}

	return true
}

// FlagsFullySpecify reports whether the supplied flag set makes the TUI
// unnecessary for the given command — that is, whether the headless CLI path
// already has everything it needs.
//
// Per the BA-locked ruling:
//
//   - "submit": fully specified (headless) iff --file is set OR (--key is set
//     AND stdin is NOT a TTY). The rationale: --file triggers the bulk path
//     (always headless); --key with a piped stdin provides the value via pipe
//     (headless single-key). --key with a TTY stdin (or no flags at all) means
//     the TUI should offer the masked value form.
//
//   - "review": fully specified (headless, single-PR print) iff --pr is
//     non-empty.
//
//   - All other commands: not TUI-eligible; always returns false (caller must
//     already have short-circuited on non-eligible commands).
//
// The function is pure given its inputs. It does not read real flags, env, or
// terminal state; all input is injected by the caller so the function is
// fully table-testable.
func FlagsFullySpecify(
	cmd string,
	env map[string]string,
	flagKey string,
	flagFile string,
	flagPR string,
	isTTYStdin bool,
	flagNonInteractive bool,
) bool {
	switch cmd {
	case "submit":
		// --file set → bulk path, always headless.
		if flagFile != "" {
			return true
		}
		// --key set AND stdin is NOT a TTY → value arrives via pipe, headless.
		if flagKey != "" && !isTTYStdin {
			return true
		}
		// Non-interactive mode → headless regardless of other flags.
		if nonInteractiveEnv(env) || flagNonInteractive {
			return true
		}
		// Any other combination (bare submit, --key at a TTY) → TUI.
		return false

	case "review":
		// --pr non-empty → single-PR headless print.
		return flagPR != ""

	default:
		// Non-TUI-eligible commands are never fully specified in the TUI sense.
		return false
	}
}

// nonInteractiveEnv reports whether the BYREIS_NON_INTERACTIVE environment
// variable is set to a truthy value in the supplied map.
func nonInteractiveEnv(env map[string]string) bool {
	v := env["BYREIS_NON_INTERACTIVE"]
	return v == "1" || v == "true" || v == "yes"
}

// EnvFromOS builds the env map required by ShouldLaunchTUI and
// FlagsFullySpecify from the real os.Environ. It is a thin adapter for the
// production call site in RunE; unit tests supply their own map directly
// instead of calling this function.
func EnvFromOS() map[string]string {
	env := os.Environ()
	m := make(map[string]string, len(env))
	for _, kv := range env {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				m[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	return m
}

// IsTTYFile reports whether the given file descriptor is a character device
// (i.e. a TTY). It is the injected isTTY probe for production RunE call sites.
// Unit tests supply a boolean directly instead of calling this function.
func IsTTYFile(f *os.File) bool {
	if f == nil {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}
