package cli_test

import (
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// adminPolicy is a helper that builds a real Policy and returns the admin mode.
// Used for rows that require the mode gate to pass (review eligible).
func adminPolicy() (*mode.Policy, mode.Mode) {
	return &mode.Policy{}, mode.ModeAdmin
}

// contributorPolicy returns a real Policy and contributor mode.
func contributorPolicy() (*mode.Policy, mode.Mode) {
	return &mode.Policy{}, mode.ModeContributor
}

// ttyEnv builds a minimal env map without any suppression variables.
func ttyEnv() map[string]string {
	return map[string]string{"TERM": "xterm-256color"}
}

// dumbEnv builds an env map with TERM=dumb.
func dumbEnv() map[string]string {
	return map[string]string{"TERM": "dumb"}
}

// nonInteractiveEnvMap builds an env map with BYREIS_NON_INTERACTIVE=1.
func nonInteractiveEnvMap() map[string]string {
	return map[string]string{"BYREIS_NON_INTERACTIVE": "1"}
}

// TestShouldLaunchTUI covers the full G/W/T matrix from the BA-locked
// FlagsFullySpecify ruling (design/REQUIREMENTS.md).
//
// Every row below maps directly to a BA matrix entry. Column order:
// cmd, flagJSON, env, isTTYStdin, isTTYStdout, policy, currentMode,
// flagKey, flagFile, flagPR, flagNonInteractive → want bool.
func TestShouldLaunchTUI(t *testing.T) {
	t.Parallel()

	adminPol, adminMode := adminPolicy()
	contrPol, contrMode := contributorPolicy()

	type row struct {
		name               string
		cmd                string
		flagJSON           bool
		env                map[string]string
		isTTYStdin         bool
		isTTYStdout        bool
		policy             *mode.Policy
		currentMode        mode.Mode
		flagKey            string
		flagFile           string
		flagPR             string
		flagNonInteractive bool
		want               bool
	}

	rows := []row{
		// --- submit rows ---

		// Bare submit at a TTY (no --key, no --file): TUI should launch.
		{
			name:        "submit bare TTY both stdin and stdout",
			cmd:         "submit",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			flagKey:     "",
			flagFile:    "",
			flagPR:      "",
			want:        true,
		},

		// submit --key K at a TTY stdin: TUI should launch (offers masked value form).
		{
			name:        "submit --key K stdin TTY (TUI masked value form)",
			cmd:         "submit",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			flagKey:     "MY_SECRET",
			flagFile:    "",
			flagPR:      "",
			want:        true,
		},

		// submit --key K with piped stdin: headless (value via pipe).
		{
			name:        "submit --key K stdin piped (headless)",
			cmd:         "submit",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  false,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			flagKey:     "MY_SECRET",
			flagFile:    "",
			flagPR:      "",
			want:        false,
		},

		// submit --file x.env: bulk path, always headless.
		{
			name:        "submit --file x.env (bulk, headless)",
			cmd:         "submit",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			flagKey:     "",
			flagFile:    "secrets.env",
			flagPR:      "",
			want:        false,
		},

		// submit --json: suppressed.
		{
			name:        "submit --json (headless)",
			cmd:         "submit",
			flagJSON:    true,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// submit BYREIS_NON_INTERACTIVE=1: suppressed.
		{
			name:        "submit BYREIS_NON_INTERACTIVE=1",
			cmd:         "submit",
			flagJSON:    false,
			env:         nonInteractiveEnvMap(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// submit TERM=dumb: suppressed.
		{
			name:        "submit TERM=dumb",
			cmd:         "submit",
			flagJSON:    false,
			env:         dumbEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// submit non-TTY stdout (piped): suppressed.
		{
			name:        "submit non-TTY stdout (piped output)",
			cmd:         "submit",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: false,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// submit non-TTY stdin (piped input), no --key: suppressed (value via pipe).
		{
			name:        "submit non-TTY stdin without --key (piped, headless)",
			cmd:         "submit",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  false,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// submit --non-interactive flag: suppressed.
		{
			name:               "submit --non-interactive flag",
			cmd:                "submit",
			flagJSON:           false,
			env:                ttyEnv(),
			isTTYStdin:         true,
			isTTYStdout:        true,
			policy:             adminPol,
			currentMode:        adminMode,
			flagNonInteractive: true,
			want:               false,
		},

		// --- review rows ---

		// admin bare review at TTY: TUI review queue should launch.
		{
			name:        "review bare admin TTY (TUI review queue)",
			cmd:         "review",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			flagKey:     "",
			flagFile:    "",
			flagPR:      "",
			want:        true,
		},

		// review --pr X: single-PR headless print.
		{
			name:        "review --pr X (headless single-PR print)",
			cmd:         "review",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			flagPR:      "myorg/secrets#42",
			want:        false,
		},

		// contributor bare review: denied by policy → false (no half-launched TUI).
		{
			name:        "review bare contributor (policy deny, no TUI)",
			cmd:         "review",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      contrPol,
			currentMode: contrMode,
			flagKey:     "",
			flagFile:    "",
			flagPR:      "",
			want:        false,
		},

		// review --json: suppressed.
		{
			name:        "review --json (headless)",
			cmd:         "review",
			flagJSON:    true,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// review BYREIS_NON_INTERACTIVE=1: suppressed.
		{
			name:        "review BYREIS_NON_INTERACTIVE=1",
			cmd:         "review",
			flagJSON:    false,
			env:         nonInteractiveEnvMap(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// review TERM=dumb: suppressed.
		{
			name:        "review TERM=dumb",
			cmd:         "review",
			flagJSON:    false,
			env:         dumbEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// review non-TTY stdout: suppressed.
		{
			name:        "review non-TTY stdout",
			cmd:         "review",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: false,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// --- non-eligible commands ---

		// merge: never eligible.
		{
			name:        "merge (non-eligible)",
			cmd:         "merge",
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// rotate: never eligible.
		{
			name:        "rotate (non-eligible)",
			cmd:         "rotate",
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// decrypt: never eligible.
		{
			name:        "decrypt (non-eligible)",
			cmd:         "decrypt",
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// request-access: never eligible.
		{
			name:        "request-access (non-eligible)",
			cmd:         "request-access",
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      contrPol,
			currentMode: contrMode,
			want:        false,
		},

		// request list: never eligible.
		{
			name:        "request list (non-eligible)",
			cmd:         "request-list",
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// reject: never eligible.
		{
			name:        "reject (non-eligible)",
			cmd:         "reject",
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// admin add: never eligible.
		{
			name:        "admin add (non-eligible)",
			cmd:         "admin-add",
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// audit show: never eligible.
		{
			name:        "audit-show (non-eligible)",
			cmd:         "audit-show",
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// doctor: never eligible.
		{
			name:        "doctor (non-eligible)",
			cmd:         "doctor",
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// init: never eligible.
		{
			name:        "init (non-eligible)",
			cmd:         "init",
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      adminPol,
			currentMode: adminMode,
			want:        false,
		},

		// --- nil policy edge case for review ---

		// nil policy with bare review at TTY: false (safe-fail — no half-launched TUI
		// when the policy cannot be consulted). Fail closed: a nil Policy for a
		// privileged command is treated as a deny, never as a pass-through.
		{
			name:        "review bare nil policy (safe-fail no TUI)",
			cmd:         "review",
			flagJSON:    false,
			env:         ttyEnv(),
			isTTYStdin:  true,
			isTTYStdout: true,
			policy:      nil,
			currentMode: adminMode,
			want:        false,
		},
	}

	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			got := cli.ShouldLaunchTUI(
				r.cmd,
				r.flagJSON,
				r.env,
				r.isTTYStdin,
				r.isTTYStdout,
				r.policy,
				r.currentMode,
				r.flagKey,
				r.flagFile,
				r.flagPR,
				r.flagNonInteractive,
			)
			if got != r.want {
				t.Errorf("ShouldLaunchTUI(%q, ...) = %v, want %v", r.cmd, got, r.want)
			}
		})
	}
}

// TestFlagsFullySpecify exercises the per-command predicate in isolation.
func TestFlagsFullySpecify(t *testing.T) {
	t.Parallel()

	type row struct {
		name               string
		cmd                string
		env                map[string]string
		flagKey            string
		flagFile           string
		flagPR             string
		isTTYStdin         bool
		flagNonInteractive bool
		want               bool
	}

	rows := []row{
		// submit --file → true (bulk, headless).
		{
			name:     "submit --file set",
			cmd:      "submit",
			env:      ttyEnv(),
			flagFile: "prod.env",
			want:     true,
		},
		// submit --key + piped stdin → true (value via pipe, headless).
		{
			name:       "submit --key piped stdin",
			cmd:        "submit",
			env:        ttyEnv(),
			flagKey:    "DB_PASS",
			isTTYStdin: false,
			want:       true,
		},
		// submit --key + TTY stdin → false (TUI masked value form).
		{
			name:       "submit --key TTY stdin",
			cmd:        "submit",
			env:        ttyEnv(),
			flagKey:    "DB_PASS",
			isTTYStdin: true,
			want:       false,
		},
		// submit no flags, TTY stdin → false (TUI).
		{
			name:       "submit bare TTY stdin",
			cmd:        "submit",
			env:        ttyEnv(),
			isTTYStdin: true,
			want:       false,
		},
		// submit no flags, piped stdin → false (FlagsFullySpecify does not check stdin alone without --key).
		{
			name:       "submit bare piped stdin (no --key)",
			cmd:        "submit",
			env:        ttyEnv(),
			isTTYStdin: false,
			want:       false,
		},
		// submit --non-interactive → true (headless regardless).
		{
			name:               "submit --non-interactive",
			cmd:                "submit",
			env:                ttyEnv(),
			isTTYStdin:         true,
			flagNonInteractive: true,
			want:               true,
		},
		// submit BYREIS_NON_INTERACTIVE=1 env → true.
		{
			name:       "submit BYREIS_NON_INTERACTIVE env",
			cmd:        "submit",
			env:        nonInteractiveEnvMap(),
			isTTYStdin: true,
			want:       true,
		},
		// review --pr set → true (headless single-PR print).
		{
			name:   "review --pr set",
			cmd:    "review",
			env:    ttyEnv(),
			flagPR: "myorg/secrets#7",
			want:   true,
		},
		// review --pr empty → false (TUI queue).
		{
			name: "review --pr empty",
			cmd:  "review",
			env:  ttyEnv(),
			want: false,
		},
		// non-eligible command → false.
		{
			name: "merge (non-eligible)",
			cmd:  "merge",
			env:  ttyEnv(),
			want: false,
		},
		{
			name: "rotate (non-eligible)",
			cmd:  "rotate",
			env:  ttyEnv(),
			want: false,
		},
	}

	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			got := cli.FlagsFullySpecify(
				r.cmd,
				r.env,
				r.flagKey,
				r.flagFile,
				r.flagPR,
				r.isTTYStdin,
				r.flagNonInteractive,
			)
			if got != r.want {
				t.Errorf("FlagsFullySpecify(%q, ...) = %v, want %v", r.cmd, got, r.want)
			}
		})
	}
}
