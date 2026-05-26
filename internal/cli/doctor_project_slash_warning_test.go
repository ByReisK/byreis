package cli_test

// REQ-V05-005 (a): the v0.4 S0.5 slice added a `byreis doctor` WARN finding
// when BYREIS_PROJECT contains a slash — under the two-var contract,
// BYREIS_PROJECT must be the slash-free logical project id and the owner/repo
// slug lives in BYREIS_PROJECT_REPO. That warning path shipped UNTESTED; this
// table-driven test pins it: the WARN fires (and is prepended) on a slashed
// value and is silent on a clean value, without depending on any other check.

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// projectSlashStubDoctor returns a fixed, all-clean DoctorResult so the only
// finding that can appear is the CLI-layer BYREIS_PROJECT slash advisory. It
// performs no I/O and ignores ctx — the warning decision is the unit under test,
// not the health checks.
type projectSlashStubDoctor struct{}

func (projectSlashStubDoctor) Diagnose(context.Context) (usecase.DoctorResult, error) {
	return usecase.DoctorResult{
		Mode:       mode.ModeContributor,
		ModeReason: "stub: no key file present",
		Findings:   nil,
	}, nil
}

// runDoctorForSlashWarning drives `byreis doctor` through the real cobra root
// with a clean stub Doctor wired and returns stdout. doctor is allowed in every
// mode, so CONTRIBUTOR is sufficient and avoids any key/decrypt setup.
func runDoctorForSlashWarning(t *testing.T) string {
	t.Helper()

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Doctor:      projectSlashStubDoctor{},
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	root := cli.NewRootCmdWithDeps(deps)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{"doctor"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("doctor: unexpected error: %v (stderr=%q)", err, stderr.String())
	}
	return stdout.String()
}

func TestDoctor_ProjectSlashWarning(t *testing.T) {
	// The slash-warning advisory text, anchored on the stable distinguishing
	// phrase the CLI emits. Asserting on the phrase (not the whole sentence)
	// keeps the test robust to wording tweaks while still proving the WARN fired.
	const slashWarningPhrase = "looks like an owner/repo slug"

	tests := []struct {
		name        string
		project     string
		wantWarning bool
	}{
		{
			name:        "slashed value warns",
			project:     "myorg/myapp",
			wantWarning: true,
		},
		{
			name:        "nested slash warns",
			project:     "myorg/group/myapp",
			wantWarning: true,
		},
		{
			name:        "slash-free value is silent",
			project:     "myapp",
			wantWarning: false,
		},
		{
			name:        "empty value is silent",
			project:     "",
			wantWarning: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv forbids t.Parallel; the doctor command reads
			// os.Getenv("BYREIS_PROJECT") directly, so we set it per-case and
			// let Setenv restore it on cleanup. BYREIS_PROJECT_REPO is left
			// unset — the advisory keys only off BYREIS_PROJECT.
			t.Setenv("BYREIS_PROJECT", tc.project)

			out := runDoctorForSlashWarning(t)
			gotWarning := strings.Contains(out, slashWarningPhrase)

			if gotWarning != tc.wantWarning {
				t.Errorf("BYREIS_PROJECT=%q: slash-warning present=%v, want %v\noutput:\n%s",
					tc.project, gotWarning, tc.wantWarning, out)
			}

			// When the warning fires it must carry the offending value and name
			// the correct remediation variable, so the operator can act on it.
			if tc.wantWarning {
				if !strings.Contains(out, tc.project) {
					t.Errorf("warning must echo the offending BYREIS_PROJECT=%q value, got:\n%s",
						tc.project, out)
				}
				if !strings.Contains(out, "BYREIS_PROJECT_REPO") {
					t.Errorf("warning must name BYREIS_PROJECT_REPO as the fix, got:\n%s", out)
				}
			}
		})
	}
}
