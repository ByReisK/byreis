//go:build docgate

// V5.R4a-CLI (REQ-R-003-DOC R4a + BO-V4-5 §V4 ship-gate addendum) — CLI
// forward-secrecy warning verbatim docgate row.
//
// This file discharges the V5.R4a-CLI obligation: given
// `byreis rotate --remove <pubkey>` (or --dry-run with --remove) the CLI
// stdout output contains the verbatim rotate.ForwardSecrecyWarning string.
//
// Assertion shape:
//   - A fake Rotator returns a plan with HasRemovals=true.
//   - The CLI's printRotationPlan function emits the verbatim
//     rotate.ForwardSecrecyWarning constant to stdout.
//   - The test asserts stdout contains every character of the constant.
//
// This is a three-way cross-check at the CLI boundary:
//   (a) rotate.ForwardSecrecyWarning (the constant, proven by the rotate-level
//       docgate in rotate/forward_secrecy_doc_gate_test.go), AND
//   (b) the CLI's printRotationPlan/printRotationResult output channel,
//       proven here.
//
// Build constraint: //go:build docgate ONLY. This tag is a sibling lane to
// shipgate; it is non-default, never compiled into a shipped binary.
//
// The test uses a fake Rotator (no real git/registry/network) consistent with
// the injected-clock/fs/keychain standard: unit tests for CLI output never
// require real network or real production fixtures.
package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// docgateHasRemovalsPlan is a pre-built RotationPlan with HasRemovals=true
// and one removed recipient, matching the precondition for the warning to fire.
var docgateHasRemovalsPlan = rotate.RotationPlan{
	ProjectID: "docgate-proj",
	NewRecipientSet: []rectypes.Recipient{
		{AgePubKey: "age1remainingrecipient000000000000000000000000000000000000000000"},
	},
	AddedRecipients: nil,
	RemovedRecipients: []rectypes.Recipient{
		{AgePubKey: "age1removedrecipient00000000000000000000000000000000000000000000"},
	},
	FilesToReencrypt: []rotate.FileSnapshot{
		{LogicalName: "prod"},
	},
	NewEpoch:    1,
	HasRemovals: true,
}

// docgateFakeRotatorWithRemovals returns a fake Rotator that returns
// docgateHasRemovalsPlan as a dry-run result (DryRun=true).
type docgateFakeRotatorWithRemovals struct{}

func (*docgateFakeRotatorWithRemovals) Rotate(_ context.Context, in rotate.RotationInput) (rotate.RotationResult, error) {
	return rotate.RotationResult{
		Plan:   docgateHasRemovalsPlan,
		DryRun: true,
	}, nil
}

// TestV5R4aCLI_RotateRemoveDryRunEmitsVerbatimForwardSecrecyWarning is the
// V5.R4a-CLI docgate row.
//
// It drives the `byreis rotate --remove <pubkey> --dry-run --yes` path
// through the REAL cobra root (cli.NewRootCmdWithDeps) with a fake Rotator
// that returns a plan with HasRemovals=true. The assertion: stdout contains
// the verbatim rotate.ForwardSecrecyWarning constant, byte-for-byte.
//
// This is NOT a structured t.Skip stub; the test drives real CLI code over
// a real fake Rotator and asserts the R4a verbatim-warning invariant.
func TestV5R4aCLI_RotateRemoveDryRunEmitsVerbatimForwardSecrecyWarning(t *testing.T) {
	t.Parallel()

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Rotator:     &docgateFakeRotatorWithRemovals{},
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	root := cli.NewRootCmdWithDeps(deps)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{
		"rotate",
		"--project", "docgate-proj",
		"--remove", "age1removedrecipient00000000000000000000000000000000000000000000",
		"--dry-run",
		"--yes",
	})

	execErr := root.ExecuteContext(context.Background())
	if execErr != nil {
		t.Fatalf("V5.R4a-CLI: rotate --remove --dry-run exited with error: %v "+
			"(stderr=%q, stdout=%q)", execErr, stderr.String(), stdout.String())
	}

	got := stdout.String()

	// R4a assertion: the verbatim rotate.ForwardSecrecyWarning must appear
	// in stdout. A missing or truncated warning is a release-blocker.
	want := rotate.ForwardSecrecyWarning //nolint:forbidigo // boundary: R4a CLI-output equality assertion
	if !strings.Contains(got, want) {
		t.Fatalf("V5.R4a-CLI: stdout does not contain the verbatim ForwardSecrecyWarning.\n"+
			"This is R4a release-blocking: the CLI must emit the full forward-secrecy\n"+
			"warning when recipients are removed, so operators cannot miss the git-history\n"+
			"retention risk.\n\n"+
			"want (substring):\n%q\n\n"+
			"got (full stdout):\n%q",
			want, got)
	}

	t.Logf("V5.R4a-CLI: PASS — stdout contains the verbatim ForwardSecrecyWarning "+
		"(%d chars)", len(want))
}

// TestV5R4aCLI_RotateRemoveNonDryRunEmitsVerbatimForwardSecrecyWarning proves
// the warning is also emitted on the non-dry-run (completed rotation) path.
// The fake Rotator returns DryRun=false; printRotationResult must also emit
// the warning when HasRemovals is true.
func TestV5R4aCLI_RotateRemoveNonDryRunEmitsVerbatimForwardSecrecyWarning(t *testing.T) {
	t.Parallel()

	completed := &docgateFakeRotatorCompleted{}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Rotator:     completed,
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	root := cli.NewRootCmdWithDeps(deps)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{
		"rotate",
		"--project", "docgate-proj",
		"--remove", "age1removedrecipient00000000000000000000000000000000000000000000",
		"--yes",
	})

	execErr := root.ExecuteContext(context.Background())
	if execErr != nil {
		t.Fatalf("V5.R4a-CLI (non-dry-run): rotate --remove exited with error: %v "+
			"(stderr=%q, stdout=%q)", execErr, stderr.String(), stdout.String())
	}

	got := stdout.String()
	want := rotate.ForwardSecrecyWarning //nolint:forbidigo // boundary: R4a CLI-output equality assertion
	if !strings.Contains(got, want) {
		t.Fatalf("V5.R4a-CLI (non-dry-run): stdout does not contain the verbatim "+
			"ForwardSecrecyWarning.\n\nwant (substring):\n%q\n\ngot:\n%q", want, got)
	}

	t.Logf("V5.R4a-CLI (non-dry-run): PASS — completed rotation emits verbatim warning")
}

// docgateFakeRotatorCompleted simulates a completed (non-dry-run) rotation
// with HasRemovals=true so printRotationResult is exercised.
type docgateFakeRotatorCompleted struct{}

func (*docgateFakeRotatorCompleted) Rotate(_ context.Context, _ rotate.RotationInput) (rotate.RotationResult, error) {
	return rotate.RotationResult{
		Plan:   docgateHasRemovalsPlan,
		DryRun: false,
		Phase2: rotate.Phase2Result{
			MergedSHA:         "aaaa0000000000000000000000000000000000000000",
			CommitRotationSHA: "bbbb1111111111111111111111111111111111111111",
			NewEpoch:          1,
		},
	}, nil
}

