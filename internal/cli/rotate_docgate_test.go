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
//
//	(a) rotate.ForwardSecrecyWarning (the constant, proven by the rotate-level
//	    docgate in rotate/forward_secrecy_doc_gate_test.go), AND
//	(b) the CLI's printRotationPlan/printRotationResult output channel,
//	    proven here.
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
	coregit "github.com/ByReisK/byreis/internal/core/git"
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

// ---- V6 docgate (T-V6-14) — RequestAccessAdminWarning verbatim emission ----

// docgateFakeRequestAccessReader returns a happy-path RequestAccessFile +
// PRMetadata pair whose values satisfy every ValidateRequestAccess check, so
// the rotate-side --from-request handler reaches the warning-print stage.
// The fake records no state; each call returns the canned response.
//
// FetchPRHeadSHA returns the same HeadSHA the YAML fetch reported, so the
// force-push-race re-check passes cleanly.
type docgateFakeRequestAccessReader struct{}

const (
	docgateRequestAccessHandle = "alice"
	// docgateRequestAccessPubkey is a canonical-bech32 age recipient that
	// passes age.ParseX25519Recipient (BO-V6-CRYPTO-5); the request-access
	// schema validator refuses any other shape. Same fixture used by
	// internal/core/usecase/rotate/request_test.go.
	docgateRequestAccessPubkey  = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
	docgateRequestAccessHeadSHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
)

func (*docgateFakeRequestAccessReader) FetchRequestAccessYAML(
	_ context.Context, _ coregit.PRRef,
) (rotate.RequestAccessFile, rotate.PRMetadata, error) {
	file := rotate.RequestAccessFile{
		SchemaVersion: "byreis.request_access.v1",
		GitHubHandle:  docgateRequestAccessHandle,
		AgePubkey:     docgateRequestAccessPubkey,
		Justification: "team A onboarding",
		RequestedAt:   "2026-05-22T00:00:00Z",
	}
	prMeta := rotate.PRMetadata{
		AuthorLogin:        docgateRequestAccessHandle,
		State:              "open",
		IsDraft:            false,
		IsMerged:           false,
		HeadSHA:            docgateRequestAccessHeadSHA,
		HeadRepoOwnerLogin: docgateRequestAccessHandle,
		AuthorType:         "User",
		Commits: []rotate.CommitInfo{
			{SHA: "cafecafecafecafecafecafecafecafecafecafe", AuthorLogin: docgateRequestAccessHandle},
		},
	}
	return file, prMeta, nil
}

func (*docgateFakeRequestAccessReader) FetchPRHeadSHA(
	_ context.Context, _ coregit.PRRef,
) (string, string, error) {
	return docgateRequestAccessHeadSHA, docgateRequestAccessHandle, nil
}

// ListOpenRequests is not exercised by the docgate --from-request fixtures; it
// satisfies the RequestAccessReader port so the fake still compiles.
func (*docgateFakeRequestAccessReader) ListOpenRequests(
	_ context.Context,
) ([]rotate.OpenRequestSummary, error) {
	return nil, nil
}

// ListOpenRequestsBounded is not exercised by the docgate --from-request
// fixtures; it satisfies the RequestAccessReader port so the fake compiles.
func (*docgateFakeRequestAccessReader) ListOpenRequestsBounded(
	_ context.Context,
) ([]rotate.OpenRequestSummary, bool, error) {
	return nil, false, nil
}

// docgateFakeRotatorFromRequest accepts the rotation input the CLI hands it
// after --from-request validation completes and returns a completed result.
// HasRemovals=false because --from-request is an additive --add path; the
// forward-secrecy warning is irrelevant on this row.
type docgateFakeRotatorFromRequest struct{}

func (*docgateFakeRotatorFromRequest) Rotate(
	_ context.Context, _ rotate.RotationInput,
) (rotate.RotationResult, error) {
	return rotate.RotationResult{
		Plan: rotate.RotationPlan{
			ProjectID:   "docgate-proj",
			NewEpoch:    2,
			HasRemovals: false,
		},
		DryRun: false,
		Phase2: rotate.Phase2Result{
			MergedSHA:         "1111111111111111111111111111111111111111",
			CommitRotationSHA: "2222222222222222222222222222222222222222",
			NewEpoch:          2,
		},
	}, nil
}

// TestDocGate_RequestAccessAdminWarning_VerbatimEmitted is the V6 docgate row
// for T-V6-14.
//
// It drives `byreis rotate --project <id> --add --from-request <PR> --yes`
// through the REAL cobra root (cli.NewRootCmdWithDeps) with:
//   - A fake RequestAccessReader that returns a happy-path YAML + PR meta
//     pair, so ValidateRequestAccess succeeds and the warning-print stage
//     is reached. (Mismatch refusals never reach the warning emission.)
//   - A fake Rotator that records the call and returns a completed result.
//   - --yes to skip the typed-fingerprint confirm (the warning emits BEFORE
//     the confirm prompt, but skipping the prompt keeps the test
//     deterministic without an stdin pipe).
//
// The assertion: stdout contains the verbatim
// rotate.RequestAccessAdminWarning constant, byte-for-byte. The Go constant
// is the single source of truth; the test does not re-declare the string.
func TestDocGate_RequestAccessAdminWarning_VerbatimEmitted(t *testing.T) {
	t.Parallel()

	deps := &cli.Deps{
		Policy:              &mode.Policy{},
		CurrentMode:         mode.ModeAdmin,
		Rotator:             &docgateFakeRotatorFromRequest{},
		RequestAccessReader: &docgateFakeRequestAccessReader{},
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	root := cli.NewRootCmdWithDeps(deps)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{
		"rotate",
		"--project", "docgate-proj",
		"--add", docgateRequestAccessPubkey,
		"--from-request", "myorg/byreis-admins#42",
		"--yes",
	})

	if execErr := root.ExecuteContext(context.Background()); execErr != nil {
		t.Fatalf("V6 T-V6-14: rotate --add --from-request --yes exited with error: %v "+
			"(stderr=%q, stdout=%q)", execErr, stderr.String(), stdout.String())
	}

	got := stdout.String()

	// T-V6-14 assertion: the verbatim rotate.RequestAccessAdminWarning must
	// appear in stdout. A missing or truncated warning is release-blocking:
	// operators rely on this admin-honesty paragraph to understand the
	// PR-author-vs-YAML byte-compare semantics before they type the
	// SHA-256 fingerprint confirm.
	want := rotate.RequestAccessAdminWarning //nolint:forbidigo // boundary: equality assertion only
	if !strings.Contains(got, want) {
		t.Fatalf("V6 T-V6-14: stdout does not contain the verbatim "+
			"RequestAccessAdminWarning.\nThis is release-blocking: the CLI must "+
			"emit the full admin-warning block before the typed-fingerprint "+
			"confirm, so operators cannot miss the BO-3 PR-author-vs-YAML "+
			"semantics.\n\nwant (substring):\n%q\n\ngot (full stdout):\n%q",
			want, got)
	}

	// The constant ends with a trailing newline + blank line (so its closing
	// boundary is `Mismatch refuses the rotation.\n\n`). Confirm the boundary
	// marker is present so a future refactor cannot silently drop the trailing
	// whitespace block and still match a prefix-only substring.
	const trailingBoundary = "Mismatch refuses the rotation.\n\n"
	if !strings.Contains(got, trailingBoundary) {
		t.Errorf("V6 T-V6-14: warning trailing boundary marker missing — "+
			"the constant ends with %q but emission truncated it.\n"+
			"got:\n%q", trailingBoundary, got)
	}

	t.Logf("V6 T-V6-14: PASS — stdout contains the verbatim "+
		"RequestAccessAdminWarning (%d chars) with trailing boundary intact",
		len(want))
}
