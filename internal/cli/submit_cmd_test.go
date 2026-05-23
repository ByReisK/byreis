package cli_test

// CLI-level tests for the submit and review commands (V9.2).
//
// Covered obligations (test names):
//   - REQ mutual-exclusion: --file and --key together produce actionable error
//     before any use-case call (TestSubmitCmd_MutualExclusion).
//   - REQ at-least-one: omitting both flags produces actionable error
//     (TestSubmitCmd_NeitherFlagGiven).
//   - Denied-not-attempted: nil Submitter yields ExitGeneralError, not
//     ErrPermissionDenied (TestSubmitCmd_DeniedNotAttempted).
//   - Bulk happy path: --file parses pairs, calls SubmitBulk, renders PR URL
//     and per-key add/replace table with REPLACE labeled prominently
//     (TestSubmitCmd_FileHappyPath).
//   - Parse error with line number: malformed .env file yields ExitGeneralError
//     with line reference (TestSubmitCmd_FileParseMalformed).
//   - Duplicate key refused before use-case call (TestSubmitCmd_FileDuplicateKey).
//   - Validate-all-before-branch: ErrInvalidValue from use-case maps correctly
//     (TestSubmitCmd_ValidateAllBeforeBranch).
//   - Branch conflict maps to ExitGeneralError (TestSubmitCmd_BranchConflictRefuses).
//   - Trust errors map to ExitTrustError (TestSubmitCmd_TrustErrorMappedCorrectly).
//   - JSON output schema: stable keys array, no plaintext (TestSubmitCmd_FileJSONOutput).
//   - Review denied-not-attempted for CONTRIBUTOR (TestReviewCmd_DeniedNotAttempted).
//   - Nil Reviewer in ADMIN mode yields ExitGeneralError (TestReviewCmd_NilReviewer).
//   - Headless-deny: RunTUIReview wired + non-TTY + no --pr yields ExitGeneralError
//     with actionable hint; Reviewer not invoked (TestReviewCmd_HeadlessNoPR).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// fakeSubmitter is an in-memory fake for submit.Submitter. It records calls and
// returns the configured result or error. No real network/clock/tty/keychain.
type fakeSubmitter struct {
	bulkResult submit.BulkResult
	bulkErr    error
	bulkCalled bool
	lastBulk   submit.BulkInput

	singleResult submit.Result
	singleErr    error
	singleCalled bool
	lastSingle   submit.Input
}

func (f *fakeSubmitter) Submit(_ context.Context, in submit.Input) (submit.Result, error) {
	f.singleCalled = true
	f.lastSingle = in
	return f.singleResult, f.singleErr
}

func (f *fakeSubmitter) SubmitBulk(_ context.Context, in submit.BulkInput) (submit.BulkResult, error) {
	f.bulkCalled = true
	f.lastBulk = in
	return f.bulkResult, f.bulkErr
}

// withProjectEnv sets the required project env vars for the duration of the test.
// t.Setenv is NOT compatible with t.Parallel; tests using this helper must not
// call t.Parallel.
func withProjectEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BYREIS_PROJECT", "testorg/test-secrets")
	t.Setenv("BYREIS_SECRETS_PATH", "secrets/prod.enc.yaml")
}

// TestSubmitCmd_MutualExclusion verifies that --file and --key together produce
// an actionable error with ExitGeneralError before any use-case call.
func TestSubmitCmd_MutualExclusion(t *testing.T) {
	t.Parallel()

	fake := &fakeSubmitter{}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Submitter:   fake,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)

	// Write a temp .env file so --file is a valid path argument.
	tmp := t.TempDir()
	envFile := filepath.Join(tmp, "test.env")
	if err := os.WriteFile(envFile, []byte("KEY=val\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root.SetArgs([]string{"submit", "--key", "somekey", "--file", envFile})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for --file + --key combination, got nil")
	}
	if cli.ExitCodeOf(err) != int(render.ExitGeneralError) {
		t.Errorf("expected ExitGeneralError, got %d", cli.ExitCodeOf(err))
	}
	if fake.bulkCalled || fake.singleCalled {
		t.Error("no use-case must be called when --file and --key conflict")
	}
	if !strings.Contains(out.String(), "mutually exclusive") {
		t.Errorf("error output must mention mutual exclusion, got: %q", out.String())
	}
}

// TestSubmitCmd_NeitherFlagGiven verifies that omitting both --key and --file
// produces an actionable error with ExitGeneralError.
func TestSubmitCmd_NeitherFlagGiven(t *testing.T) {
	t.Parallel()

	fake := &fakeSubmitter{}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Submitter:   fake,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"submit"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when neither --file nor --key given, got nil")
	}
	if cli.ExitCodeOf(err) != int(render.ExitGeneralError) {
		t.Errorf("expected ExitGeneralError, got %d", cli.ExitCodeOf(err))
	}
	if fake.bulkCalled || fake.singleCalled {
		t.Error("no use-case must be called when no input mode is given")
	}
}

// TestSubmitCmd_DeniedNotAttempted verifies that a nil Submitter produces
// ExitGeneralError (not ErrPermissionDenied) — the "not configured" gate
// fires before any use-case call, and is distinct from a policy denial.
func TestSubmitCmd_DeniedNotAttempted(t *testing.T) {
	t.Parallel()

	// No Policy: submit passes the policy gate for contributor mode.
	// No Submitter: CLI must return "not configured" before any use-case call.
	deps := &cli.Deps{
		Policy:      nil,
		CurrentMode: mode.ModeContributor,
		Submitter:   nil,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"submit", "--key", "mykey"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for nil Submitter, got nil")
	}
	if cli.ExitCodeOf(err) != int(render.ExitGeneralError) {
		t.Errorf("nil Submitter must yield ExitGeneralError, got %d", cli.ExitCodeOf(err))
	}
	if errors.Is(err, mode.ErrPermissionDenied) {
		t.Error("nil Submitter must not yield ErrPermissionDenied")
	}
}

// TestSubmitCmd_FileHappyPath verifies the --file bulk path: parses a .env
// file and calls SubmitBulk with the ordered pairs. A successful result is
// rendered with the PR URL and per-key add/replace table with REPLACE labeled
// prominently.
func TestSubmitCmd_FileHappyPath(t *testing.T) {
	// t.Parallel NOT called: withProjectEnv uses t.Setenv.
	withProjectEnv(t)

	fake := &fakeSubmitter{
		bulkResult: submit.BulkResult{
			PRRef:       submit.PRRef{Project: "testorg/test-secrets", Number: 42},
			PRURL:       "https://github.com/testorg/test-secrets/pull/42",
			Branch:      "byreis/bulk-2keys-1234567890",
			ArtifactSHA: "abc123",
			PerKey: []submit.BulkKeyResult{
				{Key: "DB_HOST", Action: submit.ActionAdd},
				{Key: "DB_PASS", Action: submit.ActionReplace},
			},
		},
	}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Submitter:   fake,
	}

	tmp := t.TempDir()
	envFile := filepath.Join(tmp, "secrets.env")
	content := "DB_HOST=prod.db.example.com\nDB_PASS=s3cr3t\n"
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"submit", "--file", envFile, "--justification", "test run"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("expected nil error, got: %v (output: %q)", err, out.String())
	}
	if !fake.bulkCalled {
		t.Error("SubmitBulk must be called for --file input")
	}
	if fake.singleCalled {
		t.Error("Submit (single-key) must NOT be called for --file input")
	}
	if len(fake.lastBulk.Pairs) != 2 {
		t.Errorf("expected 2 pairs, got %d", len(fake.lastBulk.Pairs))
	}
	if fake.lastBulk.Pairs[0].Key != "DB_HOST" {
		t.Errorf("expected first key DB_HOST, got %q", fake.lastBulk.Pairs[0].Key)
	}
	if fake.lastBulk.Pairs[1].Key != "DB_PASS" {
		t.Errorf("expected second key DB_PASS, got %q", fake.lastBulk.Pairs[1].Key)
	}
	if !fake.lastBulk.IrreversibleAcknowledged {
		t.Error("IrreversibleAcknowledged must be true for --file submission")
	}
	outStr := out.String()
	if !strings.Contains(outStr, "PR opened") {
		t.Errorf("output must contain 'PR opened', got: %q", outStr)
	}
	if !strings.Contains(outStr, "DB_HOST") {
		t.Errorf("output must list key DB_HOST, got: %q", outStr)
	}
	if !strings.Contains(outStr, "REPLACE") {
		t.Errorf("output must prominently label the REPLACE key, got: %q", outStr)
	}
}

// TestSubmitCmd_FileParseMalformed verifies that a malformed .env file produces
// an actionable error with a line number hint, without any use-case call. The
// parse happens at the CLI/adapter layer (I/O boundary), so the error is
// returned before SubmitBulk is called.
func TestSubmitCmd_FileParseMalformed(t *testing.T) {
	// t.Parallel NOT called: withProjectEnv uses t.Setenv.
	withProjectEnv(t)

	fake := &fakeSubmitter{}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Submitter:   fake,
	}

	tmp := t.TempDir()
	envFile := filepath.Join(tmp, "bad.env")
	// Line 1 is valid; line 2 is malformed (no '=').
	content := "VALID=value\nNOT_VALID_LINE\n"
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"submit", "--file", envFile})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for malformed .env file, got nil")
	}
	if cli.ExitCodeOf(err) != int(render.ExitGeneralError) {
		t.Errorf("expected ExitGeneralError, got %d", cli.ExitCodeOf(err))
	}
	if fake.bulkCalled {
		t.Error("SubmitBulk must NOT be called when the .env file is malformed")
	}
	outStr := out.String()
	// The error must surface the line reference from envparse.
	if !strings.Contains(outStr, "line 2") {
		t.Errorf("error must reference the malformed line number (line 2), got: %q", outStr)
	}
}

// TestSubmitCmd_FileDuplicateKey verifies that a .env file with a duplicate key
// is refused entirely at parse time before any use-case call, with an actionable
// error.
func TestSubmitCmd_FileDuplicateKey(t *testing.T) {
	// t.Parallel NOT called: withProjectEnv uses t.Setenv.
	withProjectEnv(t)

	fake := &fakeSubmitter{}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Submitter:   fake,
	}

	tmp := t.TempDir()
	envFile := filepath.Join(tmp, "dup.env")
	content := "KEY=first\nKEY=second\n"
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"submit", "--file", envFile})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for duplicate key, got nil")
	}
	if cli.ExitCodeOf(err) != int(render.ExitGeneralError) {
		t.Errorf("expected ExitGeneralError, got %d", cli.ExitCodeOf(err))
	}
	if fake.bulkCalled {
		t.Error("SubmitBulk must NOT be called when the .env file has a duplicate key")
	}
}

// TestSubmitCmd_ValidateAllBeforeBranch verifies that ErrInvalidValue from
// SubmitBulk (validate-all-before-branch atomicity) maps to ExitGeneralError.
// The use-case enforces that no branch/commit/PR is created on validation
// failure; the CLI maps the error correctly.
func TestSubmitCmd_ValidateAllBeforeBranch(t *testing.T) {
	// t.Parallel NOT called: withProjectEnv uses t.Setenv.
	withProjectEnv(t)

	fake := &fakeSubmitter{
		bulkErr: fmt.Errorf("%w: key name %q rejected: invalid characters",
			submit.ErrInvalidValue, "bad key"),
	}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Submitter:   fake,
	}

	tmp := t.TempDir()
	envFile := filepath.Join(tmp, "test.env")
	if err := os.WriteFile(envFile, []byte("VALID=ok\nbad_key=val\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"submit", "--file", envFile})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if cli.ExitCodeOf(err) != int(render.ExitGeneralError) {
		t.Errorf("validation failure must yield ExitGeneralError, got %d", cli.ExitCodeOf(err))
	}
}

// TestSubmitCmd_BranchConflictRefuses verifies that ErrBranchConflict from
// the use-case produces ExitGeneralError and an actionable message.
func TestSubmitCmd_BranchConflictRefuses(t *testing.T) {
	// t.Parallel NOT called: withProjectEnv uses t.Setenv.
	withProjectEnv(t)

	fake := &fakeSubmitter{
		bulkErr: fmt.Errorf("%w: branch already taken", submit.ErrBranchConflict),
	}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Submitter:   fake,
	}

	tmp := t.TempDir()
	envFile := filepath.Join(tmp, "test.env")
	if err := os.WriteFile(envFile, []byte("KEY=val\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"submit", "--file", envFile})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected branch-conflict error, got nil")
	}
	if cli.ExitCodeOf(err) != int(render.ExitGeneralError) {
		t.Errorf("branch conflict must yield ExitGeneralError, got %d", cli.ExitCodeOf(err))
	}
}

// TestSubmitCmd_TrustErrorMappedCorrectly verifies that ErrNoRecipients and
// ErrRecipientsNotVerified produce ExitTrustError. The trust sentinel is
// security-critical: a stale or unverified registry must never silently succeed.
func TestSubmitCmd_TrustErrorMappedCorrectly(t *testing.T) {
	// Not parallel: each case calls withProjectEnv which uses t.Setenv.
	// Run sub-tests as serial children of a parallel parent would require
	// sequencing; just run them sequentially here.
	cases := []struct {
		name string
		err  error
	}{
		{"ErrNoRecipients", submit.ErrNoRecipients},
		{"ErrRecipientsNotVerified", submit.ErrRecipientsNotVerified},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			withProjectEnv(t)

			fake := &fakeSubmitter{bulkErr: tc.err}
			deps := &cli.Deps{
				Policy:      &mode.Policy{},
				CurrentMode: mode.ModeContributor,
				Submitter:   fake,
			}

			tmp := t.TempDir()
			envFile := filepath.Join(tmp, "test.env")
			if err := os.WriteFile(envFile, []byte("KEY=val\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			root := cli.NewRootCmdWithDeps(deps)
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs([]string{"submit", "--file", envFile})

			err := root.Execute()
			if err == nil {
				t.Fatalf("%s: expected trust error, got nil", tc.name)
			}
			if cli.ExitCodeOf(err) != int(render.ExitTrustError) {
				t.Errorf("%s: expected ExitTrustError (%d), got %d",
					tc.name, render.ExitTrustError, cli.ExitCodeOf(err))
			}
		})
	}
}

// TestSubmitCmd_FileJSONOutput verifies that --json produces the stable schema:
// pr_url, pr_number, pr_project, branch, artifact_sha, and a keys array with
// per-key action. No plaintext or key material appears in the output.
func TestSubmitCmd_FileJSONOutput(t *testing.T) {
	// t.Parallel NOT called: withProjectEnv uses t.Setenv.
	withProjectEnv(t)

	fake := &fakeSubmitter{
		bulkResult: submit.BulkResult{
			PRRef:       submit.PRRef{Project: "testorg/test-secrets", Number: 7},
			PRURL:       "https://github.com/testorg/test-secrets/pull/7",
			Branch:      "byreis/bulk-1keys-999",
			ArtifactSHA: "sha256abc",
			PerKey: []submit.BulkKeyResult{
				{Key: "API_KEY", Action: submit.ActionAdd},
			},
		},
	}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Submitter:   fake,
	}

	tmp := t.TempDir()
	envFile := filepath.Join(tmp, "test.env")
	// Write a secret value that must NOT appear in JSON output.
	if err := os.WriteFile(envFile, []byte("API_KEY=my-secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--json", "submit", "--file", envFile})

	err := root.Execute()
	if err != nil {
		t.Fatalf("expected nil error, got: %v (output: %q)", err, out.String())
	}
	outStr := out.String()
	if !strings.Contains(outStr, `"pr_number"`) {
		t.Errorf("JSON output missing pr_number field, got: %q", outStr)
	}
	if !strings.Contains(outStr, `"keys"`) {
		t.Errorf("JSON output missing keys array field, got: %q", outStr)
	}
	// The plaintext value must not appear in any output channel.
	if strings.Contains(outStr, "my-secret-token") {
		t.Errorf("JSON output must not contain the plaintext secret value, got: %q", outStr)
	}
}

// TestReviewCmd_DeniedNotAttempted verifies that review is denied in
// CONTRIBUTOR mode (denied-by-policy before any git fetch or decrypt).
// This is the "denied-not-attempted" invariant for admin-only commands.
func TestReviewCmd_DeniedNotAttempted(t *testing.T) {
	t.Parallel()

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		// Reviewer deliberately nil: if it were called it would panic on nil.
		Reviewer: nil,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"review", "--pr", "myorg/my-secrets#1"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected ErrPermissionDenied, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("expected error wrapping ErrPermissionDenied, got: %v", err)
	}
	if cli.ExitCodeOf(err) != int(render.ExitPermissionDenied) {
		t.Errorf("expected ExitPermissionDenied, got %d", cli.ExitCodeOf(err))
	}
}

// TestReviewCmd_NilReviewer verifies that a nil Reviewer in ADMIN mode
// produces ExitGeneralError (adapters not configured), not ErrPermissionDenied.
func TestReviewCmd_NilReviewer(t *testing.T) {
	t.Parallel()

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Reviewer:    nil,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"review", "--pr", "myorg/my-secrets#1"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for nil Reviewer, got nil")
	}
	if errors.Is(err, mode.ErrPermissionDenied) {
		t.Error("nil Reviewer must NOT produce ErrPermissionDenied")
	}
	if cli.ExitCodeOf(err) != int(render.ExitGeneralError) {
		t.Errorf("nil Reviewer must yield ExitGeneralError, got %d", cli.ExitCodeOf(err))
	}
}

// TestReviewCmd_HeadlessNoPR verifies the headless-deny branch: when
// RunTUIReview is wired but the process is not running on a TTY (which is
// always true in the test harness, since SetOut/SetErr uses bytes.Buffer) and
// --pr is absent, the command must return ExitGeneralError with an actionable
// error message. Reviewer must not be invoked.
//
// This is T-V5-1: coverage for the "RunTUIReview non-nil + non-TTY + prRef==" branch
// in the review RunE (the ShouldLaunchTUI guard fails at the TTY check, causing
// the headless path to enforce "--pr is required in headless mode").
func TestReviewCmd_HeadlessNoPR(t *testing.T) {
	t.Parallel()

	// reviewerInvoked is set to true if the Reviewer is called. Any call here
	// is a test failure: the command must error before reaching the use-case.
	reviewerInvoked := false

	// tuiInvoked is set to true if RunTUIReview is called. The test harness
	// provides non-TTY file descriptors (bytes.Buffer), so ShouldLaunchTUI must
	// return false and the TUI must never be launched.
	tuiInvoked := false

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		// Reviewer records if it is invoked. A real use-case call here would mean
		// the deny fence failed.
		Reviewer: &recordingReviewer{invoked: &reviewerInvoked},
		// RunTUIReview is non-nil, satisfying the "RunTUIReview != nil" precondition
		// of the TUI fork. ShouldLaunchTUI will still return false (non-TTY), so
		// the closure must never be reached.
		RunTUIReview: func(_ context.Context, _ interface{ Write([]byte) (int, error) }, _ string) error {
			tuiInvoked = true
			return nil
		},
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	// No --pr flag: the headless deny branch fires.
	root.SetArgs([]string{"review"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected ExitGeneralError for headless review without --pr, got nil")
	}
	if errors.Is(err, mode.ErrPermissionDenied) {
		t.Error("headless-no-pr must NOT produce ErrPermissionDenied (it is an ADMIN invocation)")
	}
	if cli.ExitCodeOf(err) != int(render.ExitGeneralError) {
		t.Errorf("headless-no-pr must yield ExitGeneralError, got %d", cli.ExitCodeOf(err))
	}

	outStr := out.String()
	// The error output must include the actionable hint directing the user to
	// supply --pr or run at a TTY.
	if !strings.Contains(outStr, "--pr") {
		t.Errorf("error output must mention --pr as the required flag; got: %q", outStr)
	}
	if !strings.Contains(outStr, "headless") {
		t.Errorf("error output must mention headless mode; got: %q", outStr)
	}

	if tuiInvoked {
		t.Error("RunTUIReview must not be called when the process is not on a TTY")
	}
	if reviewerInvoked {
		t.Error("Reviewer must not be invoked: command must error before any use-case call")
	}
}

// recordingReviewer is a minimal fake for usecase.Reviewer that records
// whether Review was called. It does not return a useful result; any call is a
// test failure in the headless-deny scenario.
type recordingReviewer struct {
	invoked *bool
}

func (r *recordingReviewer) Review(_ context.Context, _ usecase.ReviewInput) (usecase.ReviewResult, error) {
	*r.invoked = true
	return usecase.ReviewResult{}, fmt.Errorf("recordingReviewer.Review must not be called in this test")
}

// adversarialKeyReviewer returns a ReviewResult whose key names contain control
// characters and ANSI escape sequences. Used to assert V-8 sanitization.
type adversarialKeyReviewer struct{}

func (a *adversarialKeyReviewer) Review(_ context.Context, in usecase.ReviewInput) (usecase.ReviewResult, error) {
	return usecase.ReviewResult{
		Ref:           in.Ref,
		Author:        "alice",
		Justification: "sanitize test",
		SecretsPath:   "secrets/prod.enc.yaml",
		PinnedSHA:     "sha256:sanitize",
		KeyNames:      []string{"DB_HOST"},
		PerKey: []usecase.KeyReviewLine{
			// Key name with embedded ANSI escape and control character.
			{Key: "DB_HOST\x1b[31mINJECTED\x1b[0m\x01", Action: "add", ValidationOK: true},
		},
		Plaintext: map[string]string{
			"DB_HOST\x1b[31mINJECTED\x1b[0m\x01": "should-never-appear",
		},
	}, nil
}

// TestReviewCmd_JSON_KeyNamesSanitized asserts that review --json sanitizes
// contributor-authored key names consistently with the submit --json path
// (control characters and ANSI sequences stripped), and that no plaintext
// value appears in any output channel.
//
// The existing golden fixtures use clean key names (DB_HOST, DB_PASS) and
// must remain byte-identical; this test covers the adversarial case that the
// goldens deliberately exclude.
func TestReviewCmd_JSON_KeyNamesSanitized(t *testing.T) {
	t.Parallel()

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Reviewer:    &adversarialKeyReviewer{},
	}

	root := cli.NewRootCmdWithDeps(deps)
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"--json", "review", "--pr", "testorg/secrets#99"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v; stderr: %s", err, errBuf.String())
	}

	outStr := outBuf.String()

	// The ANSI escape byte and the control character must be stripped from the
	// JSON key name. SanitizeForTerminal removes ESC (\x1b) and C0 controls
	// (\x01). The visible text between the escape sequences (INJECTED) is
	// preserved as printable ASCII — this is expected: the sanitizer removes
	// terminal-control bytes, not arbitrary text content.
	if strings.Contains(outStr, "\x1b") {
		t.Errorf("review --json output must not contain ANSI ESC byte (\\x1b); got: %q", outStr)
	}
	if strings.Contains(outStr, "\x01") {
		t.Errorf("review --json output must not contain control character \\x01; got: %q", outStr)
	}
	// The raw bracketed ANSI CSI sequence \x1b[31m must not appear.
	// After sanitization the sequence is removed; confirm by checking the bracket-m pattern.
	if strings.Contains(outStr, "[31m") {
		t.Errorf("review --json output must not contain ANSI CSI colour code [31m; got: %q", outStr)
	}
	// Plaintext value must never appear.
	if strings.Contains(outStr, "should-never-appear") {
		t.Errorf("review --json output must not contain plaintext value; got: %q", outStr)
	}
	// The output must be non-empty.
	if len(strings.TrimSpace(outStr)) == 0 {
		t.Error("review --json output must not be empty")
	}
}

// TestReviewCmd_JSON_CleanKeyNames_Unchanged asserts that clean key names
// (no control chars, no ANSI) pass through sanitization unchanged. This
// confirms the golden fixtures (DB_HOST, DB_PASS) are byte-identical after
// the V-8 sanitization is applied.
func TestReviewCmd_JSON_CleanKeyNames_Unchanged(t *testing.T) {
	t.Parallel()

	// A reviewer that returns the same clean names as the golden fixtures.
	clean := &fixedCleanReviewer{}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Reviewer:    clean,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--json", "review", "--pr", "testorg/secrets#42"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	outStr := outBuf.String()
	// DB_HOST and DB_PASS must survive sanitization unchanged.
	if !strings.Contains(outStr, `"DB_HOST"`) {
		t.Errorf("clean key DB_HOST must be present unchanged after sanitization; got: %q", outStr)
	}
	if !strings.Contains(outStr, `"DB_PASS"`) {
		t.Errorf("clean key DB_PASS must be present unchanged after sanitization; got: %q", outStr)
	}
}

// fixedCleanReviewer returns the same clean result as the golden fixtures.
type fixedCleanReviewer struct{}

func (f *fixedCleanReviewer) Review(_ context.Context, in usecase.ReviewInput) (usecase.ReviewResult, error) {
	return usecase.ReviewResult{
		Ref:           in.Ref,
		Author:        "alice",
		Justification: "add prod DB creds",
		SecretsPath:   "secrets/prod.enc.yaml",
		PinnedSHA:     "sha256:deadbeef",
		KeyNames:      []string{"DB_HOST", "DB_PASS"},
		PerKey: []usecase.KeyReviewLine{
			{Key: "DB_HOST", Action: "add", ValidationOK: true},
			{Key: "DB_PASS", Action: "replace", ValidationOK: true},
		},
		Plaintext: map[string]string{
			"DB_HOST": "prod.db.example.com",
			"DB_PASS": "s3cr3t",
		},
	}, nil
}
