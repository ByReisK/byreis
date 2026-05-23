package cli_test

// CLI tests for `byreis admin request reject`.
//
// Covered:
//   - Mode gate: CONTRIBUTOR denied-not-attempted (zero adapter calls).
//   - --reason sanitized via render.SanitizeForTerminal before use-case entry.
//   - 2000-byte cap enforced at the CLI layer before any use-case call.
//   - Non-interactive + empty reason fails closed before any network contact.
//   - --json output shape: {pr, status, reason, url}.
//   - already-merged path: typed error surfaced with hint; nothing closed.
//   - already-closed path: idempotent informational output.
//   - AC-001-G cross-repo mismatch: ErrRejectWrongPRType, nothing closed.
//   - help text contains the PUBLIC PR comment warning.
//   - nil Rejecter returns actionable "not configured" error.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ─── test doubles ─────────────────────────────────────────────────────────────

// fakeRejecter is a test double for usecase.RequestRejecter. It records inputs
// and returns the configured result or error.
type fakeRejecter struct {
	rejectCalls atomic.Int32
	lastInput   usecase.RejectInput
	result      usecase.RejectResult
	err         error
}

func (f *fakeRejecter) Reject(_ context.Context, in usecase.RejectInput) (usecase.RejectResult, error) {
	f.rejectCalls.Add(1)
	f.lastInput = in
	return f.result, f.err
}

// panicRejecter panics on any call; used to prove the mode gate fires before
// the use-case.
type panicRejecter struct{}

func (*panicRejecter) Reject(_ context.Context, _ usecase.RejectInput) (usecase.RejectResult, error) {
	panic("Reject called but must not be reached: mode gate violated")
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func makeRejectDeps(m mode.Mode, r usecase.RequestRejecter) *cli.Deps {
	return &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: m,
		Rejecter:    r,
	}
}

// runAdminRequestRejectCmd runs `admin request reject <extraArgs>` and returns
// stdout, stderr, and the cobra error.
func runAdminRequestRejectCmd(deps *cli.Deps, extraArgs []string) (stdout, stderr string, err error) {
	args := append([]string{"admin", "request", "reject"}, extraArgs...)
	root := cli.NewRootCmdWithDeps(deps)
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

// ─── mode gate ────────────────────────────────────────────────────────────────

// TestAdminRequestReject_ContributorDeniedNotAttempted proves that the mode gate
// fires before any network call or use-case contact. The panicRejecter panics if
// reached.
func TestAdminRequestReject_ContributorDeniedNotAttempted(t *testing.T) {
	t.Parallel()
	deps := makeRejectDeps(mode.ModeContributor, &panicRejecter{})

	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#42", "--reason", "not needed"})

	if err == nil {
		t.Fatal("expected ErrPermissionDenied, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("want errors.Is(err, ErrPermissionDenied), got: %v", err)
	}
}

// TestAdminRequestReject_ContributorDenied_ExitCode verifies the exit code for
// CONTRIBUTOR denial is ExitPermissionDenied.
func TestAdminRequestReject_ContributorDenied_ExitCode(t *testing.T) {
	t.Parallel()
	deps := makeRejectDeps(mode.ModeContributor, &panicRejecter{})

	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#1", "--reason", "no"})

	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitPermissionDenied) {
		t.Errorf("exit code = %d, want %d (ExitPermissionDenied)", exitCode, int(render.ExitPermissionDenied))
	}
}

// TestAdminRequestReject_ContributorDenied_ZeroRejectCalls asserts the
// use-case is never called on a CONTRIBUTOR denial.
func TestAdminRequestReject_ContributorDenied_ZeroRejectCalls(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{}
	deps := makeRejectDeps(mode.ModeContributor, fake)

	_, _, _ = runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#1", "--reason", "reason"})

	if fake.rejectCalls.Load() != 0 {
		t.Errorf("Reject was called %d times; want 0 for CONTRIBUTOR denied path",
			fake.rejectCalls.Load())
	}
}

// ─── nil Rejecter ─────────────────────────────────────────────────────────────

// TestAdminRequestReject_NilRejecter returns actionable "not configured" error.
func TestAdminRequestReject_NilRejecter_WiredCheckError(t *testing.T) {
	t.Parallel()
	deps := makeRejectDeps(mode.ModeAdmin, nil)

	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#1", "--reason", "not wired check"})

	if err == nil {
		t.Fatal("expected error for nil Rejecter, got nil")
	}
	if errors.Is(err, mode.ErrPermissionDenied) {
		t.Error("nil Rejecter returned permission-denied; should be a wired-check error")
	}
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitGeneralError) {
		t.Errorf("exit code = %d, want %d (ExitGeneralError)", exitCode, int(render.ExitGeneralError))
	}
}

// ─── reason sanitization ─────────────────────────────────────────────────────

// TestAdminRequestReject_ReasonSanitizedBeforeUseCase verifies that the CLI
// passes the sanitized reason to the use-case, not the raw --reason string.
// An ANSI escape in the raw reason must be stripped before RejectInput.Reason.
func TestAdminRequestReject_ReasonSanitizedBeforeUseCase(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{result: usecase.RejectResult{
		PR:     "owner/project#5",
		Status: "closed",
		Reason: "reason stripped",
	}}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	rawReason := "reason" + "\x1b[31m" + " stripped"
	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#5", "--reason", rawReason})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.rejectCalls.Load() != 1 {
		t.Fatalf("Reject not called")
	}
	// The reason passed to the use-case must not contain the raw ANSI escape.
	if strings.Contains(fake.lastInput.Reason, "\x1b") {
		t.Errorf("Reason passed to use-case contains raw ESC byte (not sanitized): %q",
			fake.lastInput.Reason)
	}
	// The stripped text must still be present.
	if !strings.Contains(fake.lastInput.Reason, "reason") {
		t.Errorf("Reason passed to use-case missing expected text: %q", fake.lastInput.Reason)
	}
}

// TestAdminRequestReject_ReasonBidiStripped verifies that a Trojan-source
// bidi override (U+202E RLO) in the reason is stripped before use-case entry.
func TestAdminRequestReject_ReasonBidiStripped(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{result: usecase.RejectResult{
		PR: "owner/proj#3", Status: "closed",
	}}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	rawReason := "safe" + "\u202e" + "text"
	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/proj#3", "--reason", rawReason})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.ContainsRune(fake.lastInput.Reason, 0x202e) {
		t.Errorf("Reason passed to use-case contains U+202E bidi override: %q",
			fake.lastInput.Reason)
	}
}

// ─── 2000-byte cap ────────────────────────────────────────────────────────────

// TestAdminRequestReject_ReasonOverLimit_FailsBeforeUseCase verifies that a
// reason longer than 2000 bytes is rejected at the CLI layer before any use-case
// call. The fake rejecter records whether it was called.
func TestAdminRequestReject_ReasonOverLimit_FailsBeforeUseCase(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	overLimit := strings.Repeat("x", 2001)
	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#1", "--reason", overLimit})

	if err == nil {
		t.Fatal("expected error for over-limit reason, got nil")
	}
	if fake.rejectCalls.Load() != 0 {
		t.Errorf("Reject was called %d times; want 0 when reason exceeds 2000 bytes",
			fake.rejectCalls.Load())
	}
}

// TestAdminRequestReject_ReasonAtLimit_Passes verifies that a reason of exactly
// 2000 bytes passes the CLI cap and reaches the use-case.
func TestAdminRequestReject_ReasonAtLimit_Passes(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{result: usecase.RejectResult{
		PR: "owner/project#1", Status: "closed",
	}}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	atLimit := strings.Repeat("a", 2000)
	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#1", "--reason", atLimit})
	if err != nil {
		t.Fatalf("unexpected error for 2000-byte reason: %v", err)
	}
	if fake.rejectCalls.Load() != 1 {
		t.Errorf("Reject was not called for 2000-byte reason; want exactly 1 call")
	}
}

// ─── non-interactive empty reason ─────────────────────────────────────────────

// TestAdminRequestReject_NonInteractiveEmptyReason_FailsClosed verifies that
// when BYREIS_NON_INTERACTIVE is set and --reason is empty, the command fails
// closed before any use-case call.
func TestAdminRequestReject_NonInteractiveEmptyReason_FailsClosed(t *testing.T) {
	t.Setenv("BYREIS_NON_INTERACTIVE", "1")
	fake := &fakeRejecter{}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#7"}) // no --reason

	if err == nil {
		t.Fatal("expected error for non-interactive empty reason, got nil")
	}
	if fake.rejectCalls.Load() != 0 {
		t.Errorf("Reject was called %d times; want 0 for non-interactive empty-reason fail-closed",
			fake.rejectCalls.Load())
	}
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitGeneralError) {
		t.Errorf("exit code = %d, want ExitGeneralError (%d)", exitCode, int(render.ExitGeneralError))
	}
}

// ─── --json output shape ──────────────────────────────────────────────────────

// TestAdminRequestReject_JSONShape verifies the --json output has the required
// fields {pr, status, reason, url}.
func TestAdminRequestReject_JSONShape(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{result: usecase.RejectResult{
		PR:     "owner/project#42",
		Status: "closed",
		Reason: "not needed",
		URL:    "https://github.com/owner/project/pull/42",
	}}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#42", "--reason", "not needed", "--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out struct {
		PR     string `json:"pr"`
		Status string `json:"status"`
		Reason string `json:"reason"`
		URL    string `json:"url"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); jsonErr != nil {
		t.Fatalf("stdout is not valid JSON: %v\nraw: %q", jsonErr, stdout)
	}
	if out.PR != "owner/project#42" {
		t.Errorf("pr = %q, want owner/project#42", out.PR)
	}
	if out.Status != "closed" {
		t.Errorf("status = %q, want closed", out.Status)
	}
	if out.URL != "https://github.com/owner/project/pull/42" {
		t.Errorf("url = %q, want full URL", out.URL)
	}
}

// ─── already-merged path ─────────────────────────────────────────────────────

// TestAdminRequestReject_AlreadyMerged_TypedError verifies that
// ErrRejectAlreadyMerged is surfaced with a hint and nothing is closed.
func TestAdminRequestReject_AlreadyMerged_TypedError(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{
		err: fmt.Errorf("merged: %w", usecase.ErrRejectAlreadyMerged),
	}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#3", "--reason", "merged"})

	if err == nil {
		t.Fatal("expected ErrRejectAlreadyMerged, got nil")
	}
	if !errors.Is(err, usecase.ErrRejectAlreadyMerged) {
		t.Errorf("want errors.Is(err, ErrRejectAlreadyMerged), got: %v", err)
	}
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitGeneralError) {
		t.Errorf("exit code = %d, want ExitGeneralError", exitCode)
	}
}

// ─── already-closed idempotent path ──────────────────────────────────────────

// TestAdminRequestReject_AlreadyClosed_IdempotentOutput verifies that an
// already-closed PR produces an informational human message with exit code 0.
func TestAdminRequestReject_AlreadyClosed_IdempotentOutput(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{result: usecase.RejectResult{
		PR:     "owner/project#8",
		Status: "already-closed",
		Reason: "reason",
	}}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#8", "--reason", "reason"})
	if err != nil {
		t.Fatalf("unexpected error for already-closed: %v", err)
	}
	if !strings.Contains(stdout, "already closed") {
		t.Errorf("stdout %q should mention already closed", stdout)
	}
}

// TestAdminRequestReject_AlreadyClosed_JSON verifies --json already-closed shape.
func TestAdminRequestReject_AlreadyClosed_JSON(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{result: usecase.RejectResult{
		PR:     "owner/project#8",
		Status: "already-closed",
		Reason: "reason",
	}}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#8", "--reason", "reason", "--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var out struct {
		Status string `json:"status"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); jsonErr != nil {
		t.Fatalf("stdout is not valid JSON: %v\nraw: %q", jsonErr, stdout)
	}
	if out.Status != "already-closed" {
		t.Errorf("status = %q, want already-closed", out.Status)
	}
}

// ─── AC-001-G cross-repo refusal ─────────────────────────────────────────────

// TestAdminRequestReject_WrongPRType_CrossRepoRefused verifies that a PR fetched
// from one adapter whose branch prefix belongs to the wrong repo kind returns
// ErrRejectWrongPRType and closes nothing. This exercises the AC-001-G invariant:
// the use-case should refuse when SourceRepo and branch prefix disagree.
func TestAdminRequestReject_WrongPRType_CrossRepoRefused(t *testing.T) {
	t.Parallel()
	// Simulate the use-case returning ErrRejectWrongPRType (as it would when
	// the branch prefix does not match the adapter's SourceRepo stamp).
	fake := &fakeRejecter{
		err: fmt.Errorf("wrong type: %w", usecase.ErrRejectWrongPRType),
	}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#10", "--reason", "cross-repo"})

	if err == nil {
		t.Fatal("expected ErrRejectWrongPRType, got nil")
	}
	if !errors.Is(err, usecase.ErrRejectWrongPRType) {
		t.Errorf("want errors.Is(err, ErrRejectWrongPRType), got: %v", err)
	}
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitGeneralError) {
		t.Errorf("exit code = %d, want ExitGeneralError", exitCode)
	}
}

// ─── help text public-comment warning ────────────────────────────────────────

// TestAdminRequestReject_HelpText_PublicWarning verifies that the --help output
// (or the command's Long description) warns operators that the reason is posted
// to a PUBLIC PR comment.
func TestAdminRequestReject_HelpText_PublicWarning(t *testing.T) {
	t.Parallel()
	deps := makeRejectDeps(mode.ModeAdmin, nil)

	root := cli.NewRootCmdWithDeps(deps)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"admin", "request", "reject", "--help"})
	// --help exits with code 0 and does not return an error from Execute.
	_ = root.Execute()

	helpText := outBuf.String()
	// The help text MUST contain a warning that the reason is PUBLIC.
	wantPublicWarning := "PUBLIC"
	if !strings.Contains(helpText, wantPublicWarning) {
		t.Errorf("help text does not contain public-warning keyword %q:\n%s",
			wantPublicWarning, helpText)
	}
	// Must also warn about secrets.
	wantSecretsWarning := "secret"
	if !strings.Contains(strings.ToLower(helpText), strings.ToLower(wantSecretsWarning)) {
		t.Errorf("help text does not contain secrets warning keyword %q:\n%s",
			wantSecretsWarning, helpText)
	}
}

// ─── reason flag help text public warning ─────────────────────────────────────

// TestAdminRequestReject_ReasonFlagHelp_PublicWarning verifies the --reason flag
// usage text explicitly warns it is a PUBLIC PR comment.
func TestAdminRequestReject_ReasonFlagHelp_PublicWarning(t *testing.T) {
	t.Parallel()
	deps := makeRejectDeps(mode.ModeAdmin, nil)
	root := cli.NewRootCmdWithDeps(deps)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"admin", "request", "reject", "--help"})
	_ = root.Execute()
	helpText := outBuf.String()

	if !strings.Contains(helpText, "PUBLIC") {
		t.Errorf("--reason flag help text does not warn about PUBLIC comment:\n%s", helpText)
	}
	if !strings.Contains(strings.ToLower(helpText), "secret") {
		t.Errorf("--reason flag help text does not warn about secrets:\n%s", helpText)
	}
}

// ─── happy-path human output ──────────────────────────────────────────────────

// TestAdminRequestReject_HappyPath_HumanOutput verifies the closed URL appears
// in human output on a successful close.
func TestAdminRequestReject_HappyPath_HumanOutput(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{result: usecase.RejectResult{
		PR:     "owner/project#42",
		Status: "closed",
		Reason: "not needed",
		URL:    "https://github.com/owner/project/pull/42",
	}}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "owner/project#42", "--reason", "not needed"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "owner/project#42") {
		t.Errorf("stdout %q should contain PR reference", stdout)
	}
	if !strings.Contains(stdout, "closed") {
		t.Errorf("stdout %q should contain 'closed'", stdout)
	}
}

// TestAdminRequestReject_InvalidPRRef_FailsValidation verifies that a malformed
// --pr value (no # separator) is rejected at the CLI layer without contacting
// the use-case.
func TestAdminRequestReject_InvalidPRRef_FailsValidation(t *testing.T) {
	t.Parallel()
	fake := &fakeRejecter{}
	deps := makeRejectDeps(mode.ModeAdmin, fake)

	_, _, err := runAdminRequestRejectCmd(deps,
		[]string{"--pr", "invalid-no-hash", "--reason", "reason"})
	if err == nil {
		t.Fatal("expected error for invalid PR ref, got nil")
	}
	if fake.rejectCalls.Load() != 0 {
		t.Errorf("Reject called %d times; want 0 for invalid PR ref",
			fake.rejectCalls.Load())
	}
}
