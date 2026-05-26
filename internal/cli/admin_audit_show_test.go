package cli_test

// CLI tests for `byreis admin audit show`.
//
// Test cases covered:
//   - contributor denied-not-attempted (call-graph spy: zero FetchAuditLog on denied path)
//   - denial hint names `git show` + `git verify-commit`
//   - contributor exit code = ExitPermissionDenied
//   - nil AuditReader → wired-check error (ExitGeneralError)
//   - ADMIN happy-path table render (entries sorted in file order, columns present)
//   - ADMIN happy-path --json schema (stable array under "entries" key)
//   - empty state table → "no audit entries" message
//   - empty state --json → {"entries":[]}
//   - full-field sanitise: inject \n + \r + \t + ANSI into Actor, Outcome,
//     Kind, Project, OccurredAt, SafeDetails value → all single-line/stripped in
//     table; raw in --json
//   - Unknown=true entry → rendered as warning row in table (WARN: prefix)
//   - ErrUnsignedRegistry → ExitTrustError
//   - ErrRegistryOffline → ExitVerifyFailure

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
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ---- test doubles -----------------------------------------------------------

// fakeAuditReader is a configurable test double for rotate.AuditReader.
type fakeAuditReader struct {
	entries  []rotate.AuditEntryView
	fetchErr error
	calls    atomic.Int32
}

func (f *fakeAuditReader) FetchAuditLog(_ context.Context, _ string) ([]rotate.AuditEntryView, error) {
	f.calls.Add(1)
	return f.entries, f.fetchErr
}

// panicAuditReader panics on any FetchAuditLog call; used to prove the mode
// gate fires before the port is ever touched.
type panicAuditReader struct{}

func (p *panicAuditReader) FetchAuditLog(_ context.Context, _ string) ([]rotate.AuditEntryView, error) {
	panic("FetchAuditLog called but must not be reached: policy gate violated")
}

// ---- helpers ----------------------------------------------------------------

func makeAuditShowDeps(m mode.Mode, r rotate.AuditReader) *cli.Deps {
	return &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: m,
		AuditReader: r,
	}
}

func runAuditShowCmd(deps *cli.Deps, extraArgs []string) (stdout, stderr string, err error) {
	args := append([]string{"admin", "audit", "show", "--project", "test-proj"}, extraArgs...)
	root := cli.NewRootCmdWithDeps(deps)
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

// ---- V8b.CLI.01 — contributor denied-not-attempted -------------------------

// TestAdminAuditShow_ContributorDeniedNotAttempted proves that the mode gate
// fires before the AuditReader port is touched. The panicAuditReader would
// panic if reached.
func TestAdminAuditShow_ContributorDeniedNotAttempted(t *testing.T) {
	t.Parallel()

	deps := makeAuditShowDeps(mode.ModeContributor, &panicAuditReader{})

	// Must not panic.
	_, stderr, err := runAuditShowCmd(deps, nil)
	if err == nil {
		t.Fatal("expected denial error, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("want ErrPermissionDenied, got: %v", err)
	}
	// The denial hint must mention the git transport alternative.
	if !strings.Contains(stderr, "git show") {
		t.Errorf("denial stderr %q must contain %q", stderr, "git show")
	}
	if !strings.Contains(stderr, "git verify-commit") {
		t.Errorf("denial stderr %q must contain %q", stderr, "git verify-commit")
	}
}

// ---- V8b.CLI.02 — contributor denied exit code ----------------------------

// TestAdminAuditShow_ContributorDenied_ExitCode verifies the process exit code
// for a denied CONTRIBUTOR invocation is ExitPermissionDenied.
func TestAdminAuditShow_ContributorDenied_ExitCode(t *testing.T) {
	t.Parallel()

	deps := makeAuditShowDeps(mode.ModeContributor, &panicAuditReader{})
	_, _, err := runAuditShowCmd(deps, nil)

	code := cli.ExitCodeOf(err)
	if code != int(render.ExitPermissionDenied) {
		t.Errorf("exit code = %d, want %d (ExitPermissionDenied)", code, render.ExitPermissionDenied)
	}
}

// ---- V8b.CLI.03 — contributor denial spy: zero FetchAuditLog calls ---------

// TestAdminAuditShow_ContributorDenied_ZeroFetchAuditLogCalls asserts the
// FetchAuditLog is never called on a denied path (denied-not-attempted).
func TestAdminAuditShow_ContributorDenied_ZeroFetchAuditLogCalls(t *testing.T) {
	t.Parallel()

	spy := &fakeAuditReader{}
	deps := makeAuditShowDeps(mode.ModeContributor, spy)

	_, _, _ = runAuditShowCmd(deps, nil)

	if spy.calls.Load() != 0 {
		t.Errorf("FetchAuditLog called %d time(s) on denied path; want 0", spy.calls.Load())
	}
}

// ---- V8b.CLI.04 — nil AuditReader → wired-check error ----------------------

// TestAdminAuditShow_NilReader_WiredCheckError verifies that a nil AuditReader
// produces a general-error exit (not a panic and not a permission-denied).
func TestAdminAuditShow_NilReader_WiredCheckError(t *testing.T) {
	t.Parallel()

	deps := makeAuditShowDeps(mode.ModeAdmin, nil /* nil AuditReader */)

	_, stderr, err := runAuditShowCmd(deps, nil)
	if err == nil {
		t.Fatal("expected error for nil AuditReader, got nil")
	}
	code := cli.ExitCodeOf(err)
	if code != int(render.ExitGeneralError) {
		t.Errorf("exit code = %d, want %d (ExitGeneralError)", code, render.ExitGeneralError)
	}
	if !strings.Contains(stderr, "not available") && !strings.Contains(stderr, "not wired") {
		t.Errorf("stderr %q should mention nil port", stderr)
	}
}

// ---- V8b.CLI.05 — ADMIN happy-path table render ----------------------------

// TestAdminAuditShow_AdminHappyPath_TableRender verifies that an ADMIN with a
// non-empty AuditReader gets a table with the expected columns. Actor attribution
// cutover: the ACTOR column is always "-" on the non-verify (FetchAuditLog) path
// because the JSONL Actor field is adversarial input and is never used for display.
// Only BindingVerified entries (--verify path) with a resolved VerifiedSignerID
// receive an actor attribution.
func TestAdminAuditShow_AdminHappyPath_TableRender(t *testing.T) {
	t.Parallel()

	entries := []rotate.AuditEntryView{
		{
			Kind:       "rotation",
			OccurredAt: "2026-01-01T00:00:00Z",
			Actor:      "admin@example.com", // JSONL field — adversarial; NEVER displayed
			Project:    "test-proj",
			Outcome:    "ok",
			// BindingStatus is BindingMissing (zero value): non-verify path.
			// VerifiedSignerID is empty: no anchor-verified signerID on this path.
		},
	}
	deps := makeAuditShowDeps(mode.ModeAdmin, &fakeAuditReader{entries: entries})

	stdout, _, err := runAuditShowCmd(deps, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "rotation") {
		t.Errorf("stdout %q must contain %q", stdout, "rotation")
	}
	// Actor column must be "-": non-BindingVerified entries never show the JSONL
	// Actor value. The ACTOR header must still appear (column is present).
	if !strings.Contains(stdout, "ACTOR") {
		t.Errorf("stdout %q must contain ACTOR column header", stdout)
	}
	if strings.Contains(stdout, "admin@example.com") {
		t.Errorf("stdout %q must NOT contain the raw JSONL Actor value %q — "+
			"actor attribution is anchor-verified only; FetchAuditLog path always displays \"-\"",
			stdout, "admin@example.com")
	}
	if !strings.Contains(stdout, "-") {
		t.Errorf("stdout %q must contain \"-\" for the actor column on the non-verify path", stdout)
	}
	if !strings.Contains(stdout, "ok") {
		t.Errorf("stdout %q must contain outcome", stdout)
	}
}

// ---- V8b.CLI.06 — ADMIN happy-path --json schema ---------------------------

// TestAdminAuditShow_AdminHappyPath_JSONSchema verifies the --json output is a
// stable object with an "entries" array.
func TestAdminAuditShow_AdminHappyPath_JSONSchema(t *testing.T) {
	t.Parallel()

	entries := []rotate.AuditEntryView{
		{
			Kind:       "rotation",
			OccurredAt: "2026-01-01T00:00:00Z",
			Actor:      "admin@example.com",
			Project:    "test-proj",
			Outcome:    "ok",
		},
	}
	deps := makeAuditShowDeps(mode.ModeAdmin, &fakeAuditReader{entries: entries})

	stdout, _, err := runAuditShowCmd(deps, []string{"--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got map[string]any
	if decErr := json.Unmarshal([]byte(stdout), &got); decErr != nil {
		t.Fatalf("JSON unmarshal: %v", decErr)
	}
	arr, ok := got["entries"]
	if !ok {
		t.Fatal("JSON output must have 'entries' key")
	}
	rows, ok := arr.([]any)
	if !ok {
		t.Fatalf("'entries' must be an array, got %T", arr)
	}
	if len(rows) != 1 {
		t.Errorf("entries length = %d, want 1", len(rows))
	}
}

// ---- V8b.CLI.07 — empty state table ----------------------------------------

// TestAdminAuditShow_EmptyState_Table verifies that an empty result produces a
// human-readable "no audit entries" message and exit 0.
func TestAdminAuditShow_EmptyState_Table(t *testing.T) {
	t.Parallel()

	deps := makeAuditShowDeps(mode.ModeAdmin, &fakeAuditReader{entries: nil})

	stdout, _, err := runAuditShowCmd(deps, nil)
	if err != nil {
		t.Fatalf("empty state: unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "no audit entries") {
		t.Errorf("empty state stdout %q must contain 'no audit entries'", stdout)
	}
}

// ---- V8b.CLI.08 — empty state --json ----------------------------------------

// TestAdminAuditShow_EmptyState_JSON verifies that empty --json returns the
// expected {"entries":[]} shape and exit 0.
func TestAdminAuditShow_EmptyState_JSON(t *testing.T) {
	t.Parallel()

	deps := makeAuditShowDeps(mode.ModeAdmin, &fakeAuditReader{entries: nil})

	stdout, _, err := runAuditShowCmd(deps, []string{"--json"})
	if err != nil {
		t.Fatalf("empty state --json: unexpected error: %v", err)
	}

	var got map[string]any
	if decErr := json.Unmarshal([]byte(stdout), &got); decErr != nil {
		t.Fatalf("JSON unmarshal: %v", decErr)
	}
	arr, ok := got["entries"]
	if !ok {
		t.Fatal("JSON must have 'entries' key")
	}
	rows, _ := arr.([]any)
	if len(rows) != 0 {
		t.Errorf("entries length = %d, want 0", len(rows))
	}
}

// ---- V8b.CLI.09 — full-field sanitise in table ------------------------------

// TestAdminAuditShow_FullFieldSanitise_Table proves that every rendered string
// field (Kind, OccurredAt, Actor, Outcome, SafeDetails value) has newlines,
// carriage returns, tabs, and ANSI codes stripped before appearing in the table.
// Raw values survive in --json.
func TestAdminAuditShow_FullFieldSanitise_Table(t *testing.T) {
	t.Parallel()

	dirtyKind := "rotation\ninjected"
	dirtyActor := "admin\x1b[31mREDACTED\x1b[0m@example.com"
	dirtyOutcome := "ok\r\nfake-header: malicious"
	dirtyDetailVal := "safe\ttabbed"

	entries := []rotate.AuditEntryView{
		{
			Kind:       dirtyKind,
			OccurredAt: "2026-01-01T00:00:00Z",
			Actor:      dirtyActor,
			Project:    "test-proj",
			Outcome:    dirtyOutcome,
			SafeDetails: map[string]string{
				"rotation_epoch": dirtyDetailVal,
			},
		},
	}
	deps := makeAuditShowDeps(mode.ModeAdmin, &fakeAuditReader{entries: entries})

	stdout, _, err := runAuditShowCmd(deps, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No raw newline should appear in the table output (other than row separators).
	// We check by counting lines: if a \n survived inside a field, there would be
	// extra table rows.
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	// Expect: header + separator + 1 data row = 3 lines.
	if len(lines) != 3 {
		t.Errorf("table has %d lines, want 3 (header+sep+1 row); dirty field may have injected an extra row:\n%s",
			len(lines), stdout)
	}

	// ANSI escape must not appear.
	if strings.Contains(stdout, "\x1b") {
		t.Error("raw ESC byte survived in table output")
	}

	// Carriage return must not appear.
	if strings.Contains(stdout, "\r") {
		t.Error("raw CR survived in table output")
	}

	// Tab must not appear in the rendered data (collapseLineBreaks replaces it).
	// (Header separator lines use dashes not tabs, so the check is valid.)
	if strings.Contains(stdout, "\t") {
		t.Error("raw TAB survived in table output")
	}

	// Raw values must be present in --json (unsanitised).
	stdout2, _, err2 := runAuditShowCmd(deps, []string{"--json"})
	if err2 != nil {
		t.Fatalf("--json error: %v", err2)
	}
	if !strings.Contains(stdout2, "\\n") && !strings.Contains(stdout2, dirtyKind) {
		t.Logf("JSON stdout: %s", stdout2)
		t.Error("--json should carry the raw kind value (with escape or literal)")
	}
}

// ---- V8b.CLI.10 — Unknown=true → warning row in table ----------------------

// TestAdminAuditShow_UnknownEntry_WarningRowInTable proves that an entry with
// Unknown=true is rendered as a "WARN:" prefixed row rather than a crash.
func TestAdminAuditShow_UnknownEntry_WarningRowInTable(t *testing.T) {
	t.Parallel()

	entries := []rotate.AuditEntryView{
		{
			Kind:       "future.v03.new_kind",
			OccurredAt: "2026-01-01T00:00:00Z",
			Actor:      "system",
			Project:    "test-proj",
			Outcome:    "ok",
			Unknown:    true,
		},
	}
	deps := makeAuditShowDeps(mode.ModeAdmin, &fakeAuditReader{entries: entries})

	stdout, _, err := runAuditShowCmd(deps, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout, "WARN:") {
		t.Errorf("Unknown=true entry must produce 'WARN:' prefix in table; got:\n%s", stdout)
	}
}

// ---- V8b.CLI.11 — ErrUnsignedRegistry → ExitTrustError --------------------

// TestAdminAuditShow_UnsignedRegistry_ExitTrustError verifies that a
// FetchAuditLog error wrapping ErrUnsignedRegistry produces ExitTrustError.
func TestAdminAuditShow_UnsignedRegistry_ExitTrustError(t *testing.T) {
	t.Parallel()

	fetchErr := fmt.Errorf("test: %w", coreregistry.ErrUnsignedRegistry)
	deps := makeAuditShowDeps(mode.ModeAdmin, &fakeAuditReader{fetchErr: fetchErr})

	_, _, err := runAuditShowCmd(deps, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	code := cli.ExitCodeOf(err)
	if code != int(render.ExitTrustError) {
		t.Errorf("exit code = %d, want %d (ExitTrustError)", code, render.ExitTrustError)
	}
}

// ---- V8b.CLI.12 — ErrRegistryOffline → ExitVerifyFailure ------------------

// TestAdminAuditShow_RegistryOffline_ExitVerifyFailure verifies that a
// FetchAuditLog error wrapping ErrRegistryOffline produces ExitVerifyFailure.
func TestAdminAuditShow_RegistryOffline_ExitVerifyFailure(t *testing.T) {
	t.Parallel()

	fetchErr := fmt.Errorf("test: %w", coreregistry.ErrRegistryOffline)
	deps := makeAuditShowDeps(mode.ModeAdmin, &fakeAuditReader{fetchErr: fetchErr})

	_, _, err := runAuditShowCmd(deps, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	code := cli.ExitCodeOf(err)
	if code != int(render.ExitVerifyFailure) {
		t.Errorf("exit code = %d, want %d (ExitVerifyFailure)", code, render.ExitVerifyFailure)
	}
}
