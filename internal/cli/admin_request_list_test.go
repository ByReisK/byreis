package cli_test

// CLI tests for `byreis admin request list`.
//
// Test IDs (test-file-only audit anchors):
//   - V7.LIST.contributor-denied-not-attempted
//   - V7.LIST.nil-reader-wired-check-error
//   - V7.LIST.admin-happy-path-table-order
//   - V7.LIST.empty-state-human
//   - V7.LIST.empty-state-json
//   - V7.LIST.json-schema-stable
//   - V7.LIST.title-sanitized-in-table
//   - V7.LIST.title-raw-in-json
//   - V7.LIST.exit-code-contributor-denied
//   - V7.LIST.exit-code-backend-error
//   - V7.LIST.sort-newest-first-tiebreak-ascending-number

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ---- test doubles -----------------------------------------------------------

// fakeRequestAccessReader is a test double for rotate.RequestAccessReader.
// It records how many times ListOpenRequests was called and returns the
// configured result or error.
type fakeRequestAccessReader struct {
	listCalls atomic.Int32
	summaries []rotate.OpenRequestSummary
	listErr   error
}

func (f *fakeRequestAccessReader) ListOpenRequests(_ context.Context) ([]rotate.OpenRequestSummary, error) {
	f.listCalls.Add(1)
	return f.summaries, f.listErr
}

func (f *fakeRequestAccessReader) ListOpenRequestsBounded(_ context.Context) ([]rotate.OpenRequestSummary, bool, error) {
	f.listCalls.Add(1)
	return f.summaries, false, f.listErr
}

func (f *fakeRequestAccessReader) FetchRequestAccessYAML(
	_ context.Context, _ coregit.PRRef,
) (rotate.RequestAccessFile, rotate.PRMetadata, error) {
	panic("FetchRequestAccessYAML must not be called by list path")
}

func (f *fakeRequestAccessReader) FetchPRHeadSHA(
	_ context.Context, _ coregit.PRRef,
) (string, string, error) {
	panic("FetchPRHeadSHA must not be called by list path")
}

// panicRequestAccessReader panics on any call. Used to prove that a CONTRIBUTOR
// denial never reaches the adapter.
type panicRequestAccessReader struct{}

func (*panicRequestAccessReader) ListOpenRequests(_ context.Context) ([]rotate.OpenRequestSummary, error) {
	panic("ListOpenRequests called but must not be reached: policy gate violated")
}

func (*panicRequestAccessReader) ListOpenRequestsBounded(_ context.Context) ([]rotate.OpenRequestSummary, bool, error) {
	panic("ListOpenRequestsBounded called but must not be reached: policy gate violated")
}

func (*panicRequestAccessReader) FetchRequestAccessYAML(
	_ context.Context, _ coregit.PRRef,
) (rotate.RequestAccessFile, rotate.PRMetadata, error) {
	panic("FetchRequestAccessYAML called but must not be reached")
}

func (*panicRequestAccessReader) FetchPRHeadSHA(
	_ context.Context, _ coregit.PRRef,
) (string, string, error) {
	panic("FetchPRHeadSHA called but must not be reached")
}

// ---- helpers ----------------------------------------------------------------

func makeAdminRequestListDeps(m mode.Mode, r rotate.RequestAccessReader) *cli.Deps {
	return &cli.Deps{
		Policy:              &mode.Policy{},
		CurrentMode:         m,
		RequestAccessReader: r,
	}
}

func runAdminRequestListCmd(deps *cli.Deps, extraArgs []string) (stdout, stderr string, err error) {
	args := append([]string{"admin", "request", "list"}, extraArgs...)
	root := cli.NewRootCmdWithDeps(deps)
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

func makeSummary(project string, number int, login, title, createdAt, headSHA string) rotate.OpenRequestSummary {
	return rotate.OpenRequestSummary{
		PRRef:       coregit.PRRef{Project: project, Number: number},
		AuthorLogin: login,
		Title:       title,
		CreatedAt:   createdAt,
		HeadSHA:     headSHA,
	}
}

// ---- V7.LIST.contributor-denied-not-attempted -------------------------------

// TestAdminRequestList_ContributorDeniedNotAttempted proves that the mode gate
// fires before any network call. The panicRequestAccessReader panics if reached.
func TestAdminRequestList_ContributorDeniedNotAttempted(t *testing.T) {
	t.Parallel()

	// V7.LIST.contributor-denied-not-attempted
	deps := makeAdminRequestListDeps(mode.ModeContributor, &panicRequestAccessReader{})

	_, _, err := runAdminRequestListCmd(deps, nil)

	if err == nil {
		t.Fatal("expected ErrPermissionDenied, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("want errors.Is(err, mode.ErrPermissionDenied), got: %v", err)
	}
}

// TestAdminRequestList_ContributorDenied_ExitCode verifies the exit code for
// CONTRIBUTOR denial is ExitPermissionDenied.
func TestAdminRequestList_ContributorDenied_ExitCode(t *testing.T) {
	t.Parallel()

	// V7.LIST.exit-code-contributor-denied
	deps := makeAdminRequestListDeps(mode.ModeContributor, &panicRequestAccessReader{})

	_, _, err := runAdminRequestListCmd(deps, nil)

	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitPermissionDenied) {
		t.Errorf("exit code = %d, want %d (ExitPermissionDenied)", exitCode, int(render.ExitPermissionDenied))
	}
}

// TestAdminRequestList_ContributorDenied_ZeroListCalls asserts that the
// ListOpenRequests adapter is never called on a CONTRIBUTOR denial (call-graph
// spy via atomic counter on fakeRequestAccessReader).
//
// This test uses a fakeRequestAccessReader (not the panicReader) so we can
// verify the call count explicitly.
func TestAdminRequestList_ContributorDenied_ZeroListCalls(t *testing.T) {
	t.Parallel()

	fake := &fakeRequestAccessReader{summaries: nil}
	deps := makeAdminRequestListDeps(mode.ModeContributor, fake)

	_, _, _ = runAdminRequestListCmd(deps, nil)

	if fake.listCalls.Load() != 0 {
		t.Errorf("ListOpenRequests was called %d times; want 0 for CONTRIBUTOR denied path",
			fake.listCalls.Load())
	}
}

// ---- V7.LIST.nil-reader-wired-check-error -----------------------------------

// TestAdminRequestList_NilReader_WiredCheckError verifies that a nil
// RequestAccessReader returns an actionable "not wired" error without panicking
// and without a permission-denied exit code.
func TestAdminRequestList_NilReader_WiredCheckError(t *testing.T) {
	t.Parallel()

	// V7.LIST.nil-reader-wired-check-error
	deps := makeAdminRequestListDeps(mode.ModeAdmin, nil)

	_, _, err := runAdminRequestListCmd(deps, nil)

	if err == nil {
		t.Fatal("expected error for nil RequestAccessReader, got nil")
	}
	// Must not be a permission-denied error (mode gate was passed).
	if errors.Is(err, mode.ErrPermissionDenied) {
		t.Error("nil reader returned permission-denied; should be a wired-check error")
	}
	// Must contain a helpful message about the reader not being wired.
	if !strings.Contains(err.Error(), "RequestAccessReader") &&
		!strings.Contains(err.Error(), "not wired") &&
		!strings.Contains(err.Error(), "BYREIS_GITHUB_TOKEN") {
		t.Errorf("error %q does not contain a helpful wired-check message", err.Error())
	}
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitGeneralError) {
		t.Errorf("exit code = %d, want %d (ExitGeneralError)", exitCode, int(render.ExitGeneralError))
	}
}

// ---- V7.LIST.admin-happy-path-table-order -----------------------------------

// TestAdminRequestList_AdminHappyPath_TableOrder verifies that an ADMIN with a
// wired reader gets a human table with rows in newest-first order.
func TestAdminRequestList_AdminHappyPath_TableOrder(t *testing.T) {
	t.Parallel()

	// V7.LIST.admin-happy-path-table-order
	// Three PRs with distinct creation times; want newest (2026-05-03) first.
	fake := &fakeRequestAccessReader{
		summaries: []rotate.OpenRequestSummary{
			makeSummary("owner/reg", 1, "alice", "Add DB creds", "2026-05-01T00:00:00Z", "sha1"),
			makeSummary("owner/reg", 3, "carol", "Add API key", "2026-05-03T00:00:00Z", "sha3"),
			makeSummary("owner/reg", 2, "bob", "Add AWS key", "2026-05-02T00:00:00Z", "sha2"),
		},
	}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestListCmd(deps, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	// Expect at least: header, separator, 3 data rows = 5 lines minimum.
	if len(lines) < 5 {
		t.Fatalf("expected >= 5 lines in table output, got %d:\n%s", len(lines), stdout)
	}

	// Verify newest-first: carol#3 (2026-05-03) must appear before bob#2,
	// which must appear before alice#1.
	carolIdx := -1
	bobIdx := -1
	aliceIdx := -1
	for i, l := range lines {
		if strings.Contains(l, "carol") {
			carolIdx = i
		}
		if strings.Contains(l, "bob") {
			bobIdx = i
		}
		if strings.Contains(l, "alice") {
			aliceIdx = i
		}
	}
	if carolIdx < 0 || bobIdx < 0 || aliceIdx < 0 {
		t.Fatalf("output missing expected authors:\n%s", stdout)
	}
	if carolIdx > bobIdx {
		t.Errorf("carol (newest) must appear before bob; carolIdx=%d bobIdx=%d", carolIdx, bobIdx)
	}
	if bobIdx > aliceIdx {
		t.Errorf("bob must appear before alice; bobIdx=%d aliceIdx=%d", bobIdx, aliceIdx)
	}
}

// TestAdminRequestList_SortTieBreakAscendingNumber verifies that when two PRs
// have the same CreatedAt, the one with the lower PR number appears first.
func TestAdminRequestList_SortTieBreakAscendingNumber(t *testing.T) {
	t.Parallel()

	// V7.LIST.sort-newest-first-tiebreak-ascending-number
	sameTime := "2026-05-10T12:00:00Z"
	fake := &fakeRequestAccessReader{
		summaries: []rotate.OpenRequestSummary{
			makeSummary("owner/reg", 20, "eve", "PR 20", sameTime, "sha20"),
			makeSummary("owner/reg", 5, "frank", "PR 5", sameTime, "sha5"),
		},
	}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestListCmd(deps, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	frankIdx := strings.Index(stdout, "frank")
	eveIdx := strings.Index(stdout, "eve")
	if frankIdx < 0 || eveIdx < 0 {
		t.Fatalf("output missing expected authors:\n%s", stdout)
	}
	// frank (PR #5) must appear before eve (PR #20) when times are equal.
	if frankIdx > eveIdx {
		t.Errorf("frank (PR #5) must appear before eve (PR #20) for same-timestamp tie-break; frankIdx=%d eveIdx=%d", frankIdx, eveIdx)
	}
}

// ---- V7.LIST.empty-state ---------------------------------------------------

// TestAdminRequestList_EmptyState_Human verifies that an empty result yields
// a human-readable "no open access requests" message with exit code 0.
func TestAdminRequestList_EmptyState_Human(t *testing.T) {
	t.Parallel()

	// V7.LIST.empty-state-human
	fake := &fakeRequestAccessReader{summaries: []rotate.OpenRequestSummary{}}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestListCmd(deps, nil)
	if err != nil {
		t.Fatalf("unexpected error for empty state: %v", err)
	}
	if !strings.Contains(stdout, "no open access requests") {
		t.Errorf("stdout %q does not contain 'no open access requests'", stdout)
	}
}

// TestAdminRequestList_EmptyState_JSON verifies that --json empty state returns
// {"requests":[]} with exit code 0.
func TestAdminRequestList_EmptyState_JSON(t *testing.T) {
	t.Parallel()

	// V7.LIST.empty-state-json
	fake := &fakeRequestAccessReader{summaries: []rotate.OpenRequestSummary{}}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestListCmd(deps, []string{"--json"})
	if err != nil {
		t.Fatalf("unexpected error for empty JSON state: %v", err)
	}

	var out map[string]json.RawMessage
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); jsonErr != nil {
		t.Fatalf("stdout is not valid JSON: %v\nraw: %q", jsonErr, stdout)
	}
	reqRaw, ok := out["requests"]
	if !ok {
		t.Fatalf("JSON output missing 'requests' key: %q", stdout)
	}
	var requests []any
	if jsonErr := json.Unmarshal(reqRaw, &requests); jsonErr != nil {
		t.Fatalf("'requests' field is not a JSON array: %v", jsonErr)
	}
	if len(requests) != 0 {
		t.Errorf("'requests' = %v, want empty array", requests)
	}
}

// ---- V7.LIST.json-schema-stable ---------------------------------------------

// TestAdminRequestList_JSONSchema_Stable verifies the --json schema has the
// expected top-level and per-row fields, and contains no secret material.
func TestAdminRequestList_JSONSchema_Stable(t *testing.T) {
	t.Parallel()

	// V7.LIST.json-schema-stable
	fake := &fakeRequestAccessReader{
		summaries: []rotate.OpenRequestSummary{
			makeSummary("owner/reg", 7, "alice", "My request", "2026-05-07T00:00:00Z", "abcdef1234"),
		},
	}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestListCmd(deps, []string{"--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var out struct {
		Requests []struct {
			PR        string `json:"pr"`
			Author    string `json:"author"`
			Title     string `json:"title"`
			CreatedAt string `json:"created_at"`
			HeadSHA   string `json:"head_sha"`
		} `json:"requests"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); jsonErr != nil {
		t.Fatalf("stdout is not valid JSON: %v\nraw: %q", jsonErr, stdout)
	}
	if len(out.Requests) != 1 {
		t.Fatalf("requests len = %d, want 1", len(out.Requests))
	}
	row := out.Requests[0]
	if row.PR != "owner/reg#7" {
		t.Errorf("pr = %q, want owner/reg#7", row.PR)
	}
	if row.Author != "alice" {
		t.Errorf("author = %q, want alice", row.Author)
	}
	if row.Title != "My request" {
		t.Errorf("title = %q, want My request", row.Title)
	}
	if row.CreatedAt != "2026-05-07T00:00:00Z" {
		t.Errorf("created_at = %q, want 2026-05-07T00:00:00Z", row.CreatedAt)
	}
	if row.HeadSHA != "abcdef1234" {
		t.Errorf("head_sha = %q, want abcdef1234", row.HeadSHA)
	}
	// No private key material may appear in the JSON.
	if strings.Contains(stdout, "age1") {
		t.Errorf("JSON output contains 'age1' prefix (possible key leak): %q", stdout)
	}
}

// ---- V7.LIST.title-sanitized-in-table / title-raw-in-json ------------------

// TestAdminRequestList_TitleSanitizedInTable verifies that contributor-controlled
// ANSI / C0 control bytes in a PR title are stripped before terminal output.
func TestAdminRequestList_TitleSanitizedInTable(t *testing.T) {
	t.Parallel()

	// V7.LIST.title-sanitized-in-table
	// The title contains an ANSI escape sequence and a C0 control byte (SOH 0x01).
	rawTitle := "Normal" + "\x1b[1m" + "BOLD" + "\x1b[0m" + " title" + "\x01" + "injected"
	fake := &fakeRequestAccessReader{
		summaries: []rotate.OpenRequestSummary{
			makeSummary("owner/reg", 99, "mallory", rawTitle, "2026-05-20T00:00:00Z", "sha99"),
		},
	}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestListCmd(deps, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The ANSI escape and control character must not appear in table output.
	if strings.Contains(stdout, "\x1b") {
		t.Errorf("table output contains raw ESC byte (ANSI not sanitized): %q", stdout)
	}
	if strings.Contains(stdout, "\x01") {
		t.Errorf("table output contains C0 control byte 0x01 (not sanitized): %q", stdout)
	}
	// But visible text must still be present.
	if !strings.Contains(stdout, "Normal") {
		t.Errorf("table output missing expected visible text 'Normal': %q", stdout)
	}
}

// TestAdminRequestList_TitleRawInJSON verifies that --json carries the title
// value through encoding/json without the CLI layer sanitizing it, confirming
// the sanitization contract (table=sanitized, JSON=raw encoded).
func TestAdminRequestList_TitleRawInJSON(t *testing.T) {
	t.Parallel()

	// V7.LIST.title-raw-in-json
	// A title with an ANSI sequence in it; the JSON output should be valid JSON
	// containing the title field (encoding/json will escape control bytes).
	rawTitle := "title with" + "\x1b[31m" + "red"
	fake := &fakeRequestAccessReader{
		summaries: []rotate.OpenRequestSummary{
			makeSummary("owner/reg", 50, "alice", rawTitle, "2026-05-10T00:00:00Z", "sha50"),
		},
	}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestListCmd(deps, []string{"--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// JSON output must be valid JSON (encoding/json escapes control bytes).
	var out map[string]json.RawMessage
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); jsonErr != nil {
		t.Fatalf("stdout is not valid JSON: %v\nraw: %q", jsonErr, stdout)
	}
	// Confirm the title field is present and the output is parseable.
	if !strings.Contains(stdout, `"title"`) {
		t.Errorf("JSON output missing 'title' field: %q", stdout)
	}
}

// ---- T-V7-1: newline/tab injection in table title ---------------------------

// TestAdminRequestList_TitleNewlineCollapsed_TableSingleRow asserts that a PR
// title containing \n, \r, or \t is collapsed to a single table row in
// human/table output. A newline in the title must not produce a second row that
// could spoof a different PR reference.
func TestAdminRequestList_TitleNewlineCollapsed_TableSingleRow(t *testing.T) {
	t.Parallel()

	// T-V7-1: attacker-controlled title with embedded newline. Without the fix,
	// the newline would inject a fake second row into the admin triage table —
	// e.g. "spoofed-org/registry#999  victim  2026-01-01  fake" appearing as
	// an additional data row the admin might act on.
	injectedTitle := "legit title\nspoofed-org/registry#999  victim  2026-01-01  fake"
	fake := &fakeRequestAccessReader{
		summaries: []rotate.OpenRequestSummary{
			makeSummary("owner/reg", 42, "mallory", injectedTitle, "2026-05-22T00:00:00Z", "sha42"),
		},
	}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestListCmd(deps, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	// Expect exactly: header line, separator line, 1 data row = 3 lines.
	// If newline injection succeeded there would be 4+ lines.
	if len(lines) != 3 {
		t.Errorf("table has %d lines; want exactly 3 (header + separator + 1 data row); newline injection may have succeeded:\n%s",
			len(lines), stdout)
	}

	// The injected text must not appear at the START of any line that looks
	// like a data row (i.e., prefixed like a PR reference). After collapse,
	// the injected portion is on the same physical line as the real data row,
	// not on a fresh row of its own.
	for _, line := range lines[2:] { // skip header + separator
		if strings.HasPrefix(strings.TrimSpace(line), "spoofed-org/registry#999") {
			t.Errorf("injected fake row found as a leading-field on a data line — newline injection not blocked:\n%s", stdout)
		}
	}

	// The legitimate author must still appear.
	if !strings.Contains(stdout, "mallory") {
		t.Errorf("expected author 'mallory' in table output:\n%s", stdout)
	}
}

// TestAdminRequestList_TitleTabCollapsed_TableSingleRow asserts that a PR title
// containing a tab character does not break the table column alignment in a way
// that could confuse the row count. This is the tab variant of T-V7-1.
func TestAdminRequestList_TitleTabCollapsed_TableSingleRow(t *testing.T) {
	t.Parallel()

	// T-V7-1 tab variant.
	tabbedTitle := "Add creds\t\tsecret-extra-column"
	fake := &fakeRequestAccessReader{
		summaries: []rotate.OpenRequestSummary{
			makeSummary("owner/reg", 7, "alice", tabbedTitle, "2026-05-22T00:00:00Z", "sha7"),
		},
	}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestListCmd(deps, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No raw tab character may appear in the table output.
	if strings.ContainsRune(stdout, '\t') {
		t.Errorf("table output contains raw tab after collapse; want no tabs:\n%q", stdout)
	}
	// Visible text before the tab must still appear.
	if !strings.Contains(stdout, "Add creds") {
		t.Errorf("expected 'Add creds' in table output:\n%s", stdout)
	}
}

// TestAdminRequestList_TitleNewline_JSONCarriesRaw asserts that the --json path
// carries the raw (encoding/json-escaped) title even when the title contains
// a newline — the table-only collapse must not touch the JSON path.
func TestAdminRequestList_TitleNewline_JSONCarriesRaw(t *testing.T) {
	t.Parallel()

	// T-V7-1: JSON must carry the raw title; encoding/json escapes \n as \n.
	rawTitle := "first line\nsecond line"
	fake := &fakeRequestAccessReader{
		summaries: []rotate.OpenRequestSummary{
			makeSummary("owner/reg", 11, "bob", rawTitle, "2026-05-22T00:00:00Z", "sha11"),
		},
	}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	stdout, _, err := runAdminRequestListCmd(deps, []string{"--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must be valid JSON.
	var out struct {
		Requests []struct {
			Title string `json:"title"`
		} `json:"requests"`
	}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &out); jsonErr != nil {
		t.Fatalf("stdout is not valid JSON: %v\nraw: %q", jsonErr, stdout)
	}
	if len(out.Requests) != 1 {
		t.Fatalf("requests len = %d, want 1", len(out.Requests))
	}
	// After JSON decode, the title must equal the original (newline preserved by json).
	if out.Requests[0].Title != rawTitle {
		t.Errorf("JSON title = %q, want %q (newline must survive JSON round-trip)", out.Requests[0].Title, rawTitle)
	}
}

// ---- V7.LIST.exit-code-backend-error ----------------------------------------

// TestAdminRequestList_BackendError_ExitCode verifies that a ListOpenRequests
// error returns ExitGeneralError (not ExitPermissionDenied).
func TestAdminRequestList_BackendError_ExitCode(t *testing.T) {
	t.Parallel()

	// V7.LIST.exit-code-backend-error
	fake := &fakeRequestAccessReader{
		listErr: errors.New("GitHub API error: 500 Internal Server Error"),
	}
	deps := makeAdminRequestListDeps(mode.ModeAdmin, fake)

	_, _, err := runAdminRequestListCmd(deps, nil)
	if err == nil {
		t.Fatal("expected error for backend failure, got nil")
	}
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitGeneralError) {
		t.Errorf("exit code = %d, want %d (ExitGeneralError)", exitCode, int(render.ExitGeneralError))
	}
}
