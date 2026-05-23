package cli_test

// Pre-TUI golden-output fixtures (delta #8 oracle).
//
// This file captures the exact stdout, stderr, and exit code produced by the
// headless CLI invocations that the TUI will later wrap. It establishes the
// oracle that V-3 through V-6 TUI work must not regress: after the TUI is
// wired in, these same invocations must produce byte-identical output because
// they all satisfy the headless condition (BYREIS_NON_INTERACTIVE, --json, or
// fully-specified flag set → ShouldLaunchTUI == false → existing CLI path).
//
// Baseline: captured at HEAD 810cf3d (v0.2 SHIPPED). The commits since that
// HEAD are comment and doc-only and do not change CLI behavior, so the fixtures
// are behaviorally equivalent to 810cf3d.
//
// Fixture invocations are driven through cli.NewRootCmdWithDeps with injected
// fakes — no real network, no real clock, no real keychain, no real filesystem.
// This keeps them fast, deterministic, and hermetic.
//
// To regenerate the golden files (e.g. after an intentional CLI behavior
// change that has been reviewed and approved):
//
//	go test ./internal/cli/ -run TestGoldenPreTUI -update
//
// The -update flag must only be used after an explicit review of the output
// diff, never automatically in CI.
//
// Gate: make test (via ./...). The golden assertion tests are not behind a
// build tag; they run on every test invocation to catch any accidental
// regression to the headless CLI output.

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// updateGolden is set by -update on the test command line. When true the test
// writes current output to the golden files instead of asserting against them.
var updateGolden = flag.Bool("update", false, "update golden fixture files instead of asserting")

// goldenDir is the directory holding the pre-TUI fixture files.
const goldenDir = "testdata/golden/pre-tui"

// ---- fake implementations for golden fixtures --------------------------------

// fixedSubmitter is an injected fake Submitter that returns canned success
// results. It simulates a wired adapter without any real network contact.
type fixedSubmitter struct {
	single submit.Result
	bulk   submit.BulkResult
}

func (f *fixedSubmitter) Submit(_ context.Context, _ submit.Input) (submit.Result, error) {
	return f.single, nil
}

func (f *fixedSubmitter) SubmitBulk(_ context.Context, _ submit.BulkInput) (submit.BulkResult, error) {
	return f.bulk, nil
}

// fixedReviewer is an injected fake Reviewer that returns a canned success result.
type fixedReviewer struct{}

func (f *fixedReviewer) Review(_ context.Context, in usecase.ReviewInput) (usecase.ReviewResult, error) {
	return usecase.ReviewResult{
		Ref:           in.Ref,
		Author:        "alice",
		Justification: "add prod DB creds",
		SecretsPath:   "secrets/prod.enc.yaml",
		PinnedSHA:     "sha256:deadbeef",
		KeyNames:      []string{"DB_HOST", "DB_PASS"},
		PerKey: []usecase.KeyReviewLine{
			{Key: "DB_HOST", Action: "add", ValidationOK: true, ValidationMsg: ""},
			{Key: "DB_PASS", Action: "replace", ValidationOK: true, ValidationMsg: ""},
		},
		Plaintext: map[string]string{
			"DB_HOST": "prod.db.example.com",
			"DB_PASS": "s3cr3t",
		},
	}, nil
}

// fixedRequestAccessReader is an injected fake for admin request list.
type fixedRequestAccessReader struct{}

func (f *fixedRequestAccessReader) ListOpenRequests(_ context.Context) ([]rotate.OpenRequestSummary, error) {
	return []rotate.OpenRequestSummary{
		{
			PRRef:       coregit.PRRef{Project: "testorg/byreis-admins", Number: 7},
			AuthorLogin: "alice",
			Title:       "Add alice age1key...",
			CreatedAt:   "2026-05-20T10:00:00Z",
			HeadSHA:     "abc123def456",
		},
	}, nil
}

func (f *fixedRequestAccessReader) ListOpenRequestsBounded(_ context.Context) ([]rotate.OpenRequestSummary, bool, error) {
	summaries, err := f.ListOpenRequests(context.Background())
	return summaries, false, err
}

func (f *fixedRequestAccessReader) FetchRequestAccessYAML(
	_ context.Context, _ coregit.PRRef,
) (rotate.RequestAccessFile, rotate.PRMetadata, error) {
	panic("FetchRequestAccessYAML not exercised by golden fixtures")
}

func (f *fixedRequestAccessReader) FetchPRHeadSHA(
	_ context.Context, _ coregit.PRRef,
) (string, string, error) {
	panic("FetchPRHeadSHA not exercised by golden fixtures")
}

// ---- fixture case definition -------------------------------------------------

// fixtureCase describes one golden-fixture invocation.
type fixtureCase struct {
	// name is the fixture file stem (without extension). Files are:
	//   testdata/golden/pre-tui/<name>.stdout.golden
	//   testdata/golden/pre-tui/<name>.stderr.golden
	//   testdata/golden/pre-tui/<name>.exit.golden
	name string

	// args are the cobra command arguments (after the binary name).
	args []string

	// deps is the injected dependency struct for this invocation.
	deps *cli.Deps

	// envOverrides is a map of environment variables to set for the duration of
	// this invocation. The test uses t.Setenv so the original values are restored.
	// Because t.Setenv is not compatible with t.Parallel, golden tests are serial.
	envOverrides map[string]string
}

// buildFixtureCases returns the full matrix of pre-TUI golden fixture cases.
// Each case represents a headless invocation whose output byte-identity must
// be preserved after TUI work lands.
func buildFixtureCases(t *testing.T) []fixtureCase {
	t.Helper()

	// Shared fake Submitter returning deterministic submit success results.
	singleResult := submit.Result{
		PRRef:       submit.PRRef{Project: "testorg/secrets", Number: 10},
		PRURL:       "https://github.com/testorg/secrets/pull/10",
		Branch:      "byreis/add-MYKEY-1748000000",
		ArtifactSHA: "sha256:aabbccdd",
		Action:      submit.ActionAdd,
	}
	bulkResult := submit.BulkResult{
		PRRef:       submit.PRRef{Project: "testorg/secrets", Number: 11},
		PRURL:       "https://github.com/testorg/secrets/pull/11",
		Branch:      "byreis/bulk-2keys-1748000001",
		ArtifactSHA: "sha256:eeff0011",
		PerKey: []submit.BulkKeyResult{
			{Key: "DB_HOST", Action: submit.ActionAdd},
			{Key: "DB_PASS", Action: submit.ActionReplace},
		},
	}
	fakeSubmitter := &fixedSubmitter{single: singleResult, bulk: bulkResult}
	fakeReviewer := &fixedReviewer{}
	fakeRequestReader := &fixedRequestAccessReader{}

	// Policy and modes.
	policy := &mode.Policy{}
	contributorDeps := func(submitter submit.Submitter) *cli.Deps {
		return &cli.Deps{
			Policy:      policy,
			CurrentMode: mode.ModeContributor,
			Submitter:   submitter,
		}
	}
	adminDeps := func(reviewer usecase.Reviewer, reader rotate.RequestAccessReader) *cli.Deps {
		return &cli.Deps{
			Policy:              policy,
			CurrentMode:         mode.ModeAdmin,
			Reviewer:            reviewer,
			RequestAccessReader: reader,
		}
	}
	adminWithSubmitter := func() *cli.Deps {
		return &cli.Deps{
			Policy:      policy,
			CurrentMode: mode.ModeAdmin,
			Submitter:   fakeSubmitter,
		}
	}

	// Write a temp .env file for --file cases. Since buildFixtureCases is called
	// from a single test function, we use t.TempDir() which is cleaned up after
	// the test completes.
	tmp := t.TempDir()
	envFile := filepath.Join(tmp, "fixture.env")
	if err := os.WriteFile(envFile, []byte("DB_HOST=prod.db.example.com\nDB_PASS=s3cr3t\n"), 0o600); err != nil {
		t.Fatalf("writing fixture env file: %v", err)
	}

	// baseEnv is the set of project env vars required for submit to reach the
	// use-case call (the "not configured" guard passes). Tests that want to
	// capture the "not configured" error use an empty envOverrides map and no
	// BYREIS_PROJECT set.
	baseProjectEnv := map[string]string{
		"BYREIS_PROJECT":      "testorg/secrets",
		"BYREIS_SECRETS_PATH": "secrets/prod.enc.yaml",
	}

	nonInteractiveEnv := map[string]string{
		"BYREIS_PROJECT":         "testorg/secrets",
		"BYREIS_SECRETS_PATH":    "secrets/prod.enc.yaml",
		"BYREIS_NON_INTERACTIVE": "1",
	}

	dumbTermEnv := map[string]string{
		"BYREIS_PROJECT":      "testorg/secrets",
		"BYREIS_SECRETS_PATH": "secrets/prod.enc.yaml",
		"TERM":                "dumb",
	}

	return []fixtureCase{
		// submit --key (contributor, nil Submitter) — "not configured" error
		{
			name: "submit-key-nil-submitter",
			args: []string{"--json", "submit", "--key", "MYKEY"},
			deps: contributorDeps(nil),
		},
		// submit --key --json (contributor, success) — standard headless path
		{
			name:         "submit-key-json-success",
			args:         []string{"--json", "submit", "--key", "MYKEY"},
			deps:         contributorDeps(fakeSubmitter),
			envOverrides: baseProjectEnv,
		},
		// submit --key BYREIS_NON_INTERACTIVE=1 (contributor, success)
		{
			name:         "submit-key-non-interactive-success",
			args:         []string{"--json", "submit", "--key", "MYKEY"},
			deps:         contributorDeps(fakeSubmitter),
			envOverrides: nonInteractiveEnv,
		},
		// submit --key TERM=dumb (contributor, success)
		{
			name:         "submit-key-dumb-term-success",
			args:         []string{"--json", "submit", "--key", "MYKEY"},
			deps:         contributorDeps(fakeSubmitter),
			envOverrides: dumbTermEnv,
		},
		// submit --file --json (contributor, success) — bulk headless path
		{
			name:         "submit-file-json-success",
			args:         []string{"--json", "submit", "--file", envFile},
			deps:         contributorDeps(fakeSubmitter),
			envOverrides: baseProjectEnv,
		},
		// submit --file BYREIS_NON_INTERACTIVE=1 (contributor, success)
		{
			name:         "submit-file-non-interactive-success",
			args:         []string{"--json", "submit", "--file", envFile},
			deps:         contributorDeps(fakeSubmitter),
			envOverrides: nonInteractiveEnv,
		},
		// submit --file TERM=dumb (contributor, success)
		{
			name:         "submit-file-dumb-term-success",
			args:         []string{"--json", "submit", "--file", envFile},
			deps:         contributorDeps(fakeSubmitter),
			envOverrides: dumbTermEnv,
		},
		// submit (admin mode, success) — confirm submit is not admin-only
		{
			name:         "submit-file-admin-mode-json-success",
			args:         []string{"--json", "submit", "--file", envFile},
			deps:         adminWithSubmitter(),
			envOverrides: baseProjectEnv,
		},
		// review --pr --json (contributor) — permission denied
		{
			name: "review-pr-contributor-denied",
			args: []string{"--json", "review", "--pr", "testorg/secrets#42"},
			deps: &cli.Deps{
				Policy:      policy,
				CurrentMode: mode.ModeContributor,
			},
		},
		// review --pr --json (admin, nil Reviewer) — "not configured" error
		{
			name: "review-pr-admin-nil-reviewer",
			args: []string{"--json", "review", "--pr", "testorg/secrets#42"},
			deps: adminDeps(nil, nil),
		},
		// review --pr --json (admin, success) — standard headless path
		{
			name: "review-pr-json-success",
			args: []string{"--json", "review", "--pr", "testorg/secrets#42"},
			deps: adminDeps(fakeReviewer, nil),
		},
		// review --pr BYREIS_NON_INTERACTIVE=1 (admin, success)
		{
			name: "review-pr-non-interactive-success",
			args: []string{"--json", "review", "--pr", "testorg/secrets#42"},
			deps: adminDeps(fakeReviewer, nil),
			envOverrides: map[string]string{
				"BYREIS_NON_INTERACTIVE": "1",
			},
		},
		// review --pr TERM=dumb (admin, success)
		{
			name: "review-pr-dumb-term-success",
			args: []string{"--json", "review", "--pr", "testorg/secrets#42"},
			deps: adminDeps(fakeReviewer, nil),
			envOverrides: map[string]string{
				"TERM": "dumb",
			},
		},
		// admin request list --json (contributor) — permission denied
		{
			name: "admin-request-list-contributor-denied",
			args: []string{"--json", "admin", "request", "list"},
			deps: &cli.Deps{
				Policy:      policy,
				CurrentMode: mode.ModeContributor,
			},
		},
		// admin request list --json (admin, success)
		{
			name: "admin-request-list-json-success",
			args: []string{"--json", "admin", "request", "list"},
			deps: adminDeps(nil, fakeRequestReader),
		},
		// admin request list BYREIS_NON_INTERACTIVE=1 (admin, success)
		{
			name: "admin-request-list-non-interactive-success",
			args: []string{"--json", "admin", "request", "list"},
			deps: adminDeps(nil, fakeRequestReader),
			envOverrides: map[string]string{
				"BYREIS_NON_INTERACTIVE": "1",
			},
		},
		// admin request list TERM=dumb (admin, success)
		{
			name: "admin-request-list-dumb-term-success",
			args: []string{"--json", "admin", "request", "list"},
			deps: adminDeps(nil, fakeRequestReader),
			envOverrides: map[string]string{
				"TERM": "dumb",
			},
		},
	}
}

// ---- golden test runner ------------------------------------------------------

// TestGoldenPreTUI is the pre-TUI oracle gate. It runs every fixture case and
// either writes the golden file (when -update is set) or asserts byte identity
// with the committed golden file. A diff on any fixture after TUI work lands is
// a release blocker (REQ-002 byte-identical fallback).
//
// NOT parallel: uses t.Setenv, and the fixture files are written/read in the
// same testdata directory. Serial execution keeps the output deterministic.
func TestGoldenPreTUI(t *testing.T) {
	cases := buildFixtureCases(t)

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Apply environment overrides for this case.
			for k, v := range tc.envOverrides {
				t.Setenv(k, v)
			}
			// Clear vars not in the override map that could leak from a parent
			// test using withProjectEnv. The golden cases are self-contained.
			if _, ok := tc.envOverrides["BYREIS_PROJECT"]; !ok {
				t.Setenv("BYREIS_PROJECT", "")
			}
			if _, ok := tc.envOverrides["BYREIS_SECRETS_PATH"]; !ok {
				t.Setenv("BYREIS_SECRETS_PATH", "")
			}

			stdout, stderr, exitCode := runGoldenCase(t, tc)
			assertOrUpdate(t, tc.name+".stdout.golden", stdout)
			assertOrUpdate(t, tc.name+".stderr.golden", stderr)
			assertOrUpdate(t, tc.name+".exit.golden", exitCode)
		})
	}
}

// runGoldenCase executes the fixture invocation and returns captured
// stdout, stderr (as normalized strings), and the exit code string.
func runGoldenCase(t *testing.T, tc fixtureCase) (stdout, stderr, exitCode string) {
	t.Helper()

	var outBuf, errBuf bytes.Buffer
	root := cli.NewRootCmdWithDeps(tc.deps)
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(tc.args)

	err := root.Execute()
	code := cli.ExitCodeOf(err)

	// Normalize JSON output: pretty-print so the golden files are diff-friendly.
	// Non-JSON output is left as-is.
	outStr := normalizeOutput(outBuf.String())
	errStr := normalizeOutput(errBuf.String())

	return outStr, errStr, strings.TrimSpace(exitCodeString(code))
}

// normalizeOutput normalizes output for golden file storage. If the string is
// valid JSON, it is pretty-printed for readability. Otherwise it is returned
// trimmed of trailing whitespace.
func normalizeOutput(s string) string {
	s = strings.TrimRight(s, "\n")
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return ""
	}
	// Attempt JSON pretty-print.
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err == nil {
		pretty, ppErr := json.MarshalIndent(v, "", "  ")
		if ppErr == nil {
			return string(pretty)
		}
	}
	return s
}

// exitCodeString converts an exit code int to its string representation.
func exitCodeString(code int) string {
	// Render as a decimal integer; the exit code IS the documentation.
	// Using a string conversion avoids depending on a String() method that does
	// not exist on render.ExitCode.
	switch render.ExitCode(code) {
	case render.ExitOK:
		return "0"
	case render.ExitGeneralError:
		return "1"
	case render.ExitPermissionDenied:
		return "2"
	case render.ExitAuthError:
		return "3"
	case render.ExitNotFound:
		return "4"
	case render.ExitReplay:
		return "5"
	case render.ExitCounterReconcile:
		return "6"
	case render.ExitTrustError:
		return "7"
	case render.ExitDecodeMalformed:
		return "8"
	case render.ExitVerifyFailure:
		return "9"
	default:
		return "1"
	}
}

// assertOrUpdate either writes the fixture file (when -update) or asserts
// that the current output matches the committed golden file.
func assertOrUpdate(t *testing.T, filename, content string) {
	t.Helper()
	path := filepath.Join(goldenDir, filename)

	if *updateGolden {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("creating golden dir %s: %v", dir, err)
		}
		if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
			t.Fatalf("writing golden file %s: %v", path, err)
		}
		t.Logf("UPDATED: %s", path)
		return
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("GOLDEN FIXTURE MISSING: %s\n"+
			"Run: go test ./internal/cli/ -run TestGoldenPreTUI -update\n"+
			"to generate the initial golden files from the current CLI output.\n"+
			"Review the generated files before committing.", path)
	}
	// Normalize the stored content (trim trailing newline added on write).
	want := strings.TrimRight(string(raw), "\n")
	got := content

	if got != want {
		t.Errorf("GOLDEN FIXTURE REGRESSION: %s\n"+
			"The headless CLI output has changed from the pre-TUI baseline.\n"+
			"This is a release blocker (byte-identical fallback requirement).\n"+
			"If the change is intentional and reviewed, regenerate with:\n"+
			"  go test ./internal/cli/ -run TestGoldenPreTUI -update\n\n"+
			"WANT:\n%s\n\nGOT:\n%s",
			path, want, got)
	}
}
