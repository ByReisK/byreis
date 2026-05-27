package cli_test

// Tests for `byreis audit verify`.
//
// Covered:
//   - T-S1-B (O-S1-2): AST import-discipline — the CLI file must NOT import
//     crypto/identity or crypto/decrypt. Hard-fails if go list cannot run.
//   - All-modes ALLOW: contributor, admin, super all succeed for a clean history.
//   - Nil AuditVerifier → ExitGeneralError (not a panic).
//   - Policy gate fires before port touch (panic verifier is never reached when
//     permitted but verifier is not nil — this is the all-modes path so denied
//     only on forged mode; covered by mode package bypass tests).
//   - FetchAuditLog is NEVER called (O-S1-3): spy confirms zero calls.
//   - Tamper error → non-zero exit (ExitTrustError) AND entries still rendered.
//   - --json schema: "entries" array present, binding_status field present.
//   - Forged/unknown mode with an admin command still denied (regression guard
//     that CommandAuditShow is not relaxed by the presence of CommandAuditVerify
//     — covered by mode package bypass tests, mirrored here for CLI-layer parity).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
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

// fakeAuditVerifier is a configurable test double for rotate.AuditVerifier.
type fakeAuditVerifier struct {
	result    rotate.AuditVerifyResult
	verifyErr error
	calls     atomic.Int32
}

func (f *fakeAuditVerifier) VerifyAuditLog(_ context.Context, _ string) (rotate.AuditVerifyResult, error) {
	f.calls.Add(1)
	return f.result, f.verifyErr
}

// spyAuditReader counts FetchAuditLog calls. Used to assert the audit verify
// verb never touches the plaintext/decode path (O-S1-3 binding).
type spyAuditReader struct {
	calls atomic.Int32
}

func (s *spyAuditReader) FetchAuditLog(_ context.Context, _ string) ([]rotate.AuditEntryView, error) {
	s.calls.Add(1)
	return nil, nil
}

// ---- helpers ----------------------------------------------------------------

func makeAuditVerifyDeps(m mode.Mode, av rotate.AuditVerifier) *cli.Deps {
	return &cli.Deps{
		Policy:        &mode.Policy{},
		CurrentMode:   m,
		AuditVerifier: av,
	}
}

func runAuditVerifyCmd(deps *cli.Deps, extraArgs []string) (stdout, stderr string, err error) {
	args := append([]string{"audit", "verify", "--project", "test-proj"}, extraArgs...)
	root := cli.NewRootCmdWithDeps(deps)
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

// ---- T-S1-B: AST import-discipline test ------------------------------------

// TestAuditVerifyCmd_ImportDiscipline_NoCryptoEdge asserts that
// internal/cli/audit_verify_cmd.go does NOT import crypto/identity or
// crypto/decrypt. This is the defence-in-depth parity with the engine's
// existing assertion in internal/adapter/registry.
//
// Scope: the assertion is on the VERB'S OWN SOURCE FILE only, not the entire
// cli package. The admin commands (`admin_cmds.go`, `admin_audit_show_test.go`)
// legitimately import these packages for the plaintext-decode and identity-load
// paths; those imports are not a violation. The contributor audit-verify verb
// must be an island within the cli package: it MUST NOT directly import any
// private-key or decrypt package. The import graph confinement at the engine
// layer (internal/adapter/registry) prevents the verifier from acquiring a
// private-key capability at any depth; this test is the CLI-file-specific
// defence-in-depth layer.
//
// A missing source file is a hard failure (not a skip). The AST check is the
// authoritative assertion; go list on the full cli package would also catch
// transitive imports through the admin commands and is therefore not suitable
// for this per-file assertion.
func TestAuditVerifyCmd_ImportDiscipline_NoCryptoEdge(t *testing.T) {
	t.Parallel()

	// Locate the source file via runtime.Caller. The implementation file is a
	// sibling of this test file. Hard-fail if runtime.Caller cannot determine
	// the path — a gate that cannot run is a failure, never a silent pass.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("T-S1-B: runtime.Caller(0) failed — cannot locate source file; " +
			"a gate that cannot run is a failure, never a silent pass")
	}
	srcFile := filepath.Join(filepath.Dir(thisFile), "audit_verify_cmd.go")

	fset := token.NewFileSet()
	f, parseErr := parser.ParseFile(fset, srcFile, nil, parser.ImportsOnly)
	if parseErr != nil {
		t.Fatalf("T-S1-B: failed to parse %s: %v\n"+
			"Source file must exist and be parseable; a gate that cannot run fails.", srcFile, parseErr)
	}
	if len(f.Imports) == 0 {
		// A file with zero imports is suspicious for an implementation file; fail
		// hard so this cannot accidentally pass on an empty placeholder.
		t.Fatalf("T-S1-B: %s has zero imports — expected at least cobra and render imports; "+
			"the file may be a stub rather than the real implementation", srcFile)
	}

	forbidden := []string{
		"crypto/identity",
		"crypto/decrypt",
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, bad := range forbidden {
			if strings.Contains(path, bad) {
				t.Errorf("T-S1-B FAIL: audit_verify_cmd.go imports %q\n"+
					"The contributor audit-verify CLI file must NOT directly import %q.\n"+
					"Any direct edge to crypto/identity or crypto/decrypt from this file "+
					"creates a code-path from the contributor verify verb to private-key or "+
					"decrypt capability — a write-only violation. Admin-path files in the "+
					"same package may legitimately import these; the restriction is "+
					"verb-file-specific.",
					path, bad)
			}
		}
	}

	// Additionally check the audit_verify_cmd.go has the expected imports
	// (cobra and render are required; their absence would indicate the file
	// was replaced with a stub).
	required := []string{"cobra", "render"}
	for _, req := range required {
		found := false
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, req) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("T-S1-B: audit_verify_cmd.go does not import %q — "+
				"expected implementation file is absent or replaced with a stub", req)
		}
	}

	// Check that audit_verify_cmd.go does NOT import go-git or go-github (no
	// transport/network/SDK imports in CLI files per the architecture rules).
	forbiddenSDK := []string{"go-git", "go-github", "go-keyring"}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		for _, bad := range forbiddenSDK {
			if strings.Contains(path, bad) {
				t.Errorf("T-S1-B FAIL: audit_verify_cmd.go imports SDK package %q — "+
					"CLI files must not import network/SDK packages directly", path)
			}
		}
	}

	if !t.Failed() {
		t.Logf("T-S1-B PASS: audit_verify_cmd.go has no forbidden crypto or SDK imports (%d imports checked)",
			len(f.Imports))
	}
}

// ---- all-modes ALLOW with clean history ------------------------------------

// TestAuditVerify_AllModes_CleanHistory_ExitZero asserts that a clean (no
// tamper) VerifyAuditLog result produces exit 0 in every mode.
func TestAuditVerify_AllModes_CleanHistory_ExitZero(t *testing.T) {
	t.Parallel()

	entries := []rotate.AuditEntryView{
		{
			Kind:          "merge",
			OccurredAt:    "2026-01-01T00:00:00Z",
			Project:       "test-proj",
			Outcome:       "ok",
			BindingStatus: rotate.BindingVerified,
		},
	}

	for _, m := range []mode.Mode{mode.ModeContributor, mode.ModeAdmin, mode.ModeSuper} {
		m := m
		t.Run(m.String(), func(t *testing.T) {
			t.Parallel()

			verifier := &fakeAuditVerifier{
				result: rotate.AuditVerifyResult{Entries: entries, FullWalk: true},
			}
			deps := makeAuditVerifyDeps(m, verifier)

			stdout, _, err := runAuditVerifyCmd(deps, nil)
			if err != nil {
				t.Fatalf("mode %v: expected exit 0, got error: %v", m, err)
			}
			if cli.ExitCodeOf(err) != 0 {
				t.Fatalf("mode %v: expected exit code 0, got %d", m, cli.ExitCodeOf(err))
			}
			if !strings.Contains(stdout, "merge") {
				t.Errorf("mode %v: stdout %q should contain entry kind %q", m, stdout, "merge")
			}
			// BINDING column must be present when showBinding=true.
			if !strings.Contains(stdout, "BINDING") {
				t.Errorf("mode %v: stdout %q must contain BINDING column header", m, stdout)
			}
		})
	}
}

// ---- O-S1-3: FetchAuditLog is NEVER called ---------------------------------

// TestAuditVerify_FetchAuditLogNeverCalled asserts that the verify verb never
// calls the AuditReader.FetchAuditLog port. The port carries the plaintext
// decode path; O-S1-3 mandates the verify verb uses ONLY VerifyAuditLog.
func TestAuditVerify_FetchAuditLogNeverCalled(t *testing.T) {
	t.Parallel()

	spy := &spyAuditReader{}
	verifier := &fakeAuditVerifier{
		result: rotate.AuditVerifyResult{Entries: nil, FullWalk: true},
	}
	deps := &cli.Deps{
		Policy:        &mode.Policy{},
		CurrentMode:   mode.ModeContributor,
		AuditVerifier: verifier,
		AuditReader:   spy, // wired but must NEVER be called
	}

	_, _, _ = runAuditVerifyCmd(deps, nil)

	if spy.calls.Load() != 0 {
		t.Errorf("O-S1-3 VIOLATION: FetchAuditLog called %d time(s); "+
			"the verify verb must NEVER call the AuditReader plaintext-decode path",
			spy.calls.Load())
	}
}

// ---- nil AuditVerifier → ExitGeneralError ----------------------------------

// TestAuditVerify_NilVerifier_GeneralError verifies that a nil AuditVerifier
// produces ExitGeneralError (not a panic) with an actionable error message.
func TestAuditVerify_NilVerifier_GeneralError(t *testing.T) {
	t.Parallel()

	for _, m := range []mode.Mode{mode.ModeContributor, mode.ModeAdmin, mode.ModeSuper} {
		m := m
		t.Run(m.String(), func(t *testing.T) {
			t.Parallel()

			deps := makeAuditVerifyDeps(m, nil)
			_, stderr, err := runAuditVerifyCmd(deps, nil)
			if err == nil {
				t.Fatal("expected error for nil AuditVerifier, got nil")
			}
			code := cli.ExitCodeOf(err)
			if code != int(render.ExitGeneralError) {
				t.Errorf("mode %v: exit code = %d, want %d (ExitGeneralError)", m, code, render.ExitGeneralError)
			}
			if !strings.Contains(stderr, "not available") && !strings.Contains(stderr, "not wired") {
				t.Errorf("mode %v: stderr %q should mention nil port", m, stderr)
			}
		})
	}
}

// ---- tamper → non-zero exit AND entries rendered ---------------------------

// TestAuditVerify_Tamper_NonZeroExitAndEntriesRendered asserts that when
// VerifyAuditLog returns ErrAuditLogTampered, the command:
//   - exits non-zero (ExitTrustError), and
//   - renders per-line entry output BEFORE the error (entries are not withheld).
//
// Exit-0-on-tamper is a shipgate-class defect (AC-001-B). The per-line
// projection must always be surfaced alongside the tamper error so operators
// can identify the offending line.
func TestAuditVerify_Tamper_NonZeroExitAndEntriesRendered(t *testing.T) {
	t.Parallel()

	tamperedEntry := rotate.AuditEntryView{
		Kind:          "merge",
		OccurredAt:    "2026-01-01T00:00:00Z",
		Project:       "test-proj",
		Outcome:       "ok",
		BindingStatus: rotate.BindingTampered,
	}

	verifier := &fakeAuditVerifier{
		result:    rotate.AuditVerifyResult{Entries: []rotate.AuditEntryView{tamperedEntry}, FullWalk: true},
		verifyErr: fmt.Errorf("audit log tampered at line 1: %w", coreregistry.ErrAuditLogTampered),
	}
	deps := makeAuditVerifyDeps(mode.ModeContributor, verifier)

	stdout, _, err := runAuditVerifyCmd(deps, nil)
	if err == nil {
		t.Fatal("AC-001-B VIOLATION: expected non-zero exit on tamper, got nil error — " +
			"exit-0-on-tamper is a shipgate-class defect")
	}
	code := cli.ExitCodeOf(err)
	if code != int(render.ExitTrustError) {
		t.Errorf("AC-001-B: exit code = %d, want %d (ExitTrustError)", code, render.ExitTrustError)
	}
	if !errors.Is(err, coreregistry.ErrAuditLogTampered) {
		t.Errorf("error must wrap ErrAuditLogTampered, got: %v", err)
	}
	// Per-line entries MUST be rendered even on a tamper outcome.
	if !strings.Contains(stdout, "merge") {
		t.Errorf("per-line entries must be rendered on tamper path — "+
			"stdout %q does not contain entry kind %q", stdout, "merge")
	}
}

// ---- --json schema ----------------------------------------------------------

// TestAuditVerify_JSON_BindingStatusPresent verifies the --json schema:
// the "entries" array is present and each entry carries a "binding_status" field.
func TestAuditVerify_JSON_BindingStatusPresent(t *testing.T) {
	t.Parallel()

	verifier := &fakeAuditVerifier{
		result: rotate.AuditVerifyResult{
			Entries: []rotate.AuditEntryView{
				{
					Kind:          "rotation",
					OccurredAt:    "2026-01-01T00:00:00Z",
					Project:       "test-proj",
					Outcome:       "ok",
					BindingStatus: rotate.BindingVerified,
				},
			},
			FullWalk: true,
		},
	}
	deps := makeAuditVerifyDeps(mode.ModeContributor, verifier)

	stdout, _, err := runAuditVerifyCmd(deps, []string{"--json"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got map[string]any
	if decErr := json.Unmarshal([]byte(stdout), &got); decErr != nil {
		t.Fatalf("JSON unmarshal: %v; raw output: %q", decErr, stdout)
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
		t.Fatalf("entries length = %d, want 1", len(rows))
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("entry must be a JSON object, got %T", rows[0])
	}
	if _, hasBs := row["binding_status"]; !hasBs {
		t.Errorf("JSON entry must have 'binding_status' field; got keys: %v", mapKeys(row))
	}
}

// ---- regression: CommandAuditShow still denied for contributor -------------

// TestAuditVerify_AuditShowStillDeniedForContributor is the CLI-layer regression
// guard complementing mode/policy_test.go TestPolicy_AuditShowStaysAdminOnly.
// Adding the all-modes `audit verify` verb must NOT relax the admin-only
// `audit show` gate: a contributor calling `admin audit show` is still denied.
func TestAuditVerify_AuditShowStillDeniedForContributor(t *testing.T) {
	t.Parallel()

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		AuditReader: &panicAuditReader{}, // must never be reached
	}

	args := []string{"admin", "audit", "show", "--project", "test-proj"}
	root := cli.NewRootCmdWithDeps(deps)
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err := root.Execute()

	if err == nil {
		t.Fatal("contributor calling 'admin audit show' must be denied; got nil error — " +
			"audit-show gate must not be relaxed by the presence of audit-verify")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("denial must wrap ErrPermissionDenied, got: %v", err)
	}
	code := cli.ExitCodeOf(err)
	if code != int(render.ExitPermissionDenied) {
		t.Errorf("exit code = %d, want %d (ExitPermissionDenied)", code, render.ExitPermissionDenied)
	}
}

// ---- helpers ----------------------------------------------------------------

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
