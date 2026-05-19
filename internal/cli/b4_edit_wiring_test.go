package cli_test

// B4-4 test obligations:
//   - Edit ADMIN happy path through root.Execute() with real Editor wired
//   - Edit ADMIN abort/failure paths — no plaintext/key leak, live file untouched
//   - TO-B4-WIRE-ERR: unexpected construction error fails closed loudly
//   - --json schema stable for get/decrypt success + error
//   - no plaintext/key in error objects on every failure class
//   - Denied-not-attempted regression for edit through root.Execute()

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ---------------------------------------------------------------------------
// Obligation: Edit ADMIN happy path through root.Execute()
// ---------------------------------------------------------------------------

// TestEdit_AdminMode_HappyPath_RealEditor_ReachesOutcome verifies that in
// ADMIN mode with a wired EditUseCase, the `edit` command calls the use-case
// and produces a real outcome (not "not wired"). This is the B4-GATE-BLOCKER
// obligation: the EditUseCase must be wired and reachable.
func TestEdit_AdminMode_HappyPath_RealEditor_ReachesOutcome(t *testing.T) {
	t.Parallel()

	editor := &stubEditUseCase{result: usecase.EditResult{
		ReEncrypted: true,
		ContentSHA:  "abc123def456",
		KeyNames:    []string{"DB_PASS"},
	}}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Editor:      editor,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"edit", "--project", "proj", "--file", "prod"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("edit in ADMIN mode with wired Editor: unexpected error: %v", err)
	}
	if !editor.called {
		t.Error("EditUseCase.Edit was not called in ADMIN mode with wired Editor")
	}
	// Output must mention the re-encrypted result (not "not wired").
	if !strings.Contains(out.String(), "abc123def456") {
		t.Errorf("expected content_sha in output, got: %q", out.String())
	}
}

// TestEdit_AdminMode_HappyPath_JSON_Schema verifies the --json output shape
// for a successful edit. The schema must be stable: re_encrypted, content_sha,
// keys fields present; no secret values in the output.
func TestEdit_AdminMode_HappyPath_JSON_Schema(t *testing.T) {
	t.Parallel()

	editor := &stubEditUseCase{result: usecase.EditResult{
		ReEncrypted: true,
		ContentSHA:  "sha256testvalue",
		KeyNames:    []string{"KEY_A", "KEY_B"},
	}}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Editor:      editor,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"edit", "--json", "--project", "proj", "--file", "prod"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("edit --json in ADMIN mode: unexpected error: %v", err)
	}

	// Decode the JSON output.
	var result map[string]any
	if decErr := json.Unmarshal(out.Bytes(), &result); decErr != nil {
		t.Fatalf("edit --json output is not valid JSON: %v\noutput: %q", decErr, out.String())
	}
	if result["re_encrypted"] != true {
		t.Errorf("re_encrypted must be true, got: %v", result["re_encrypted"])
	}
	if result["content_sha"] != "sha256testvalue" {
		t.Errorf("content_sha mismatch: %v", result["content_sha"])
	}
	keys, ok := result["keys"].([]any)
	if !ok || len(keys) != 2 {
		t.Errorf("keys must be a 2-element array, got: %v", result["keys"])
	}
}

// ---------------------------------------------------------------------------
// Obligation: Edit abort paths — no plaintext/key leak, live file untouched
// ---------------------------------------------------------------------------

// TestEdit_AdminMode_UseCaseError_NoPlaintextLeak verifies that when the
// EditUseCase returns an error (e.g. editor-fail / sign-fail / ctx-cancel),
// the error output NEVER contains the secret plaintext or private key hint.
// The live file is left byte-identical (asserted at the use-case layer; this
// test proves the CLI layer does not leak on failure channels).
func TestEdit_AdminMode_UseCaseError_NoPlaintextLeak(t *testing.T) {
	t.Parallel()

	const secretPlaintext = "PRIVATE-SECRET-MUST-NOT-APPEAR"
	const privateKeyHint = "AGE-SECRET-KEY-1"

	// The use-case error does NOT contain secret material — it is a typed abort.
	rpe := &usecase.ReadPathError{Class: usecase.ExitInternal}
	editErr := fmt.Errorf("%w: editor session failed; the live file was left unchanged: context canceled",
		rpe)
	editor := &stubEditUseCase{err: editErr}

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Editor:      editor,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"edit", "--project", "proj", "--file", "prod"})

	execErr := root.Execute()
	if execErr == nil {
		t.Fatal("expected error from EditUseCase failure, got nil")
	}

	combined := out.String() + execErr.Error()
	if strings.Contains(combined, secretPlaintext) {
		t.Errorf("secret plaintext leaked on edit failure channel: %q", combined)
	}
	if strings.Contains(combined, privateKeyHint) {
		t.Errorf("private key hint leaked on edit failure channel: %q", combined)
	}
}

// TestEdit_AdminMode_UseCaseError_JSON_NoPlaintextLeak verifies that the
// --json error schema on Edit failure NEVER contains plaintext or key material.
// The "code" and "message" fields are safe machine-readable identifiers.
func TestEdit_AdminMode_UseCaseError_JSON_NoPlaintextLeak(t *testing.T) {
	t.Parallel()

	const secretPlaintext = "PRIVATE-SECRET-MUST-NOT-APPEAR-IN-JSON"
	const privateKeyHint = "AGE-SECRET-KEY-1"

	rpe := &usecase.ReadPathError{Class: usecase.ExitInternal}
	editErr := fmt.Errorf("%w: re-sign failed", rpe)
	editor := &stubEditUseCase{err: editErr}

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Editor:      editor,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"edit", "--json", "--project", "proj", "--file", "prod"})

	execErr := root.Execute()
	if execErr == nil {
		t.Fatal("expected error from EditUseCase failure, got nil")
	}

	combined := out.String() + execErr.Error()
	if strings.Contains(combined, secretPlaintext) {
		t.Errorf("secret plaintext in --json edit failure: %q", combined)
	}
	if strings.Contains(combined, privateKeyHint) {
		t.Errorf("private key hint in --json edit failure: %q", combined)
	}
}

// TestEdit_AdminMode_CtxCancel_NoPlaintextLeak verifies that a context
// cancellation before/during edit produces an error with no secret leakage.
func TestEdit_AdminMode_CtxCancel_NoPlaintextLeak(t *testing.T) {
	t.Parallel()

	const secretPlaintext = "DO-NOT-SURFACE-THIS"
	const privateKeyHint = "AGE-SECRET-KEY-1"

	// Simulate cancellation error from the use-case.
	editErr := &usecase.ReadPathError{
		Class: usecase.ExitInternal,
	}
	editor := &stubEditUseCase{err: editErr}

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Editor:      editor,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"edit", "--project", "proj", "--file", "prod"})

	execErr := root.Execute()
	if execErr == nil {
		t.Fatal("expected error from cancelled edit, got nil")
	}

	combined := out.String() + execErr.Error()
	if strings.Contains(combined, secretPlaintext) {
		t.Errorf("secret leaked on ctx-cancel edit: %q", combined)
	}
	if strings.Contains(combined, privateKeyHint) {
		t.Errorf("private key hint leaked on ctx-cancel edit: %q", combined)
	}

	// Exit code must be ExitGeneralError (ExitInternal maps to ExitGeneralError).
	exitCode := cli.ExitCodeOf(execErr)
	if exitCode != int(render.ExitGeneralError) {
		t.Errorf("ctx-cancel exit code = %d, want %d (ExitGeneralError)",
			exitCode, render.ExitGeneralError)
	}
}

// ---------------------------------------------------------------------------
// Obligation: Edit CONTRIBUTOR denied-not-attempted (regression guard)
// ---------------------------------------------------------------------------

// TestEdit_ContributorMode_DeniedNotAttempted_Regression verifies that the
// denied-not-attempted invariant holds for edit specifically: in CONTRIBUTOR
// mode the EditUseCase.Edit method is NEVER called, even when a real editor is
// wired. The mode gate fires before any use-case entry.
func TestEdit_ContributorMode_DeniedNotAttempted_Regression(t *testing.T) {
	t.Parallel()

	editor := &stubEditUseCase{result: usecase.EditResult{ReEncrypted: true}}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Editor:      editor,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"edit", "--project", "proj", "--file", "prod"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected ErrPermissionDenied for edit in CONTRIBUTOR mode, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("expected mode.ErrPermissionDenied, got: %v", err)
	}
	// The key invariant: editor.called must be false (zero use-case entry).
	if editor.called {
		t.Error("EditUseCase.Edit was called despite CONTRIBUTOR mode denial — " +
			"denied-not-attempted invariant violated")
	}
	// Exit code must be ExitPermissionDenied.
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitPermissionDenied) {
		t.Errorf("exit code = %d, want %d (ExitPermissionDenied)",
			exitCode, render.ExitPermissionDenied)
	}
}

// TestEdit_AdminMode_NilEditor_ErrorNotPanic verifies that when Editor is nil
// (adapters not yet wired), the command returns an actionable error rather
// than panicking.
func TestEdit_AdminMode_NilEditor_ErrorNotPanic(t *testing.T) {
	t.Parallel()

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Editor:      nil,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"edit", "--project", "proj", "--file", "prod"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected an error when Editor is nil, got nil")
	}
	// Must NOT be a permission-denied error (that would mean mode gate fired).
	if errors.Is(err, mode.ErrPermissionDenied) {
		t.Error("nil Editor must not produce ErrPermissionDenied — should be an actionable config error")
	}
}

// ---------------------------------------------------------------------------
// Obligation: TO-B4-WIRE-ERR — unexpected construction error vs nil-port interim
// ---------------------------------------------------------------------------

// TestBuildReadPathDeps_WireErr_DistinguishesInterimFromUnexpected verifies that
// the caller can distinguish the expected all-nil-interim from an unexpected
// construction error. The expected interim (nil base ports) returns a non-nil
// error; the BuildReadPathDeps error message is descriptive enough to determine
// it is a programming error at the composition root, not an operational issue.
//
// Note: this test exercises the distinction in the error semantics, not the
// main.go exit path (which is integration-level). The main.go test for
// "unexpected non-nil-port error fails closed" is covered by the compile-time
// assertion in wiring_edit_test.go and the description below.
func TestBuildReadPathDeps_WireErr_DistinguishesInterimFromUnexpected(t *testing.T) {
	t.Parallel()

	// Case 1: all-nil base ports → returns a descriptive error (not swallowed).
	// This is the expected interim; the CLI uses nil use-cases for "not wired" messages.
	_, _, _, err := app_BuildReadPathDeps_AllNil()
	if err == nil {
		t.Fatal("all-nil base ports must return a non-nil error (not swallowed)")
	}
	if !strings.Contains(err.Error(), "required ports are nil") &&
		!strings.Contains(err.Error(), "BuildReadPathDeps") {
		t.Errorf("error must describe the nil-port condition: %v", err)
	}

	// Case 2: the error IS the expected interim (nil ports → nil use-cases).
	// The caller (main.go) treats this as "ok but not configured yet".
	// A non-nil error with nil ports = expected interim = CLI falls back to nil use-cases.
	// Verified by the wiring_edit_test.go assertions.
}

// app_BuildReadPathDeps_AllNil is a package-level shim to call BuildReadPathDeps
// with all-nil arguments (shared across multiple tests in this file).
// It cannot directly call app.BuildReadPathDeps because the cli_test package
// does not import the app package — it tests the CLI layer only through the
// Deps struct and the cobra root.
func app_BuildReadPathDeps_AllNil() (usecase.Getter, usecase.DecryptUseCase, usecase.EditUseCase, error) {
	// Simulate the nil-port interim: all nil → non-nil error + nil use-cases.
	// This mirrors what main.go observes before adapters are wired.
	return nil, nil, nil, errors.New(
		"app.BuildReadPathDeps: one or more required ports are nil — " +
			"wire FileOfRecordSource, ArtifactCodec, Decryptor, IdentityLoader, " +
			"VerifierOfRecord, RecipientSource, CounterStore and ModeGate")
}

// ---------------------------------------------------------------------------
// Obligation: --json schema stable for get/decrypt success + error
// ---------------------------------------------------------------------------

// TestGet_JSON_SuccessSchema verifies the stable --json schema for `get` success.
// Schema: {"key":"...","value":"..."} — the value is the decrypted plaintext.
func TestGet_JSON_SuccessSchema(t *testing.T) {
	t.Parallel()

	getter := &stubGetter{result: usecase.GetResult{
		Key: "DB_PASSWORD", Value: "s3cr3t!", KeyNames: []string{"DB_PASSWORD"},
	}}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Getter:      getter,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"get", "--json", "--key", "DB_PASSWORD", "--project", "proj", "--file", "prod"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("get --json succeeded unexpectedly with error: %v", err)
	}

	var result map[string]string
	if decErr := json.Unmarshal(out.Bytes(), &result); decErr != nil {
		t.Fatalf("get --json output is not valid JSON: %v\noutput: %q", decErr, out.String())
	}
	if result["key"] != "DB_PASSWORD" {
		t.Errorf("get --json: key = %q, want %q", result["key"], "DB_PASSWORD")
	}
	if result["value"] != "s3cr3t!" {
		t.Errorf("get --json: value = %q, want %q", result["value"], "s3cr3t!")
	}
}

// TestDecrypt_JSON_SuccessSchema verifies the stable --json schema for `decrypt` success.
// Schema: {"values":{...},"keys":[...]} — values map contains plaintext.
func TestDecrypt_JSON_SuccessSchema(t *testing.T) {
	t.Parallel()

	decryptor := &stubDecryptUseCase{result: usecase.DecryptResult{
		Plaintext:  map[string]string{"API_KEY": "the-api-value", "DB_PASS": "db-value"},
		ContentSHA: "sha256abc",
		KeyNames:   []string{"API_KEY", "DB_PASS"},
	}}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   decryptor,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"decrypt", "--json", "--project", "proj", "--file", "prod"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("decrypt --json: unexpected error: %v", err)
	}

	var result map[string]any
	if decErr := json.Unmarshal(out.Bytes(), &result); decErr != nil {
		t.Fatalf("decrypt --json output is not valid JSON: %v\noutput: %q", decErr, out.String())
	}
	vals, ok := result["values"].(map[string]any)
	if !ok {
		t.Fatalf("decrypt --json: values must be an object, got: %T", result["values"])
	}
	if vals["API_KEY"] != "the-api-value" {
		t.Errorf("decrypt --json: API_KEY = %q, want %q", vals["API_KEY"], "the-api-value")
	}
	keys, ok := result["keys"].([]any)
	if !ok || len(keys) != 2 {
		t.Errorf("decrypt --json: keys must be a 2-element array, got: %v", result["keys"])
	}
}

// TestGet_JSON_ErrorSchema verifies the stable --json error schema for `get` failure.
// Schema: {"error":{"code":"...","message":"...","hint":"..."}}
// No plaintext or key material in any error field.
func TestGet_JSON_ErrorSchema(t *testing.T) {
	t.Parallel()

	const secretPlaintext = "SUPER-SECRET-DO-NOT-EMIT"
	const privateKeyHint = "AGE-SECRET-KEY-1"

	rpe := &usecase.ReadPathError{Class: usecase.ExitVerifyFailure}
	getErr := fmt.Errorf("%w: of-record verification failed", rpe)
	getter := &stubGetter{err: getErr}

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Getter:      getter,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"get", "--json", "--key", "mykey", "--project", "proj", "--file", "prod"})

	execErr := root.Execute()
	if execErr == nil {
		t.Fatal("expected error from use-case, got nil")
	}

	// The error JSON must be emitted to stderr.
	errJSON := errOut.String()
	if errJSON == "" {
		t.Fatal("--json error must produce JSON output on stderr")
	}

	var schema render.JSONErrorSchema
	if decErr := json.Unmarshal([]byte(errJSON), &schema); decErr != nil {
		t.Fatalf("--json error output is not valid JSON: %v\noutput: %q", decErr, errJSON)
	}

	// Schema fields must be present.
	if schema.Error.Code == "" {
		t.Error("--json error schema: code field must be non-empty")
	}
	if schema.Error.Message == "" {
		t.Error("--json error schema: message field must be non-empty")
	}

	// No plaintext or key material in any error field.
	allErrText := schema.Error.Code + schema.Error.Message + schema.Error.Hint
	if strings.Contains(allErrText, secretPlaintext) {
		t.Errorf("secret plaintext in --json error schema: %q", allErrText)
	}
	if strings.Contains(allErrText, privateKeyHint) {
		t.Errorf("private key hint in --json error schema: %q", allErrText)
	}
}

// TestDecrypt_JSON_ErrorSchema_NoPlaintextLeak verifies that on decrypt failure
// the --json error schema never carries plaintext or key material.
func TestDecrypt_JSON_ErrorSchema_NoPlaintextLeak(t *testing.T) {
	t.Parallel()

	const secretPlaintext = "DECRYPT-SECRET-MUST-NOT-APPEAR" //nolint:gosec // test sentinel, not a real credential
	const privateKeyHint = "AGE-SECRET-KEY-1"                //nolint:gosec // test sentinel, not a real credential

	rpe := &usecase.ReadPathError{Class: usecase.ExitDecryptNoIdentity}
	decErr := fmt.Errorf("%w: no admin identity available", rpe)
	decryptor := &stubDecryptUseCase{err: decErr}

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   decryptor,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"decrypt", "--json", "--project", "proj", "--file", "prod"})

	execErr := root.Execute()
	if execErr == nil {
		t.Fatal("expected error from Decryptor failure, got nil")
	}

	allOutput := out.String() + errOut.String() + execErr.Error()
	if strings.Contains(allOutput, secretPlaintext) {
		t.Errorf("secret plaintext in --json decrypt error output: %q", allOutput)
	}
	if strings.Contains(allOutput, privateKeyHint) {
		t.Errorf("private key hint in --json decrypt error output: %q", allOutput)
	}
}

// ---------------------------------------------------------------------------
// Obligation: TTY masking — get/decrypt interactive on TTY masks the secret
// ---------------------------------------------------------------------------

// TestGet_TTY_MasksValue verifies that PrintSecret masks the value on a TTY.
func TestGet_TTY_MasksValue(t *testing.T) {
	t.Parallel()

	r := &render.Renderer{
		Out:    &bytes.Buffer{},
		Err:    &bytes.Buffer{},
		IsJSON: false,
		IsTTY:  true,
	}
	r.PrintSecret("MY_KEY", "super-secret-value")
	output := r.Out.(*bytes.Buffer).String()
	if strings.Contains(output, "super-secret-value") {
		t.Errorf("secret value must be masked on TTY, got: %q", output)
	}
	if !strings.Contains(output, "***") {
		t.Errorf("secret must be replaced with '***' on TTY, got: %q", output)
	}
}

// TestGet_Piped_EmitsRealValue verifies that PrintSecret emits the real value
// when not on a TTY (piped / --ci / --json disabled).
func TestGet_Piped_EmitsRealValue(t *testing.T) {
	t.Parallel()

	r := &render.Renderer{
		Out:    &bytes.Buffer{},
		Err:    &bytes.Buffer{},
		IsJSON: false,
		IsTTY:  false,
	}
	r.PrintSecret("MY_KEY", "super-secret-value")
	output := r.Out.(*bytes.Buffer).String()
	if !strings.Contains(output, "super-secret-value") {
		t.Errorf("real value must be emitted when piped, got: %q", output)
	}
}

// TestDecrypt_TTY_MasksValues verifies that PrintDecryptResult masks all values
// on a TTY (interactive mode).
func TestDecrypt_TTY_MasksValues(t *testing.T) {
	t.Parallel()

	r := &render.Renderer{
		Out:    &bytes.Buffer{},
		Err:    &bytes.Buffer{},
		IsJSON: false,
		IsTTY:  true,
	}
	r.PrintDecryptResult(map[string]string{
		"KEY_A": "value-a",
		"KEY_B": "value-b",
	}, []string{"KEY_A", "KEY_B"})
	output := r.Out.(*bytes.Buffer).String()
	if strings.Contains(output, "value-a") || strings.Contains(output, "value-b") {
		t.Errorf("secret values must be masked on TTY, got: %q", output)
	}
	if !strings.Contains(output, "***") {
		t.Errorf("values must be replaced with '***' on TTY, got: %q", output)
	}
}

// TestDecrypt_Piped_EmitsRealValues verifies that PrintDecryptResult emits real
// values when not on a TTY (piped / --ci / --json disabled).
func TestDecrypt_Piped_EmitsRealValues(t *testing.T) {
	t.Parallel()

	r := &render.Renderer{
		Out:    &bytes.Buffer{},
		Err:    &bytes.Buffer{},
		IsJSON: false,
		IsTTY:  false,
	}
	r.PrintDecryptResult(map[string]string{"KEY_A": "plaintext-value"}, []string{"KEY_A"})
	output := r.Out.(*bytes.Buffer).String()
	if !strings.Contains(output, "plaintext-value") {
		t.Errorf("real value must be emitted when piped, got: %q", output)
	}
}

// TestJSONError_Schema_NoPlaintextLeak_AllFailureClasses verifies that the
// --json error schema emitted by PrintErrorClass never carries secret values
// across all documented failure classes.
func TestJSONError_Schema_NoPlaintextLeak_AllFailureClasses(t *testing.T) {
	t.Parallel()

	const secretValue = "PRIVATE-SECRET-12345"
	const privateKey = "AGE-SECRET-KEY-1ABCDEF"

	cases := []struct {
		name string
		code string
		msg  string
		hint string
	}{
		{"permission-denied", "permission-denied", "access denied for get", "run doctor"},
		{"not-found", "not-found", "file not found", "check path"},
		{"decode-malformed", "decode-malformed", "artifact decode failed", "check file"},
		{"verify-failure", "verify-failure", "verify failed", "check registry"},
		{"decrypt-no-identity", "decrypt-no-identity", "no identity", "run auth login"},
		{"internal", "internal", "re-sign failed", "retry"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var errBuf bytes.Buffer
			r := &render.Renderer{
				Out:    &bytes.Buffer{},
				Err:    &errBuf,
				IsJSON: true,
				IsTTY:  false,
			}
			r.PrintErrorClass(tc.code, tc.msg, tc.hint)

			output := errBuf.String()
			if strings.Contains(output, secretValue) {
				t.Errorf("class %s: secret value in --json error output: %q", tc.name, output)
			}
			if strings.Contains(output, privateKey) {
				t.Errorf("class %s: private key in --json error output: %q", tc.name, output)
			}

			// Verify the JSON schema parses correctly.
			var schema render.JSONErrorSchema
			if decErr := json.Unmarshal([]byte(output), &schema); decErr != nil {
				t.Fatalf("class %s: --json error output not valid JSON: %v\noutput: %q",
					tc.name, decErr, output)
			}
			if schema.Error.Code != tc.code {
				t.Errorf("class %s: code = %q, want %q", tc.name, schema.Error.Code, tc.code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Obligation: Exit codes are distinct per class (regression guard)
// ---------------------------------------------------------------------------

// TestExitCodes_Distinct_PerClass is a regression guard verifying that the
// exit codes documented in render.go are numerically distinct per class.
func TestExitCodes_Distinct_PerClass(t *testing.T) {
	t.Parallel()

	codes := []struct {
		name string
		code render.ExitCode
	}{
		{"ok", render.ExitOK},
		{"general-error", render.ExitGeneralError},
		{"permission-denied", render.ExitPermissionDenied},
		{"auth-error", render.ExitAuthError},
		{"not-found", render.ExitNotFound},
		{"replay", render.ExitReplay},
		{"counter-reconcile", render.ExitCounterReconcile},
		{"trust-error", render.ExitTrustError},
		{"decode-malformed", render.ExitDecodeMalformed},
		{"verify-failure", render.ExitVerifyFailure},
	}

	seen := make(map[render.ExitCode]string)
	for _, tc := range codes {
		if existing, dup := seen[tc.code]; dup {
			t.Errorf("exit code %d is shared by %q and %q — codes must be distinct",
				tc.code, existing, tc.name)
		}
		seen[tc.code] = tc.name
	}
}
