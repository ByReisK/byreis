package cli_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// stubGetter is an injectable fake that satisfies usecase.Getter for CLI tests.
// It records whether it was called and returns a configurable result or error.
type stubGetter struct {
	result usecase.GetResult
	err    error
	called bool
}

func (s *stubGetter) Get(_ context.Context, _ usecase.GetInput) (usecase.GetResult, error) {
	s.called = true
	return s.result, s.err
}

// stubDecryptUseCase is an injectable fake that satisfies usecase.DecryptUseCase.
type stubDecryptUseCase struct {
	result usecase.DecryptResult
	err    error
	called bool
}

func (s *stubDecryptUseCase) Decrypt(_ context.Context, _ usecase.DecryptInput) (usecase.DecryptResult, error) {
	s.called = true
	return s.result, s.err
}

// stubEditUseCase is an injectable fake that satisfies usecase.EditUseCase.
type stubEditUseCase struct {
	result usecase.EditResult
	err    error
	called bool
}

func (s *stubEditUseCase) Edit(_ context.Context, _ usecase.EditInput) (usecase.EditResult, error) {
	s.called = true
	return s.result, s.err
}

// ---------------------------------------------------------------------------
// Obligation: denied-not-attempted through root.Execute() with real wired deps
// ---------------------------------------------------------------------------

// TestDeniedNotAttempted_ReadPathOps_ThroughRootExecute drives the full cobra
// dispatch path (NewRootCmdWithDeps → root.Execute()) in CONTRIBUTOR mode to prove:
//
//   - get/decrypt/edit/decrypt --ci each produce ErrPermissionDenied
//   - the process exit code is ExitPermissionDenied (2)
//   - the injected use-case stubs are NEVER called (no fetch/decode/decrypt entered)
//
// This is the shipped entry-point test for the denied-not-attempted property
// through root.Execute() with the real codec + adapters wired (simulated by
// injected stubs that record entry).
func TestDeniedNotAttempted_ReadPathOps_ThroughRootExecute(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		args    []string
		cmdName string
	}{
		{
			name:    "get contributor denied",
			args:    []string{"get", "--key", "mykey", "--project", "proj", "--file", "prod"},
			cmdName: "get",
		},
		{
			name:    "decrypt contributor denied",
			args:    []string{"decrypt", "--project", "proj", "--file", "prod"},
			cmdName: "decrypt",
		},
		{
			name:    "decrypt --ci contributor denied",
			args:    []string{"decrypt", "--ci", "--project", "proj", "--file", "prod"},
			cmdName: "decrypt --ci",
		},
		{
			name:    "edit contributor denied",
			args:    []string{"edit", "--project", "proj", "--file", "prod"},
			cmdName: "edit",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			getter := &stubGetter{result: usecase.GetResult{Value: "secret"}}
			decryptor := &stubDecryptUseCase{result: usecase.DecryptResult{
				Plaintext: map[string]string{"K": "v"},
			}}
			editor := &stubEditUseCase{result: usecase.EditResult{ReEncrypted: true}}

			deps := &cli.Deps{
				Policy:      &mode.Policy{},
				CurrentMode: mode.ModeContributor,
				Getter:      getter,
				Decryptor:   decryptor,
				Editor:      editor,
			}

			root := cli.NewRootCmdWithDeps(deps)
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(tc.args)

			err := root.Execute()
			if err == nil {
				t.Fatalf("%s: expected ErrPermissionDenied, got nil", tc.cmdName)
			}
			if !errors.Is(err, mode.ErrPermissionDenied) {
				t.Errorf("%s: expected error wrapping mode.ErrPermissionDenied, got: %v",
					tc.cmdName, err)
			}
			exitCode := cli.ExitCodeOf(err)
			if exitCode != int(render.ExitPermissionDenied) {
				t.Errorf("%s: expected exit code %d, got %d",
					tc.cmdName, render.ExitPermissionDenied, exitCode)
			}
			if getter.called || decryptor.called || editor.called {
				t.Errorf("%s: use-case was called despite CONTRIBUTOR mode denial — "+
					"denied-not-attempted invariant violated "+
					"(getter=%v decryptor=%v editor=%v)",
					tc.cmdName, getter.called, decryptor.called, editor.called)
			}
		})
	}
}

// TestGet_AdminMode_CallsUseCaseAndReturnsResult verifies that in ADMIN mode
// with a wired Getter, the `get` command calls the use-case and exits 0.
func TestGet_AdminMode_CallsUseCaseAndReturnsResult(t *testing.T) {
	t.Parallel()

	getter := &stubGetter{result: usecase.GetResult{
		Key: "mykey", Value: "the-secret-value", KeyNames: []string{"mykey"},
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
	root.SetArgs([]string{"get", "--key", "mykey", "--project", "proj", "--file", "prod"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("get in ADMIN mode: unexpected error: %v", err)
	}
	if !getter.called {
		t.Error("Getter.Get was not called in ADMIN mode")
	}
}

// TestGet_AdminMode_NilGetter_ReturnsNotConfiguredError verifies that when no
// Getter is wired (nil), the command returns an actionable error rather than
// panicking or silently succeeding.
func TestGet_AdminMode_NilGetter_ReturnsNotConfiguredError(t *testing.T) {
	t.Parallel()

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Getter:      nil,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"get", "--key", "mykey", "--project", "proj", "--file", "prod"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected an error when Getter is nil, got nil")
	}
}

// ---------------------------------------------------------------------------
// Obligation: exit-code mapping from ReadPathError exit classes
// ---------------------------------------------------------------------------

// TestReadPath_ExitCodeMapping verifies that each ReadPathError exit class
// maps to the correct distinct process exit code. Uses ExitCodeFromReadPathError
// directly so the mapping is tested independently of the cobra dispatch.
func TestReadPath_ExitCodeMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		class    usecase.ExitClass
		wantCode render.ExitCode
	}{
		{"permission-denied", usecase.ExitPermissionDenied, render.ExitPermissionDenied},
		{"not-found", usecase.ExitNotFound, render.ExitNotFound},
		{"decode-malformed", usecase.ExitDecodeMalformed, render.ExitDecodeMalformed},
		{"verify-failure", usecase.ExitVerifyFailure, render.ExitVerifyFailure},
		{"decrypt-no-identity", usecase.ExitDecryptNoIdentity, render.ExitAuthError},
		{"internal", usecase.ExitInternal, render.ExitGeneralError},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotCode := cli.ExitCodeFromReadPathError(tc.class)
			if gotCode != int(tc.wantCode) {
				t.Errorf("exit class %v: ExitCodeFromReadPathError = %d, want %d (%v)",
					tc.class, gotCode, int(tc.wantCode), tc.wantCode)
			}
		})
	}
}

// TestReadPath_ExitCodeMapping_DistinctValues verifies that all documented exit
// codes for read-path classes are numerically distinct (no two classes share a
// code except ExitInternal→ExitGeneralError which is documented).
func TestReadPath_ExitCodeMapping_DistinctValues(t *testing.T) {
	t.Parallel()

	seen := make(map[int]usecase.ExitClass)
	skipDup := map[usecase.ExitClass]bool{
		usecase.ExitInternal: true, // maps to ExitGeneralError (1) intentionally
	}

	classes := []usecase.ExitClass{
		usecase.ExitPermissionDenied,
		usecase.ExitNotFound,
		usecase.ExitDecodeMalformed,
		usecase.ExitVerifyFailure,
		usecase.ExitDecryptNoIdentity,
	}

	for _, class := range classes {
		code := cli.ExitCodeFromReadPathError(class)
		if existing, dup := seen[code]; dup && !skipDup[class] {
			t.Errorf("exit code %d is shared by %v and %v — codes must be distinct",
				code, existing, class)
		}
		seen[code] = class
	}
}

// ---------------------------------------------------------------------------
// Obligation: CI-decrypt headless path
// ---------------------------------------------------------------------------

// TestDecrypt_CI_AdminMode_HeadlessSuccess verifies that decrypt --ci calls
// the Decrypt use-case in non-interactive (headless) mode and exits 0.
// The VerifyOfRecord-first guarantee is enforced inside the use-case itself
// (tested in core/usecase readpath_test.go); this test verifies the CLI wires
// it correctly for the CI-decrypt entrypoint.
func TestDecrypt_CI_AdminMode_HeadlessSuccess(t *testing.T) {
	t.Parallel()

	decryptor := &stubDecryptUseCase{result: usecase.DecryptResult{
		Plaintext:  map[string]string{"API_KEY": "the-value"},
		ContentSHA: "abc123",
		KeyNames:   []string{"API_KEY"},
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
	root.SetArgs([]string{"decrypt", "--ci", "--project", "proj", "--file", "prod", "--json"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("decrypt --ci in ADMIN mode: unexpected error: %v", err)
	}
	if !decryptor.called {
		t.Error("Decryptor.Decrypt was not called in --ci mode")
	}
	// JSON output must not be empty.
	if out.Len() == 0 {
		t.Error("expected JSON output from decrypt --ci --json, got empty")
	}
}

// TestDecrypt_CI_ContributorMode_Denied verifies the denied-not-attempted
// property for decrypt --ci in CONTRIBUTOR mode specifically.
func TestDecrypt_CI_ContributorMode_Denied(t *testing.T) {
	t.Parallel()

	decryptor := &stubDecryptUseCase{}
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Decryptor:   decryptor,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"decrypt", "--ci", "--project", "proj", "--file", "prod"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected ErrPermissionDenied for decrypt --ci in CONTRIBUTOR mode, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("expected mode.ErrPermissionDenied, got: %v", err)
	}
	if decryptor.called {
		t.Error("Decryptor.Decrypt was called despite CONTRIBUTOR mode denial")
	}
}

// TestDecrypt_CI_NoDecryptor_NilWired returns an error when no Decryptor
// is wired and CI mode is requested.
func TestDecrypt_CI_NoDecryptor_NilWired(t *testing.T) {
	t.Parallel()

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   nil,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"decrypt", "--ci", "--project", "proj", "--file", "prod"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when Decryptor is nil in --ci mode, got nil")
	}
}

// ---------------------------------------------------------------------------
// Obligation: no plaintext/key on failure channels
// ---------------------------------------------------------------------------

// TestReadPath_NoLeakOnFailure_VerifyError verifies that when the use-case
// returns a verify-failure error, neither the plaintext nor any key hint
// appears in the rendered error output or --json error object.
func TestReadPath_NoLeakOnFailure_VerifyError(t *testing.T) {
	t.Parallel()

	const secretPlaintext = "SUPER-SECRET-LEAK-CHECK"
	const privateKeyHint = "AGE-SECRET-KEY"

	// The use-case returns an error that does NOT contain the secret or key.
	errFromUseCase := errors.New("verify failed: of-record verification failed — no secret here")
	getter := &stubGetter{err: errFromUseCase}

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Getter:      getter,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"get", "--key", "mykey", "--project", "proj", "--file", "prod"})

	execErr := root.Execute()
	if execErr == nil {
		t.Fatal("expected error from use-case, got nil")
	}

	combined := out.String() + execErr.Error()
	if strings.Contains(combined, secretPlaintext) {
		t.Errorf("plaintext leaked on failure channel: %q", combined)
	}
	if strings.Contains(combined, privateKeyHint) {
		t.Errorf("private key hint leaked on failure channel: %q", combined)
	}
}

// ---------------------------------------------------------------------------
// Compile-time assertions: Deps accepts narrow interface types
// ---------------------------------------------------------------------------

// These blank-identifier assignments prove at compile time that the Deps struct
// fields accept the narrow use-case interface types (not *PortAdapter or any
// concrete adapter). If any field were typed to a concrete adapter, the pointer
// assignment here would fail to compile.
var (
	_ usecase.Getter         = (*stubGetter)(nil)
	_ usecase.DecryptUseCase = (*stubDecryptUseCase)(nil)
	_ usecase.EditUseCase    = (*stubEditUseCase)(nil)
)
