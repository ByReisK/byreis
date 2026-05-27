package cli

// White-box tests for the `export` verb. White-box (package cli) so the tests
// can drive the unexported newRenderer seam — which lets a test set the
// resolved IsTTY value directly without a real terminal — and exercise RunE
// end-to-end through the cobra command tree.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// recordingDecryptor is an injectable fake usecase.DecryptUseCase that records
// the last DecryptInput it received and returns a configurable result/error.
type recordingDecryptor struct {
	result usecase.DecryptResult
	err    error
	called bool
	gotIn  usecase.DecryptInput
}

func (d *recordingDecryptor) Decrypt(_ context.Context, in usecase.DecryptInput) (usecase.DecryptResult, error) {
	d.called = true
	d.gotIn = in
	return d.result, d.err
}

// panicDecryptor panics on any Decrypt call. Used to prove the mode gate denies
// a CONTRIBUTOR before the decrypt port is ever reached (denied-not-attempted),
// mirroring admin_audit_show_test.go's panicAuditReader.
type panicDecryptor struct{}

func (panicDecryptor) Decrypt(_ context.Context, _ usecase.DecryptInput) (usecase.DecryptResult, error) {
	panic("decrypt port must NOT be reached when export is denied-by-policy")
}

// withInjectedTTY temporarily overrides the newRenderer seam so RunE builds a
// renderer with the given IsTTY value, then restores the production seam. Only
// IsTTY is injected here: RunE assigns r.Out/r.Err from the cobra command's
// writers (which runExport wires to the returned buffers), mirroring the
// production path exactly. Returns the captured stdout/stderr buffers.
func withInjectedTTY(t *testing.T, isTTY bool) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errBuf bytes.Buffer
	curOut, curErr = &out, &errBuf
	orig := newRenderer
	newRenderer = func(jsonMode bool) *render.Renderer {
		return &render.Renderer{IsJSON: jsonMode, IsTTY: isTTY}
	}
	t.Cleanup(func() {
		newRenderer = orig
		curOut, curErr = nil, nil
	})
	return &out, &errBuf
}

// curOut/curErr hold the per-test cobra writers so runExport can wire stdout
// and stderr to separate buffers (the test asserts on each independently).
var curOut, curErr *bytes.Buffer

// runExport drives the export verb through the full root command tree, with
// stdout and stderr wired to the per-test buffers set by withInjectedTTY.
func runExport(deps *Deps, args ...string) error {
	root := NewRootCmdWithDeps(deps)
	if curOut != nil {
		root.SetOut(curOut)
	}
	if curErr != nil {
		root.SetErr(curErr)
	}
	root.SetArgs(append([]string{"export"}, args...))
	return root.Execute()
}

// AC-001-A: an ADMIN reaches the decrypt path and the env/dotenv stream is
// emitted via the emitter.
func TestExport_AdminMode_ReachesDecryptAndEmits(t *testing.T) {
	cases := []struct {
		name   string
		format string
		want   string
	}{
		{
			name:   "env format prefixes export",
			format: "env",
			want:   "export API_KEY=\"abc123\"\nexport DB_HOST=\"db.local\"\n",
		},
		{
			name:   "dotenv format has no export prefix",
			format: "dotenv",
			want:   "API_KEY=\"abc123\"\nDB_HOST=\"db.local\"\n",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out, _ := withInjectedTTY(t, false) // not a TTY: plaintext allowed

			dec := &recordingDecryptor{result: usecase.DecryptResult{
				Plaintext: map[string]string{"API_KEY": "abc123", "DB_HOST": "db.local"},
				KeyNames:  []string{"API_KEY", "DB_HOST"},
			}}
			deps := &Deps{
				Policy:      &mode.Policy{},
				CurrentMode: mode.ModeAdmin,
				Decryptor:   dec,
			}

			if err := runExport(deps, "--project", "proj", "--file", "prod", "--format", tc.format); err != nil {
				t.Fatalf("export ADMIN %s: unexpected error: %v", tc.format, err)
			}
			if !dec.called {
				t.Fatal("Decryptor.Decrypt was not called in ADMIN mode")
			}
			if dec.gotIn.Op != "export" {
				t.Errorf("DecryptInput.Op = %q, want %q", dec.gotIn.Op, "export")
			}
			if got := out.String(); got != tc.want {
				t.Errorf("emitted output:\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}

// AC-001-B: a CONTRIBUTOR invocation is denied-not-attempted. The decrypt port
// is a panic-spy that fails the test if reached; the result is
// ErrPermissionDenied with exit code 2.
func TestExport_Contributor_DeniedNotAttempted(t *testing.T) {
	deps := &Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Decryptor:   panicDecryptor{}, // must never be reached
	}

	err := runExport(deps, "--project", "proj", "--file", "prod", "--format", "env")
	if err == nil {
		t.Fatal("expected ErrPermissionDenied, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("expected error wrapping mode.ErrPermissionDenied, got: %v", err)
	}
	if code := ExitCodeOf(err); code != int(render.ExitPermissionDenied) {
		t.Errorf("exit code = %d, want %d (ExitPermissionDenied)", code, render.ExitPermissionDenied)
	}
}

// REQ-V07-002 AC-A: stdout is an interactive TTY → refuse. No plaintext on
// stdout, non-zero exit, the escape hint is on stderr. The decrypt port is a
// panic-spy: the fail-fast refusal happens before any decrypt.
func TestExport_TTY_RefusesWithNoPlaintext(t *testing.T) {
	out, errBuf := withInjectedTTY(t, true) // interactive terminal

	deps := &Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   panicDecryptor{}, // refusal is fail-fast, before decrypt
	}

	err := runExport(deps, "--project", "proj", "--file", "prod", "--format", "env")
	if err == nil {
		t.Fatal("expected TTY refusal error, got nil")
	}
	if code := ExitCodeOf(err); code == 0 {
		t.Errorf("expected non-zero exit on TTY refusal, got %d", code)
	}
	if out.Len() != 0 {
		t.Errorf("no plaintext must reach stdout on TTY refusal, got: %q", out.String())
	}
	if !strings.Contains(errBuf.String(), "pipe") && !strings.Contains(errBuf.String(), "redirect") {
		t.Errorf("stderr must name the pipe/redirect escape, got: %q", errBuf.String())
	}
}

// REQ-V07-002 AC-B: stdout is NOT a TTY (piped/redirected) → plaintext emitted,
// exit 0.
func TestExport_Piped_EmitsPlaintextExitZero(t *testing.T) {
	out, _ := withInjectedTTY(t, false)

	dec := &recordingDecryptor{result: usecase.DecryptResult{
		Plaintext: map[string]string{"TOKEN": "s3cr3t"},
		KeyNames:  []string{"TOKEN"},
	}}
	deps := &Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   dec,
	}

	if err := runExport(deps, "--project", "proj", "--file", "prod", "--format", "dotenv"); err != nil {
		t.Fatalf("piped export: unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), `TOKEN="s3cr3t"`) {
		t.Errorf("piped export must emit plaintext, got: %q", out.String())
	}
}

// --format invalid or missing → actionable error, decrypt never reached.
func TestExport_BadFormat_NoDecrypt(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{
			name: "unknown format value",
			args: []string{"--project", "proj", "--file", "prod", "--format", "yaml"},
		},
		// A missing --format is rejected by cobra's MarkFlagRequired before RunE
		// (the decrypt port is likewise never reached).
		{
			name: "missing format flag",
			args: []string{"--project", "proj", "--file", "prod"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			withInjectedTTY(t, false)
			deps := &Deps{
				Policy:      &mode.Policy{},
				CurrentMode: mode.ModeAdmin,
				Decryptor:   panicDecryptor{}, // must never be reached
			}
			if err := runExport(deps, tc.args...); err == nil {
				t.Fatal("expected an error for invalid/missing --format, got nil")
			}
		})
	}
}

// REQ-V07-004: a collision or leading-digit in the recovered key set propagates
// as a fail-closed error — NO plaintext is emitted.
func TestExport_MappingFailure_FailClosedNoPlaintext(t *testing.T) {
	cases := []struct {
		name     string
		plain    map[string]string
		keyNames []string
		sentinel error
	}{
		{
			name:     "leading digit",
			plain:    map[string]string{"2fa_seed": "v"},
			keyNames: []string{"2fa_seed"},
			sentinel: render.ErrLeadingDigit,
		},
		{
			name:     "post-mapping collision",
			plain:    map[string]string{"api.key": "v1", "api-key": "v2"},
			keyNames: []string{"api.key", "api-key"},
			sentinel: render.ErrVarCollision,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out, errBuf := withInjectedTTY(t, false)

			dec := &recordingDecryptor{result: usecase.DecryptResult{
				Plaintext: tc.plain,
				KeyNames:  tc.keyNames,
			}}
			deps := &Deps{
				Policy:      &mode.Policy{},
				CurrentMode: mode.ModeAdmin,
				Decryptor:   dec,
			}

			err := runExport(deps, "--project", "proj", "--file", "prod", "--format", "env")
			if err == nil {
				t.Fatal("expected a fail-closed mapping error, got nil")
			}
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("expected error wrapping %v, got: %v", tc.sentinel, err)
			}
			if out.Len() != 0 {
				t.Errorf("no plaintext must be emitted on mapping failure, got: %q", out.String())
			}
			// The error must name the offending key but never a secret value.
			for _, v := range tc.plain {
				if strings.Contains(errBuf.String(), v) {
					t.Errorf("error output leaked a secret value %q: %q", v, errBuf.String())
				}
			}
		})
	}
}

// REQ-V07-006: a decrypt error fails the whole export closed — no plaintext,
// the error propagates and the exit code reflects the failure class.
func TestExport_DecryptError_FailClosed(t *testing.T) {
	cases := []struct {
		name     string
		class    usecase.ExitClass
		wantCode int
	}{
		{"malformed envelope", usecase.ExitDecodeMalformed, int(render.ExitDecodeMalformed)},
		{"verify failure", usecase.ExitVerifyFailure, int(render.ExitVerifyFailure)},
		{"not a recipient", usecase.ExitDecryptNoIdentity, int(render.ExitAuthError)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out, errBuf := withInjectedTTY(t, false)

			const secret = "MUST-NOT-LEAK-9999"
			dec := &recordingDecryptor{
				// A real decryptAll discards plaintext on error; we set a result
				// here only to prove the verb never emits it when err != nil.
				result: usecase.DecryptResult{Plaintext: map[string]string{"K": secret}, KeyNames: []string{"K"}},
				err:    &usecase.ReadPathError{Class: tc.class, Op: "decrypt"},
			}
			deps := &Deps{
				Policy:      &mode.Policy{},
				CurrentMode: mode.ModeAdmin,
				Decryptor:   dec,
			}

			err := runExport(deps, "--project", "proj", "--file", "prod", "--format", "env")
			if err == nil {
				t.Fatal("expected a fail-closed decrypt error, got nil")
			}
			if code := ExitCodeOf(err); code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if out.Len() != 0 {
				t.Errorf("no plaintext must be emitted on decrypt failure, got: %q", out.String())
			}
			if strings.Contains(out.String(), secret) || strings.Contains(errBuf.String(), secret) {
				t.Errorf("secret value leaked on decrypt failure: out=%q err=%q", out.String(), errBuf.String())
			}
		})
	}
}

// Nil Decryptor → actionable "not wired" error (mirrors decrypt's nil-guard).
func TestExport_NilDecryptor_NotConfigured(t *testing.T) {
	withInjectedTTY(t, false)
	deps := &Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   nil,
	}
	err := runExport(deps, "--project", "proj", "--file", "prod", "--format", "env")
	if err == nil {
		t.Fatal("expected a not-configured error when Decryptor is nil, got nil")
	}
	if code := ExitCodeOf(err); code != int(render.ExitGeneralError) {
		t.Errorf("exit code = %d, want %d (ExitGeneralError)", code, render.ExitGeneralError)
	}
}
