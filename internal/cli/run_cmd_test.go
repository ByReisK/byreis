package cli

// White-box tests for the `run` verb. White-box (package cli) so the tests can
// drive the unexported newRenderer + runEnvProvider seams and exercise RunE
// end-to-end through the cobra command tree. The fakes below are run-specific;
// recordingDecryptor / panicDecryptor / withInjectedTTY / curOut / curErr are
// shared with export_cmd_test.go (same package).

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// recordingRunChild is an injectable fake RunChild that records the argv and
// env block it was handed and returns a configurable ChildExit/error.
type recordingRunChild struct {
	exit   ChildExit
	err    error
	called bool
	gotCtx context.Context
	gotArg []string
	gotEnv []string
}

func (r *recordingRunChild) run(ctx context.Context, argv []string, env []string) (ChildExit, error) {
	r.called = true
	r.gotCtx = ctx
	r.gotArg = argv
	r.gotEnv = env
	return r.exit, r.err
}

// panicRunChild panics if invoked. Used to prove the verb never spawns a child
// when the gate denies, the decrypt fails, or the env-block build fails.
func panicRunChild(_ context.Context, _ []string, _ []string) (ChildExit, error) {
	panic("RunChild must NOT be reached on this path")
}

// withRunEnv overrides the runEnvProvider seam so the verb sees a deterministic
// parent environment, then restores the production seam.
func withRunEnv(t *testing.T, env []string) {
	t.Helper()
	orig := runEnvProvider
	runEnvProvider = func() []string { return env }
	t.Cleanup(func() { runEnvProvider = orig })
}

// runRun drives the run verb through the full root command tree, with stdout
// and stderr wired to the per-test buffers set by withInjectedTTY.
func runRun(deps *Deps, args ...string) error {
	root := NewRootCmdWithDeps(deps)
	if curOut != nil {
		root.SetOut(curOut)
	}
	if curErr != nil {
		root.SetErr(curErr)
	}
	root.SetArgs(append([]string{"run"}, args...))
	return root.Execute()
}

// envVal extracts the value for name from a "KEY=VALUE" env block, or "",false.
func envVal(block []string, name string) (string, bool) {
	for _, e := range block {
		if eq := strings.IndexByte(e, '='); eq >= 0 && e[:eq] == name {
			return e[eq+1:], true
		}
	}
	return "", false
}

// AC-001-A: an ADMIN reaches the decrypt path, RunChild is called with the
// verbatim post-`--` argv, and the env block carries the secrets with
// injected-wins over a planted inherited variable.
func TestRun_AdminMode_DecryptsAndSpawns(t *testing.T) {
	withInjectedTTY(t, false)
	// Plant an inherited var that collides with an injected secret name, plus a
	// non-colliding inherited var that must survive into the child block.
	withRunEnv(t, []string{"API_KEY=inherited-loser", "PATH=/usr/bin"})

	dec := &recordingDecryptor{result: usecase.DecryptResult{
		Plaintext: map[string]string{"API_KEY": "abc123", "DB_HOST": "db.local"},
		KeyNames:  []string{"API_KEY", "DB_HOST"},
	}}
	spawn := &recordingRunChild{exit: ChildExit{Code: 0}}
	deps := &Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   dec,
		RunChild:    spawn.run,
	}

	if err := runRun(deps, "--project", "proj", "--file", "prod", "--", "deploy.sh", "--flag", "x"); err != nil {
		t.Fatalf("run ADMIN: unexpected error: %v", err)
	}
	if !dec.called {
		t.Fatal("Decryptor.Decrypt was not called in ADMIN mode")
	}
	if !spawn.called {
		t.Fatal("RunChild was not called in ADMIN mode")
	}
	// Child argv is the post-`--` command, verbatim.
	wantArgv := []string{"deploy.sh", "--flag", "x"}
	if len(spawn.gotArg) != len(wantArgv) {
		t.Fatalf("child argv = %v, want %v", spawn.gotArg, wantArgv)
	}
	for i := range wantArgv {
		if spawn.gotArg[i] != wantArgv[i] {
			t.Fatalf("child argv = %v, want %v", spawn.gotArg, wantArgv)
		}
	}
	// Injected secrets present.
	if v, ok := envVal(spawn.gotEnv, "API_KEY"); !ok || v != "abc123" {
		t.Errorf("API_KEY in child env = %q,%v; want \"abc123\",true (injected-wins)", v, ok)
	}
	if v, ok := envVal(spawn.gotEnv, "DB_HOST"); !ok || v != "db.local" {
		t.Errorf("DB_HOST in child env = %q,%v; want \"db.local\",true", v, ok)
	}
	// Injected-wins: the inherited API_KEY must not survive.
	if cnt := countVar(spawn.gotEnv, "API_KEY"); cnt != 1 {
		t.Errorf("API_KEY appears %d times in child env; want exactly 1 (injected-wins)", cnt)
	}
	for _, e := range spawn.gotEnv {
		if e == "API_KEY=inherited-loser" {
			t.Error("inherited API_KEY survived; injected value must win")
		}
	}
	// Non-colliding inherited var survives.
	if v, ok := envVal(spawn.gotEnv, "PATH"); !ok || v != "/usr/bin" {
		t.Errorf("inherited PATH = %q,%v; want \"/usr/bin\",true", v, ok)
	}
	// op="run" recorded; no child args reach the decrypt input.
	if dec.gotIn.Op != "run" {
		t.Errorf("DecryptInput.Op = %q, want %q", dec.gotIn.Op, "run")
	}
}

func countVar(block []string, name string) int {
	n := 0
	for _, e := range block {
		if eq := strings.IndexByte(e, '='); eq >= 0 && e[:eq] == name {
			n++
		}
	}
	return n
}

// AC-001-B / S2-1: a CONTRIBUTOR invocation is denied-not-attempted. NEITHER the
// decrypt port NOR RunChild is reached (dual panic-spy), and the result is
// ErrPermissionDenied with exit code 2.
func TestRun_Contributor_DeniedNotAttempted_DualPanicSpy(t *testing.T) {
	withInjectedTTY(t, false)
	withRunEnv(t, []string{"PATH=/usr/bin"})
	deps := &Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
		Decryptor:   panicDecryptor{}, // must never be reached
		RunChild:    panicRunChild,    // must never be reached
	}

	err := runRun(deps, "--project", "proj", "--file", "prod", "--", "printenv")
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

// S2-1: a decrypt error fails closed — RunChild is NEVER called (panic-spy) and
// no plaintext is emitted. The child code path is not entered.
func TestRun_DecryptError_NoSpawn(t *testing.T) {
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
			withRunEnv(t, []string{"PATH=/usr/bin"})

			const secret = "MUST-NOT-LEAK-9999"
			dec := &recordingDecryptor{
				result: usecase.DecryptResult{Plaintext: map[string]string{"K": secret}, KeyNames: []string{"K"}},
				err:    &usecase.ReadPathError{Class: tc.class, Op: "run"},
			}
			deps := &Deps{
				Policy:      &mode.Policy{},
				CurrentMode: mode.ModeAdmin,
				Decryptor:   dec,
				RunChild:    panicRunChild, // must never be reached on decrypt error
			}

			err := runRun(deps, "--project", "proj", "--file", "prod", "--", "printenv")
			if err == nil {
				t.Fatal("expected a fail-closed decrypt error, got nil")
			}
			if code := ExitCodeOf(err); code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if strings.Contains(out.String(), secret) || strings.Contains(errBuf.String(), secret) {
				t.Errorf("secret value leaked on decrypt failure: out=%q err=%q", out.String(), errBuf.String())
			}
		})
	}
}

// S2-1: a mapping/collision error fails closed — RunChild is NEVER called, no
// plaintext, and the error names the offending key(s) only (no secret value).
func TestRun_MappingFailure_NoSpawn(t *testing.T) {
	cases := []struct {
		name     string
		plain    map[string]string
		keyNames []string
		sentinel error
	}{
		{
			name:     "leading digit",
			plain:    map[string]string{"2fa_seed": "v-secret"},
			keyNames: []string{"2fa_seed"},
			sentinel: render.ErrLeadingDigit,
		},
		{
			name:     "post-mapping collision",
			plain:    map[string]string{"api.key": "v1-secret", "api-key": "v2-secret"},
			keyNames: []string{"api.key", "api-key"},
			sentinel: render.ErrVarCollision,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, errBuf := withInjectedTTY(t, false)
			withRunEnv(t, []string{"PATH=/usr/bin"})

			dec := &recordingDecryptor{result: usecase.DecryptResult{
				Plaintext: tc.plain,
				KeyNames:  tc.keyNames,
			}}
			deps := &Deps{
				Policy:      &mode.Policy{},
				CurrentMode: mode.ModeAdmin,
				Decryptor:   dec,
				RunChild:    panicRunChild, // must never be reached on mapping error
			}

			err := runRun(deps, "--project", "proj", "--file", "prod", "--", "printenv")
			if err == nil {
				t.Fatal("expected a fail-closed mapping error, got nil")
			}
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("expected error wrapping %v, got: %v", tc.sentinel, err)
			}
			for _, v := range tc.plain {
				if strings.Contains(errBuf.String(), v) {
					t.Errorf("error output leaked a secret value %q: %q", v, errBuf.String())
				}
			}
		})
	}
}

// S2-1: a NUL byte in an injected value fails closed in BuildChildEnvBlock —
// RunChild is NEVER called and the error names the variable only.
func TestRun_NulInValue_NoSpawn(t *testing.T) {
	_, errBuf := withInjectedTTY(t, false)
	withRunEnv(t, []string{"PATH=/usr/bin"})

	const secret = "bad\x00value-SECRET"
	dec := &recordingDecryptor{result: usecase.DecryptResult{
		Plaintext: map[string]string{"TOKEN": secret},
		KeyNames:  []string{"TOKEN"},
	}}
	deps := &Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   dec,
		RunChild:    panicRunChild, // must never be reached on NUL error
	}

	err := runRun(deps, "--project", "proj", "--file", "prod", "--", "printenv")
	if err == nil {
		t.Fatal("expected a NUL fail-closed error, got nil")
	}
	if !errors.Is(err, render.ErrNulInValue) {
		t.Errorf("expected error wrapping render.ErrNulInValue, got: %v", err)
	}
	if strings.Contains(errBuf.String(), "value-SECRET") {
		t.Errorf("error leaked secret value: %q", errBuf.String())
	}
}

// AC-003: the child's exit code is passed through unchanged as byreis's own
// exit code, including the 128+signal encoding for a signalled child.
func TestRun_ExitCodePassthrough(t *testing.T) {
	cases := []struct {
		name string
		exit ChildExit
		want int
	}{
		{"clean exit 0", ChildExit{Code: 0}, 0},
		{"nonzero exit 42", ChildExit{Code: 42}, 42},
		{"signalled SIGINT (128+2)", ChildExit{Code: 130, Signalled: true, Signal: 2}, 130},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			withInjectedTTY(t, false)
			withRunEnv(t, []string{"PATH=/usr/bin"})

			dec := &recordingDecryptor{result: usecase.DecryptResult{
				Plaintext: map[string]string{"K": "v"},
				KeyNames:  []string{"K"},
			}}
			spawn := &recordingRunChild{exit: tc.exit}
			deps := &Deps{
				Policy:      &mode.Policy{},
				CurrentMode: mode.ModeAdmin,
				Decryptor:   dec,
				RunChild:    spawn.run,
			}

			err := runRun(deps, "--project", "proj", "--file", "prod", "--", "child")
			if !spawn.called {
				t.Fatal("RunChild was not called")
			}
			if got := ExitCodeOf(err); got != tc.want {
				t.Errorf("byreis exit code = %d, want %d (child passthrough)", got, tc.want)
			}
		})
	}
}

// S2-2: the verb must NOT capture/tee/buffer the child's stdio. The verb hands
// argv + env to RunChild and never passes any io.Writer/Reader to it — the
// adapter wires os.Std* directly. Asserting the RunChild signature carries no
// stream and that the verb does not read child output (the fake returns no
// stream and the verb produces no stdout of its own on success).
func TestRun_NoStdioCapture(t *testing.T) {
	out, _ := withInjectedTTY(t, false)
	withRunEnv(t, []string{"PATH=/usr/bin"})

	dec := &recordingDecryptor{result: usecase.DecryptResult{
		Plaintext: map[string]string{"K": "v"},
		KeyNames:  []string{"K"},
	}}
	spawn := &recordingRunChild{exit: ChildExit{Code: 0}}
	deps := &Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   dec,
		RunChild:    spawn.run,
	}

	if err := runRun(deps, "--project", "proj", "--file", "prod", "--", "child"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The verb itself writes nothing to stdout on a successful run: it does not
	// interpose on the child's streams (no capture/tee/buffer). The child's own
	// stdio is inherited inside the adapter, never routed through the verb's
	// renderer buffer.
	if out.Len() != 0 {
		t.Errorf("verb wrote to stdout on success; it must not interpose on child stdio, got: %q", out.String())
	}
}

// S2-3 / AC-005-C: the audit op is "run" and ZERO child args (and zero secret
// values) reach the decrypt input. The shipped use-case records the audit
// event from DecryptInput.Op; the verb must pass only the op literal and never
// fold the child argv/args into the decrypt input.
func TestRun_Audit_OpRunOnly_NoChildArgs(t *testing.T) {
	withInjectedTTY(t, false)
	withRunEnv(t, []string{"PATH=/usr/bin"})

	dec := &recordingDecryptor{result: usecase.DecryptResult{
		Plaintext: map[string]string{"K": "v"},
		KeyNames:  []string{"K"},
	}}
	spawn := &recordingRunChild{exit: ChildExit{Code: 0}}
	deps := &Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   dec,
		RunChild:    spawn.run,
	}

	const sentinelArg = "SECRET-ARG-DO-NOT-AUDIT"
	if err := runRun(deps, "--project", "proj", "--file", "prod", "--", "deploy", sentinelArg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.gotIn.Op != "run" {
		t.Errorf("DecryptInput.Op = %q, want %q", dec.gotIn.Op, "run")
	}
	// The decrypt input carries only project/file/op — never the child argv.
	if len(dec.gotIn.Keys) != 0 {
		t.Errorf("DecryptInput.Keys = %v, want empty (whole-file run)", dec.gotIn.Keys)
	}
	// Reconstruct every field the use-case could audit and prove the child argv
	// (incl. the sentinel arg) appears in none of them.
	audited := strings.Join([]string{dec.gotIn.Op, dec.gotIn.ProjectID, dec.gotIn.FileName}, " ")
	if strings.Contains(audited, sentinelArg) || strings.Contains(audited, "deploy") {
		t.Errorf("child argv reached the decrypt/audit input: %q", audited)
	}
	// The child argv that DID reach the spawner still carries the args verbatim
	// (proving the args exist and were intentionally kept out of the audit path).
	if len(spawn.gotArg) != 2 || spawn.gotArg[1] != sentinelArg {
		t.Errorf("child argv = %v, want [deploy %s]", spawn.gotArg, sentinelArg)
	}
}

// REQ-V08 GATED-RUN-E: an empty secret set still spawns cleanly — RunChild is
// called with just the inherited env (no injected pairs).
func TestRun_EmptySecretSet_CleanSpawn(t *testing.T) {
	withInjectedTTY(t, false)
	parent := []string{"PATH=/usr/bin", "HOME=/home/u"}
	withRunEnv(t, parent)

	dec := &recordingDecryptor{result: usecase.DecryptResult{
		Plaintext: map[string]string{},
		KeyNames:  []string{},
	}}
	spawn := &recordingRunChild{exit: ChildExit{Code: 0}}
	deps := &Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeAdmin,
		Decryptor:   dec,
		RunChild:    spawn.run,
	}

	if err := runRun(deps, "--project", "proj", "--file", "prod", "--", "child"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !spawn.called {
		t.Fatal("RunChild was not called for an empty secret set")
	}
	got := append([]string{}, spawn.gotEnv...)
	want := append([]string{}, parent...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("child env = %v, want just the inherited env %v", spawn.gotEnv, parent)
	}
}

// Missing child argv (nothing after `--`, or no `--` at all) → actionable
// error, decrypt and spawn never reached.
func TestRun_MissingChildArgv_NoDecrypt(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no -- separator", []string{"--project", "proj", "--file", "prod"}},
		{"-- with nothing after", []string{"--project", "proj", "--file", "prod", "--"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			withInjectedTTY(t, false)
			withRunEnv(t, []string{"PATH=/usr/bin"})
			deps := &Deps{
				Policy:      &mode.Policy{},
				CurrentMode: mode.ModeAdmin,
				Decryptor:   panicDecryptor{}, // must never be reached
				RunChild:    panicRunChild,    // must never be reached
			}
			err := runRun(deps, tc.args...)
			if err == nil {
				t.Fatal("expected an error for missing child argv, got nil")
			}
			if code := ExitCodeOf(err); code != int(render.ExitGeneralError) {
				t.Errorf("exit code = %d, want %d (ExitGeneralError)", code, render.ExitGeneralError)
			}
		})
	}
}

// Nil RunChild / nil Decryptor → actionable "not configured" error.
func TestRun_NotConfigured(t *testing.T) {
	cases := []struct {
		name string
		deps *Deps
	}{
		{
			name: "nil Decryptor",
			deps: &Deps{Policy: &mode.Policy{}, CurrentMode: mode.ModeAdmin, Decryptor: nil, RunChild: panicRunChild},
		},
		{
			name: "nil RunChild",
			deps: &Deps{Policy: &mode.Policy{}, CurrentMode: mode.ModeAdmin, Decryptor: panicDecryptor{}, RunChild: nil},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			withInjectedTTY(t, false)
			withRunEnv(t, []string{"PATH=/usr/bin"})
			err := runRun(tc.deps, "--project", "proj", "--file", "prod", "--", "child")
			if err == nil {
				t.Fatal("expected a not-configured error, got nil")
			}
			if code := ExitCodeOf(err); code != int(render.ExitGeneralError) {
				t.Errorf("exit code = %d, want %d (ExitGeneralError)", code, render.ExitGeneralError)
			}
		})
	}
}
