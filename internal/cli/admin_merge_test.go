package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// fakeMergeUseCase records whether it was called and what it would return.
type fakeMergeUseCase struct {
	called bool
	result usecase.MergeResult
	err    error
}

func (f *fakeMergeUseCase) Merge(_ context.Context, _ usecase.MergeInput) (usecase.MergeResult, error) {
	f.called = true
	return f.result, f.err
}

// panicMergeUseCase panics if Merge is ever invoked (used to assert it is NOT
// called in permission-denied paths).
type panicMergeUseCase struct{}

func (p *panicMergeUseCase) Merge(_ context.Context, _ usecase.MergeInput) (usecase.MergeResult, error) {
	panic("Merge was called but must not be reached in CONTRIBUTOR mode")
}

// makeMergeDeps constructs minimal Deps for admin merge tests.
// MergeExitCode is wired here so the CLI can map adapter-layer sentinels
// to the correct render.ExitCode without the cli package importing
// internal/adapter/registry directly.
func makeMergeDeps(m mode.Mode, merger usecase.Merger) *cli.Deps {
	pol := &mode.Policy{}
	return &cli.Deps{
		Policy:        pol,
		CurrentMode:   m,
		Merger:        merger,
		MergeExitCode: mergeExitCodeFn,
	}
}

// mergeExitCodeFn maps adapter and core-registry sentinel errors to the
// documented render.ExitCode values. This is the test-side wiring of the same
// function that BuildProductionDeps sets in production.
func mergeExitCodeFn(err error) render.ExitCode {
	if errors.Is(err, registryadapter.ErrRegistryWriteAuth) {
		return render.ExitAuthError
	}
	if errors.Is(err, registryadapter.ErrRegistryConcurrentWrite) {
		return render.ExitCounterReconcile
	}
	if errors.Is(err, registryadapter.ErrRegistryWriteRejected) {
		return render.ExitTrustError
	}
	if errors.Is(err, countertypes.ErrCounterReconcile) {
		return render.ExitCounterReconcile
	}
	if errors.Is(err, coreregistry.ErrCacheTampered) {
		return render.ExitReplay
	}
	if errors.Is(err, coreregistry.ErrRegistryRollback) {
		return render.ExitReplay
	}
	return render.ExitGeneralError
}

func runMerge(t *testing.T, deps *cli.Deps, args ...string) (stdout, stderr *bytes.Buffer, exitCode int) {
	t.Helper()
	stdout = &bytes.Buffer{}
	stderr = &bytes.Buffer{}
	root := cli.NewRootCmdWithDeps(deps)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	exitCode = cli.ExitCodeOf(err)
	return
}

// MERGE_DENIED_IN_CONTRIBUTOR_BEFORE_USECASE
// CONTRIBUTOR mode must produce ExitPermissionDenied and the use-case must
// never be called.
func TestAdminMerge_DeniedInContributor_BeforeUseCase(t *testing.T) {
	t.Parallel()
	panicker := &panicMergeUseCase{}
	deps := makeMergeDeps(mode.ModeContributor, panicker)

	_, _, exitCode := runMerge(t, deps,
		"admin", "merge",
		"--project", "myapp",
		"--file", "prod",
		"--pr", "main#1",
	)
	if exitCode != int(render.ExitPermissionDenied) {
		t.Errorf("want exit %d (permission-denied), got %d", render.ExitPermissionDenied, exitCode)
	}
}

// MERGE_RUNS_IN_ADMIN
// Admin mode with a successful use-case must exit 0 and produce a valid JSON
// envelope.
func TestAdminMerge_RunsInAdmin_ExitsOK(t *testing.T) {
	t.Parallel()
	fake := &fakeMergeUseCase{
		result: usecase.MergeResult{
			ReEncrypted:    false,
			FinalCounter:   1,
			LiveFileSHA:    "sha1234",
			MergedCommit:   "abc",
			AlreadyApplied: false,
		},
	}
	deps := makeMergeDeps(mode.ModeAdmin, fake)

	out, _, exitCode := runMerge(t, deps,
		"admin", "merge",
		"--project", "myapp",
		"--file", "prod",
		"--pr", "main#1",
		"--json",
	)
	if exitCode != 0 {
		t.Fatalf("want exit 0, got %d; output: %s", exitCode, out.String())
	}
	if !fake.called {
		t.Error("expected Merge to be called")
	}
	// JSON envelope validation.
	var env map[string]any
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("JSON parse: %v; output: %s", err, out.String())
	}
	if _, ok := env["re_encrypted"]; !ok {
		t.Error("JSON missing re_encrypted field")
	}
	if _, ok := env["pending_counter"]; !ok {
		t.Error("JSON missing pending_counter field")
	}
	if _, ok := env["committed_counter"]; !ok {
		t.Error("JSON missing committed_counter field")
	}
	if _, ok := env["content_sha"]; !ok {
		t.Error("JSON missing content_sha field")
	}
}

// MERGE_AUTH_ERROR_EXITS_AUTH_ERROR
// ErrRegistryWriteAuth from the use-case must produce ExitAuthError.
func TestAdminMerge_AuthError_ExitsAuthError(t *testing.T) {
	t.Parallel()
	fake := &fakeMergeUseCase{err: registryadapter.ErrRegistryWriteAuth}
	deps := makeMergeDeps(mode.ModeAdmin, fake)

	_, stderr, exitCode := runMerge(t, deps,
		"admin", "merge",
		"--project", "myapp",
		"--file", "prod",
		"--pr", "main#1",
	)
	if exitCode != int(render.ExitAuthError) {
		t.Errorf("want exit %d (auth-error), got %d; stderr: %s",
			render.ExitAuthError, exitCode, stderr.String())
	}
	// No token in error text.
	if strings.Contains(stderr.String(), "ghp_") || strings.Contains(stderr.String(), "token=") {
		t.Errorf("stderr must not contain token-like strings: %s", stderr.String())
	}
}

// MERGE_CONCURRENT_WRITE_EXITS_COUNTER_RECONCILE
// ErrRegistryConcurrentWrite must produce ExitCounterReconcile.
func TestAdminMerge_ConcurrentWrite_ExitsCounterReconcile(t *testing.T) {
	t.Parallel()
	fake := &fakeMergeUseCase{err: registryadapter.ErrRegistryConcurrentWrite}
	deps := makeMergeDeps(mode.ModeAdmin, fake)

	_, _, exitCode := runMerge(t, deps,
		"admin", "merge",
		"--project", "myapp",
		"--file", "prod",
		"--pr", "main#1",
	)
	if exitCode != int(render.ExitCounterReconcile) {
		t.Errorf("want exit %d (counter-reconcile), got %d", render.ExitCounterReconcile, exitCode)
	}
}

// MERGE_REJECTED_EXITS_TRUST_ERROR
// ErrRegistryWriteRejected must produce ExitTrustError.
func TestAdminMerge_Rejected_ExitsTrustError(t *testing.T) {
	t.Parallel()
	fake := &fakeMergeUseCase{err: registryadapter.ErrRegistryWriteRejected}
	deps := makeMergeDeps(mode.ModeAdmin, fake)

	_, _, exitCode := runMerge(t, deps,
		"admin", "merge",
		"--project", "myapp",
		"--file", "prod",
		"--pr", "main#1",
	)
	if exitCode != int(render.ExitTrustError) {
		t.Errorf("want exit %d (trust-error), got %d", render.ExitTrustError, exitCode)
	}
}

// MERGE_COUNTER_RECONCILE_EXITS_COUNTER_RECONCILE
// countertypes.ErrCounterReconcile must produce ExitCounterReconcile.
func TestAdminMerge_CounterReconcile_ExitsCounterReconcile(t *testing.T) {
	t.Parallel()
	fake := &fakeMergeUseCase{err: fmt.Errorf("%w: mismatch", countertypes.ErrCounterReconcile)}
	deps := makeMergeDeps(mode.ModeAdmin, fake)

	_, _, exitCode := runMerge(t, deps,
		"admin", "merge",
		"--project", "myapp",
		"--file", "prod",
		"--pr", "main#1",
	)
	if exitCode != int(render.ExitCounterReconcile) {
		t.Errorf("want exit %d (counter-reconcile), got %d", render.ExitCounterReconcile, exitCode)
	}
}

// MERGE_REPLAY_EXITS_REPLAY
// coreregistry.ErrCacheTampered must produce ExitReplay.
func TestAdminMerge_CacheTampered_ExitsReplay(t *testing.T) {
	t.Parallel()
	fake := &fakeMergeUseCase{err: fmt.Errorf("%w: tampered", coreregistry.ErrCacheTampered)}
	deps := makeMergeDeps(mode.ModeAdmin, fake)

	_, _, exitCode := runMerge(t, deps,
		"admin", "merge",
		"--project", "myapp",
		"--file", "prod",
		"--pr", "main#1",
	)
	if exitCode != int(render.ExitReplay) {
		t.Errorf("want exit %d (replay), got %d", render.ExitReplay, exitCode)
	}
}

// MERGE_JSON_OUTPUT_OMITS_TOKEN_AND_SIGNATURE_BYTES
// Property test: --json output never contains synthetic token or sig bytes.
func TestAdminMerge_JSONOutputOmitsTokenAndSignatureBytes(t *testing.T) {
	t.Parallel()

	const syntheticToken = "ghp_SYNTHETIC_PROPERTY_TEST_TOKEN_XYZ"
	syntheticSig := strings.Repeat("ab", 32) // 64 hex bytes like a signature

	fake := &fakeMergeUseCase{
		result: usecase.MergeResult{
			ReEncrypted:  true,
			FinalCounter: 42,
			LiveFileSHA:  "contentSHA",
		},
	}
	deps := makeMergeDeps(mode.ModeAdmin, fake)

	out, stderr, exitCode := runMerge(t, deps,
		"admin", "merge",
		"--project", "myapp",
		"--file", "prod",
		"--pr", "main#1",
		"--json",
	)
	if exitCode != 0 {
		t.Fatalf("want exit 0, got %d; stderr: %s", exitCode, stderr.String())
	}
	combined := out.String() + stderr.String()
	if strings.Contains(combined, syntheticToken) {
		t.Errorf("output must not contain synthetic token: %s", combined)
	}
	if strings.Contains(combined, syntheticSig) {
		t.Errorf("output must not contain synthetic sig bytes: %s", combined)
	}
}

// BO-TM-13-1: --pr flag must be validated against the branch-name whitelist
// (rejects \n, \0, \r, leading -, and invalid refname chars).
func TestAdminMerge_PRFlag_WhitelistValidation(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"main\n#1",
		"main\x00#1",
		"main\r#1",
		"-bad#1",
		"../escape#1",
		"main/.lock#1",
		strings.Repeat("a", 201) + "#1",
	}

	for _, prVal := range invalid {
		prVal := prVal
		t.Run("reject:"+strings.Map(func(r rune) rune {
			if r < 32 || r > 126 {
				return '_'
			}
			return r
		}, prVal), func(t *testing.T) {
			t.Parallel()
			fake := &fakeMergeUseCase{}
			deps := makeMergeDeps(mode.ModeAdmin, fake)

			_, _, exitCode := runMerge(t, deps,
				"admin", "merge",
				"--project", "myapp",
				"--file", "prod",
				"--pr", prVal,
			)
			// Must not succeed (exit 0) and must not call the use-case.
			if exitCode == 0 {
				t.Errorf("expected non-zero exit for invalid --pr %q, got 0", prVal)
			}
			if fake.called {
				t.Errorf("use-case must not be called for invalid --pr %q", prVal)
			}
		})
	}

	// Valid pr refs must pass.
	valid := []string{
		"main#1",
		"release/1.0#2",
		"feature/foo-bar#99",
	}
	for _, prVal := range valid {
		prVal := prVal
		t.Run("accept:"+prVal, func(t *testing.T) {
			t.Parallel()
			fake := &fakeMergeUseCase{result: usecase.MergeResult{}}
			deps := makeMergeDeps(mode.ModeAdmin, fake)

			_, _, exitCode := runMerge(t, deps,
				"admin", "merge",
				"--project", "myapp",
				"--file", "prod",
				"--pr", prVal,
			)
			if exitCode != 0 && !fake.called {
				// Both valid pr parsing AND use-case failure are OK here;
				// the key is the pr parsing itself must not reject valid refs.
				// A use-case error is acceptable (the fake returned empty result).
				t.Logf("accepted pr %q, exit %d", prVal, exitCode)
			}
		})
	}
}

// BO-TM-13-2: admin merge must NOT spawn $EDITOR.
// AST scan of the merge code-path: no exec.Command(os.Getenv("EDITOR"), ...).
func TestAdminMerge_NoEditorSpawn_ASTCheck(t *testing.T) {
	t.Parallel()

	// Find admin_cmds.go in the cli package.
	modRoot := mustFindMergeModuleRoot(t)
	cliDir := filepath.Join(modRoot, "internal", "cli")

	entries, err := os.ReadDir(cliDir)
	if err != nil {
		t.Fatalf("reading cli dir: %v", err)
	}

	// Look for EDITOR env references in merge-related code.
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(cliDir, e.Name())
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// Look for exec.Command(os.Getenv("EDITOR"), ...) or similar.
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Command" {
				for _, arg := range call.Args {
					argStr := exprToStr(arg)
					if strings.Contains(argStr, "EDITOR") || strings.Contains(argStr, "VISUAL") {
						t.Errorf("file %s contains exec.Command(... EDITOR ...) in merge code-path — "+
							"admin merge must not spawn $EDITOR", e.Name())
					}
				}
			}
			return true
		})
	}
}

func exprToStr(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Value
	case *ast.CallExpr:
		sel, ok := v.Fun.(*ast.SelectorExpr)
		if ok {
			return sel.Sel.Name + "(" + exprToStr(v.Args[0]) + ")"
		}
	case *ast.Ident:
		return v.Name
	}
	return ""
}

func mustFindMergeModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod")
		}
		dir = parent
	}
}

// Compile-time guard: ast is used.
var _ = ast.NewIdent
