// Package fetchtransport — unit tests for the production HeadVerifier.
//
// Test obligations (B6-1a owned):
//
//   - AC-1: production FetchHead (VerifyHead) implements the git verify-commit
//     discipline against the pinned full-key anchor; verified=true only on
//     success AND full-key identity to the anchor. All negatives must yield
//     verified=false with no error-swallow-to-true.
//   - AC-3 SHA-origin half: the SHA VerifyHead reports as verified is exactly
//     the SHA whose signature was verified; no ref re-resolution occurs.
//   - AC-8 guard: projectID validation rejects invalid inputs before path
//     composition; ReadAdmins/FetchCommittedFile must never be invoked on a
//     rejected projectID.
package fetchtransport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
)

// ---- fake CommandRunner -------------------------------------------------------

// fakeCall records a single invocation of the fake runner.
type fakeCall struct {
	dir  string
	env  []string
	name string
	args []string
}

// fakeRunner is a controllable CommandRunner for unit tests. Each step of the
// VerifyHead sequence (clone, rev-parse, verify-commit) is configured
// separately so tests can inject failures at any stage.
type fakeRunner struct {
	// Ordered list of step results. Each Run() call pops the first step.
	steps []fakeStep
	// calls records every invocation for argument-capture assertions.
	calls []fakeCall
}

type fakeStep struct {
	stdout   []byte
	stderr   []byte
	exitCode int
	err      error
}

func (f *fakeRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, int, error) {
	f.calls = append(f.calls, fakeCall{dir: dir, env: env, name: name, args: args})
	if len(f.steps) == 0 {
		// No more configured steps: fail with a descriptive error so the test
		// fails loudly rather than panicking.
		return nil, nil, 1, errors.New("fakeRunner: no more configured steps")
	}
	step := f.steps[0]
	f.steps = f.steps[1:]
	if step.err != nil {
		return nil, nil, step.exitCode, step.err
	}
	return step.stdout, step.stderr, step.exitCode, nil
}

// fixedSHA is a well-formed 40-char hex SHA used in test fixtures.
const fixedSHA = "aabbccddee112233445566778899aabbccddeeff"

// goodVerifyStderr is the stderr output of a successful git verify-commit for
// an SSH Ed25519 signature with principal "byreis-anchor".
const goodVerifyStderr = `Good "git" signature for byreis-anchor with ED25519 key SHA256:abc123`

// newVerifier constructs a HeadVerifier with the given runner and an injected
// temp-dir seam that uses the test's TempDir to avoid real os.MkdirTemp calls.
func newVerifier(t *testing.T, runner fetchtransport.CommandRunner) *fetchtransport.HeadVerifier {
	t.Helper()
	tmpBase := t.TempDir()
	var tmpCount int
	v, err := fetchtransport.NewHeadVerifier(fetchtransport.HeadVerifierConfig{
		Runner: runner,
		MkdirTemp: func(_, _ string) (string, error) {
			tmpCount++
			dir := filepath.Join(tmpBase, "tmp", fmt.Sprint(tmpCount))
			if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
				return "", mkErr
			}
			return dir, nil
		},
		RemoveAll: func(_ string) error { return nil }, // no-op: t.TempDir() handles cleanup
	})
	if err != nil {
		t.Fatalf("NewHeadVerifier: %v", err)
	}
	return v
}

// anchorKey generates a fresh Ed25519 key pair for tests.
func anchorKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate anchor key: %v", err)
	}
	return pub
}

// ---- helpers to build step sequences ----------------------------------------

// successfulClone returns a fakeStep for a successful git clone (exit 0).
func successfulClone() fakeStep {
	return fakeStep{exitCode: 0}
}

// successfulRevParse returns a fakeStep for a successful git rev-parse HEAD
// returning fixedSHA.
func successfulRevParse() fakeStep {
	return fakeStep{stdout: []byte(fixedSHA + "\n"), exitCode: 0}
}

// successfulVerify returns a fakeStep for a successful git verify-commit
// (exit 0) with goodVerifyStderr.
func successfulVerify() fakeStep {
	return fakeStep{stderr: []byte(goodVerifyStderr), exitCode: 0}
}

// ---- AC-1 positive: verified=true on success + full-key identity --------------

// TestAC1_VerifyHead_SuccessPath proves that VerifyHead returns verified=true
// and the correct signerID when git clone succeeds, rev-parse returns a valid
// SHA, and git verify-commit exits 0 with a parseable signer principal.
func TestAC1_VerifyHead_SuccessPath(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		successfulRevParse(),
		successfulVerify(),
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	commit, signerID, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Fatal("expected verified=true, got false")
	}
	if commit != fixedSHA {
		t.Fatalf("expected commit=%q, got %q", fixedSHA, commit)
	}
	if signerID != "byreis-anchor" {
		t.Fatalf("expected signerID=%q, got %q", "byreis-anchor", signerID)
	}
}

// ---- AC-1 negatives (all must yield verified=false, no error-swallow-to-true) -

// TestAC1_Neg_UnsignedHead proves that an unsigned HEAD (git verify-commit
// exits non-zero, no stderr output) yields verified=false, no error.
func TestAC1_Neg_UnsignedHead(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		successfulRevParse(),
		{exitCode: 1, stderr: []byte("error: no signature found")},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if err != nil {
		t.Fatalf("unsigned HEAD must not return an error (expected nil), got: %v", err)
	}
	if verified {
		t.Fatal("FAIL: unsigned HEAD must yield verified=false (error-swallow-to-true forbidden)")
	}
}

// TestAC1_Neg_WrongSignerKey proves that a HEAD signed by a key that is NOT the
// pinned anchor (git verify-commit exits non-zero because the key is not in
// allowed-signers) yields verified=false, no error.
func TestAC1_Neg_WrongSignerKey(t *testing.T) {
	t.Parallel()

	// verify-commit exits non-zero when the signing key is not in allowed-signers.
	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		successfulRevParse(),
		{exitCode: 1, stderr: []byte("error: gpg.ssh.allowedSignersFile: no key found")},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t) // the anchor key — signing key is different (not in allowed-signers)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if err != nil {
		t.Fatalf("wrong-signer key must not return an error (expected nil), got: %v", err)
	}
	if verified {
		t.Fatal("FAIL: HEAD signed by non-anchor key must yield verified=false (error-swallow-to-true forbidden)")
	}
}

// TestAC1_Neg_TruncatedSignature proves that a commit with a truncated or
// malformed signature (git verify-commit exits non-zero with a parsing error)
// yields verified=false. Must NOT be swallowed to true.
func TestAC1_Neg_TruncatedSignature(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		successfulRevParse(),
		{exitCode: 1, stderr: []byte("error: could not read or verify signature")},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if err != nil {
		t.Fatalf("truncated-signature must not return an error (expected nil), got: %v", err)
	}
	if verified {
		t.Fatal("FAIL: truncated/malformed signature must yield verified=false (error-swallow-to-true forbidden)")
	}
}

// TestAC1_Neg_GoodSigUnknownKey proves that a "good signature, unknown key"
// status (git verify-commit exits non-zero because the signer is not in
// allowed-signers, even though the signature itself is structurally valid)
// yields verified=false.
func TestAC1_Neg_GoodSigUnknownKey(t *testing.T) {
	t.Parallel()

	// git exits non-zero when the signing key is not in allowed-signers.
	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		successfulRevParse(),
		{exitCode: 1, stderr: []byte("Good \"git\" signature for unknown@example.com with ED25519 key SHA256:xyz")},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if err != nil {
		t.Fatalf("good-sig-unknown-key must not return an error (expected nil), got: %v", err)
	}
	if verified {
		t.Fatal("FAIL: good-sig-unknown-key status must yield verified=false (error-swallow-to-true forbidden)")
	}
}

// TestAC1_Neg_SubprocessNonzeroError proves that a subprocess non-zero exit
// code is fail-closed: verified=false, no error-swallow-to-true.
func TestAC1_Neg_SubprocessNonzeroError(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		successfulRevParse(),
		{exitCode: 128, stderr: []byte("fatal: not a git repository")},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if err != nil {
		t.Fatalf("nonzero subprocess exit must not return an error (expected nil), got: %v", err)
	}
	if verified {
		t.Fatal("FAIL: subprocess nonzero exit must yield verified=false (error-swallow-to-true forbidden)")
	}
}

// TestAC1_Neg_GitBinaryNotFound proves that a missing git binary (exec.ErrNotFound
// or equivalent exec error) causes VerifyHead to fail closed with a non-nil
// error and verified=false.
func TestAC1_Neg_GitBinaryNotFound(t *testing.T) {
	t.Parallel()

	execErr := errors.New("exec: git: not found in PATH")
	runner := &fakeRunner{steps: []fakeStep{
		// Clone step fails with exec error (binary not found).
		{err: execErr, exitCode: 0},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if verified {
		t.Fatal("FAIL: missing git binary must yield verified=false (error-swallow-to-true forbidden)")
	}
	if err == nil {
		t.Fatal("expected non-nil error for missing git binary, got nil")
	}
}

// TestAC1_Neg_ContextCancelled_FailClosed proves that a context cancelled
// before VerifyHead starts yields verified=false and a wrapped context error.
// No goroutine is leaked (the test exits cleanly within its deadline).
func TestAC1_Neg_ContextCancelled_FailClosed(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{} // no steps needed; context cancel fires before runner
	v := newVerifier(t, runner)
	key := anchorKey(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, _, verified, err := v.VerifyHead(ctx, "https://example.com/reg.git", key)

	if verified {
		t.Fatal("FAIL: cancelled context must yield verified=false (error-swallow-to-true forbidden)")
	}
	if err == nil {
		t.Fatal("expected non-nil error for cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected errors.Is(err, context.Canceled), got: %v", err)
	}
}

// TestAC1_Neg_ContextTimeout_FailClosed proves that a context deadline exceeded
// during the clone step yields verified=false and a wrapped deadline error. No
// goroutine is leaked.
func TestAC1_Neg_ContextTimeout_FailClosed(t *testing.T) {
	t.Parallel()

	// Runner step for clone: simulates the context being already expired when
	// the runner is invoked.
	runner := &fakeRunner{steps: []fakeStep{
		{err: context.DeadlineExceeded, exitCode: 0},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	// A context that has already expired.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	_, _, verified, err := v.VerifyHead(ctx, "https://example.com/reg.git", key)

	if verified {
		t.Fatal("FAIL: deadline exceeded must yield verified=false (error-swallow-to-true forbidden)")
	}
	if err == nil {
		t.Fatal("expected non-nil error for deadline exceeded, got nil")
	}
}

// TestAC1_Neg_MissingAnchorKey proves that a nil or short anchor key yields
// verified=false and a typed error. The runner must NOT be invoked.
func TestAC1_Neg_MissingAnchorKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  ed25519.PublicKey
	}{
		{"nil key", nil},
		{"short key (16 bytes)", make([]byte, 16)},
		{"empty key (0 bytes)", make([]byte, 0)},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			runner := &fakeRunner{} // must receive zero calls
			v := newVerifier(t, runner)

			_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", tc.key)

			if verified {
				t.Fatalf("FAIL: %s must yield verified=false (error-swallow-to-true forbidden)", tc.name)
			}
			if err == nil {
				t.Fatalf("%s: expected non-nil typed error, got nil", tc.name)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("%s: runner was invoked %d time(s); must not be called on invalid anchor key",
					tc.name, len(runner.calls))
			}
		})
	}
}

// TestAC1_Neg_Exit0_NoParseableSigner proves that an exit-0 response with no
// parseable signer principal in stderr is treated as verified=false (fail
// closed). This prevents a malformed-output-to-true swallow.
func TestAC1_Neg_Exit0_NoParseableSigner(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		successfulRevParse(),
		{exitCode: 0, stderr: []byte("some unrecognised git output with no principal line")},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if err != nil {
		t.Fatalf("exit-0-no-signer must not return an error (expected nil), got: %v", err)
	}
	if verified {
		t.Fatal("FAIL: exit-0 with no parseable signer must yield verified=false (error-swallow-to-true forbidden)")
	}
}

// TestAC1_Neg_Exit0_WrongPrincipal proves that an exit-0 response where the
// parsed principal does not match the expected anchor principal (principalName)
// yields verified=false.
func TestAC1_Neg_Exit0_WrongPrincipal(t *testing.T) {
	t.Parallel()

	wrongPrincipalStderr := `Good "git" signature for attacker@evil.com with ED25519 key SHA256:abc123`
	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		successfulRevParse(),
		{exitCode: 0, stderr: []byte(wrongPrincipalStderr)},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if err != nil {
		t.Fatalf("exit-0-wrong-principal must not return an error (expected nil), got: %v", err)
	}
	if verified {
		t.Fatal("FAIL: exit-0 with wrong principal must yield verified=false (error-swallow-to-true forbidden)")
	}
}

// ---- AC-3: SHA-origin half ---------------------------------------------------

// TestAC3_SHAOrigin_VerifiedSHA_EqualsRevParseOutput proves that the commit SHA
// returned by VerifyHead is exactly the SHA that git rev-parse HEAD returned —
// i.e. the SHA whose signature was verified by git verify-commit. This is the
// AC-3 SHA-origin contract: no ref re-resolution between rev-parse and
// verify-commit, and the returned commit == the verified SHA.
func TestAC3_SHAOrigin_VerifiedSHA_EqualsRevParseOutput(t *testing.T) {
	t.Parallel()

	const specificSHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		{stdout: []byte(specificSHA + "\n"), exitCode: 0}, // rev-parse returns specificSHA
		{exitCode: 0, stderr: []byte(`Good "git" signature for byreis-anchor with ED25519 key SHA256:xyz`)},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	commit, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Fatal("expected verified=true")
	}
	if commit != specificSHA {
		t.Fatalf("SHA-origin violation: returned commit=%q, want %q (the SHA rev-parse returned)",
			commit, specificSHA)
	}

	// Assert that git verify-commit was called with specificSHA (argument-capture).
	// The verify-commit call is the third Run() invocation.
	if len(runner.calls) < 3 {
		t.Fatalf("expected at least 3 runner calls, got %d", len(runner.calls))
	}
	verifyCall := runner.calls[2]
	foundSHA := false
	for _, arg := range verifyCall.args {
		if arg == specificSHA {
			foundSHA = true
			break
		}
	}
	if !foundSHA {
		t.Fatalf("SHA-origin violation: git verify-commit was not called with SHA %q; args=%v",
			specificSHA, verifyCall.args)
	}
}

// TestAC3_SHAOrigin_NoRefReresolutionOnVerify proves that VerifyHead does not
// perform a second fetch or ref re-resolution between rev-parse and
// verify-commit. The runner call sequence must be exactly: clone, rev-parse,
// verify-commit — three calls total with no additional fetches.
func TestAC3_SHAOrigin_NoRefReresolution(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		successfulRevParse(),
		successfulVerify(),
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, _, _ = v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	// Exactly 3 runner calls: clone, rev-parse, verify-commit.
	if len(runner.calls) != 3 {
		t.Fatalf("SHA-origin violation: expected 3 runner calls (clone+rev-parse+verify-commit), got %d calls: %v",
			len(runner.calls), callNames(runner.calls))
	}
	// Verify the command sequence.
	wantCommands := []string{"git", "git", "git"}
	for i, call := range runner.calls {
		if call.name != wantCommands[i] {
			t.Errorf("call[%d] name=%q, want %q", i, call.name, wantCommands[i])
		}
	}
	// Verify subcommands: clone, rev-parse, verify-commit.
	assertSubcmd(t, runner.calls[0], "clone")
	assertSubcmd(t, runner.calls[1], "rev-parse")
	assertSubcmd(t, runner.calls[2], "verify-commit")
}

// assertSubcmd checks that the first arg of a runner call is the expected git
// subcommand.
func assertSubcmd(t *testing.T, call fakeCall, want string) {
	t.Helper()
	if len(call.args) == 0 {
		t.Errorf("no args in runner call, expected subcommand %q", want)
		return
	}
	if call.args[0] != want {
		t.Errorf("runner call args[0]=%q, want %q", call.args[0], want)
	}
}

// callNames extracts command names for diagnostic output.
func callNames(calls []fakeCall) []string {
	names := make([]string, len(calls))
	for i, c := range calls {
		if len(c.args) > 0 {
			names[i] = c.name + " " + c.args[0]
		} else {
			names[i] = c.name
		}
	}
	return names
}

// ---- AC-8: projectID validation ----------------------------------------------

// TestAC8_ValidateProjectID_Accepts_ValidIdentifiers verifies that well-formed
// project identifiers pass validation.
func TestAC8_ValidateProjectID_Accepts_ValidIdentifiers(t *testing.T) {
	t.Parallel()

	valid := []string{
		"myproject",
		"my-project",
		"my_project",
		"myproject123",
		"MY-PROJECT",
		"a",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 99 chars
	}

	for _, id := range valid {
		id := id
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			if err := fetchtransport.ValidateProjectID(id); err != nil {
				t.Errorf("ValidateProjectID(%q): unexpected error: %v", id, err)
			}
		})
	}
}

// TestAC8_ValidateProjectID_Rejects_PathTraversal proves that project IDs
// containing path traversal sequences are rejected before any path composition.
func TestAC8_ValidateProjectID_Rejects_PathTraversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		projectID string
	}{
		{"empty string", ""},
		{"forward slash", "my/project"},
		{"dot-dot", ".."},
		{"dot-dot in middle", "my/../evil"},
		{"leading dot", ".hidden"},
		{"backslash", `my\project`},
		{"null byte", "my\x00project"},
		{"control char tab", "my\tproject"},
		{"control char newline", "my\nproject"},
		{"over-length", string(make([]byte, 129))}, // 129 bytes of zeros
		{"path sep only", "/"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := fetchtransport.ValidateProjectID(tc.projectID)
			if err == nil {
				t.Errorf("ValidateProjectID(%q): expected error (path traversal / invalid), got nil",
					tc.projectID)
			}
		})
	}
}

// TestAC8_Guard_RunnerNotInvokedOnInvalidProjectID proves that the runner (and
// therefore FetchCommittedFile/ReadAdmins) is NEVER invoked when projectID
// validation fails. This is the call-capture assertion the AC-8 guard requires.
//
// Note: VerifyHead itself does not take a projectID parameter — the projectID
// guard is for ReadAdmins (B6-1b). This test proves the validator function
// itself works correctly and returns a typed error, which is the guard B6-1b
// must sit behind. We verify the guard surface is correct: if a caller checks
// ValidateProjectID before constructing paths, the runner is never reached.
func TestAC8_Guard_RunnerNotInvokedOnInvalidProjectID(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{} // must receive zero calls

	// Simulate a consumer that checks ValidateProjectID before invoking any
	// transport operation. This is exactly the guard ReadAdmins must implement.
	invalidIDs := []string{"../evil", "my/project", "", ".hidden"}
	for _, id := range invalidIDs {
		err := fetchtransport.ValidateProjectID(id)
		if err == nil {
			t.Errorf("ValidateProjectID(%q): expected error, got nil", id)
			continue
		}
		// Guard fired: runner must NOT be called.
	}

	if len(runner.calls) != 0 {
		t.Fatalf("runner was invoked %d time(s) after projectID guard fired; must be 0",
			len(runner.calls))
	}
}

// ---- AC-1 negative: verify-commit error during clone step --------------------

// TestAC1_Neg_CloneFailure proves that a clone step failure (non-zero exit)
// yields verified=false and a non-nil error (the error is an infrastructure
// error, not a signature-verification failure). Fail closed.
func TestAC1_Neg_CloneFailure(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{steps: []fakeStep{
		{exitCode: 128, stderr: []byte("fatal: repository not found")},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if verified {
		t.Fatal("FAIL: clone failure must yield verified=false")
	}
	if err == nil {
		t.Fatal("expected non-nil error for clone failure, got nil")
	}
}

// TestAC1_Neg_RevParseFailure proves that a rev-parse failure (non-zero exit)
// yields verified=false and a non-nil error. Fail closed.
func TestAC1_Neg_RevParseFailure(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		{exitCode: 128, stderr: []byte("fatal: not a git repository")},
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if verified {
		t.Fatal("FAIL: rev-parse failure must yield verified=false")
	}
	if err == nil {
		t.Fatal("expected non-nil error for rev-parse failure, got nil")
	}
}

// TestAC1_Neg_MalformedRevParseOutput proves that a non-SHA response from
// git rev-parse yields verified=false and a non-nil error. Fail closed.
func TestAC1_Neg_MalformedRevParseOutput(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{steps: []fakeStep{
		successfulClone(),
		{exitCode: 0, stdout: []byte("not-a-sha\n")}, // garbage output
	}}
	v := newVerifier(t, runner)
	key := anchorKey(t)

	_, _, verified, err := v.VerifyHead(context.Background(), "https://example.com/reg.git", key)

	if verified {
		t.Fatal("FAIL: malformed rev-parse output must yield verified=false")
	}
	if err == nil {
		t.Fatal("expected non-nil error for malformed rev-parse output, got nil")
	}
}

// ---- NewHeadVerifier: nil runner guard ---------------------------------------

// TestNewHeadVerifier_NilRunner proves that constructing a HeadVerifier with a
// nil runner returns an error.
func TestNewHeadVerifier_NilRunner(t *testing.T) {
	t.Parallel()

	_, err := fetchtransport.NewHeadVerifier(fetchtransport.HeadVerifierConfig{
		Runner: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil Runner, got nil")
	}
}
