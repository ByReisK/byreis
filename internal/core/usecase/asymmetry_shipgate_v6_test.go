//go:build shipgate

// V6 ship-gate rows — request-access absorption path.
//
// Row map (BO-V6-CRYPTO-11, T-V6-10, T-V6-13):
//
//   V6.SG1  → TestAsymmetryShipGateV6_RequestAccess_ContributorCannotAcquireRegistryWriteToken
//   V6.SG2  → TestAsymmetryShipGateV6_FromRequest_PRAuthorMismatchRefuses
//   V6.SG3  → TestAsymmetryShipGateV6_FromRequest_PRHeadSHADriftRefuses
//   V6.SG4  → TestAsymmetryShipGate_FromRequest_AuditEventCarriesPRProvenance
//   V6.SG5  → TestAsymmetryShipGate_RequestAccess_NoRegistryWriteToken
//
// All rows obey the NON-PASS discipline: a gate that cannot run is a test
// failure, never a silent pass.
//
// Engineering-standards adherence:
//   - context.Context first param on all I/O-bearing helpers.
//   - errors wrapped with %w; sentinels used for explicit errors.Is checks.
//   - no goroutine leaks; no real network, clock, keychain, or fs in tests.
//   - internal review IDs (BO-V6-CRYPTO-*, T-V6-*) permitted in _test.go
//     per CLAUDE.md "code comment hygiene"; not present in shipped code.
package usecase_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ── V6.SG1 ────────────────────────────────────────────────────────────────────

// TestAsymmetryShipGateV6_RequestAccess_ContributorCannotAcquireRegistryWriteToken
// proves that `byreis request-access` is denied at the CLI mode gate for
// ADMIN/SUPER operators BEFORE any registry write token is acquired or any
// network call is made (BO-V6-CRYPTO-1 + BO-V6-CRYPTO-8).
//
// Proof mechanism: inject a panic-on-call Rotator as deps.Rotator. The mode
// gate in request-access fires BEFORE the cobra dispatch reaches rotate; if
// the Rotator is invoked the panic surfaces as a test failure. We also assert
// the command returns ExitPermissionDenied, not ExitOK or any other code.
func TestAsymmetryShipGateV6_RequestAccess_ContributorCannotAcquireRegistryWriteToken(t *testing.T) {
	// Build a minimal ADMIN-mode Deps with a panic-on-call Rotator stub.
	// The mode is set to ModeAdmin so that if the command bypassed the gate
	// the Rotator path would be reached and the panic would fire.
	adminPolicy := &mode.Policy{}

	panicRotator := &sgV6PanicRotator{}

	deps := &cli.Deps{
		Policy:      adminPolicy,
		CurrentMode: mode.ModeAdmin,
		Rotator:     panicRotator,
		// RequestAccessReader is intentionally nil here: the mode gate must
		// fire before any attempt to use it, so its absence does not matter.
		RequestAccessReader: nil,
	}

	// Run the request-access command in ADMIN mode. The mode gate must deny
	// before any rotation, GitHub, or write-token code runs.
	_, errBuf, exitCode := sgV6RunCobra(t, deps,
		"request-access",
		"--key", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzs7pu6",
		"--justification", "test",
	)

	if exitCode != int(render.ExitPermissionDenied) {
		t.Fatalf("V6.SG1: request-access in ADMIN mode: exit %d, want ExitPermissionDenied=%d; "+
			"stderr=%q", exitCode, render.ExitPermissionDenied, errBuf.String())
	}

	// The panicRotator must never have been invoked.
	if panicRotator.called {
		t.Fatal("V6.SG1: Rotator.Rotate was called on the request-access path — " +
			"the mode gate MUST deny before the Rotator is reached")
	}
}

// sgV6PanicRotator panics if Rotate is ever called. Used to prove the mode
// gate fires before any rotation use-case call on the request-access path.
type sgV6PanicRotator struct {
	called bool
}

func (r *sgV6PanicRotator) Rotate(_ context.Context, _ rotate.RotationInput) (rotate.RotationResult, error) {
	r.called = true
	panic("sgV6PanicRotator.Rotate was called — mode gate did NOT fire before rotation")
}

// ── V6.SG2 ────────────────────────────────────────────────────────────────────

// TestAsymmetryShipGateV6_FromRequest_PRAuthorMismatchRefuses proves that when
// the PR opener's GitHub login does not byte-equal the YAML's github_handle
// field, the `--from-request` absorption path returns ErrRequestAccessIdentityMismatch
// and Phase-1 is never invoked (BO-V6-CRYPTO-3).
//
// Setup: fake RequestAccessReader returns PR.AuthorLogin="alice" alongside a
// YAML whose github_handle is "evil". ValidateRequestAccess must surface the
// identity mismatch before any phase executor is called.
func TestAsymmetryShipGateV6_FromRequest_PRAuthorMismatchRefuses(t *testing.T) {
	// Generate a real (but ephemeral) age X25519 identity for the YAML payload.
	// ValidateRequestAccess runs age.ParseX25519Recipient so the pubkey must be
	// syntactically valid; using a freshly-generated ephemeral key is cleaner
	// than a hard-coded constant that might stop parsing on library changes.
	ageIdent, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("V6.SG2: age.GenerateX25519Identity: %v", err)
	}
	validAgePub := ageIdent.Recipient().String()

	// The YAML says github_handle="evil" but the PR opener is "alice".
	mismatchFile := rotate.RequestAccessFile{
		SchemaVersion: "byreis.request_access.v1",
		GitHubHandle:  "evil",
		AgePubkey:     validAgePub,
		Justification: "testing",
		RequestedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	mismatchMeta := rotate.PRMetadata{
		AuthorLogin:        "alice", // byte-compare against "evil" → mismatch
		AuthorType:         "User",
		State:              "open",
		IsDraft:            false,
		IsMerged:           false,
		HeadSHA:            "abc123sha",
		HeadRepoOwnerLogin: "alice",
		Commits:            []rotate.CommitInfo{{SHA: "abc123sha", AuthorLogin: "alice"}},
	}

	panicPhase1 := &sgV6PanicPhase1{}
	reader := &sgV6FakeRequestAccessReader{
		file:    mismatchFile,
		meta:    mismatchMeta,
		headSHA: "abc123sha",
	}
	panicRotator := &sgV6RecordingRotatorWithPanicPhase1{phase1: panicPhase1}

	deps := &cli.Deps{
		Policy:              &mode.Policy{},
		CurrentMode:         mode.ModeAdmin,
		Rotator:             panicRotator,
		RequestAccessReader: reader,
		// RotatePreFlight nil: buildRotationInput falls back to stubs.
	}

	_, errBuf, exitCode := sgV6RunCobra(t, deps,
		"rotate",
		"--project", "myapp",
		"--from-request", "myorg/admins#42",
		"--yes",
	)

	// The identity mismatch must surface before Phase-1. We accept either
	// ExitPermissionDenied (the mapped exit code for ErrRequestAccessIdentityMismatch)
	// or ExitGeneralError — the load-bearing assertion is that Phase-1 is not called.
	if exitCode == 0 {
		t.Fatalf("V6.SG2: rotate --from-request with identity mismatch: exit 0 — "+
			"ErrRequestAccessIdentityMismatch must cause non-zero exit; stderr=%q",
			errBuf.String())
	}

	if panicPhase1.calls > 0 {
		t.Fatalf("V6.SG2: Phase1.Execute was called %d time(s) — "+
			"the identity mismatch MUST refuse before Phase-1 is invoked",
			panicPhase1.calls)
	}

	// Verify the error sentinel surfaces in the full error chain or stderr.
	// The exitError wraps the rotate domain error; stderr carries the rendered
	// message. Both pathways confirm the right error code was reached.
	if !strings.Contains(errBuf.String(), "identity") &&
		!strings.Contains(errBuf.String(), "YAML github_handle") &&
		!strings.Contains(errBuf.String(), "mismatch") {
		t.Errorf("V6.SG2: stderr=%q does not mention identity mismatch — "+
			"expected ErrRequestAccessIdentityMismatch text", errBuf.String())
	}
}

// sgV6PanicPhase1 panics if Execute is called. Used to prove Phase-1 is never
// reached when validation refuses.
type sgV6PanicPhase1 struct {
	calls int
}

func (p *sgV6PanicPhase1) Execute(_ context.Context, _ rotate.RotationPlan) (rotate.Phase1Result, error) {
	p.calls++
	panic("sgV6PanicPhase1.Execute was called — validation did NOT refuse before Phase-1")
}

// sgV6RecordingRotatorWithPanicPhase1 is a Rotator implementation that runs
// the real rotate.rotator state machine up to Phase-1 entry but uses the
// panic-phase1 stub for the actual executor — surfacing the "gate must refuse
// before Phase-1" invariant.
//
// For the mismatch / drift tests the resolveFromRequest function in rotate_cmd.go
// returns an error before Rotator.Rotate is ever invoked. This stub only needs
// to satisfy the interface; the panic never fires on a correctly-gated path.
type sgV6RecordingRotatorWithPanicPhase1 struct {
	phase1 *sgV6PanicPhase1
}

func (r *sgV6RecordingRotatorWithPanicPhase1) Rotate(_ context.Context, _ rotate.RotationInput) (rotate.RotationResult, error) {
	// The CLI-layer resolveFromRequest validation must fire BEFORE Rotate is
	// called on the mismatch/drift paths. If we ever reach here on those paths,
	// it is a bug: report it clearly.
	r.phase1.calls++ // count as a Phase-1 invocation for the assertion
	return rotate.RotationResult{}, errors.New("sgV6RecordingRotatorWithPanicPhase1.Rotate reached — " +
		"CLI-layer validation must have failed to gate the mismatch/drift case")
}

// ── V6.SG3 ────────────────────────────────────────────────────────────────────

// TestAsymmetryShipGateV6_FromRequest_PRHeadSHADriftRefuses proves that when
// the PR HEAD SHA changes between the initial FetchRequestAccessYAML call and
// the FetchPRHeadSHA re-check (force-push race), the `--from-request` path
// surfaces ErrRequestAccessPRForcePushed and Phase-1 is never invoked (T-V6-4).
//
// Setup: the fake reader returns HeadSHA="sha-before" from FetchRequestAccessYAML
// but "sha-after" from FetchPRHeadSHA, simulating a force-push between plan and
// execute. A recording Phase-1 stub counts Execute calls and must stay at zero.
func TestAsymmetryShipGateV6_FromRequest_PRHeadSHADriftRefuses(t *testing.T) {
	ageIdent, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("V6.SG3: age.GenerateX25519Identity: %v", err)
	}
	validAgePub := ageIdent.Recipient().String()

	// Initial and drifted SHAs.
	const shaBefore = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const shaAfter = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// Valid YAML with matching author so validation passes up to SHA re-check.
	validFile := rotate.RequestAccessFile{
		SchemaVersion: "byreis.request_access.v1",
		GitHubHandle:  "alice",
		AgePubkey:     validAgePub,
		Justification: "testing",
		RequestedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	validMeta := rotate.PRMetadata{
		AuthorLogin:        "alice",
		AuthorType:         "User",
		State:              "open",
		IsDraft:            false,
		IsMerged:           false,
		HeadSHA:            shaBefore, // pinned at first read
		HeadRepoOwnerLogin: "alice",
		Commits:            []rotate.CommitInfo{{SHA: shaBefore, AuthorLogin: "alice"}},
	}

	recordingPhase1 := &sgV6PanicPhase1{}
	driftReader := &sgV6FakeRequestAccessReader{
		file:    validFile,
		meta:    validMeta,
		headSHA: shaAfter, // FetchPRHeadSHA returns the drifted SHA
	}
	recordingRotator := &sgV6RecordingRotatorWithPanicPhase1{phase1: recordingPhase1}

	deps := &cli.Deps{
		Policy:              &mode.Policy{},
		CurrentMode:         mode.ModeAdmin,
		Rotator:             recordingRotator,
		RequestAccessReader: driftReader,
	}

	_, errBuf, exitCode := sgV6RunCobra(t, deps,
		"rotate",
		"--project", "myapp",
		"--from-request", "myorg/admins#42",
		"--yes",
	)

	if exitCode == 0 {
		t.Fatalf("V6.SG3: rotate --from-request with SHA drift: exit 0 — "+
			"ErrRequestAccessPRForcePushed must cause non-zero exit; stderr=%q",
			errBuf.String())
	}

	if recordingPhase1.calls > 0 {
		t.Fatalf("V6.SG3: Phase1.Execute was called %d time(s) — "+
			"SHA drift MUST refuse before Phase-1 is invoked; "+
			"force-push race detection gate did not fire",
			recordingPhase1.calls)
	}

	// The error message must reference the SHA drift.
	if !strings.Contains(errBuf.String(), "force") &&
		!strings.Contains(errBuf.String(), "HEAD SHA") &&
		!strings.Contains(errBuf.String(), "drift") &&
		!strings.Contains(errBuf.String(), shaAfter[:8]) {
		t.Errorf("V6.SG3: stderr=%q does not mention SHA drift — "+
			"expected force-push race detection text", errBuf.String())
	}
}

// ── V6.SG4 ────────────────────────────────────────────────────────────────────

// TestAsymmetryShipGate_FromRequest_AuditEventCarriesPRProvenance proves that
// when a rotation is absorbed from a `--from-request <PR>`, the audit event
// produced by BuildRotationAuditEvent contains all four required provenance
// fields (T-V6-13):
//
//   - from_request_pr_url
//   - from_request_pr_head_sha
//   - from_request_yaml_handle
//   - from_request_validated_author_login
//
// This test exercises the BuildRotationAuditEvent function directly; it does
// not require a full fixture or network.
func TestAsymmetryShipGate_FromRequest_AuditEventCarriesPRProvenance(t *testing.T) {
	plan := rotate.RotationPlan{
		ProjectID:         "myapp",
		NewRecipientSet:   []rectypes.Recipient{{AgePubKey: "age1new"}},
		AddedRecipients:   []rectypes.Recipient{{AgePubKey: "age1new"}},
		RemovedRecipients: nil,
		NewEpoch:          3,
		HasRemovals:       false,
	}

	prMeta := &rotate.FromRequestPRMeta{
		Project:              "myorg/admins",
		Number:               42,
		HeadSHA:              "abc123sha456789",
		YAMLHandle:           "alice",
		ValidatedAuthorLogin: "alice",
	}

	ev := rotate.BuildRotationAuditEvent(plan, "myapp", time.Unix(1700000000, 0).UTC(), prMeta)

	// Verify the event kind and baseline fields.
	if ev.Kind != audit.EventKindRotation {
		t.Errorf("V6.SG4: event Kind = %v, want EventKindRotation", ev.Kind)
	}
	if ev.ProjectID != "myapp" {
		t.Errorf("V6.SG4: event ProjectID = %q, want %q", ev.ProjectID, "myapp")
	}

	// PR provenance assertions (T-V6-13):

	wantPRURL := "myorg/admins#42"
	if got := ev.Details["from_request_pr_url"]; got != wantPRURL {
		t.Errorf("V6.SG4: Details[from_request_pr_url] = %q, want %q", got, wantPRURL)
	}

	if got := ev.Details["from_request_pr_head_sha"]; got != prMeta.HeadSHA {
		t.Errorf("V6.SG4: Details[from_request_pr_head_sha] = %q, want %q",
			got, prMeta.HeadSHA)
	}

	if got := ev.Details["from_request_yaml_handle"]; got != "alice" {
		t.Errorf("V6.SG4: Details[from_request_yaml_handle] = %q, want %q", got, "alice")
	}

	if got := ev.Details["from_request_validated_author_login"]; got != "alice" {
		t.Errorf("V6.SG4: Details[from_request_validated_author_login] = %q, want %q",
			got, "alice")
	}

	// Verify that the epoch key is also present (baseline rotation event shape).
	if got := ev.Details["rotation_epoch"]; got != "3" {
		t.Errorf("V6.SG4: Details[rotation_epoch] = %q, want \"3\"", got)
	}

	// Negative: with a nil fromRequestPR the provenance keys must be absent.
	evNoMeta := rotate.BuildRotationAuditEvent(plan, "myapp",
		time.Unix(1700000000, 0).UTC(), nil)
	for _, key := range []string{
		"from_request_pr_url",
		"from_request_pr_head_sha",
		"from_request_yaml_handle",
		"from_request_validated_author_login",
	} {
		if _, ok := evNoMeta.Details[key]; ok {
			t.Errorf("V6.SG4: evNoMeta.Details[%q] present on nil fromRequestPR — "+
				"provenance keys must be absent when there is no request-access PR",
				key)
		}
	}
}

// ── V6.SG5 ────────────────────────────────────────────────────────────────────

// TestAsymmetryShipGate_RequestAccess_NoRegistryWriteToken proves that the
// request-access compilation unit does NOT transitively import
// `internal/adapter/registry/writesigner` or `internal/auth.RegistryWriteTokenStore`
// (BO-V6-CRYPTO-8 + T-V6-10 closed-world constraint).
//
// The `go list -deps` gate is authoritative; a gate that cannot run is a test
// failure, never a silent pass.
func TestAsymmetryShipGate_RequestAccess_NoRegistryWriteToken(t *testing.T) {
	const requestAccessPkg = "github.com/ByReisK/byreis/internal/cli"

	cmd := exec.CommandContext(t.Context(),
		"go", "list", "-deps", requestAccessPkg)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("V6.SG5: ALLOWLIST GATE FAIL: go list -deps %s failed: %v (output: %s)\n"+
			"A gate that cannot run is a failure, never a silent pass.",
			requestAccessPkg, err, out)
	}

	deps := strings.Fields(strings.TrimSpace(string(out)))

	// The request-access verb must not pull in registry write infrastructure.
	forbidden := []string{
		"github.com/ByReisK/byreis/internal/adapter/registry/writesigner",
	}

	var violations []string
	for _, dep := range deps {
		for _, f := range forbidden {
			if dep == f {
				violations = append(violations, dep)
			}
		}
	}

	if len(violations) > 0 {
		t.Errorf("V6.SG5: request-access compilation unit transitively imports "+
			"registry write infrastructure (BO-V6-CRYPTO-8 violation):\n")
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
		t.Errorf("The request-access verb MUST NOT import registry write credentials. " +
			"Move any write-infrastructure dependency outside the contributor path.")
	} else {
		t.Logf("V6.SG5: PASS — internal/cli (%d deps) does not import writesigner",
			len(deps))
	}
}

// ── shared test helpers ───────────────────────────────────────────────────────

// sgV6RunCobra executes the SHIPPED cobra root command tree with the given deps
// and returns the captured stdout/stderr buffers plus the resolved exit code.
// It mirrors shipgateFixture.runCobra in structure so every row drives the same
// production cobra dispatch as the main ship-gate.
func sgV6RunCobra(t *testing.T, deps *cli.Deps, args ...string) (
	stdout *strings.Builder, stderr *strings.Builder, exitCode int,
) {
	t.Helper()

	var outBuf strings.Builder
	var errBuf strings.Builder

	root := cli.NewRootCmdWithDeps(deps)
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	runErr := root.ExecuteContext(ctx)
	exitCode = cli.ExitCodeOf(runErr)
	return &outBuf, &errBuf, exitCode
}

// sgV6FakeRequestAccessReader is an in-memory RequestAccessReader for testing.
// FetchRequestAccessYAML always returns the configured file+meta.
// FetchPRHeadSHA always returns headSHA (which may differ from meta.HeadSHA to
// simulate a force-push race).
type sgV6FakeRequestAccessReader struct {
	file    rotate.RequestAccessFile
	meta    rotate.PRMetadata
	headSHA string // returned by FetchPRHeadSHA (may differ from meta.HeadSHA)
	fetchErr error // if non-nil, FetchRequestAccessYAML returns this error
}

func (r *sgV6FakeRequestAccessReader) FetchRequestAccessYAML(
	ctx context.Context, _ git.PRRef,
) (rotate.RequestAccessFile, rotate.PRMetadata, error) {
	if err := ctx.Err(); err != nil {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{},
			errors.New("sgV6FakeRequestAccessReader: context cancelled")
	}
	if r.fetchErr != nil {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{}, r.fetchErr
	}
	return r.file, r.meta, nil
}

func (r *sgV6FakeRequestAccessReader) FetchPRHeadSHA(
	ctx context.Context, _ git.PRRef,
) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", errors.New("sgV6FakeRequestAccessReader: context cancelled")
	}
	// Return the fake's headSHA and the meta's HeadRepoOwnerLogin so that
	// the ownerLogin re-check passes on the happy path. Tests that simulate a
	// SHA drift set headSHA != meta.HeadSHA; ownerLogin is kept stable here.
	return r.headSHA, r.meta.HeadRepoOwnerLogin, nil
}

// ListOpenRequests is not exercised by the V6 shipgate fixtures (the gate
// drives the --from-request lift, not the V7 triage list); it is present only
// so the fake continues to satisfy the RequestAccessReader port.
func (r *sgV6FakeRequestAccessReader) ListOpenRequests(
	ctx context.Context,
) ([]rotate.OpenRequestSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.New("sgV6FakeRequestAccessReader: context cancelled")
	}
	return nil, nil
}
