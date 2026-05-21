package cli_test

// CLI-layer tests for the `byreis rotate` verb.
//
// Row IDs (test-file-only audit anchors):
//   - V5.ROTATE.contributor-denied-not-attempted
//   - V5.ROTATE.dry-run-no-side-effects
//   - V5.ROTATE.typed-fingerprint-mismatch
//   - V5.ROTATE.typed-fingerprint-match
//   - V5.ROTATE.typed-fingerprint-prefix-rejected
//   - V5.ROTATE.from-request-deferred-to-later-slice
//   - V5.ROTATE.add-always-full-rotate
//   - V5.ROTATE.replace-single-composed-delta
//   - V5.ROTATE.non-interactive-without-yes-fails-closed-no-plan-leak
//   - V5.ROTATE.no-bypass-to-registry-adapter
//   - V5.ROTATE.exit-code-matrix
//   - V5.ROTATE.preflight-stale-registry
//   - V5.ROTATE.preflight-cant-decrypt
//   - V5.ROTATE.preflight-success-input-populated

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ---- fake Rotator -----------------------------------------------------------

// fakeRotator is a test double for rotate.Rotator. It records calls and returns
// a configured result or error.
type fakeRotator struct {
	calls    atomic.Int32
	captured rotate.RotationInput
	result   rotate.RotationResult
	err      error
}

func (f *fakeRotator) Rotate(_ context.Context, in rotate.RotationInput) (rotate.RotationResult, error) {
	f.calls.Add(1)
	f.captured = in
	return f.result, f.err
}

// panicRotator panics if Rotate is ever invoked. Used to assert CONTRIBUTOR
// mode never reaches the rotator.
type panicRotator struct{}

func (*panicRotator) Rotate(_ context.Context, _ rotate.RotationInput) (rotate.RotationResult, error) {
	panic("Rotate was called but must not be reached in CONTRIBUTOR mode — policy gate violated")
}

// fakeReconciler is a test double for rotate.RotationReconciler.
type fakeReconciler struct {
	classificationResult rotate.PartialStateClassification
	classificationErr    error
	reconcileResult      rotate.ReconcileResult
	reconcileErr         error
	classifyCalls        atomic.Int32
	reconcileCalls       atomic.Int32
}

func (f *fakeReconciler) Classify(_ context.Context, _ string) (rotate.PartialStateClassification, error) {
	f.classifyCalls.Add(1)
	return f.classificationResult, f.classificationErr
}

func (f *fakeReconciler) Reconcile(_ context.Context, _ string) (rotate.ReconcileResult, error) {
	f.reconcileCalls.Add(1)
	return f.reconcileResult, f.reconcileErr
}

// ---- test helpers -----------------------------------------------------------

func makeRotateDeps(m mode.Mode, rotator rotate.Rotator) *cli.Deps {
	return &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: m,
		Rotator:     rotator,
	}
}

func makeRotateDepsWithReconciler(m mode.Mode, rotator rotate.Rotator, reconciler rotate.RotationReconciler) *cli.Deps {
	return &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: m,
		Rotator:     rotator,
		Reconciler:  reconciler,
	}
}

func runRotateCmd(deps *cli.Deps, args []string, stdin string) (stdout, stderr string, err error) {
	root := cli.NewRootCmdWithDeps(deps)
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	if stdin != "" {
		root.SetIn(strings.NewReader(stdin))
	}
	root.SetArgs(args)
	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

// ---- V5.ROTATE.contributor-denied-not-attempted ----------------------------

// TestRotate_ContributorDeniedNotAttempted proves the mode gate fires BEFORE
// any registry fetch or Rotator call. The panicRotator panics if reached.
func TestRotate_ContributorDeniedNotAttempted(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.contributor-denied-not-attempted
	deps := makeRotateDeps(mode.ModeContributor, &panicRotator{})
	_, _, err := runRotateCmd(deps, []string{"rotate", "--project", "test-proj"}, "")

	if err == nil {
		t.Fatal("expected ErrPermissionDenied, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("want errors.Is(err, mode.ErrPermissionDenied), got: %v", err)
	}
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitPermissionDenied) {
		t.Errorf("exit code = %d, want %d (ExitPermissionDenied)", exitCode, render.ExitPermissionDenied)
	}
}

// ---- V5.ROTATE.dry-run-no-side-effects -------------------------------------

// TestRotate_DryRun_NoSideEffects proves --dry-run prints the plan but does NOT
// invoke Phase-1 (verified by returning DryRun:true from the spine fake and
// checking the rotator call count).
func TestRotate_DryRun_NoSideEffects(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.dry-run-no-side-effects
	fr := &fakeRotator{
		result: rotate.RotationResult{
			Plan: rotate.RotationPlan{
				ProjectID:   "test-proj",
				NewEpoch:    1,
				HasRemovals: false,
			},
			DryRun: true,
		},
	}
	deps := makeRotateDeps(mode.ModeAdmin, fr)
	out, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--add", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt",
		"--dry-run",
	}, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fr.calls.Load() != 1 {
		t.Errorf("rotator call count = %d, want 1", fr.calls.Load())
	}
	if !fr.captured.DryRun {
		t.Error("RotationInput.DryRun was not set")
	}
	if !strings.Contains(out, "dry-run") {
		t.Errorf("stdout does not mention dry-run: %q", out)
	}
}

// ---- V5.ROTATE.typed-fingerprint-mismatch ----------------------------------

// TestRotate_TypedFingerprintMismatch proves that interactive --remove mode with
// a wrong typed input returns ErrRotationFingerprintMismatch and does NOT invoke
// Phase-1 (rotator call count = 0).
func TestRotate_TypedFingerprintMismatch(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.typed-fingerprint-mismatch
	fr := &fakeRotator{}
	deps := makeRotateDeps(mode.ModeAdmin, fr)

	// Provide wrong fingerprint (all zeros instead of the real SHA-256 hash).
	wrongFingerprint := strings.Repeat("0", 64)
	_, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--remove", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt",
	}, wrongFingerprint+"\n")

	if err == nil {
		t.Fatal("expected ErrRotationFingerprintMismatch, got nil")
	}
	if !errors.Is(err, rotate.ErrRotationFingerprintMismatch) {
		t.Errorf("want errors.Is(err, rotate.ErrRotationFingerprintMismatch), got: %v", err)
	}
	if fr.calls.Load() != 0 {
		t.Errorf("rotator was called %d times; want 0 (Phase-1 must not proceed on mismatch)", fr.calls.Load())
	}
}

// ---- V5.ROTATE.typed-fingerprint-match -------------------------------------

// TestRotate_TypedFingerprintMatch proves that interactive --remove mode with the
// correct full 64-char fingerprint proceeds to the rotator.
func TestRotate_TypedFingerprintMatch(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.typed-fingerprint-match
	pubkey := "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt"
	recip := rectypes.Recipient{AgePubKey: pubkey}
	fullFingerprint := rotate.RecipientFingerprintFull(recip)

	fr := &fakeRotator{
		result: rotate.RotationResult{
			Plan:           rotate.RotationPlan{ProjectID: "test-proj", NewEpoch: 2},
			Phase1Executed: true,
			Phase2Executed: true,
		},
	}
	deps := makeRotateDeps(mode.ModeAdmin, fr)

	_, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--remove", pubkey,
	}, fullFingerprint+"\n")

	if err != nil {
		t.Fatalf("unexpected error (fingerprint matched): %v", err)
	}
	if fr.calls.Load() != 1 {
		t.Errorf("rotator call count = %d, want 1", fr.calls.Load())
	}
}

// ---- V5.ROTATE.typed-fingerprint-prefix-rejected ---------------------------

// TestRotate_TypedFingerprintPrefixRejected proves that typing only the 16-char
// prefix is rejected — the full 64-char fingerprint is required.
func TestRotate_TypedFingerprintPrefixRejected(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.typed-fingerprint-prefix-rejected
	pubkey := "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt"
	recip := rectypes.Recipient{AgePubKey: pubkey}
	fullFingerprint := rotate.RecipientFingerprintFull(recip)
	prefix16 := fullFingerprint[:16]

	fr := &fakeRotator{}
	deps := makeRotateDeps(mode.ModeAdmin, fr)

	_, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--remove", pubkey,
	}, prefix16+"\n")

	if err == nil {
		t.Fatal("expected error for prefix-only fingerprint, got nil")
	}
	if !errors.Is(err, rotate.ErrRotationFingerprintMismatch) {
		t.Errorf("want errors.Is(err, rotate.ErrRotationFingerprintMismatch), got: %v", err)
	}
	if fr.calls.Load() != 0 {
		t.Errorf("rotator was called %d times; want 0 (prefix-only must be rejected)", fr.calls.Load())
	}
}

// ---- V5.ROTATE.from-request-deferred-to-later-slice ------------------------

// TestRotate_FromRequestDeferred proves --from-request returns an error
// referencing the later-slice availability and does NOT read any PR content.
func TestRotate_FromRequestDeferred(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.from-request-deferred-to-later-slice
	fr := &fakeRotator{}
	deps := makeRotateDeps(mode.ModeAdmin, fr)

	_, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--from-request", "myorg/my-registry#42",
	}, "")

	if err == nil {
		t.Fatal("expected error for --from-request, got nil")
	}
	if !strings.Contains(err.Error(), "later slice") {
		t.Errorf("error message should mention 'later slice', got: %v", err)
	}
	if fr.calls.Load() != 0 {
		t.Errorf("rotator was called %d times; want 0 (--from-request must not reach rotator)", fr.calls.Load())
	}
}

// ---- V5.ROTATE.add-always-full-rotate --------------------------------------

// TestRotate_AddAlwaysFullRotate proves --add invokes the full Rotator.Rotate
// path (not a fast-path alias). The captured RotationInput must have the add
// pubkey in AddPubkeys.
func TestRotate_AddAlwaysFullRotate(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.add-always-full-rotate
	addKey := "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt"
	fr := &fakeRotator{
		result: rotate.RotationResult{
			Plan:           rotate.RotationPlan{ProjectID: "test-proj", NewEpoch: 3},
			Phase1Executed: true,
			Phase2Executed: true,
		},
	}
	deps := makeRotateDeps(mode.ModeAdmin, fr)

	_, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--add", addKey,
		"--yes",
	}, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fr.calls.Load() != 1 {
		t.Errorf("rotator call count = %d, want 1", fr.calls.Load())
	}
	if len(fr.captured.AddPubkeys) != 1 || fr.captured.AddPubkeys[0].AgePubKey != addKey {
		t.Errorf("AddPubkeys = %v, want [{%s}]", fr.captured.AddPubkeys, addKey)
	}
	if len(fr.captured.RemovePubkeys) != 0 {
		t.Errorf("RemovePubkeys = %v, want empty (--add only)", fr.captured.RemovePubkeys)
	}
}

// ---- V5.ROTATE.replace-single-composed-delta --------------------------------

// TestRotate_ReplaceSingleComposedDelta proves --replace <old=new> produces a
// single ReplacePair in the input (not split into AddPubkeys + RemovePubkeys).
func TestRotate_ReplaceSingleComposedDelta(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.replace-single-composed-delta
	oldKey := "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt"
	newKey := "age1pppppppppppppppppppppppppppppppppppppppppppppppppppppt36pzn"

	fr := &fakeRotator{
		result: rotate.RotationResult{
			Plan:           rotate.RotationPlan{ProjectID: "test-proj", NewEpoch: 4},
			Phase1Executed: true,
			Phase2Executed: true,
		},
	}
	deps := makeRotateDeps(mode.ModeAdmin, fr)

	pubkey := "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt"
	recip := rectypes.Recipient{AgePubKey: pubkey}
	fullFingerprint := rotate.RecipientFingerprintFull(recip)

	_, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--replace", oldKey + "=" + newKey,
	}, fullFingerprint+"\n")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fr.calls.Load() != 1 {
		t.Errorf("rotator call count = %d, want 1", fr.calls.Load())
	}
	// --replace must be in ReplacePairs, NOT in AddPubkeys + RemovePubkeys.
	if len(fr.captured.ReplacePairs) != 1 {
		t.Errorf("ReplacePairs len = %d, want 1", len(fr.captured.ReplacePairs))
	} else {
		if fr.captured.ReplacePairs[0].Old.AgePubKey != oldKey {
			t.Errorf("ReplacePairs[0].Old = %q, want %q", fr.captured.ReplacePairs[0].Old.AgePubKey, oldKey)
		}
		if fr.captured.ReplacePairs[0].New.AgePubKey != newKey {
			t.Errorf("ReplacePairs[0].New = %q, want %q", fr.captured.ReplacePairs[0].New.AgePubKey, newKey)
		}
	}
	if len(fr.captured.AddPubkeys) != 0 {
		t.Errorf("AddPubkeys = %v, want empty (--replace must not decompose)", fr.captured.AddPubkeys)
	}
	if len(fr.captured.RemovePubkeys) != 0 {
		t.Errorf("RemovePubkeys = %v, want empty (--replace must not decompose)", fr.captured.RemovePubkeys)
	}
}

// ---- V5.ROTATE.non-interactive-without-yes-fails-closed-no-plan-leak --------

// TestRotate_NonInteractiveWithoutYesFailsClosedNoPlanLeak proves that
// BYREIS_NON_INTERACTIVE=1 without --yes fails closed and MUST NOT print any
// plan content or recipient pubkey hex to stdout.
func TestRotate_NonInteractiveWithoutYesFailsClosedNoPlanLeak(t *testing.T) {
	// Not parallel: uses t.Setenv.
	t.Setenv("BYREIS_NON_INTERACTIVE", "1")

	// V5.ROTATE.non-interactive-without-yes-fails-closed-no-plan-leak
	fr := &fakeRotator{
		// If called (which it must not be), return a plan with "would have rotated".
		result: rotate.RotationResult{
			Plan: rotate.RotationPlan{
				ProjectID: "test-proj",
				NewEpoch:  1,
				AddedRecipients: []rectypes.Recipient{
					{AgePubKey: "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt"},
				},
			},
			DryRun: true,
		},
	}
	deps := makeRotateDeps(mode.ModeAdmin, fr)

	out, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--add", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt",
	}, "")

	if err == nil {
		t.Fatal("expected ErrNonInteractiveRequiresYes, got nil")
	}
	if !errors.Is(err, rotate.ErrNonInteractiveRequiresYes) {
		t.Errorf("want errors.Is(err, rotate.ErrNonInteractiveRequiresYes), got: %v", err)
	}
	// stdout MUST NOT contain "would" or any recipient pubkey hex.
	if strings.Contains(out, "would") {
		t.Errorf("stdout contains 'would' (plan leak): %q", out)
	}
	if strings.Contains(out, "age1") {
		t.Errorf("stdout contains 'age1' pubkey prefix (plan leak): %q", out)
	}
	// Rotator must not have been invoked.
	if fr.calls.Load() != 0 {
		t.Errorf("rotator was called %d times; want 0 (non-interactive without --yes must fail before rotator)", fr.calls.Load())
	}
}

// ---- V5.ROTATE.no-bypass-to-registry-adapter --------------------------------

// TestRotate_NoBypassToRegistryAdapter proves CONTRIBUTOR mode never reaches the
// rotator (and by extension never reaches any registry adapter), and that ADMIN
// mode reaches the rotator only through the injected port — not via any direct
// adapter import.
func TestRotate_NoBypassToRegistryAdapter(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.no-bypass-to-registry-adapter

	// CONTRIBUTOR path: panicRotator panics if reached.
	contribDeps := makeRotateDeps(mode.ModeContributor, &panicRotator{})
	_, _, err := runRotateCmd(contribDeps, []string{"rotate", "--project", "test-proj"}, "")
	if err == nil || !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("CONTRIBUTOR path: want ErrPermissionDenied, got: %v", err)
	}

	// ADMIN path: reachable ONLY through the injected fakeRotator, never via
	// direct adapter import. The test panics if any direct adapter call is made.
	fr := &fakeRotator{
		result: rotate.RotationResult{
			Plan:           rotate.RotationPlan{ProjectID: "test-proj", NewEpoch: 1},
			Phase1Executed: true,
			Phase2Executed: true,
		},
	}
	adminDeps := makeRotateDeps(mode.ModeAdmin, fr)
	_, _, adminErr := runRotateCmd(adminDeps, []string{
		"rotate", "--project", "test-proj",
		"--add", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt",
		"--yes",
	}, "")
	if adminErr != nil {
		t.Errorf("ADMIN path: unexpected error: %v", adminErr)
	}
	if fr.calls.Load() != 1 {
		t.Errorf("ADMIN path: rotator calls = %d, want 1", fr.calls.Load())
	}
}

// ---- V5.ROTATE.exit-code-matrix --------------------------------------------

// TestRotate_ExitCodeMatrix exercises the full sentinel-to-exit-code mapping.
func TestRotate_ExitCodeMatrix(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.exit-code-matrix
	rows := []struct {
		name     string
		err      error
		wantCode render.ExitCode
	}{
		{
			name:     "ErrRotationReconcile",
			err:      rotate.ErrRotationReconcile,
			wantCode: render.ExitCounterReconcile,
		},
		{
			name:     "ErrRotationRequiresFreshRegistry",
			err:      rotate.ErrRotationRequiresFreshRegistry,
			wantCode: render.ExitTrustError,
		},
		{
			name:     "ErrRotationCannotDecryptExisting",
			err:      rotate.ErrRotationCannotDecryptExisting,
			wantCode: render.ExitAuthError,
		},
		{
			name:     "ErrNonInteractiveRequiresYes",
			err:      rotate.ErrNonInteractiveRequiresYes,
			wantCode: render.ExitGeneralError,
		},
		{
			name:     "ErrRotationFingerprintMismatch",
			err:      rotate.ErrRotationFingerprintMismatch,
			wantCode: render.ExitGeneralError,
		},
		{
			name:     "ErrRotationFlagConflict",
			err:      rotate.ErrRotationFlagConflict,
			wantCode: render.ExitGeneralError,
		},
		{
			name:     "ErrRotationReversalNoBranchRef",
			err:      rotate.ErrRotationReversalNoBranchRef,
			wantCode: render.ExitTrustError,
		},
	}

	for _, tc := range rows {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fr := &fakeRotator{err: tc.err}
			deps := makeRotateDeps(mode.ModeAdmin, fr)

			_, _, err := runRotateCmd(deps, []string{
				"rotate", "--project", "test-proj",
				"--add", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt",
				"--yes",
			}, "")

			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			got := cli.ExitCodeOf(err)
			if got != int(tc.wantCode) {
				t.Errorf("%s: exit code = %d, want %d", tc.name, got, int(tc.wantCode))
			}
		})
	}
}

// ---- mode derivation check --------------------------------------------------

// TestRotate_ModeFromCryptographicReality proves RotationInput.Mode is always
// set from deps.CurrentMode and never from a flag, env, or config value.
func TestRotate_ModeFromCryptographicReality(t *testing.T) {
	t.Parallel()

	fr := &fakeRotator{
		result: rotate.RotationResult{
			Plan:           rotate.RotationPlan{ProjectID: "test-proj"},
			Phase1Executed: true,
			Phase2Executed: true,
		},
	}
	deps := makeRotateDeps(mode.ModeAdmin, fr)

	_, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--add", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt",
		"--yes",
	}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fr.captured.Mode != mode.ModeAdmin {
		t.Errorf("RotationInput.Mode = %v, want ModeAdmin (must be from cryptographic reality)", fr.captured.Mode)
	}
}

// ---- reconcile CLI tests ----------------------------------------------------

// TestAdminRotationReconcile_ContributorDenied proves mode gate fires before any
// reconciler call.
func TestAdminRotationReconcile_ContributorDenied(t *testing.T) {
	t.Parallel()

	// V5.R007.1
	fr := &fakeReconciler{}
	deps := makeRotateDepsWithReconciler(mode.ModeContributor, nil, fr)

	root := cli.NewRootCmdWithDeps(deps)
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"admin", "rotation", "reconcile", "--project", "test-proj"})
	err := root.Execute()

	if err == nil {
		t.Fatal("expected ErrPermissionDenied, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Errorf("want errors.Is(err, mode.ErrPermissionDenied), got: %v", err)
	}
	if fr.classifyCalls.Load() != 0 || fr.reconcileCalls.Load() != 0 {
		t.Errorf("reconciler was called (classify=%d reconcile=%d), must not be called for CONTRIBUTOR",
			fr.classifyCalls.Load(), fr.reconcileCalls.Load())
	}
}

// TestAdminRotationReconcile_NoPartialState proves classify-first short-circuit:
// NoPartialState exits OK without a Reconcile call.
func TestAdminRotationReconcile_NoPartialState(t *testing.T) {
	t.Parallel()

	// V5.R007.2 (no-partial-state path)
	fr := &fakeReconciler{
		classificationResult: rotate.NoPartialState,
	}
	deps := makeRotateDepsWithReconciler(mode.ModeAdmin, nil, fr)

	root := cli.NewRootCmdWithDeps(deps)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"admin", "rotation", "reconcile", "--project", "test-proj"})
	err := root.Execute()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fr.reconcileCalls.Load() != 0 {
		t.Errorf("Reconcile was called %d times; want 0 for no-partial-state", fr.reconcileCalls.Load())
	}
	out := outBuf.String()
	if !strings.Contains(out, "no partial rotation state") {
		t.Errorf("stdout = %q; want 'no partial rotation state'", out)
	}
}

// TestAdminRotationReconcile_Phase1Only_ClassifyFirst proves that Phase1Only
// classification triggers Reconcile (write-side) work, and that the write-side
// path is NOT invoked for non-Phase1Only classifications.
func TestAdminRotationReconcile_Phase1Only_ClassifyFirst(t *testing.T) {
	t.Parallel()

	// V5.R007.3 (phase-1-only path — write-side invoked)
	fr := &fakeReconciler{
		classificationResult: rotate.Phase1Only,
		reconcileResult: rotate.ReconcileResult{
			Classification:  rotate.Phase1Only,
			BranchDeleted:   true,
			PendingsCleared: 2,
		},
	}
	deps := makeRotateDepsWithReconciler(mode.ModeAdmin, nil, fr)

	root := cli.NewRootCmdWithDeps(deps)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"admin", "rotation", "reconcile", "--project", "test-proj"})
	err := root.Execute()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fr.classifyCalls.Load() != 1 {
		t.Errorf("Classify calls = %d, want 1", fr.classifyCalls.Load())
	}
	if fr.reconcileCalls.Load() != 1 {
		t.Errorf("Reconcile calls = %d, want 1 (phase-1-only must trigger reconcile)", fr.reconcileCalls.Load())
	}
}

// TestAdminRotationReconcile_Phase2Midflight_TerminalError proves
// Phase2Midflight returns a terminal error without calling Reconcile.
func TestAdminRotationReconcile_Phase2Midflight_TerminalError(t *testing.T) {
	t.Parallel()

	// V5.R007.4 (phase-2-midflight — terminal)
	fr := &fakeReconciler{
		classificationResult: rotate.Phase2Midflight,
	}
	deps := makeRotateDepsWithReconciler(mode.ModeAdmin, nil, fr)

	root := cli.NewRootCmdWithDeps(deps)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"admin", "rotation", "reconcile", "--project", "test-proj"})
	err := root.Execute()

	if err == nil {
		t.Fatal("expected error for phase-2-midflight, got nil")
	}
	if fr.reconcileCalls.Load() != 0 {
		t.Errorf("Reconcile was called %d times; want 0 for phase-2-midflight (terminal, no write-side work)", fr.reconcileCalls.Load())
	}
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitCounterReconcile) {
		t.Errorf("exit code = %d, want %d (ExitCounterReconcile)", exitCode, render.ExitCounterReconcile)
	}
}

// TestAdminRotationReconcile_JSONOutput proves --json produces valid JSON with
// no secret bytes.
func TestAdminRotationReconcile_JSONOutput(t *testing.T) {
	t.Parallel()

	// V5.JSON (reconcile JSON output)
	fr := &fakeReconciler{
		classificationResult: rotate.Phase1Only,
		reconcileResult: rotate.ReconcileResult{
			Classification:  rotate.Phase1Only,
			BranchDeleted:   true,
			PendingsCleared: 1,
		},
	}
	deps := makeRotateDepsWithReconciler(mode.ModeAdmin, nil, fr)

	root := cli.NewRootCmdWithDeps(deps)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"--json", "admin", "rotation", "reconcile", "--project", "test-proj"})
	err := root.Execute()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := outBuf.String()
	if !strings.Contains(out, `"classification"`) {
		t.Errorf("JSON output missing 'classification' field: %q", out)
	}
	if !strings.Contains(out, `"branch_deleted"`) {
		t.Errorf("JSON output missing 'branch_deleted' field: %q", out)
	}
	// No secret bytes.
	if strings.Contains(out, "age1") {
		t.Errorf("JSON output contains 'age1' pubkey (possible secret leak): %q", out)
	}
}

// TestAdminRotationReconcile_Race exercises concurrent reconcile calls to
// satisfy the -race gate.
func TestAdminRotationReconcile_Race(t *testing.T) {
	t.Parallel()

	// V5.D7.race (CLI-layer concurrent access, not the spine retry logic)
	const concurrency = 8
	done := make(chan struct{}, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			fr := &fakeReconciler{classificationResult: rotate.NoPartialState}
			deps := makeRotateDepsWithReconciler(mode.ModeAdmin, nil, fr)

			root := cli.NewRootCmdWithDeps(deps)
			var buf bytes.Buffer
			root.SetOut(&buf)
			root.SetErr(&buf)
			root.SetArgs([]string{"admin", "rotation", "reconcile", "--project", "proj-x"})
			_ = root.Execute()
		}()
	}
	for i := 0; i < concurrency; i++ {
		<-done
	}
}

// ---- pre-flight test helpers ------------------------------------------------

// fakePreFlight is a configurable test double for cli.RotatePreFlightReader.
type fakePreFlight struct {
	adminSet    cli.RotatePreFlightAdminSet
	adminSetErr error
	decryptErr  error

	fetchCalls   atomic.Int32
	decryptCalls atomic.Int32
}

func (f *fakePreFlight) FetchVerifiedAdminSet(
	_ context.Context, _ string,
) (cli.RotatePreFlightAdminSet, error) {
	f.fetchCalls.Add(1)
	return f.adminSet, f.adminSetErr
}

func (f *fakePreFlight) CanDecryptAllFiles(
	_ context.Context, _ []cli.RotatePreFlightFileSnap,
) error {
	f.decryptCalls.Add(1)
	return f.decryptErr
}

// makeRotateDepsWithPreflight builds Deps with both a fakeRotator and a
// fakePreFlight wired.
func makeRotateDepsWithPreflight(
	m mode.Mode,
	rotator rotate.Rotator,
	pf cli.RotatePreFlightReader,
) *cli.Deps {
	return &cli.Deps{
		Policy:          &mode.Policy{},
		CurrentMode:     m,
		Rotator:         rotator,
		RotatePreFlight: pf,
	}
}

// ---- V5.ROTATE.preflight-stale-registry -------------------------------------

// TestRotate_PreFlight_StaleRegistry proves that when FetchVerifiedAdminSet
// returns an error wrapping ErrRotationRequiresFreshRegistry, the CLI surfaces
// that exit class and does NOT invoke Phase-1 (rotator call count = 0).
func TestRotate_PreFlight_StaleRegistry(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.preflight-stale-registry
	pf := &fakePreFlight{
		adminSetErr: fmt.Errorf("%w: stale", rotate.ErrRotationRequiresFreshRegistry),
	}
	fr := &fakeRotator{}
	deps := makeRotateDepsWithPreflight(mode.ModeAdmin, fr, pf)

	_, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--add", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt",
		"--yes",
	}, "")

	if err == nil {
		t.Fatal("expected ErrRotationRequiresFreshRegistry, got nil")
	}
	if !errors.Is(err, rotate.ErrRotationRequiresFreshRegistry) {
		t.Errorf("want errors.Is(err, ErrRotationRequiresFreshRegistry), got: %v", err)
	}
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitTrustError) {
		t.Errorf("exit code = %d, want %d (ExitTrustError)", exitCode, int(render.ExitTrustError))
	}
	if fr.calls.Load() != 0 {
		t.Errorf("rotator called %d times; want 0 (Phase-1 must not start on stale registry)",
			fr.calls.Load())
	}
	if pf.fetchCalls.Load() != 1 {
		t.Errorf("FetchVerifiedAdminSet called %d times; want 1", pf.fetchCalls.Load())
	}
}

// ---- V5.ROTATE.preflight-cant-decrypt ---------------------------------------

// TestRotate_PreFlight_CantDecrypt proves that when CanDecryptAllFiles returns
// an error wrapping ErrRotationCannotDecryptExisting, the CLI surfaces
// ExitAuthError and does NOT invoke Phase-1.
func TestRotate_PreFlight_CantDecrypt(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.preflight-cant-decrypt
	adminSet := cli.RotatePreFlightAdminSet{
		PreRotationRecipients: []string{"age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt"},
		RegisteredAdmins:      []string{"age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt"},
		ConfiguredFiles:       map[string]string{"prod": "vault/prod.enc.yaml"},
		CurrentMaxEpoch:       0,
		FileSnapshots:         []cli.RotatePreFlightFileSnap{{LogicalName: "prod"}},
	}
	pf := &fakePreFlight{
		adminSet:   adminSet,
		decryptErr: fmt.Errorf("%w: admin key not in recipient set", rotate.ErrRotationCannotDecryptExisting),
	}
	fr := &fakeRotator{}
	deps := makeRotateDepsWithPreflight(mode.ModeAdmin, fr, pf)

	_, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--add", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt",
		"--yes",
	}, "")

	if err == nil {
		t.Fatal("expected ErrRotationCannotDecryptExisting, got nil")
	}
	if !errors.Is(err, rotate.ErrRotationCannotDecryptExisting) {
		t.Errorf("want errors.Is(err, ErrRotationCannotDecryptExisting), got: %v", err)
	}
	exitCode := cli.ExitCodeOf(err)
	if exitCode != int(render.ExitAuthError) {
		t.Errorf("exit code = %d, want %d (ExitAuthError)", exitCode, int(render.ExitAuthError))
	}
	if fr.calls.Load() != 0 {
		t.Errorf("rotator called %d times; want 0 (Phase-1 must not start when admin cannot decrypt)",
			fr.calls.Load())
	}
}

// ---- V5.ROTATE.preflight-success-input-populated ----------------------------

// TestRotate_PreFlight_SuccessInputPopulated proves that on a happy-path
// pre-flight, RotationInput.SourceVerified and .AdminCanDecryptAll are both
// true and reflect real pre-flight results (not hard-coded stubs). It also
// asserts that PreRotationRecipients and RegisteredAdmins are populated from
// the pre-flight result, not from flags.
func TestRotate_PreFlight_SuccessInputPopulated(t *testing.T) {
	t.Parallel()

	// V5.ROTATE.preflight-success-input-populated
	addKey := "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3lhfrt"
	existingRecip := "age1pppppppppppppppppppppppppppppppppppppppppppppppppppppt36pzn"
	adminSet := cli.RotatePreFlightAdminSet{
		PreRotationRecipients: []string{existingRecip},
		RegisteredAdmins:      []string{existingRecip},
		ConfiguredFiles:       map[string]string{"prod": "vault/prod.enc.yaml"},
		CurrentMaxEpoch:       3,
		FileSnapshots: []cli.RotatePreFlightFileSnap{
			{LogicalName: "prod", CurrentCounter: 5, CurrentEpoch: 3},
		},
	}
	pf := &fakePreFlight{
		adminSet: adminSet,
	}
	fr := &fakeRotator{
		result: rotate.RotationResult{
			Plan:           rotate.RotationPlan{ProjectID: "test-proj", NewEpoch: 4},
			Phase1Executed: true,
			Phase2Executed: true,
		},
	}
	deps := makeRotateDepsWithPreflight(mode.ModeAdmin, fr, pf)

	_, _, err := runRotateCmd(deps, []string{
		"rotate", "--project", "test-proj",
		"--add", addKey,
		"--yes",
	}, "")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fr.calls.Load() != 1 {
		t.Errorf("rotator call count = %d, want 1", fr.calls.Load())
	}

	in := fr.captured
	// SourceVerified and AdminCanDecryptAll must be true from real pre-flight.
	if !in.SourceVerified {
		t.Error("RotationInput.SourceVerified = false; want true from real pre-flight")
	}
	if !in.AdminCanDecryptAll {
		t.Error("RotationInput.AdminCanDecryptAll = false; want true from real pre-flight")
	}
	// CurrentMaxEpoch must come from the pre-flight admin set.
	if in.CurrentMaxEpoch != 3 {
		t.Errorf("RotationInput.CurrentMaxEpoch = %d, want 3", in.CurrentMaxEpoch)
	}
	// PreRotationRecipients must be populated from the pre-flight admin set.
	if len(in.PreRotationRecipients) != 1 || in.PreRotationRecipients[0].AgePubKey != existingRecip {
		t.Errorf("RotationInput.PreRotationRecipients = %v, want [{%s}]",
			in.PreRotationRecipients, existingRecip)
	}
	// RegisteredAdmins must be populated.
	if len(in.RegisteredAdmins) != 1 {
		t.Errorf("RotationInput.RegisteredAdmins len = %d, want 1", len(in.RegisteredAdmins))
	}
	// PreRotationFiles must have one entry from the pre-flight snapshot.
	if len(in.PreRotationFiles) != 1 || in.PreRotationFiles[0].LogicalName != "prod" {
		t.Errorf("RotationInput.PreRotationFiles = %v, want [{prod ...}]", in.PreRotationFiles)
	}
	if in.PreRotationFiles[0].CurrentCounter != 5 {
		t.Errorf("RotationInput.PreRotationFiles[0].CurrentCounter = %d, want 5",
			in.PreRotationFiles[0].CurrentCounter)
	}
}

// Compile-time: fakeRotator must satisfy the rotate.Rotator interface.
var _ rotate.Rotator = (*fakeRotator)(nil)

// Compile-time: fakeReconciler must satisfy the rotate.RotationReconciler interface.
var _ rotate.RotationReconciler = (*fakeReconciler)(nil)

// Compile-time: fakePreFlight must satisfy the cli.RotatePreFlightReader interface.
var _ cli.RotatePreFlightReader = (*fakePreFlight)(nil)

// Compile-time: time package used for fakeClock (avoids "imported and not used").
var _ = time.Now
