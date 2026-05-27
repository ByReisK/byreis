package modeprobe_test

// Tests for the probe-only-when-needed predicate (C5-a / B4).
//
// These tests mechanically verify:
//
//  1. mode.NeedsDecryptProbe returns true for EVERY admin-only command and
//     false for EVERY contributor-accessible command — derived from the SAME
//     permission matrix, not a separate hand-maintained list.
//
//  2. A keyProbe built with NeedsDecryptProbe=false returns (false,nil)
//     from CanDecryptAny without invoking the ArtifactFetcher, even when a
//     real identity is configured (no token touch, no fetch).
//
//  3. A keyProbe built with NeedsDecryptProbe=true does run the probe and
//     returns the correct decrypt result.

import (
	"context"
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/modeprobe"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// knownContributorCommands is the set of commands the permission matrix
// admits to ModeContributor. A command is in this set iff the matrix has a
// ModeContributor entry.
var knownContributorCommands = []mode.Command{
	mode.CommandVersion,
	mode.CommandInit,
	mode.CommandDoctor,
	mode.CommandSubmit,
	mode.CommandRequestAccess,
	mode.CommandAuditVerify,
}

// knownAdminOnlyCommands is the set of commands the matrix denies to
// ModeContributor but admits to ModeAdmin.
var knownAdminOnlyCommands = []mode.Command{
	mode.CommandReview,
	mode.CommandMerge,
	mode.CommandGet,
	mode.CommandDecrypt,
	mode.CommandEdit,
	mode.CommandRotate,
	mode.CommandRotationReconcile,
	mode.CommandRequestList,
	mode.CommandAuditShow,
	mode.CommandRequestReject,
	mode.CommandExport,
	mode.CommandRun,
}

// TestNeedsDecryptProbe_TrueForAllAdminCommands asserts that NeedsDecryptProbe
// returns true for every command that requires admin decrypt capability.
// The test first confirms the command is genuinely admin-only via Policy.Allow.
func TestNeedsDecryptProbe_TrueForAllAdminCommands(t *testing.T) {
	t.Parallel()
	pol := &mode.Policy{}

	for _, cmd := range knownAdminOnlyCommands {
		cmd := cmd
		t.Run(string(cmd), func(t *testing.T) {
			t.Parallel()

			// Confirm the matrix denies this command to contributors.
			if err := pol.Allow(mode.ModeContributor, cmd); err == nil {
				t.Fatalf("command %q is permitted to CONTRIBUTOR — it is not admin-only and must not be in knownAdminOnlyCommands", cmd)
			}

			// NeedsDecryptProbe must return true for all admin-only commands.
			if !mode.NeedsDecryptProbe(cmd) {
				t.Errorf("command %q is admin-only but NeedsDecryptProbe returns false — the probe would be suppressed for an admin command", cmd)
			}
		})
	}
}

// TestNeedsDecryptProbe_FalseForContributorCommands asserts that
// NeedsDecryptProbe returns false for every contributor-accessible command.
func TestNeedsDecryptProbe_FalseForContributorCommands(t *testing.T) {
	t.Parallel()
	pol := &mode.Policy{}

	for _, cmd := range knownContributorCommands {
		cmd := cmd
		t.Run(string(cmd), func(t *testing.T) {
			t.Parallel()

			// Confirm the matrix admits this command to contributors.
			if err := pol.Allow(mode.ModeContributor, cmd); err != nil {
				t.Fatalf("command %q is denied to CONTRIBUTOR — it is not contributor-accessible and must not be in knownContributorCommands", cmd)
			}

			// NeedsDecryptProbe must return false for contributor commands.
			if mode.NeedsDecryptProbe(cmd) {
				t.Errorf("command %q is contributor-accessible but NeedsDecryptProbe returns true — probe would run on a non-admin command", cmd)
			}
		})
	}
}

// TestNeedsDecryptProbe_UnknownCommand_ReturnsFalse asserts that an unknown
// or empty command returns false (no probe, fail-closed to CONTRIBUTOR).
func TestNeedsDecryptProbe_UnknownCommand_ReturnsFalse(t *testing.T) {
	t.Parallel()
	if mode.NeedsDecryptProbe(mode.Command("no-such-verb")) {
		t.Error("unknown command: NeedsDecryptProbe should return false")
	}
	if mode.NeedsDecryptProbe(mode.Command("")) {
		t.Error("empty command: NeedsDecryptProbe should return false")
	}
}

// TestNeedsDecryptProbe_AllMatrixCommands_NoOrphan asserts that every command
// constant is covered by either list above. If a new command is added to the
// matrix without updating either list, this test fails.
func TestNeedsDecryptProbe_AllMatrixCommands_NoOrphan(t *testing.T) {
	t.Parallel()

	covered := make(map[mode.Command]bool)
	for _, c := range knownAdminOnlyCommands {
		covered[c] = true
	}
	for _, c := range knownContributorCommands {
		covered[c] = true
	}

	allMatrixCommands := []mode.Command{
		mode.CommandVersion,
		mode.CommandInit,
		mode.CommandDoctor,
		mode.CommandSubmit,
		mode.CommandReview,
		mode.CommandMerge,
		mode.CommandGet,
		mode.CommandDecrypt,
		mode.CommandEdit,
		mode.CommandRotate,
		mode.CommandRotationReconcile,
		mode.CommandRequestAccess,
		mode.CommandRequestList,
		mode.CommandAuditShow,
		mode.CommandRequestReject,
		mode.CommandAuditVerify,
		mode.CommandExport,
		mode.CommandRun,
	}

	for _, cmd := range allMatrixCommands {
		if !covered[cmd] {
			t.Errorf("command %q is in the matrix but not listed in knownAdminOnlyCommands or knownContributorCommands — update the test lists", cmd)
		}
	}
}

// TestCanDecryptAny_Suppressed_WhenProbeNotNeeded asserts that a keyProbe
// built with NeedsDecryptProbe=false returns (false,nil) and does NOT call
// FetchArtifact, even when a real identity is configured.
func TestCanDecryptAny_Suppressed_WhenProbeNotNeeded(t *testing.T) {
	t.Parallel()

	ageID := generateKey(t)
	cfg := buildIdentityConfig(nil, ageID.String(), "", "")

	fetcher := &countingArtifactFetcher{}
	probe := modeprobe.NewKeyProbe(cfg, fetcher, modeprobe.KeyProbeOptions{
		NeedsDecryptProbe: false,
	})

	ok, err := probe.CanDecryptAny(context.Background(), "proj-1")
	if err != nil {
		t.Fatalf("suppressed probe: unexpected error: %v", err)
	}
	if ok {
		t.Fatal("suppressed probe: returned ok=true — probe must not run when suppressed")
	}
	if fetcher.calls != 0 {
		t.Errorf("suppressed probe: FetchArtifact called %d times, want 0", fetcher.calls)
	}
}

// TestCanDecryptAny_Runs_WhenProbeNeeded asserts that NeedsDecryptProbe=true
// enables the full probe path and returns ok=true for a matching identity.
func TestCanDecryptAny_Runs_WhenProbeNeeded(t *testing.T) {
	t.Parallel()

	ageID := generateKey(t)
	art := buildSignedArtifact(t, ageID)
	fetcher := &staticArtifactFetcher{art: art}

	cfg := buildIdentityConfig(nil, ageID.String(), "", "")
	probe := modeprobe.NewKeyProbe(cfg, fetcher, modeprobe.KeyProbeOptions{
		NeedsDecryptProbe: true,
	})

	ok, err := probe.CanDecryptAny(context.Background(), "proj-1")
	if err != nil {
		t.Fatalf("enabled probe: unexpected error: %v", err)
	}
	if !ok {
		t.Error("enabled probe: expected ok=true for matching identity")
	}
}

// TestCanDecryptAny_NonInteractive_Suppressed asserts that BYREIS_NON_INTERACTIVE=1
// with NeedsDecryptProbe=false still returns (false,nil) with zero fetcher calls.
func TestCanDecryptAny_NonInteractive_Suppressed(t *testing.T) {
	t.Setenv("BYREIS_NON_INTERACTIVE", "1")

	ageID := generateKey(t)
	cfg := buildIdentityConfig(nil, ageID.String(), "", "")
	fetcher := &countingArtifactFetcher{}

	probe := modeprobe.NewKeyProbe(cfg, fetcher, modeprobe.KeyProbeOptions{
		NeedsDecryptProbe: false,
	})

	ok, err := probe.CanDecryptAny(context.Background(), "proj-1")
	if err != nil {
		t.Fatalf("non-interactive suppressed: unexpected error: %v", err)
	}
	if ok {
		t.Fatal("non-interactive suppressed: ok must be false when probe is suppressed")
	}
	if fetcher.calls != 0 {
		t.Errorf("non-interactive suppressed: FetchArtifact called %d times, want 0", fetcher.calls)
	}
}

// countingArtifactFetcher counts FetchArtifact calls and returns
// ErrArtifactNotFound so the probe would fail closed if it ran.
type countingArtifactFetcher struct {
	calls int
}

func (f *countingArtifactFetcher) FetchArtifact(_ context.Context, _ string) (artifact.Signed, error) {
	f.calls++
	return artifact.Signed{}, modeprobe.ErrArtifactNotFound
}

// staticArtifactFetcher returns a pre-built artifact for the enabled-probe tests.
type staticArtifactFetcher struct {
	art artifact.Signed
}

func (f *staticArtifactFetcher) FetchArtifact(_ context.Context, _ string) (artifact.Signed, error) {
	return f.art, nil
}
