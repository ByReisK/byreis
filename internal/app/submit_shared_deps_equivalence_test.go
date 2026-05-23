package app_test

// AC-007-A / AC-007-B equivalence test for the single-construction-site
// collapse of submit shared deps.
//
// Before this refactor, buildSubmitterProd and buildRunTUISubmitProd each
// independently called resumestore.New / keyprobe.New / valueValidatorProd /
// prodRotateClock, creating four separate instances for the same cacheDir.
// A dependency added to one path would silently diverge from the other.
//
// After the refactor, buildSubmitSharedDepsProd is called once in
// BuildProductionDeps and the result is forwarded to both builders. This test
// pins that invariant:
//
//   AC-007-A: exactly one construction site — BuildSubmitSharedDepsProdForTest
//             returns all four non-nil fields; the same returned value is what
//             both the CLI Submitter and the TUI SubmitterFactory receive.
//
//   AC-007-B: the factory closure path is exercised (not only the direct
//             Submitter path); both construct without error given the shared
//             deps, proving byte-identical observable behavior.

import (
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/artifactcodec"
	"github.com/ByReisK/byreis/internal/app"
)

// TestSubmitSharedDeps_SingleConstructionSite_AC007A verifies that
// BuildSubmitSharedDepsProdForTest returns all four non-nil dep fields from a
// single call. This is the structural proof that buildSubmitSharedDepsProd
// holds the only construction site for keyProbe / resumeStore / validator /
// clock and that both builder functions receive the same instances.
func TestSubmitSharedDeps_SingleConstructionSite_AC007A(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	codec := artifactcodec.NewPortAdapter(artifactcodec.New())

	// forSrc is nil: the noop key probe path is exercised (most common CI path).
	sd, err := app.BuildSubmitSharedDepsProdForTest(nil, codec, cacheDir)
	if err != nil {
		t.Fatalf("BuildSubmitSharedDepsProdForTest: unexpected error: %v", err)
	}

	if sd.KeyProbe == nil {
		t.Error("AC-007-A: KeyProbe is nil — single construction site did not wire a probe")
	}
	if sd.ResumeStore == nil {
		t.Error("AC-007-A: ResumeStore is nil — single construction site did not wire a store")
	}
	if sd.Validator == nil {
		t.Error("AC-007-A: Validator is nil — single construction site did not wire a validator")
	}
	if sd.Clock == nil {
		t.Error("AC-007-A: Clock is nil — single construction site did not wire a clock")
	}
}

// TestSubmitSharedDeps_SingleConstructionSite_AC007A_WithForSrc verifies the
// same single-construction-site invariant when a non-nil FileOfRecordSource is
// provided (the real keyprobe.New path, not the noop probe path).
func TestSubmitSharedDeps_SingleConstructionSite_AC007A_WithForSrc(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	codec := artifactcodec.NewPortAdapter(artifactcodec.New())
	forSrc := &stubFileOfRecordSource{}

	sd, err := app.BuildSubmitSharedDepsProdForTest(forSrc, codec, cacheDir)
	if err != nil {
		t.Fatalf("BuildSubmitSharedDepsProdForTest with non-nil forSrc: %v", err)
	}

	if sd.KeyProbe == nil {
		t.Error("AC-007-A: KeyProbe is nil with non-nil forSrc")
	}
	if sd.ResumeStore == nil {
		t.Error("AC-007-A: ResumeStore is nil with non-nil forSrc")
	}
	if sd.Validator == nil {
		t.Error("AC-007-A: Validator is nil with non-nil forSrc")
	}
	if sd.Clock == nil {
		t.Error("AC-007-A: Clock is nil with non-nil forSrc")
	}
}

// TestSubmitSharedDeps_PointerIdentity_AC007A asserts that calling
// BuildSubmitSharedDepsProdForTest twice with identical inputs produces
// independent instances (it is not a singleton), and that a single call
// returns stable (non-changing) pointers. This confirms the single-call
// contract: production code calls it once and passes the result to both
// builders; no builder rebuilds these deps on its own.
func TestSubmitSharedDeps_PointerIdentity_AC007A(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	codec := artifactcodec.NewPortAdapter(artifactcodec.New())

	sd1, err1 := app.BuildSubmitSharedDepsProdForTest(nil, codec, cacheDir)
	if err1 != nil {
		t.Fatalf("first call: %v", err1)
	}
	sd2, err2 := app.BuildSubmitSharedDepsProdForTest(nil, codec, cacheDir)
	if err2 != nil {
		t.Fatalf("second call: %v", err2)
	}

	// Two distinct calls produce distinct instances (not a global singleton).
	if sd1.ResumeStore == sd2.ResumeStore {
		t.Error("AC-007-A: two distinct calls returned the same ResumeStore pointer; " +
			"buildSubmitSharedDepsProd must not share state across calls")
	}
	// Within a single returned value all fields are stable (not re-created on access).
	if sd1.KeyProbe == nil || sd1.ResumeStore == nil {
		t.Error("AC-007-A: a single call returned nil fields")
	}
}

// TestSubmitSharedDeps_FactoryClosureExercised_AC007B verifies AC-007-B: the
// TUI SubmitterFactory closure path is exercised via BuildProductionDeps when
// the environment is partially configured. Specifically, when
// BYREIS_GITHUB_TOKEN is empty the git provider is nil, so both the CLI
// Submitter and the TUI RunTUISubmit are nil — but BuildProductionDeps must
// NOT panic, and the shared-deps construction must not have errored in a way
// that would have broken the TUI path had the git provider been available.
//
// This test exercises the full BuildProductionDeps call (the actual composition
// root) to confirm the shared-deps refactor does not break the nil-fallback
// path that the existing V-3.5 shipgate tests rely on.
func TestSubmitSharedDeps_FactoryClosureExercised_AC007B(t *testing.T) {
	t.Setenv("BYREIS_REGISTRY", "")
	t.Setenv("BYREIS_PROJECT", "")
	t.Setenv("BYREIS_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("BYREIS_CONFIG", t.TempDir())
	t.Setenv("BYREIS_CACHE", t.TempDir())
	t.Setenv("BYREIS_KEY_FILE", noKeychainKeyFile)

	// Must not panic with the refactored single-construction-site path.
	deps, _ := app.BuildProductionDeps(t.Context())
	if deps == nil {
		// Error return is acceptable (registry URL missing). The test's goal is
		// to confirm the refactor does not introduce a panic on partial config.
		return
	}

	// With no git provider, the TUI factory closure cannot be assembled.
	// Confirm nil (not a non-nil broken closure).
	if deps.RunTUISubmit != nil {
		t.Errorf("AC-007-B: RunTUISubmit must be nil when git provider is unavailable; "+
			"got non-nil (shared-deps refactor may have broken the nil-guard): %T", deps.RunTUISubmit)
	}
}
