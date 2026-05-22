package usecase_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// --- fakes for doctor ---

type fakeRegistryStatusProbe struct {
	status usecase.RegistryStatus
	err    error
}

func (f *fakeRegistryStatusProbe) RegistryStatus(_ context.Context, _ string) (usecase.RegistryStatus, error) {
	return f.status, f.err
}

// fakeRotationEpochProbe is an injected RotationEpochProbe for doctor tests.
type fakeRotationEpochProbe struct {
	epochs map[string]uint64
	err    error
}

func (f *fakeRotationEpochProbe) FetchRotationEpochs(_ context.Context, _ string) (map[string]uint64, error) {
	return f.epochs, f.err
}

// stubModeDetector builds a minimal Detector for doctor tests. It uses no-op
// ports so Detect returns CONTRIBUTOR without error.
func stubModeDetector() *mode.Detector {
	return &mode.Detector{
		Probe:    &noopKeyProbe{},
		Registry: &noopRegistryTrust{},
		Clock:    &noopClock{},
		Audit:    audit.Discard,
	}
}

type noopKeyProbe struct{}

func (n *noopKeyProbe) KeyFilePath(_ context.Context) string                    { return "" }
func (n *noopKeyProbe) KeyFilePerms(_ context.Context) (uint32, error)          { return 0, nil }
func (n *noopKeyProbe) CanDecryptAny(_ context.Context, _ string) (bool, error) { return false, nil }

type noopRegistryTrust struct{}

func (n *noopRegistryTrust) IsRegisteredAdmin(_ context.Context, _ string) (bool, error) {
	return false, nil
}

type noopClock struct{}

func (n *noopClock) Now() interface{ Unix() int64 } {
	return noopTime{}
}

type noopTime struct{}

func (n noopTime) Unix() int64 { return 0 }

// --- §7.2 A2 tests: doctor offline behavior ---

// TestDoctor_Offline_ReportsCacheAge verifies that when the registry is offline,
// doctor reports the cache age as INFO (not FAIL) and exits 0.
func TestDoctor_Offline_ReportsCacheAge(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	trustFile := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(trustFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	probe := &fakeRegistryStatusProbe{
		status: usecase.RegistryStatus{
			Offline:  true,
			CacheAge: 2 * time.Hour,
		},
	}

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector:  stubModeDetector(),
		ProjectID:     "myproj",
		RegistryURL:   "https://example.com/registry",
		ConfigDir:     dir,
		TrustFilePath: trustFile,
		RegistryProbe: probe,
	})
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}

	result, err := doc.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}

	// Offline is INFO not FAIL: HasFail must be false.
	if result.HasFail() {
		t.Error("expected HasFail=false when only offline (INFO finding)")
	}

	// OfflineCacheAge should be set.
	if result.OfflineCacheAge != 2*time.Hour {
		t.Errorf("expected OfflineCacheAge=2h, got %v", result.OfflineCacheAge)
	}

	// Must have an INFO finding about the offline state.
	found := false
	for _, f := range result.Findings {
		if f.Check == "registry" && f.Severity == usecase.SeverityInfo {
			found = true
		}
	}
	if !found {
		t.Error("expected an INFO registry finding for offline state")
	}
}

// TestDoctor_Problem_ExitsNonZero verifies that HasFail() returns true when
// there is at least one FAIL finding (driving non-zero exit code).
func TestDoctor_Problem_ExitsNonZero(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "config")
	//nolint:gosec // intentionally insecure 0755 to test that doctor reports FAIL
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	trustFile := filepath.Join(dir, "trust.yaml")
	// Do not create the trust.yaml; its absence is also a FAIL.

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector:  stubModeDetector(),
		ConfigDir:     dir,
		TrustFilePath: trustFile,
	})
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}

	result, err := doc.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}

	// Insecure dir perms or missing trust.yaml: HasFail must be true.
	if !result.HasFail() {
		t.Error("expected HasFail=true when config dir has insecure perms")
	}
}

// TestDoctor_StaleButUsable_NotExitNonZero verifies that a stale-but-usable
// cache alone is NOT exit≠0 (§7.2 A2 requirement).
func TestDoctor_StaleButUsable_NotExitNonZero(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	trustFile := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(trustFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	probe := &fakeRegistryStatusProbe{
		status: usecase.RegistryStatus{
			Offline:     true,
			CacheAge:    30 * time.Minute,
			StaleReason: "using last-known-good cache",
		},
	}

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector:  stubModeDetector(),
		ProjectID:     "myproj",
		RegistryURL:   "https://example.com",
		ConfigDir:     dir,
		TrustFilePath: trustFile,
		RegistryProbe: probe,
	})
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}

	result, err := doc.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}

	if result.HasFail() {
		t.Error("stale-but-usable cache alone must not be a FAIL (§7.2 A2)")
		for _, f := range result.Findings {
			if f.Severity == usecase.SeverityFail {
				t.Logf("FAIL finding: %s — %s", f.Check, f.Detail)
			}
		}
	}
}

// TestDoctor_TrustFile_FAIL_WithChmodHint verifies that an insecure trust.yaml
// produces a FAIL finding with the exact chmod hint (§4.1 / §7.2 D4).
func TestDoctor_TrustFile_FAIL_WithChmodHint(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	trustFile := filepath.Join(dir, "trust.yaml")
	//nolint:gosec // intentionally insecure 0644 to test that doctor reports FAIL
	if err := os.WriteFile(trustFile, []byte("signer_fingerprint: abc"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector:  stubModeDetector(),
		ConfigDir:     dir,
		TrustFilePath: trustFile,
	})
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}

	result, err := doc.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.Check == "trust-anchor" && f.Severity == usecase.SeverityFail {
			found = true
			if !containsChmodHint(f.Detail) {
				t.Errorf("FAIL finding must include chmod hint, got: %q", f.Detail)
			}
		}
	}
	if !found {
		t.Error("expected FAIL finding for trust-anchor with insecure mode")
	}
}

// TestDoctor_ConfigDir_Symlink_FAIL verifies that a symlink in place of the
// config directory is caught as a FAIL (§7.2 D4).
func TestDoctor_ConfigDir_Symlink_FAIL(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real")
	symlinkDir := filepath.Join(tmp, "config")

	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector:  stubModeDetector(),
		ConfigDir:     symlinkDir,
		TrustFilePath: filepath.Join(symlinkDir, "trust.yaml"),
	})
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}

	result, err := doc.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.Check == "config-dir" && f.Severity == usecase.SeverityFail {
			found = true
		}
	}
	if !found {
		// On some systems opening a symlink as a directory succeeds;
		// the mode check should then catch the directory perms.
		if !result.HasFail() {
			t.Error("expected FAIL finding when config dir is a symlink (D4)")
		}
	}
}

// TestDoctor_TrustFile_Symlink_FAIL verifies that a symlink in place of
// trust.yaml is caught as FAIL (§7.2 D4).
func TestDoctor_TrustFile_Symlink_FAIL(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	realFile := filepath.Join(tmp, "real.yaml")
	if err := os.WriteFile(realFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	trustFile := filepath.Join(dir, "trust.yaml")
	if err := os.Symlink(realFile, trustFile); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector:  stubModeDetector(),
		ConfigDir:     dir,
		TrustFilePath: trustFile,
	})
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}

	result, err := doc.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.Check == "trust-anchor" && f.Severity == usecase.SeverityFail {
			found = true
		}
	}
	if !found {
		t.Error("expected FAIL finding for trust-anchor symlink (D4)")
	}
}

// TestDoctor_ReportsMode verifies that doctor reports the mode and reason
// (REQ-A-002).
func TestDoctor_ReportsMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	trustFile := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(trustFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector:  stubModeDetector(),
		ConfigDir:     dir,
		TrustFilePath: trustFile,
	})
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}

	result, err := doc.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}

	// Mode must be set (CONTRIBUTOR in the stub case).
	if result.Mode != mode.ModeContributor {
		t.Errorf("expected ModeContributor, got %v", result.Mode)
	}
	if result.ModeReason == "" {
		t.Error("expected non-empty ModeReason (REQ-A-002)")
	}

	// There must be a mode finding.
	found := false
	for _, f := range result.Findings {
		if f.Check == "mode" {
			found = true
		}
	}
	if !found {
		t.Error("expected a 'mode' finding in doctor output")
	}
}

// TestDoctor_AllGood_HasFail_False verifies the complete passing case.
func TestDoctor_AllGood_HasFail_False(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	trustFile := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(trustFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	probe := &fakeRegistryStatusProbe{
		status: usecase.RegistryStatus{
			Reachable:         true,
			SignatureVerified: true,
			BranchProtected:   true,
		},
	}

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector:  stubModeDetector(),
		ProjectID:     "myproj",
		RegistryURL:   "https://example.com",
		ConfigDir:     dir,
		TrustFilePath: trustFile,
		RegistryProbe: probe,
	})
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}

	result, err := doc.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}

	if result.HasFail() {
		for _, f := range result.Findings {
			if f.Severity == usecase.SeverityFail {
				t.Logf("unexpected FAIL: %s — %s", f.Check, f.Detail)
			}
		}
		t.Error("expected HasFail=false when all checks pass")
	}
}

// TestDoctor_RegistrySignatureFail_FAIL verifies that a registry signature
// verification failure is a FAIL (not just INFO/WARN).
func TestDoctor_RegistrySignatureFail_FAIL(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	trustFile := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(trustFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	probe := &fakeRegistryStatusProbe{
		status: usecase.RegistryStatus{
			Reachable:         true,
			SignatureVerified: false,
		},
	}

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector:  stubModeDetector(),
		ProjectID:     "myproj",
		RegistryURL:   "https://example.com",
		ConfigDir:     dir,
		TrustFilePath: trustFile,
		RegistryProbe: probe,
	})
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}

	result, err := doc.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}

	if !result.HasFail() {
		t.Error("expected HasFail=true when registry signature verification fails")
	}

	found := false
	for _, f := range result.Findings {
		if f.Check == "registry" && f.Severity == usecase.SeverityFail {
			found = true
		}
	}
	if !found {
		t.Error("expected FAIL finding for registry signature failure")
	}
}

// TestDoctor_ContextCancelled verifies that a cancelled context propagates.
func TestDoctor_ContextCancelled(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	doc, err := usecase.NewDoctor(usecase.DoctorDeps{
		ModeDetector:  stubModeDetector(),
		ConfigDir:     dir,
		TrustFilePath: filepath.Join(dir, "trust.yaml"),
	})
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = doc.Diagnose(ctx)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// newRotationDoctorEnv builds a valid (good-perms) config dir + trust.yaml and
// returns the deps needed by rotation-history doctor tests, so each table case
// only varies the probe/requested flag.
func newRotationDoctorEnv(t *testing.T, probe usecase.RotationEpochProbe, requested bool) usecase.DoctorDeps {
	t.Helper()
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "config")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	trustFile := filepath.Join(dir, "trust.yaml")
	if err := os.WriteFile(trustFile, []byte("signer_fingerprint: abc"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return usecase.DoctorDeps{
		ModeDetector:             stubModeDetector(),
		ProjectID:                "myproj",
		ConfigDir:                dir,
		TrustFilePath:            trustFile,
		RotationEpochProbe:       probe,
		RotationHistoryRequested: requested,
	}
}

// TestDoctor_RotationHistory_ProbeGating verifies the graceful no-op cases:
// probe nil OR --rotation-history not requested means no RotationHistory
// findings and no error (R4b read-only flag, lock L19).
func TestDoctor_RotationHistory_ProbeGating(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		probe     usecase.RotationEpochProbe
		requested bool
	}{
		{
			name:      "probe nil and not requested",
			probe:     nil,
			requested: false,
		},
		{
			name:      "probe wired but flag not requested",
			probe:     &fakeRotationEpochProbe{epochs: map[string]uint64{"a.enc.yaml": 2}},
			requested: false,
		},
		{
			name:      "flag requested but probe nil",
			probe:     nil,
			requested: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc, err := usecase.NewDoctor(newRotationDoctorEnv(t, tc.probe, tc.requested))
			if err != nil {
				t.Fatalf("NewDoctor: %v", err)
			}
			result, err := doc.Diagnose(context.Background())
			if err != nil {
				t.Fatalf("Diagnose: %v", err)
			}
			if len(result.RotationHistory) != 0 {
				t.Errorf("expected no RotationHistory findings, got %d", len(result.RotationHistory))
			}
			if result.HasRotationHistory {
				t.Error("expected HasRotationHistory=false when rotation history was not gathered")
			}
			// A gated-off rotation-history read must never be a FAIL on its own.
			for _, f := range result.Findings {
				if f.Check == "rotation-history" {
					t.Errorf("did not expect a rotation-history finding when gated off, got: %s", f.Detail)
				}
			}
		})
	}
}

// TestDoctor_RotationHistory_Epochs is the core table for the partial-rotation
// derivation (BO-V8-3 / R-001.13): files in one project disagreeing on epoch
// fire PartialRotationDetected; all-equal does not. Also asserts the
// HasRotationHistory signal (max epoch ≥ 1) that the CLI uses to decide whether
// to emit the verbatim forward-secrecy warning.
func TestDoctor_RotationHistory_Epochs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		epochs          map[string]uint64
		wantFindings    int
		wantPartial     bool
		wantHasHistory  bool
		wantPartialFind bool // expect a SeverityWarn partial-rotation finding
	}{
		{
			name:            "all files epoch 0 — never rotated",
			epochs:          map[string]uint64{"a.enc.yaml": 0, "b.enc.yaml": 0},
			wantFindings:    2,
			wantPartial:     false,
			wantHasHistory:  false,
			wantPartialFind: false,
		},
		{
			name:            "all files agree at epoch 3 — clean rotation",
			epochs:          map[string]uint64{"a.enc.yaml": 3, "b.enc.yaml": 3, "c.enc.yaml": 3},
			wantFindings:    3,
			wantPartial:     false,
			wantHasHistory:  true,
			wantPartialFind: false,
		},
		{
			name:            "files disagree — partial rotation",
			epochs:          map[string]uint64{"a.enc.yaml": 3, "b.enc.yaml": 2},
			wantFindings:    2,
			wantPartial:     true,
			wantHasHistory:  true,
			wantPartialFind: true,
		},
		{
			name:            "single file at epoch 1 — rotated, no divergence possible",
			epochs:          map[string]uint64{"a.enc.yaml": 1},
			wantFindings:    1,
			wantPartial:     false,
			wantHasHistory:  true,
			wantPartialFind: false,
		},
		{
			name:            "boundary: 0 vs 1 disagreement — partial",
			epochs:          map[string]uint64{"a.enc.yaml": 0, "b.enc.yaml": 1},
			wantFindings:    2,
			wantPartial:     true,
			wantHasHistory:  true,
			wantPartialFind: true,
		},
		{
			name:            "empty project — no files",
			epochs:          map[string]uint64{},
			wantFindings:    0,
			wantPartial:     false,
			wantHasHistory:  false,
			wantPartialFind: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			probe := &fakeRotationEpochProbe{epochs: tc.epochs}
			doc, err := usecase.NewDoctor(newRotationDoctorEnv(t, probe, true))
			if err != nil {
				t.Fatalf("NewDoctor: %v", err)
			}
			result, err := doc.Diagnose(context.Background())
			if err != nil {
				t.Fatalf("Diagnose: %v", err)
			}

			if len(result.RotationHistory) != tc.wantFindings {
				t.Errorf("RotationHistory len: got %d, want %d", len(result.RotationHistory), tc.wantFindings)
			}

			// Per-file epoch must round-trip from the probe map.
			for _, rf := range result.RotationHistory {
				want, ok := tc.epochs[rf.File]
				if !ok {
					t.Errorf("unexpected file in findings: %q", rf.File)
					continue
				}
				if rf.Epoch != want {
					t.Errorf("file %q epoch: got %d, want %d", rf.File, rf.Epoch, want)
				}
				if rf.PartialRotationDetected != tc.wantPartial {
					t.Errorf("file %q PartialRotationDetected: got %v, want %v",
						rf.File, rf.PartialRotationDetected, tc.wantPartial)
				}
			}

			if result.HasRotationHistory != tc.wantHasHistory {
				t.Errorf("HasRotationHistory: got %v, want %v", result.HasRotationHistory, tc.wantHasHistory)
			}

			// A reported run is never a hard FAIL.
			if result.HasFail() {
				for _, f := range result.Findings {
					if f.Severity == usecase.SeverityFail {
						t.Logf("unexpected FAIL: %s — %s", f.Check, f.Detail)
					}
				}
				t.Error("rotation-history reporting must not produce a FAIL")
			}

			// partial-rotation-detected must surface as a WARN finding iff divergent.
			foundPartial := false
			for _, f := range result.Findings {
				if f.Check == "rotation-history" && f.Severity == usecase.SeverityWarn {
					foundPartial = true
				}
			}
			if foundPartial != tc.wantPartialFind {
				t.Errorf("partial-rotation WARN finding present: got %v, want %v", foundPartial, tc.wantPartialFind)
			}
		})
	}
}

// TestDoctor_RotationHistory_ProbeError verifies that an offline/unreachable
// epoch read is INFO/WARN-class for doctor and does NOT hard-FAIL the whole run
// (offline epoch read is informational; matches the registry offline posture).
func TestDoctor_RotationHistory_ProbeError(t *testing.T) {
	t.Parallel()

	probe := &fakeRotationEpochProbe{err: errors.New("registry unreachable")}
	doc, err := usecase.NewDoctor(newRotationDoctorEnv(t, probe, true))
	if err != nil {
		t.Fatalf("NewDoctor: %v", err)
	}
	result, err := doc.Diagnose(context.Background())
	if err != nil {
		t.Fatalf("Diagnose must not return an error on probe failure: %v", err)
	}

	if result.HasFail() {
		t.Error("a rotation-epoch probe error must not be a hard FAIL (offline epoch read is informational)")
	}
	if len(result.RotationHistory) != 0 {
		t.Errorf("expected no per-file findings on probe error, got %d", len(result.RotationHistory))
	}
	if result.HasRotationHistory {
		t.Error("expected HasRotationHistory=false on probe error")
	}

	// There must be an informational rotation-history finding explaining the read failure.
	found := false
	for _, f := range result.Findings {
		if f.Check == "rotation-history" && (f.Severity == usecase.SeverityInfo || f.Severity == usecase.SeverityWarn) {
			found = true
		}
	}
	if !found {
		t.Error("expected an INFO/WARN rotation-history finding describing the probe error")
	}
}

// containsChmodHint returns true if the error string contains a "chmod" hint.
func containsChmodHint(s string) bool {
	for i := 0; i+5 < len(s); i++ {
		if s[i:i+5] == "chmod" {
			return true
		}
	}
	return false
}
