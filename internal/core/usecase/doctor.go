package usecase

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/trust"
)

// DoctorSeverity indicates how serious a finding is.
type DoctorSeverity int

const (
	// SeverityOK means the check passed.
	SeverityOK DoctorSeverity = iota
	// SeverityInfo is informational (no action required).
	SeverityInfo
	// SeverityWarn is an advisory (action recommended but not required).
	SeverityWarn
	// SeverityFail means the check failed and byreis will refuse to run
	// commands that consult this component. Exit code is non-zero when any
	// finding has this severity.
	SeverityFail
)

func (s DoctorSeverity) String() string {
	switch s {
	case SeverityOK:
		return "OK"
	case SeverityInfo:
		return "INFO"
	case SeverityWarn:
		return "WARN"
	case SeverityFail:
		return "FAIL"
	default:
		return "UNKNOWN"
	}
}

// DoctorFinding is one check result from `byreis doctor`.
type DoctorFinding struct {
	// Check is the human-readable name of the check.
	Check string
	// Severity is the result level.
	Severity DoctorSeverity
	// Detail carries the check-specific observation and, for FAIL, the exact
	// chmod/fix hint.
	Detail string
}

// DoctorResult is the aggregate output of a `byreis doctor` run.
type DoctorResult struct {
	// Mode is the cryptographically-derived mode at the time doctor ran.
	Mode mode.Mode
	// ModeReason is a human-readable explanation of why the mode was resolved
	// to its value (key absent/present, perms OK/bad, decrypt yes/no, registry
	// yes/no).
	ModeReason string
	// Findings is the ordered list of check results. The CLI exits non-zero iff
	// any finding has SeverityFail.
	Findings []DoctorFinding
	// OfflineCacheAge is non-zero when the registry is offline and the result
	// was served from cache. An offline registry is reported as an INFO, not a
	// FAIL.
	OfflineCacheAge time.Duration
}

// HasFail reports whether any finding is SeverityFail (drives exit code).
func (r DoctorResult) HasFail() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityFail {
			return true
		}
	}
	return false
}

// RegistryStatusProbe is the consumer-defined port for querying the registry
// state without performing a full admin-set fetch. It reports whether the
// registry HEAD is reachable and signature-verified, and the age of the cached
// data if the registry is offline.
type RegistryStatusProbe interface {
	// RegistryStatus returns a brief status for the doctor report.
	// If the registry is offline (network error), Offline is true and
	// CacheAge is the age of the last cached data. The error field is non-nil
	// only for unexpected failures (not for "offline-but-cache-present").
	RegistryStatus(ctx context.Context, registryURL string) (RegistryStatus, error)
}

// RegistryStatus is the result of RegistryStatusProbe.RegistryStatus.
type RegistryStatus struct {
	// Reachable is true when the registry responded over the network.
	Reachable bool
	// SignatureVerified is true when the registry HEAD commit signature was
	// verified against the trust anchor.
	SignatureVerified bool
	// Offline is true when the registry is not reachable.
	Offline bool
	// CacheAge is the age of the cached data when Offline is true.
	CacheAge time.Duration
	// StaleReason is a human-readable explanation of the stale state.
	StaleReason string
	// BranchProtected is true when the secrets repository has branch
	// protection enabled on the default branch (T6 check).
	BranchProtected bool
	// BranchProtectionDetail carries the check result for the T6 hint.
	BranchProtectionDetail string
}

// DoctorDeps bundles the injected ports for the Doctor use-case.
type DoctorDeps struct {
	// ModeDetector detects the current mode and its reason.
	ModeDetector *mode.Detector
	// ProjectID is the project to check (from .byreis.yaml).
	ProjectID string
	// RegistryURL is the registry URL to check (from .byreis.yaml).
	RegistryURL string
	// ConfigDir is the path to ~/.config/byreis/ (or $BYREIS_CONFIG).
	ConfigDir string
	// TrustFilePath is the path to trust.yaml.
	TrustFilePath string
	// RegistryProbe provides the registry connectivity status.
	RegistryProbe RegistryStatusProbe
}

// Doctor is the consumer-defined interface for the Doctor use-case.
type Doctor interface {
	// Diagnose runs all health checks and returns the aggregate result.
	// The result's HasFail() drives the exit code: non-zero iff any FAIL.
	// Offline registry state is reported as INFO (cache age), not FAIL.
	Diagnose(ctx context.Context) (DoctorResult, error)
}

type doctorUseCase struct {
	d DoctorDeps
}

// NewDoctor returns a Doctor. ModeDetector is required; RegistryProbe may be
// nil when no registry is configured (doctor reports a FAIL for that check).
func NewDoctor(d DoctorDeps) (Doctor, error) {
	if d.ModeDetector == nil {
		return nil, errors.New(
			"usecase.NewDoctor: ModeDetector is required")
	}
	return &doctorUseCase{d: d}, nil
}

// Diagnose runs all byreis health checks. The exit code is driven by HasFail().
//
// Checks performed (in order):
//  1. Config directory (parent dir) permissions: exactly 0700, not a symlink,
//     owned by the invoking user (FAIL with chmod hint). TOCTOU-safe.
//  2. trust.yaml permissions: exactly 0600, not a symlink, regular file, owned
//     by the invoking user (FAIL with chmod hint). TOCTOU-safe.
//  3. Mode detection: reports the resolved mode and its reason. The perms FAIL
//     from check 1/2 is reflected here as well.
//  4. Registry connectivity: offline = INFO (cache age shown), not FAIL.
//     Signature verify failure = FAIL. Branch protection check = INFO/WARN.
func (doc *doctorUseCase) Diagnose(ctx context.Context) (DoctorResult, error) {
	if err := ctx.Err(); err != nil {
		return DoctorResult{}, fmt.Errorf("doctor cancelled: %w", err)
	}

	result := DoctorResult{}
	var findings []DoctorFinding

	// (1) Config directory check (TOCTOU-safe).
	dirFinding := doc.checkConfigDir()
	findings = append(findings, dirFinding)

	// (2) trust.yaml check (TOCTOU-safe).
	trustFinding := doc.checkTrustFile()
	findings = append(findings, trustFinding)

	// (3) Mode detection.
	m, modeReason := doc.detectMode(ctx)
	result.Mode = m
	result.ModeReason = modeReason
	findings = append(findings, DoctorFinding{
		Check:    "mode",
		Severity: SeverityOK,
		Detail:   fmt.Sprintf("resolved mode: %s — %s", m, modeReason),
	})

	// (4) Registry status.
	if doc.d.RegistryProbe != nil && doc.d.RegistryURL != "" {
		rsFindings, cacheAge := doc.checkRegistry(ctx)
		findings = append(findings, rsFindings...)
		result.OfflineCacheAge = cacheAge
	} else {
		findings = append(findings, DoctorFinding{
			Check:    "registry",
			Severity: SeverityInfo,
			Detail:   "no registry URL configured — run `byreis init` to configure",
		})
	}

	result.Findings = findings
	return result, nil
}

// checkConfigDir checks the config directory with TOCTOU-safe O_NOFOLLOW+fstat.
func (doc *doctorUseCase) checkConfigDir() DoctorFinding {
	if doc.d.ConfigDir == "" {
		return DoctorFinding{
			Check:    "config-dir",
			Severity: SeverityFail,
			Detail:   "config directory path not configured — run `byreis init`",
		}
	}

	f, err := trust.CheckTrustDirTOCTOU(doc.d.ConfigDir)
	if err != nil {
		hint := dirCheckHint(err, doc.d.ConfigDir)
		return DoctorFinding{
			Check:    "config-dir",
			Severity: SeverityFail,
			Detail:   hint,
		}
	}
	_ = f.Close()

	return DoctorFinding{
		Check:    "config-dir",
		Severity: SeverityOK,
		Detail:   fmt.Sprintf("config directory %s has correct permissions (0700)", doc.d.ConfigDir),
	}
}

// checkTrustFile checks trust.yaml with TOCTOU-safe O_NOFOLLOW+fstat.
func (doc *doctorUseCase) checkTrustFile() DoctorFinding {
	if doc.d.TrustFilePath == "" {
		return DoctorFinding{
			Check:    "trust-anchor",
			Severity: SeverityFail,
			Detail:   "trust anchor path not configured — run `byreis init`",
		}
	}

	f, err := trust.CheckTrustFileTOCTOU(doc.d.TrustFilePath)
	if err != nil {
		hint := trustFileCheckHint(err, doc.d.TrustFilePath)
		return DoctorFinding{
			Check:    "trust-anchor",
			Severity: SeverityFail,
			Detail:   hint,
		}
	}
	_ = f.Close()

	return DoctorFinding{
		Check:    "trust-anchor",
		Severity: SeverityOK,
		Detail:   fmt.Sprintf("trust anchor %s has correct permissions (0600)", doc.d.TrustFilePath),
	}
}

// detectMode runs mode detection and returns the mode and a human-readable reason.
func (doc *doctorUseCase) detectMode(ctx context.Context) (mode.Mode, string) {
	if doc.d.ModeDetector == nil {
		return mode.ModeContributor, "mode detector not configured"
	}
	r, err := doc.d.ModeDetector.Detect(ctx, doc.d.ProjectID)
	if err != nil {
		if errors.Is(err, mode.ErrKeyPermissions) {
			return mode.ModeContributor, fmt.Sprintf("FAIL: admin key permissions error — %v", err)
		}
		return mode.ModeContributor, fmt.Sprintf("mode detection failed: %v", err)
	}
	switch r.Mode {
	case mode.ModeAdmin, mode.ModeSuper:
		return r.Mode, "admin key present, decrypts project file, and public key is in a verified registry"
	case mode.ModeContributor:
		switch r.Warning {
		case mode.WarningNone:
			return r.Mode, "no admin key or key cannot decrypt — contributor mode"
		case mode.WarningKeyUnregistered:
			return r.Mode, "admin key can decrypt but public key is not in a verified registry — key-unregistered"
		default:
			return r.Mode, "no admin key or key cannot decrypt — contributor mode"
		}
	default:
		return r.Mode, "unknown mode"
	}
}

// checkRegistry checks registry connectivity and branch protection.
func (doc *doctorUseCase) checkRegistry(ctx context.Context) ([]DoctorFinding, time.Duration) {
	var findings []DoctorFinding
	var cacheAge time.Duration

	status, err := doc.d.RegistryProbe.RegistryStatus(ctx, doc.d.RegistryURL)
	if err != nil {
		findings = append(findings, DoctorFinding{
			Check:    "registry",
			Severity: SeverityFail,
			Detail:   fmt.Sprintf("registry check failed: %v — run `byreis doctor` when the registry is reachable", err),
		})
		return findings, 0
	}

	if status.Offline {
		cacheAge = status.CacheAge
		detail := fmt.Sprintf(
			"registry is offline; last cached data is %s old — "+
				"admin operations require network access; contributor operations may proceed",
			formatDuration(cacheAge))
		if status.StaleReason != "" {
			detail += " (" + status.StaleReason + ")"
		}
		findings = append(findings, DoctorFinding{
			Check:    "registry",
			Severity: SeverityInfo,
			Detail:   detail,
		})
	} else if !status.SignatureVerified {
		findings = append(findings, DoctorFinding{
			Check:    "registry",
			Severity: SeverityFail,
			Detail: "registry HEAD commit signature verification failed — " +
				"admin operations are blocked; run `byreis doctor` after verifying the registry signer; " +
				"run: chmod 600 " + doc.d.TrustFilePath + " and re-run if the trust anchor is wrong",
		})
	} else {
		findings = append(findings, DoctorFinding{
			Check:    "registry",
			Severity: SeverityOK,
			Detail:   "registry is reachable and HEAD commit signature verified",
		})
	}

	// Branch protection check (T6).
	if status.BranchProtected {
		findings = append(findings, DoctorFinding{
			Check:    "branch-protection",
			Severity: SeverityOK,
			Detail:   "secrets repository default branch has protection enabled",
		})
	} else {
		detail := "secrets repository branch protection status could not be confirmed — " +
			"enable branch protection on the default branch to prevent force-push of secrets"
		if status.BranchProtectionDetail != "" {
			detail = status.BranchProtectionDetail
		}
		findings = append(findings, DoctorFinding{
			Check:    "branch-protection",
			Severity: SeverityWarn,
			Detail:   detail,
		})
	}

	return findings, cacheAge
}

// dirCheckHint builds the exact chmod hint string from a trust.CheckTrustDirTOCTOU error.
func dirCheckHint(err error, dirPath string) string {
	if errors.Is(err, trust.ErrTrustDirSymlink) {
		return fmt.Sprintf(
			"config directory %s is a symlink — replace with a real directory; "+
				"remove the symlink and run: mkdir -m 700 %s", dirPath, dirPath)
	}
	if errors.Is(err, trust.ErrTrustDirWrongOwner) {
		return fmt.Sprintf(
			"config directory %s is not owned by the current user — "+
				"this is a security risk; investigate ownership before proceeding", dirPath)
	}
	if errors.Is(err, trust.ErrTrustDirPerms) {
		// The error message already contains the exact mode and chmod hint.
		return err.Error()
	}
	// Check for fs.ErrNotExist.
	var pe *os.PathError
	if errors.As(err, &pe) && errors.Is(pe.Err, fs.ErrNotExist) {
		return fmt.Sprintf(
			"config directory %s does not exist — run: mkdir -m 700 %s", dirPath, dirPath)
	}
	return fmt.Sprintf("config directory check failed: %v", err)
}

// trustFileCheckHint builds the exact chmod hint string from a trust.CheckTrustFileTOCTOU error.
func trustFileCheckHint(err error, filePath string) string {
	if errors.Is(err, trust.ErrTrustAnchorSymlink) {
		return fmt.Sprintf(
			"trust anchor %s is a symlink or not a regular file — "+
				"replace with a regular file: rm %s && byreis init", filePath, filePath)
	}
	if errors.Is(err, trust.ErrTrustAnchorWrongOwner) {
		return fmt.Sprintf(
			"trust anchor %s is not owned by the current user — "+
				"this is a security risk; investigate ownership", filePath)
	}
	if errors.Is(err, trust.ErrTrustAnchorPerms) {
		// The error message already contains the exact mode and chmod hint.
		return err.Error()
	}
	var pe *os.PathError
	if errors.As(err, &pe) && errors.Is(pe.Err, fs.ErrNotExist) {
		return fmt.Sprintf(
			"trust anchor %s does not exist — run `byreis init` to create it", filePath)
	}
	return fmt.Sprintf("trust anchor check failed: %v", err)
}

// formatDuration formats a duration for human-readable display.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// Compile-time assertion.
var _ Doctor = (*doctorUseCase)(nil)
