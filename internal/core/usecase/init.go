package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/ByReisK/byreis/internal/core/config"
)

// Sentinel errors owned by the Init use-case.
var (
	// ErrSignerChanged is returned during init when an existing trust pin has a
	// different signer fingerprint than the one presented by the registry. The
	// operator must manually re-pin; this is never auto-replaced.
	ErrSignerChanged = errors.New(
		"registry signer has changed from the pinned trust anchor — " +
			"the signer key in trust.yaml does not match the registry's current signer; " +
			"if you trust this new signer, run `byreis init --accept-signer <fp>` " +
			"after manually verifying the key")

	// ErrSignerNotAccepted is returned on first init when the operator did not
	// explicitly accept the signer fingerprint (no --accept-signer flag) in
	// non-interactive mode.
	ErrSignerNotAccepted = errors.New(
		"registry signer fingerprint must be explicitly accepted — " +
			"pass --accept-signer <fingerprint> or run interactively to confirm; " +
			"run `byreis init --accept-signer <fingerprint>` with the displayed fingerprint")

	// ErrRegistryVerifyFailed is returned when the registry signature check
	// fails during init. No project config or pin is written on this path.
	ErrRegistryVerifyFailed = errors.New(
		"registry signature verification failed during init — " +
			"no project config was written; " +
			"run `byreis doctor` to diagnose the registry state")
)

// TrustAnchor is the pinned signer key stored in trust.yaml.
type TrustAnchor struct {
	// SignerFingerprint is the hex-encoded fingerprint of the registry
	// commit-signer key that was explicitly accepted at first init.
	SignerFingerprint string `yaml:"signer_fingerprint"`
}

// TrustAnchorStore is the consumer-defined port for reading and writing the
// trust anchor file. The implementation must enforce TOCTOU-safe O_NOFOLLOW +
// fstat-on-fd semantics. Defined in the consumer package (usecase) per the
// Clean Architecture consumer-defined-interface rule.
type TrustAnchorStore interface {
	// ReadAnchor reads the trust anchor from the config directory. It performs
	// the TOCTOU-safe open: open the parent dir with O_NOFOLLOW|O_DIRECTORY,
	// fstat the dir fd (enforce 0700/owner), then openat trust.yaml relative to
	// that fd with O_NOFOLLOW, fstat the file fd (enforce exactly 0600/owner),
	// then read the same fd. An error is returned on any violation.
	ReadAnchor(ctx context.Context) (TrustAnchor, error)

	// WriteAnchor writes the trust anchor to the config directory. The parent
	// directory is created with mode 0700 if absent; the file is written with
	// mode 0600. Writing never touches an existing trust anchor unless the caller
	// has already verified it matches or is performing a manual re-pin.
	WriteAnchor(ctx context.Context, anchor TrustAnchor) error

	// AnchorExists reports whether a trust anchor file is present. This does NOT
	// open or read the file; it is used only to decide whether to prompt for
	// first-init acceptance.
	AnchorExists(ctx context.Context) (bool, error)
}

// SignerProbe is the consumer-defined port for querying the registry signer
// fingerprint without running the full registry fetch. The implementation
// fetches the HEAD commit metadata and returns the signer's fingerprint.
type SignerProbe interface {
	// RegistrySignerFingerprint returns the hex-encoded fingerprint of the
	// current registry HEAD commit signer. Returns an error (which wraps
	// ErrRegistryVerifyFailed) if the HEAD is unsigned or unreachable.
	RegistrySignerFingerprint(ctx context.Context, registryURL string) (string, error)
}

// ConfirmPrompter is the consumer-defined port for explicit operator
// confirmation during the first-init TOFU flow. Core never reads a real TTY;
// the CLI injects the implementation.
type ConfirmPrompter interface {
	// ConfirmSignerFingerprint displays the fingerprint and waits for the
	// operator to type it back or otherwise confirm. Returns nil on confirmation,
	// an error on decline.
	ConfirmSignerFingerprint(ctx context.Context, fingerprint string) error
}

// InitInput carries all inputs for an Init call.
type InitInput struct {
	// RegistryURL is the URL of the admin registry repository.
	RegistryURL string
	// ProjectID is the registry-canonical project identifier.
	ProjectID string
	// AcceptSigner is the explicitly-supplied signer fingerprint from
	// --accept-signer. When non-empty it bypasses the interactive prompt.
	AcceptSigner string
	// NonInteractive is true when BYREIS_NON_INTERACTIVE is set or --non-interactive
	// is passed. In this mode, --accept-signer is required or init fails closed.
	NonInteractive bool
	// ConfigDir is the directory where .byreis.yaml will be written.
	ConfigDir string
}

// InitResult is returned by a successful Init call.
type InitResult struct {
	// ProjectConfigWritten is true when .byreis.yaml was written.
	ProjectConfigWritten bool
	// PinWritten is true when trust.yaml was written (first-init path).
	PinWritten bool
	// SignerFingerprint is the fingerprint that was pinned or that was already
	// pinned and verified to match.
	SignerFingerprint string
}

// InitDeps bundles the injected ports for the Init use-case.
type InitDeps struct {
	TrustStore    TrustAnchorStore
	SignerProbe   SignerProbe
	Prompter      ConfirmPrompter
	ConfigWriter  config.Filesystem
	NetworkRounds *int // optional counter for test assertions; nil in production
}

// Initializer is the consumer-defined interface for the Init use-case.
type Initializer interface {
	// Init bootstraps the project: verifies the registry signer, pins the trust
	// anchor on first use (with explicit confirmation), and writes .byreis.yaml.
	// On signature-verify failure, NOTHING is written (no-side-effect negative).
	Init(ctx context.Context, in InitInput) (InitResult, error)
}

type initUseCase struct {
	d InitDeps
}

// NewInitializer returns an Initializer. All required ports must be non-nil.
func NewInitializer(d InitDeps) (Initializer, error) {
	if d.TrustStore == nil || d.SignerProbe == nil || d.ConfigWriter == nil {
		return nil, errors.New(
			"usecase.NewInitializer: TrustStore, SignerProbe, and ConfigWriter are required — " +
				"wire them before constructing Init")
	}
	// Prompter may be nil only if the caller will always set NonInteractive +
	// AcceptSigner. The use-case validates at call time.
	return &initUseCase{d: d}, nil
}

// Init bootstraps a project. Strict ordering: nothing is written on any failure.
//
//  1. Probe the registry signer fingerprint (network round-trip; counted when
//     NetworkRounds is injected for test assertions).
//  2. On first init (no existing pin): require explicit confirmation via
//     --accept-signer or interactive prompt; --non-interactive without
//     --accept-signer fails closed.
//  3. On subsequent init (existing pin): compare with the probed fingerprint;
//     a mismatch is ErrSignerChanged (manual re-pin required; never auto-replaced).
//  4. Only after the fingerprint check passes: write trust.yaml (0600) and
//     .byreis.yaml. On any prior failure, NO file is written.
func (u *initUseCase) Init(ctx context.Context, in InitInput) (InitResult, error) {
	if err := ctx.Err(); err != nil {
		return InitResult{}, fmt.Errorf("init cancelled: %w", err)
	}

	if in.RegistryURL == "" {
		return InitResult{}, fmt.Errorf(
			"init requires a registry URL — pass --registry <url> or set BYREIS_REGISTRY")
	}
	if in.ProjectID == "" {
		return InitResult{}, fmt.Errorf(
			"init requires a project ID — pass --project <id>")
	}

	// (1) Probe the registry signer. This is the ONLY network operation in the
	// init call graph; the count is bounded to 1.
	if u.d.NetworkRounds != nil {
		*u.d.NetworkRounds++
	}
	fp, err := u.d.SignerProbe.RegistrySignerFingerprint(ctx, in.RegistryURL)
	if err != nil {
		// Registry verification failed: write NOTHING.
		return InitResult{}, fmt.Errorf("%w: %v", ErrRegistryVerifyFailed, err)
	}

	// (2)/(3) Check whether a trust anchor already exists.
	exists, err := u.d.TrustStore.AnchorExists(ctx)
	if err != nil {
		return InitResult{}, fmt.Errorf("checking trust anchor existence failed: %w", err)
	}

	pinWritten := false
	if !exists {
		// First init: require explicit fingerprint acceptance.
		if in.NonInteractive {
			if in.AcceptSigner == "" {
				return InitResult{}, fmt.Errorf(
					"%w: --non-interactive mode requires --accept-signer <fingerprint>",
					ErrSignerNotAccepted)
			}
			if in.AcceptSigner != fp {
				return InitResult{}, fmt.Errorf(
					"%w: --accept-signer %q does not match the registry signer fingerprint %q",
					ErrSignerNotAccepted, in.AcceptSigner, fp)
			}
		} else if in.AcceptSigner != "" {
			// --accept-signer supplied in interactive mode: compare without prompting.
			if in.AcceptSigner != fp {
				return InitResult{}, fmt.Errorf(
					"%w: --accept-signer %q does not match the registry signer fingerprint %q",
					ErrSignerNotAccepted, in.AcceptSigner, fp)
			}
		} else {
			// Interactive first-init: require the prompter.
			if u.d.Prompter == nil {
				return InitResult{}, fmt.Errorf(
					"%w: no prompter available for interactive first-init confirmation",
					ErrSignerNotAccepted)
			}
			if err := u.d.Prompter.ConfirmSignerFingerprint(ctx, fp); err != nil {
				return InitResult{}, fmt.Errorf(
					"%w: operator declined the signer fingerprint confirmation: %v",
					ErrSignerNotAccepted, err)
			}
		}

		// Acceptance confirmed: write the trust anchor (0600, parent 0700).
		if err := u.d.TrustStore.WriteAnchor(ctx, TrustAnchor{SignerFingerprint: fp}); err != nil {
			return InitResult{}, fmt.Errorf("writing trust anchor failed: %w", err)
		}
		pinWritten = true
	} else {
		// Subsequent init: read and compare the existing pin.
		existing, err := u.d.TrustStore.ReadAnchor(ctx)
		if err != nil {
			return InitResult{}, fmt.Errorf("reading existing trust anchor failed: %w", err)
		}
		if existing.SignerFingerprint != fp {
			return InitResult{}, fmt.Errorf(
				"%w: pinned fingerprint %q, registry signer %q",
				ErrSignerChanged, existing.SignerFingerprint, fp)
		}
		// Pin matches: no re-write.
	}

	// (4) Write .byreis.yaml only after the signer chain is settled.
	projectYAML := fmt.Sprintf(
		"registry_url: %q\nproject_id: %q\n",
		in.RegistryURL, in.ProjectID)
	configPath := in.ConfigDir + "/.byreis.yaml"
	if err := u.d.ConfigWriter.WriteFile(ctx, configPath, []byte(projectYAML), 0o600); err != nil {
		return InitResult{}, fmt.Errorf("writing project config failed: %w", err)
	}

	return InitResult{
		ProjectConfigWritten: true,
		PinWritten:           pinWritten,
		SignerFingerprint:    fp,
	}, nil
}

// Compile-time assertion.
var _ Initializer = (*initUseCase)(nil)
