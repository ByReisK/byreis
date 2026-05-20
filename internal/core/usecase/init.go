package usecase

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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

	// ErrTrustAnchorIntegrity is returned when pinned or probed signer material
	// is internally inconsistent: the key is not exactly a 32-byte ed25519
	// public key, or its recomputed sha256 does not equal the accompanying
	// fingerprint. This is a distinct, fail-closed integrity failure — it is
	// neither a signer-rotation (ErrSignerChanged) nor a filesystem-permissions
	// failure. No key in this state may reach the registry client.
	ErrTrustAnchorIntegrity = errors.New(
		"trust anchor integrity check failed — the pinned signer key is " +
			"malformed or does not match its fingerprint; " +
			"the trust.yaml file is corrupt or was tampered with — " +
			"do not proceed; restore a known-good trust.yaml or re-pin via " +
			"`byreis init --accept-signer <fingerprint>` after manual verification")
)

// TrustAnchor is the pinned registry commit-signer material stored in
// trust.yaml. It carries the full Ed25519 public key (the trust root the
// registry client verifies HEAD-commit signatures against) plus the derived
// fingerprint. The fingerprint is sha256(SignerKey) — it is retained purely
// for operator display, typed confirmation, signer-rotation detection, and
// doctor UX; it is never the sole persisted material and is never trusted
// independently of the key (the key comparison is always authoritative).
type TrustAnchor struct {
	// SignerKey is the raw 32-byte Ed25519 public key of the registry commit
	// signer. This is the authoritative pinned material. The on-disk encoding
	// (base64 in the canonical trust.yaml `signers` list) is the store
	// adapter's concern; this field always holds the decoded raw key.
	SignerKey ed25519.PublicKey `yaml:"-"`

	// SignerFingerprint is the hex-encoded sha256 of SignerKey, retained for
	// the explicit-acceptance operator UX and doctor display. On read it is
	// recomputed from SignerKey and the anchor is rejected on any mismatch.
	SignerFingerprint string `yaml:"signer_fingerprint"`
}

// ProbedSigner is the registry commit-signer material surfaced by SignerProbe:
// the raw Ed25519 public key plus the probe's claimed fingerprint. The probe
// implementation derives the fingerprint as sha256(Key); the use-case
// independently re-verifies this binding before any acceptance so a probe that
// surfaces a key whose sha256 disagrees with its claimed fingerprint is
// rejected at the trust boundary.
type ProbedSigner struct {
	// Key is the raw 32-byte Ed25519 public key of the registry commit signer.
	Key ed25519.PublicKey
	// Fingerprint is the probe's claimed hex sha256 of Key.
	Fingerprint string
}

// fingerprintOf returns the canonical hex-encoded sha256 of an Ed25519 public
// key. This is the single derivation used for pinning, display, and the
// integrity recompute so the on-disk and probed fingerprints are comparable.
func fingerprintOf(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

// ValidateTrustAnchor enforces the trust-anchor integrity invariant: the key
// must be exactly an Ed25519 public key (32 bytes) and its recomputed
// sha256 fingerprint must equal the stored fingerprint. It returns the
// validated anchor (with the fingerprint normalised to the recomputed value)
// or ErrTrustAnchorIntegrity. It performs no I/O; the store adapter is
// responsible for the TOCTOU-safe O_NOFOLLOW read and base64 decode before
// calling this. This is the single gate every pinned or probed key passes
// through before it can reach the registry client — empty, short, long,
// non-key, or key/fingerprint-mismatched material all fail closed here.
func ValidateTrustAnchor(a TrustAnchor) (TrustAnchor, error) {
	if len(a.SignerKey) != ed25519.PublicKeySize {
		return TrustAnchor{}, fmt.Errorf(
			"%w: signer key is %d bytes, expected exactly %d",
			ErrTrustAnchorIntegrity, len(a.SignerKey), ed25519.PublicKeySize)
	}
	computed := fingerprintOf(a.SignerKey)
	if computed != a.SignerFingerprint {
		return TrustAnchor{}, fmt.Errorf(
			"%w: stored fingerprint does not match sha256(key)",
			ErrTrustAnchorIntegrity)
	}
	return TrustAnchor{SignerKey: a.SignerKey, SignerFingerprint: computed}, nil
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

// SignerProbe is the consumer-defined port for querying the registry commit
// signer without running the full registry fetch. The implementation fetches
// the HEAD commit metadata and returns the signer's raw Ed25519 public key
// together with its derived fingerprint, so first-init can pin the full key
// (the registry client verifies signatures against the key, not a fingerprint)
// while the operator still confirms via the human-readable fingerprint.
type SignerProbe interface {
	// RegistrySigner returns the current registry HEAD commit signer's raw
	// Ed25519 public key and its hex-encoded sha256 fingerprint. Returns an
	// error (which wraps ErrRegistryVerifyFailed) if the HEAD is unsigned or
	// unreachable. The use-case independently re-derives sha256(Key) and
	// rejects the probe if it disagrees with the returned Fingerprint.
	RegistrySigner(ctx context.Context, registryURL string) (ProbedSigner, error)
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
//  1. Probe the registry signer (network round-trip; counted when
//     NetworkRounds is injected for test assertions). The probed key↔fingerprint
//     binding is independently re-verified at the trust boundary; a probe whose
//     sha256(key) disagrees with its claimed fingerprint is rejected with
//     ErrTrustAnchorIntegrity and nothing is written.
//  2. On first init (no existing pin): require explicit confirmation via
//     --accept-signer or interactive prompt; --non-interactive without
//     --accept-signer fails closed. The FULL probed key is then pinned with the
//     derived fingerprint.
//  3. On subsequent init (existing pin): re-validate the stored pin's own
//     key↔fingerprint integrity, then compare the pinned KEY (authoritative —
//     a colliding fingerprint must not pass) with the probed key; a mismatch is
//     ErrSignerChanged (manual re-pin required; never auto-replaced).
//  4. Only after the signer chain is settled: write trust.yaml (0600) and
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
	probed, err := u.d.SignerProbe.RegistrySigner(ctx, in.RegistryURL)
	if err != nil {
		// Registry verification failed: write NOTHING.
		return InitResult{}, fmt.Errorf("%w: %v", ErrRegistryVerifyFailed, err)
	}

	// Re-verify the probe's key↔fingerprint binding at the trust boundary: a
	// probe surfacing a key whose sha256 disagrees with its claimed
	// fingerprint (or a non-32-byte key) is rejected before any acceptance,
	// pin, or registry use. The recomputed fingerprint is authoritative
	// thereafter.
	probedAnchor, err := ValidateTrustAnchor(TrustAnchor{
		SignerKey:         probed.Key,
		SignerFingerprint: probed.Fingerprint,
	})
	if err != nil {
		return InitResult{}, err
	}
	fp := probedAnchor.SignerFingerprint

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
			// Interactive first-init: require the prompter. The operator is
			// shown the human fingerprint, never the raw key blob.
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

		// Acceptance confirmed: pin the FULL key plus the derived fingerprint
		// (0600, parent 0700).
		if err := u.d.TrustStore.WriteAnchor(ctx, TrustAnchor{
			SignerKey:         probedAnchor.SignerKey,
			SignerFingerprint: fp,
		}); err != nil {
			return InitResult{}, fmt.Errorf("writing trust anchor failed: %w", err)
		}
		pinWritten = true
	} else {
		// Subsequent init: read the existing pin. A store-side TOCTOU/perms
		// failure propagates as a refuse-to-run error — never downgraded.
		existing, err := u.d.TrustStore.ReadAnchor(ctx)
		if err != nil {
			return InitResult{}, fmt.Errorf("reading existing trust anchor failed: %w", err)
		}
		// The stored pin must itself be internally consistent: a tampered
		// on-disk key↔fingerprint pair fails closed before any comparison so a
		// corrupt pin is never silently trusted or auto-rewritten.
		validated, err := ValidateTrustAnchor(existing)
		if err != nil {
			return InitResult{}, err
		}
		// Key comparison is authoritative: a colliding fingerprint with a
		// different key must NOT pass. A different key is a signer rotation
		// requiring an explicit manual re-pin; it is never auto-replaced.
		if !validated.SignerKey.Equal(probedAnchor.SignerKey) {
			return InitResult{}, fmt.Errorf(
				"%w: pinned fingerprint %q, registry signer %q",
				ErrSignerChanged, validated.SignerFingerprint, fp)
		}
		// Pinned key matches: no re-write.
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
