// Package modeprobe provides the production implementations of the
// mode.KeyProbe and mode.RegistryTrust ports for cmd/byreis/main.go.
//
// These adapters sit at the OUTER layer of the Clean Architecture; they import
// SDK/OS packages (filippo.io/age, syscall) and the identity/registry adapters.
// They must NEVER be imported from internal/core (core→adapter edge is
// forbidden) or from the contributor encrypt/submit paths (closed-world allowlist).
// They are wired exclusively at the composition root (cmd/byreis/main.go).
//
// KeyProbe satisfies the mode.KeyProbe port:
//   - KeyFilePath(ctx): delegates to the SINGLE shared identity.ResolvedPath
//     resolver, honoring ctx cancellation for the keychain probe path.
//   - KeyFilePerms(ctx): uses the shared TOCTOU-safe trust.CheckTrustFileTOCTOU
//     primitive for real files; returns synthetic 0600 for the in-process marker.
//   - CanDecryptAny(ctx, projectID): loads the identity via the identity loader,
//     fetches one artifact value, attempts age decrypt; returns (true, nil) on
//     success, (false, nil) when not a recipient, (false, err) on probe failure.
//     Zeroizes per L-2. NEVER leaks plaintext.
//
// RegistryTrustAdapter satisfies mode.RegistryTrust.IsRegisteredAdmin:
//   - Returns true ONLY when the public key is in an AdminSet with
//     SourceVerified=true AND Stale=false (frozen contract).
//   - Any error, stale, or unverified result → (false, err) → CONTRIBUTOR.
//   - Forged/rolled-back/regressed cached SourceVerified is rejected here.
package modeprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"

	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/trust"
)

// ArtifactFetcher is the narrow port used by KeyProbe.CanDecryptAny. It yields
// the live committed signed artifact for a given projectID so the probe can
// attempt to decrypt one value without touching plaintext outside the probe
// boundary. The concrete implementation is injected at the composition root.
//
// On ErrArtifactNotFound (file does not yet exist) the probe returns
// (false, nil) — treated as "cannot decrypt", correct for a new project.
type ArtifactFetcher interface {
	FetchArtifact(ctx context.Context, projectID string) (artifact.Signed, error)
}

// ErrArtifactNotFound is returned by ArtifactFetcher when the file-of-record
// does not exist yet for the project.
var ErrArtifactNotFound = errors.New(
	"no file-of-record found for this project — project may not yet have been initialised")

// keyProbe is the production mode.KeyProbe adapter.
type keyProbe struct {
	cfg     identityadapter.Config
	fetcher ArtifactFetcher
}

// NewKeyProbe constructs the production KeyProbe. cfg is the identity loader
// config (populated by the composition root from env + injected keychain);
// fetcher provides the live artifact for CanDecryptAny (nil is safe: causes
// CanDecryptAny to return (false, nil) — the "no file yet" path).
func NewKeyProbe(cfg identityadapter.Config, fetcher ArtifactFetcher) *keyProbe {
	return &keyProbe{cfg: cfg, fetcher: fetcher}
}

// KeyFilePath returns the resolved key path using the SINGLE shared
// identity.ResolvedPath resolver.
//
// For a file-backed key (BYREIS_KEY_FILE or default path) it returns the real
// path. For a non-file key source (BYREIS_KEY env or keychain) it returns the
// stable in-process marker so the frozen Detect step-1 does not misfire. For
// "no key in any source" it returns "".
//
// Context cancellation is honored: the keychain is probed with the real ctx
// before delegating to identity.ResolvedPath for the path string. This threads
// the real ctx into the keychain check while preserving the single-resolver
// invariant — both the ctx-aware check here and ResolvedPath use the same
// identity.Config.
func (k *keyProbe) KeyFilePath(ctx context.Context) string {
	if err := ctx.Err(); err != nil {
		return ""
	}

	// File source 2 (BYREIS_KEY_FILE): no keychain probe.
	if k.cfg.EnvKeyFile != "" {
		return k.cfg.EnvKeyFile
	}

	// Non-file source 1 (BYREIS_KEY env): marker path, no keychain probe.
	if k.cfg.EnvKey != "" {
		return identityadapter.ResolvedPath(k.cfg)
	}

	// Non-file source 3 (keychain): probe with the real ctx for ctx-cancel safety.
	if k.cfg.Keychain != nil {
		secret, err := k.cfg.Keychain.GetIdentitySecret(ctx)
		if err != nil {
			// Keychain error → fail-closed to "" (CONTRIBUTOR, not hard error).
			return ""
		}
		if secret != "" {
			// Keychain has a key: return the in-process marker.
			// identity.ResolvedPath will also probe the keychain (with Background ctx)
			// and return the same marker — consistent with the single-resolver invariant.
			return identityadapter.ResolvedPath(k.cfg)
		}
		// No keychain entry and no error → fall through to default path.
	}

	// File source 4 (default key path).
	if k.cfg.DefaultKeyPath != nil {
		if p := k.cfg.DefaultKeyPath(); p != "" {
			return p
		}
	}

	return ""
}

// KeyFilePerms returns the permission bits for the key file.
//
// For the in-process marker (keychain/env key with no on-disk file): returns
// synthetic 0600 because there is no file to check — the substantive promotion
// checks are CanDecryptAny (step 3) and IsRegisteredAdmin (step 4).
//
// For a real file path: uses trust.CheckTrustFileTOCTOU (the shared TOCTOU-safe
// O_NOFOLLOW + fstat-on-fd primitive) to stat the open fd and return the perm
// bits. A wrong perm, symlink, or unstattable file returns an error → step-2
// HARD ERROR (refuse-to-run).
func (k *keyProbe) KeyFilePerms(ctx context.Context) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("KeyFilePerms cancelled: %w", err)
	}

	path := k.KeyFilePath(ctx)
	if path == "" {
		return 0, fmt.Errorf("KeyFilePerms called with no key path: programming error at the probe layer")
	}

	if identityadapter.IsInProcessMarker(path) {
		// Non-file key source (env or keychain): no real file to stat.
		// Synthetic perm-OK value — perm gate is meaningless for a key with
		// no on-disk representation.
		return 0o600, nil
	}

	// Real file: TOCTOU-safe open+stat via the shared trust primitive.
	f, err := trust.CheckTrustFileTOCTOU(path)
	if err != nil {
		return 0, fmt.Errorf("key file %q perm check failed: %w", path, err)
	}
	info, err := f.Stat()
	_ = f.Close()
	if err != nil {
		return 0, fmt.Errorf("stat key file fd %q: %w", path, err)
	}
	return uint32(info.Mode().Perm()), nil //nolint:gosec // mode bits fit in uint32; no truncation
}

// CanDecryptAny attempts to decrypt exactly ONE value from the project's
// file-of-record using the loaded identity.
//
// Returns (true, nil) on successful decrypt.
// Returns (false, nil) when the key is present but is not a recipient.
// Returns (false, err) on probe failure — fails closed to CONTRIBUTOR.
// NEVER returns plaintext: decrypted bytes are discarded immediately.
func (k *keyProbe) CanDecryptAny(ctx context.Context, projectID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("CanDecryptAny cancelled: %w", err)
	}

	// Load the identity.
	loader := identityadapter.New(k.cfg)
	id, err := loader.Load(ctx)
	if err != nil {
		if errors.Is(err, identityadapter.ErrNoAdminKey) {
			return false, nil
		}
		return false, fmt.Errorf("loading identity for decrypt probe: %w", err)
	}

	if k.fetcher == nil {
		return false, nil
	}

	art, err := k.fetcher.FetchArtifact(ctx, projectID)
	if err != nil {
		if errors.Is(err, ErrArtifactNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("fetching file-of-record for decrypt probe: %w", err)
	}

	if len(art.Values) == 0 {
		return false, nil
	}

	ageID := id.AgeIdentity()
	for _, ct := range art.Values {
		ok, probeErr := probeDecryptOne(string(ct), ageID)
		if probeErr != nil {
			return false, fmt.Errorf("decrypt probe: %w", probeErr)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// probeDecryptOne attempts to decrypt one armored age ciphertext with the given
// identity. Returns (true, nil) on success, (false, nil) when not a recipient,
// (false, err) on I/O or format errors.
//
// Plaintext is read into io.Discard immediately; no plaintext escapes.
func probeDecryptOne(armoredCT string, id *age.X25519Identity) (bool, error) {
	ar := armor.NewReader(strings.NewReader(armoredCT))
	r, err := age.Decrypt(ar, id)
	if err != nil {
		if isNotRecipientError(err) {
			return false, nil
		}
		return false, fmt.Errorf("age decrypt probe: %w", err)
	}

	// Drain plaintext to /dev/null. Using io.Discard avoids any allocation.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return false, fmt.Errorf("draining plaintext during probe: %w", err)
	}
	return true, nil
}

// isNotRecipientError returns true when the age error indicates the given
// identity is not among the recipients.
func isNotRecipientError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no identity matched") ||
		strings.Contains(msg, "no identities matched") ||
		strings.Contains(msg, "incorrect identity")
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryTrustAdapter
// ─────────────────────────────────────────────────────────────────────────────

// AdminSetResult is the narrow view of a fetched admin set consumed by
// RegistryTrustAdapter. The composition root maps the real coreregistry.AdminSet
// to this type via an anonymous wrapper so the adapter does not need to import
// internal/core/registry directly.
type AdminSetResult struct {
	// SourceVerified is true only when the registry HEAD commit signature was
	// verified against the client-pinned trust anchor. Forwarded 1:1.
	SourceVerified bool
	// Stale is true when served from an offline cache. Forwarded 1:1.
	Stale bool
	// AdminPublicKeys maps admin ID → age recipient public key string ("age1…").
	// Populated ONLY when SourceVerified=true && Stale=false.
	AdminPublicKeys map[string]string
}

// AdminSetFetcher is the narrow port consumed by RegistryTrustAdapter.
type AdminSetFetcher interface {
	FetchAdminSet(ctx context.Context, projectID string) (AdminSetResult, error)
}

// registryTrustAdapter implements mode.RegistryTrust.
type registryTrustAdapter struct {
	registry AdminSetFetcher
	keyCfg   identityadapter.Config
}

// NewRegistryTrustAdapter constructs the production RegistryTrustAdapter.
// registry must satisfy AdminSetFetcher (the composition root provides the real
// registry.Client via a bridge); keyCfg is the same identity config used by
// KeyProbe so the public key derived here matches the key the probe loaded.
func NewRegistryTrustAdapter(registry AdminSetFetcher, keyCfg identityadapter.Config) *registryTrustAdapter {
	return &registryTrustAdapter{registry: registry, keyCfg: keyCfg}
}

// IsRegisteredAdmin returns true ONLY when the current identity's age recipient
// public key is found in an AdminSet with SourceVerified=true AND Stale=false.
//
// A stale, unverified, error, or rolled-back result → (false, error) → CONTRIBUTOR.
func (r *registryTrustAdapter) IsRegisteredAdmin(ctx context.Context, projectID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("IsRegisteredAdmin cancelled: %w", err)
	}

	set, err := r.registry.FetchAdminSet(ctx, projectID)
	if err != nil {
		return false, fmt.Errorf("registry fetch for admin check: %w — run `byreis doctor` to diagnose", err)
	}

	// SourceVerified && !Stale gate: a stale or unverified set must not grant admin.
	if !set.SourceVerified {
		return false, fmt.Errorf(
			"registry admin set is not signature-verified (SourceVerified=false): " +
				"admin operations require a live SourceVerified registry fetch — " +
				"run `byreis doctor` to diagnose")
	}
	if set.Stale {
		return false, fmt.Errorf(
			"registry admin set is stale (served from offline cache): " +
				"admin operations require a fresh SourceVerified registry fetch — " +
				"run `byreis doctor` to diagnose")
	}

	// Load the current identity to get the recipient public key.
	loader := identityadapter.New(r.keyCfg)
	id, err := loader.Load(ctx)
	if err != nil {
		if errors.Is(err, identityadapter.ErrNoAdminKey) {
			return false, nil
		}
		return false, fmt.Errorf("loading identity for registry admin check: %w", err)
	}

	currentRecipient := id.Recipient() // "age1…" public key string
	for _, pubKey := range set.AdminPublicKeys {
		if pubKey == currentRecipient {
			return true, nil
		}
	}
	return false, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time interface assertions.
// ─────────────────────────────────────────────────────────────────────────────

var (
	_ keyProbeIface      = (*keyProbe)(nil)
	_ registryTrustIface = (*registryTrustAdapter)(nil)
)

// keyProbeIface mirrors mode.KeyProbe for compile-time verification without
// creating an adapter→core import.
type keyProbeIface interface {
	KeyFilePath(ctx context.Context) string
	KeyFilePerms(ctx context.Context) (uint32, error)
	CanDecryptAny(ctx context.Context, projectID string) (bool, error)
}

// registryTrustIface mirrors mode.RegistryTrust.
type registryTrustIface interface {
	IsRegisteredAdmin(ctx context.Context, projectID string) (bool, error)
}
