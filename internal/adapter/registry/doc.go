// Package registry implements the internal/core/registry.RegistryClient port
// as a concrete adapter backed by git/HTTP transports.
//
// # On-disk cache integrity: canonical recipe (Alt-β posture)
//
// This package (via its countercache sub-package) defines the canonical
// integrity posture for all future on-disk caches in byreis. The binding
// posture is Alt-β: no HMAC, no novel MAC construction. The rationale is
// that the threat model is "local attacker with the process owner's
// privileges", against which an
// HMAC keyed by public bytes adds performative protection only. The
// file-system discipline below provides the actual security property.
//
// # The canonical 6-step recipe
//
// Every future on-disk cache implementation (admin-set cache, recipient cache,
// signer-key cache, audit-log persistence) MUST follow this pattern verbatim:
//
//  1. O_NOFOLLOW open + fstat-on-fd (NOT os.Stat on the path).
//     Reject ELOOP/ENOTDIR as ErrCounterCacheUnsafePath (or equivalent
//     package sentinel). Read content ONLY from the verified file descriptor.
//     Source: internal/core/trust/trust_unix.go:31-46 (openNoFollow).
//
//  2. checkOwner against os.Geteuid() using fstat result from step 1.
//     Cross-owner file → fail-closed (return error, do NOT delete).
//     Source: internal/core/trust/trust_unix.go:61-73 (checkOwner).
//
//  3. checkFileMode requiring exact 0o600.
//     Any other mode → fail-closed (return error, do NOT delete).
//     Source: internal/core/trust/trust_unix.go:88-96 (checkFileMode).
//
//  4. Parent directory checks (one level up = registry dir, two levels up =
//     cache root) via openNoFollowDir + fstat-on-fd + checkOwner + checkDirMode
//     requiring 0o077-bits clear (0o700 or stricter).
//     Source: internal/core/trust/trust_unix.go:14-27 (openNoFollowDir),
//     internal/core/trust/trust_unix.go:77-85 (checkDirMode).
//
//  5. All writes transit internal/adapter/fs/atomicwrite.WriteFile (Unix)
//     or return ErrAtomicWriteWindowsUnsupported (Windows).
//     Never use os.Rename or ioutil.WriteFile directly.
//
//  6. Per-registry path isolation: derive the cache directory name as
//     hex(sha256(registryURL))[:16]. Never use the registry URL as a directory
//     name verbatim (avoids /, :, and case-insensitive-filesystem collisions).
//     Include schema_version (int) and registry_id_sha256_prefix (string) as
//     parse-validated fields in the JSON envelope. A mismatch triggers
//     fail-rebuild: delete the file (under perm-permit) and return zero
//     (cold-cache semantics). Do NOT delete on permission failures.
//
// # Windows fallback
//
// Windows is not a supported release target for byreis write operations.
// Every cache sub-package MUST provide a cache_windows.go tagged //go:build
// windows that returns a typed ErrSomethingWindowsUnsupported sentinel from
// all persistence methods. The sentinel MUST NOT be defined in unix-tagged
// files. Unix sentinels (ErrCounterCacheUnsafePath, ErrCounterCacheUnsafePerms)
// MUST NOT be defined in windows-tagged files. Cross-platform callers use
// errors.Is, never type assertions.
//
// # Build-tag discipline
//
// cache_unix.go  (//go:build unix)    — full implementation.
// cache_windows.go (//go:build windows) — typed sentinel, every method fails.
// cache.go (no build tag)             — Store struct, constructor, port types.
//
// # Rotation-epoch anti-rollback floor: backing-store posture
//
// The rotation-epoch anti-rollback floor (epochFloor / epochFloorHydrated in
// registry.Client, persisted via CounterCacheStore.StoreRotationEpoch /
// LoadRotationEpoch) shares the same epochs.json backing store as the cached
// rotation_epoch value for each (project, file) pair, and inherits the same
// Alt-β posture described above.
//
// Forgery resistance relies on the identical O_NOFOLLOW + fstat-on-fd +
// checkOwner + checkFileMode (0o600) + per-registry path-namespacing discipline
// used for the counter floor. There is no HMAC over the epochs.json content.
// A same-uid disk attacker who can rewrite epochs.json can zero both the floor
// and the stored epoch value, bypassing the anti-rollback check. This
// limitation is accepted, and is identical to the counter floor limitation.
//
// If the counter floor is ever hardened to use a separate HMAC-protected file,
// the epoch floor MUST migrate in lockstep — the two stores must share the
// same integrity posture at all times.
//
// # Future implementers
//
// Do NOT default to a novel keyed MAC. The Alt-β posture is binding. If a
// future slice has a genuine need for a MAC (e.g. protecting
// a cache artefact that escapes the O_NOFOLLOW + 0o600 boundary), escalate
// to the crypto reviewer before implementing — do not self-certify a new
// cryptographic construction.
package registry
