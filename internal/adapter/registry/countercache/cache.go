// Package countercache provides the on-disk persistence layer for the
// registry client's counter, HEAD, and pending-bump caches. It is a pure
// outward adapter: core packages depend on the CounterCacheStore port defined
// in internal/core/registry; this package implements that port.
//
// The canonical on-disk integrity posture is Alt-β: no HMAC; forgery resistance
// relies on O_NOFOLLOW + fstat-on-fd + checkOwner + checkFileMode (0o600), per
// the trust_unix.go pattern transplanted verbatim in cache_unix.go, plus a
// per-registry path derived from sha256(registryURL)[:16] that prevents
// cross-registry replay without requiring novel cryptographic construction.
//
// See internal/adapter/registry/doc.go for the canonical recipe that future
// on-disk cache implementers must follow.
package countercache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"

	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// currentSchemaVersion is the JSON envelope schema version. A mismatch on
// load triggers fail-rebuild semantics.
const currentSchemaVersion = 1

// ErrCounterCacheUnsafePath is returned when a symlink is detected at a
// cache file path or any parent directory. The caller must not delete the
// offending file when this error is returned because the directory itself
// may be hostile.
//
// Operator remediation: remove ~/.cache/byreis/ and retry.
var ErrCounterCacheUnsafePath = errors.New(
	"counter cache path is a symlink; remove ~/.cache/byreis/ and retry")

// ErrCounterCacheUnsafePerms is returned when a cache file or parent directory
// is owned by a different user or has a mode wider than allowed.
//
// Operator remediation: run chmod 600 <path>; chown $(id -u) <path>.
var ErrCounterCacheUnsafePerms = errors.New(
	"counter cache file or directory has unsafe ownership or permissions; " +
		"run: chmod 600 <path>; chown $(id -u) <path>")

// Store implements coreregistry.CounterCacheStore using per-registry on-disk
// JSON files protected by the trust_unix.go security pattern.
//
// The zero value is not valid; use New to construct.
type Store struct {
	// registryURL is the URL of the admin registry. Used to derive the
	// per-registry directory name as sha256(url)[:16].
	registryURL string

	// cacheRoot is the absolute path to ~/.cache/byreis/registry (or the
	// injected test root).
	cacheRoot string

	// log is the structured logger; receives INFO-level cache warnings.
	log *slog.Logger

	// platformState holds platform-specific fields (e.g. Windows-only log-once state).
	platformState //nolint:unused // used on Windows build; empty struct on Unix
}

// New constructs a Store for the given registry URL and cache root directory.
// cacheRoot is the absolute path to the parent cache directory
// (~/.cache/byreis/registry in production). logger may be nil; a discard
// logger is used in that case.
func New(registryURL, cacheRoot string, logger *slog.Logger) (*Store, error) {
	if registryURL == "" {
		return nil, fmt.Errorf("countercache.New: registryURL must not be empty")
	}
	if cacheRoot == "" {
		return nil, fmt.Errorf("countercache.New: cacheRoot must not be empty")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(noOpWriter{}, nil))
	}
	return &Store{
		registryURL: registryURL,
		cacheRoot:   cacheRoot,
		log:         logger,
	}, nil
}

// RegistryIDPrefix returns the 16-hex-char sha256 prefix of the registry URL.
// This is the directory name used under cacheRoot/registry/<prefix>/.
func RegistryIDPrefix(registryURL string) string {
	sum := sha256.Sum256([]byte(registryURL))
	return hex.EncodeToString(sum[:])[:16]
}

// registryDir returns the per-registry directory path.
func (s *Store) registryDir() string {
	return filepath.Join(s.cacheRoot, RegistryIDPrefix(s.registryURL))
}

// headFilePath returns the path to head.json for this registry.
func (s *Store) headFilePath() string {
	return filepath.Join(s.registryDir(), "head.json")
}

// countersFilePath returns the path to counters.json for this registry.
func (s *Store) countersFilePath() string {
	return filepath.Join(s.registryDir(), "counters.json")
}

// pendingFilePath returns the path to pending.json for this registry.
func (s *Store) pendingFilePath() string {
	return filepath.Join(s.registryDir(), "pending.json")
}

// epochsFilePath returns the path to epochs.json for this registry.
func (s *Store) epochsFilePath() string {
	return filepath.Join(s.registryDir(), "epochs.json")
}

// ---- JSON envelope types ----------------------------------------------------

// envelope is the on-disk JSON schema. schema_version and
// registry_id_sha256_prefix are parse-validated on every load.
type envelope[T any] struct {
	SchemaVersion          int    `json:"schema_version"`
	RegistryIDSHA256Prefix string `json:"registry_id_sha256_prefix"`
	Entries                T      `json:"entries"`
}

// headEntries maps projectID → HEAD SHA string.
type headEntries = map[string]string

// counterEntries maps "projectID/fileName" → uint64 counter.
type counterEntries = map[string]uint64

// pendingEntries maps "projectID/fileName" → PendingBump.
type pendingEntries = map[string]*countertypes.PendingBump

// epochEntries maps "projectID/fileName" → uint64 rotation_epoch.
// A missing key means no rotation has occurred (epoch == 0).
type epochEntries = map[string]uint64

// ---- context check helper ---------------------------------------------------

func ctxCheck(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("counter cache: context cancelled: %w", err)
	}
	return nil
}

// ---- marshal/unmarshal helpers ----------------------------------------------

func marshalEnvelope[T any](registryURL string, entries T) ([]byte, error) {
	env := envelope[T]{
		SchemaVersion:          currentSchemaVersion,
		RegistryIDSHA256Prefix: RegistryIDPrefix(registryURL),
		Entries:                entries,
	}
	return json.Marshal(env)
}

// unmarshalEnvelope parses a JSON envelope and validates schema_version and
// registry_id_sha256_prefix. On mismatch it returns a typed error so the
// caller can apply fail-rebuild semantics.
func unmarshalEnvelope[T any](data []byte, registryURL string) (T, error) {
	var env envelope[T]
	if err := json.Unmarshal(data, &env); err != nil {
		var zero T
		return zero, fmt.Errorf("counter cache: unparseable JSON: %w", err)
	}
	if env.SchemaVersion != currentSchemaVersion {
		var zero T
		return zero, fmt.Errorf("counter cache: schema_version %d != expected %d",
			env.SchemaVersion, currentSchemaVersion)
	}
	expectedPrefix := RegistryIDPrefix(registryURL)
	if env.RegistryIDSHA256Prefix != expectedPrefix {
		var zero T
		return zero, fmt.Errorf("counter cache: registry_id_sha256_prefix %q != expected %q",
			env.RegistryIDSHA256Prefix, expectedPrefix)
	}
	return env.Entries, nil
}

// ---- Compile-time interface assertion ---------------------------------------

// Ensure Store satisfies the CounterCacheStore port including the V2 rotation
// epoch methods.
var _ coreregistry.CounterCacheStore = (*Store)(nil)

// ---- noOpWriter for discard logger ------------------------------------------

type noOpWriter struct{}

func (noOpWriter) Write(p []byte) (int, error) { return len(p), nil }

// ---- LoadHead / StoreHead ---------------------------------------------------

// LoadHead returns the HEAD SHA for the given projectID from the on-disk head.json.
func (s *Store) LoadHead(ctx context.Context, projectID string) (string, error) {
	if err := ctxCheck(ctx); err != nil {
		return "", err
	}

	entries, err := s.loadHeadEntries(ctx)
	if err != nil {
		return "", err
	}
	if entries == nil {
		return "", nil
	}
	return entries[projectID], nil
}

// StoreHead writes the HEAD SHA for the given projectID to the on-disk head.json.
func (s *Store) StoreHead(ctx context.Context, projectID, commitSHA string) error {
	if err := ctxCheck(ctx); err != nil {
		return err
	}
	return s.updateHeadEntries(ctx, func(entries headEntries) {
		entries[projectID] = commitSHA
	})
}

// ---- LoadCounter / StoreCounter ---------------------------------------------

// LoadCounter returns the counter for the given (projectID, fileName) pair from
// the on-disk counters.json.
func (s *Store) LoadCounter(ctx context.Context, projectID, fileName string) (uint64, error) {
	if err := ctxCheck(ctx); err != nil {
		return 0, err
	}

	entries, err := s.loadCounterEntries(ctx)
	if err != nil {
		return 0, err
	}
	if entries == nil {
		return 0, nil
	}
	return entries[projectID+"/"+fileName], nil
}

// StoreCounter writes the counter for the given (projectID, fileName) pair to
// the on-disk counters.json.
func (s *Store) StoreCounter(ctx context.Context, projectID, fileName string, counter uint64) error {
	if err := ctxCheck(ctx); err != nil {
		return err
	}
	return s.updateCounterEntries(ctx, func(entries counterEntries) {
		entries[projectID+"/"+fileName] = counter
	})
}

// ---- LoadPending / StorePending / ClearPending ------------------------------

// LoadPending returns the pending bump for the given (projectID, fileName) pair
// from the on-disk pending.json.
func (s *Store) LoadPending(ctx context.Context, projectID, fileName string) (*countertypes.PendingBump, error) {
	if err := ctxCheck(ctx); err != nil {
		return nil, err
	}

	entries, err := s.loadPendingEntries(ctx)
	if err != nil {
		return nil, err
	}
	if entries == nil {
		return nil, nil
	}
	return entries[projectID+"/"+fileName], nil
}

// StorePending writes the pending bump for the given (projectID, fileName) pair
// to the on-disk pending.json.
func (s *Store) StorePending(ctx context.Context, projectID, fileName string, pending *countertypes.PendingBump) error {
	if err := ctxCheck(ctx); err != nil {
		return err
	}
	return s.updatePendingEntries(ctx, func(entries pendingEntries) {
		entries[projectID+"/"+fileName] = pending
	})
}

// ClearPending removes the pending bump for the given (projectID, fileName)
// pair from the on-disk pending.json. A missing record is not an error.
func (s *Store) ClearPending(ctx context.Context, projectID, fileName string) error {
	if err := ctxCheck(ctx); err != nil {
		return err
	}
	return s.updatePendingEntries(ctx, func(entries pendingEntries) {
		delete(entries, projectID+"/"+fileName)
	})
}

// ---- LoadRotationEpoch / StoreRotationEpoch ---------------------------------

// LoadRotationEpoch returns the rotation_epoch for the given (projectID, fileName)
// pair from the on-disk epochs.json. Returns (0, nil) on cold cache or when
// the field is absent (backwards-compatible default for v0.1-written files).
func (s *Store) LoadRotationEpoch(ctx context.Context, projectID, fileName string) (uint64, error) {
	if err := ctxCheck(ctx); err != nil {
		return 0, err
	}

	entries, err := s.loadEpochEntries(ctx)
	if err != nil {
		return 0, err
	}
	if entries == nil {
		return 0, nil
	}
	return entries[projectID+"/"+fileName], nil
}

// StoreRotationEpoch writes the rotation_epoch for the given (projectID, fileName)
// pair to the on-disk epochs.json. Uses the same fail-closed atomic-write
// semantics as StoreCounter.
func (s *Store) StoreRotationEpoch(ctx context.Context, projectID, fileName string, epoch uint64) error {
	if err := ctxCheck(ctx); err != nil {
		return err
	}
	return s.updateEpochEntries(ctx, func(entries epochEntries) {
		entries[projectID+"/"+fileName] = epoch
	})
}

// ---- Generic read/update helpers --------------------------------------------
// The platform-specific load/write primitives (readSecureFile, ensureRegistryDir,
// writeSecureFile) are in cache_unix.go and cache_windows.go respectively.

func (s *Store) loadHeadEntries(ctx context.Context) (headEntries, error) {
	return loadEntries[headEntries](ctx, s, s.headFilePath())
}

func (s *Store) updateHeadEntries(ctx context.Context, fn func(headEntries)) error {
	return updateEntries[headEntries](ctx, s, s.headFilePath(),
		func() headEntries { return make(headEntries) }, fn)
}

func (s *Store) loadCounterEntries(ctx context.Context) (counterEntries, error) {
	return loadEntries[counterEntries](ctx, s, s.countersFilePath())
}

func (s *Store) updateCounterEntries(ctx context.Context, fn func(counterEntries)) error {
	return updateEntries[counterEntries](ctx, s, s.countersFilePath(),
		func() counterEntries { return make(counterEntries) }, fn)
}

func (s *Store) loadPendingEntries(ctx context.Context) (pendingEntries, error) {
	return loadEntries[pendingEntries](ctx, s, s.pendingFilePath())
}

func (s *Store) updatePendingEntries(ctx context.Context, fn func(pendingEntries)) error {
	return updateEntries[pendingEntries](ctx, s, s.pendingFilePath(),
		func() pendingEntries { return make(pendingEntries) }, fn)
}

func (s *Store) loadEpochEntries(ctx context.Context) (epochEntries, error) {
	return loadEntries[epochEntries](ctx, s, s.epochsFilePath())
}

func (s *Store) updateEpochEntries(ctx context.Context, fn func(epochEntries)) error {
	return updateEntries[epochEntries](ctx, s, s.epochsFilePath(),
		func() epochEntries { return make(epochEntries) }, fn)
}

// mapIsNil reports whether a generic map value is nil. Required because a Go
// generic type parameter does not support direct == nil comparison.
func mapIsNil[T any](v T) bool {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return true
	}
	if rv.Kind() == reflect.Map {
		return rv.IsNil()
	}
	return false
}

// loadEntries reads and parses a cache JSON file of type T.
// Returns (nil, nil) on a cold cache (file not present).
// Returns (nil, err) with ErrCounterCacheUnsafePath or ErrCounterCacheUnsafePerms
// on security violations — the caller must NOT delete on these.
// On binding failure (schema_version mismatch, registry-id mismatch, unparseable
// JSON): deletes the file and returns (nil, nil) (fail-rebuild semantics).
func loadEntries[T any](ctx context.Context, s *Store, filePath string) (T, error) {
	if err := ctxCheck(ctx); err != nil {
		var zero T
		return zero, err
	}

	data, err := s.readSecureFile(ctx, filePath)
	if err != nil {
		var zero T
		// If the file does not exist: cold cache — return (nil, nil).
		if errors.Is(err, os.ErrNotExist) {
			return zero, nil
		}
		// Security failures: propagate — do NOT delete.
		if errors.Is(err, ErrCounterCacheUnsafePath) ||
			errors.Is(err, ErrCounterCacheUnsafePerms) {
			return zero, err
		}
		// Other I/O errors: treat as cold.
		s.log.Info("counter cache: load error; treating as cold cache",
			"path", filePath, "error", err.Error())
		return zero, nil
	}

	entries, parseErr := unmarshalEnvelope[T](data, s.registryURL)
	if parseErr != nil {
		// Binding failure: fail-rebuild. We already verified owner/perm so
		// we are safe to delete; return (nil, nil) so caller starts fresh.
		s.log.Info("counter cache: binding failure; deleting and rebuilding",
			"path", filePath, "error", parseErr.Error())
		if rmErr := os.Remove(filePath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			s.log.Info("counter cache: failed to remove invalid cache file",
				"path", filePath, "error", rmErr.Error())
		}
		var zero T
		return zero, nil
	}

	return entries, nil
}

// updateEntries reads the current cache file, applies fn to the entries map,
// and writes the result back atomically. Missing file is treated as empty map.
// newMap constructs a fresh empty map when the file is cold or failed to load.
func updateEntries[T any](ctx context.Context, s *Store, filePath string, newMap func() T, fn func(T)) error {
	if err := ctxCheck(ctx); err != nil {
		return err
	}

	// Ensure the per-registry directory exists and is correctly permissioned.
	if err := s.ensureRegistryDir(ctx); err != nil {
		return fmt.Errorf("counter cache: ensuring registry dir: %w", err)
	}

	// Load current state. loadEntries returns (zero/nil, nil) on cold cache,
	// (zero/nil, securityErr) on security failures. Start with newMap() and
	// layer in the loaded state if available.
	loaded, loadErr := loadEntries[T](ctx, s, filePath)
	if loadErr != nil {
		// Security failures propagate; do not attempt to write into a hostile dir.
		if errors.Is(loadErr, ErrCounterCacheUnsafePath) ||
			errors.Is(loadErr, ErrCounterCacheUnsafePerms) {
			return fmt.Errorf("counter cache update blocked by security violation at %q: %w",
				filePath, loadErr)
		}
		// Other errors: treat as cold cache — start fresh.
		loaded = newMap()
	}

	// Use the loaded map if non-nil (successful parse), else start fresh.
	// json.Unmarshal returns a nil map when the entries field is null or
	// absent; we need an initialised map before calling fn.
	existing := loaded
	if mapIsNil[T](existing) {
		existing = newMap()
	}

	fn(existing)

	blob, err := marshalEnvelope(s.registryURL, existing)
	if err != nil {
		return fmt.Errorf("counter cache: marshalling entries: %w", err)
	}

	if err := s.writeSecureFile(ctx, filePath, blob); err != nil {
		return fmt.Errorf("counter cache: writing %q: %w — "+
			"remove the file and retry if the issue persists: rm -rf ~/.cache/byreis/registry",
			filePath, err)
	}

	return nil
}
