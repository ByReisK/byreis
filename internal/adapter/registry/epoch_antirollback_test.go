// Package registry_test — anti-rollback epoch-floor tests for FetchRotationEpochs.
//
// Five mandatory negative tests required by the crypto-auditor conditional ACK
// on the rotation-history doctor feature. Each test name is the exact label
// the auditor specified; do not rename without a corresponding audit note.
//
// EPOCH_FALLBACK_REJECTS_ROLLED_BACK_CACHE
// EPOCH_FALLBACK_COLD_CACHE_FAILS_CLOSED
// EPOCH_FALLBACK_DOES_NOT_SUPPRESS_R4b
// EPOCH_UNSIGNED_HEAD_DOES_NOT_FALL_BACK
// EPOCH_STALE_SERVE_CARRIES_WARN
package registry_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// ---- helpers shared by this file --------------------------------------------

// epochFakeTransport is a minimal FetchTransport whose behaviour is controlled
// by its fields. It is distinct from the other fake transports in this package
// so each test can set exactly the properties it needs.
type epochFakeTransport struct {
	// verified controls the signature-verification result returned by FetchHead.
	verified bool
	// fetchHeadErr is returned by FetchHead when non-nil.
	fetchHeadErr error
	// epochs is the per-fileName epoch map served by ReadRotationEpoch.
	epochs map[string]uint64
	// projectFiles is the per-fileName map returned by ReadProjectConfig.
	projectFiles map[string]string
}

func (ft *epochFakeTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	if ft.fetchHeadErr != nil {
		return "", "", false, ft.fetchHeadErr
	}
	return "fake-epoch-head-sha", "fake-signer", ft.verified, nil
}

func (ft *epochFakeTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}

func (ft *epochFakeTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}

func (ft *epochFakeTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}

func (ft *epochFakeTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}

func (ft *epochFakeTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	if ft.projectFiles == nil {
		return registry.ProjectConfig{}, nil
	}
	return registry.ProjectConfig{Files: ft.projectFiles}, nil
}

func (ft *epochFakeTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}

func (ft *epochFakeTransport) DiscardCounterSession(_ context.Context, _ string) {}

func (ft *epochFakeTransport) ReadRotationEpoch(_ context.Context, _, _ string, _, fileName string) (uint64, error) {
	if ft.epochs == nil {
		return 0, nil
	}
	return ft.epochs[fileName], nil
}

func (ft *epochFakeTransport) ReadAuditLog(_ context.Context, _, _, _ string) ([]byte, error) {
	return nil, nil
}

// fakeDiskCache is a minimal CounterCacheStore that stores only rotation epochs
// in memory, returning explicit values set by the test. This lets tests control
// what the offline fallback reads from "disk" without touching the real filesystem.
type fakeDiskCache struct {
	// epochsByKey maps "projectID/fileName" to the stored epoch value.
	epochsByKey map[string]uint64
}

func newFakeDiskCache() *fakeDiskCache {
	return &fakeDiskCache{epochsByKey: make(map[string]uint64)}
}

func (f *fakeDiskCache) setEpoch(projectID, fileName string, epoch uint64) {
	f.epochsByKey[projectID+"/"+fileName] = epoch
}

func (f *fakeDiskCache) LoadRotationEpoch(_ context.Context, projectID, fileName string) (uint64, error) {
	return f.epochsByKey[projectID+"/"+fileName], nil
}

func (f *fakeDiskCache) StoreRotationEpoch(_ context.Context, projectID, fileName string, epoch uint64) error {
	f.epochsByKey[projectID+"/"+fileName] = epoch
	return nil
}

// Stub all remaining CounterCacheStore methods — unused by the epoch tests.

func (f *fakeDiskCache) LoadHead(_ context.Context, _ string) (string, error) { return "", nil }

func (f *fakeDiskCache) StoreHead(_ context.Context, _, _ string) error { return nil }

func (f *fakeDiskCache) LoadCounter(_ context.Context, _, _ string) (uint64, error) { return 0, nil }

func (f *fakeDiskCache) StoreCounter(_ context.Context, _, _ string, _ uint64) error { return nil }

func (f *fakeDiskCache) LoadPending(_ context.Context, _, _ string) (*countertypes.PendingBump, error) {
	return nil, nil
}

func (f *fakeDiskCache) StorePending(_ context.Context, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}

func (f *fakeDiskCache) ClearPending(_ context.Context, _, _ string) error { return nil }

// Compile-time assertion: fakeDiskCache must satisfy CounterCacheStore.
var _ coreregistry.CounterCacheStore = (*fakeDiskCache)(nil)

// buildEpochClient constructs a registry.Client for epoch anti-rollback tests.
// onlineFT is the transport used for the initial (floor-establishing) online call.
// disk is the fake disk cache. The client is returned ready to use.
func buildEpochClient(t *testing.T, onlineFT registry.FetchTransport, disk coreregistry.CounterCacheStore) *registry.Client {
	t.Helper()
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-epoch",
		TrustAnchorKey: make([]byte, ed25519.PublicKeySize),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: onlineFT,
		DiskCache:      disk,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	return c
}

// ---- EPOCH_FALLBACK_REJECTS_ROLLED_BACK_CACHE --------------------------------

// TestEPOCH_FALLBACK_REJECTS_ROLLED_BACK_CACHE proves that when the anti-rollback
// floor is 2 (set by a prior verified online fetch in this process lifetime) and
// the on-disk cache was subsequently overwritten to epoch 0 (simulating an
// adversarial replay of an old cache file), the offline fallback returns
// ErrCacheTampered rather than silently serving epoch 0.
//
// The critical path: the in-memory floor persists across the transport swap
// (online → offline) within the SAME client instance, and the disk holds the
// adversary-controlled epoch 0. The anti-rollback assertion compares the disk
// value against the in-memory floor and correctly fires.
//
// This validates BO-V8-2.a: a cached epoch below the in-memory anti-rollback
// floor is a tamper sentinel.
func TestEPOCH_FALLBACK_REJECTS_ROLLED_BACK_CACHE(t *testing.T) {
	t.Parallel()

	const projectID = "proj-epoch"
	const fileName = "secrets/prod.enc.yaml"

	disk := newFakeDiskCache()

	// Build a client that starts online at epoch=2.
	onlineFT := &epochFakeTransport{
		verified:     true,
		epochs:       map[string]uint64{fileName: 2},
		projectFiles: map[string]string{fileName: fileName},
	}
	client := buildEpochClient(t, onlineFT, disk)

	// Online call: sets the in-memory floor to 2 and write-through to disk.
	epochs, err := client.FetchRotationEpochs(context.Background(), projectID)
	if err != nil {
		t.Fatalf("online FetchRotationEpochs: unexpected error: %v", err)
	}
	if epochs[fileName] != 2 {
		t.Fatalf("online epoch = %d, want 2", epochs[fileName])
	}
	// At this point: in-memory floor = 2, disk epoch = 2.

	// Seed the admin-set cache so the offline path can discover the file name
	// without a network call (the counterCache is empty in this test because no
	// CounterAuthority call was made).
	if seedErr := client.SeedCache(context.Background(), projectID, coreregistry.AdminSet{
		ProjectID:       projectID,
		HeadCommit:      "seeded-head",
		ConfiguredFiles: map[string]string{fileName: fileName},
	}); seedErr != nil {
		t.Fatalf("SeedCache: %v", seedErr)
	}

	// Simulate an adversary overwriting the disk cache back to epoch 0 (replay).
	disk.setEpoch(projectID, fileName, 0)

	// Swap the transport to nil (offline). The in-memory floor remains 2.
	client.SetTransportForTest(nil)

	// Offline call: disk returns epoch 0; in-memory floor is 2.
	// The anti-rollback assertion (0 < 2) must fire → ErrCacheTampered.
	_, offlineErr := client.FetchRotationEpochs(context.Background(), projectID)
	if offlineErr == nil {
		t.Fatal("EPOCH_FALLBACK_REJECTS_ROLLED_BACK_CACHE: expected error, got nil — " +
			"a replayed epoch-0 cache must be rejected when in-memory floor is 2")
	}
	if !errors.Is(offlineErr, coreregistry.ErrCacheTampered) {
		t.Errorf("EPOCH_FALLBACK_REJECTS_ROLLED_BACK_CACHE: error = %v; want wrapping ErrCacheTampered", offlineErr)
	}
}

// ---- EPOCH_FALLBACK_COLD_CACHE_FAILS_CLOSED ----------------------------------

// TestEPOCH_FALLBACK_COLD_CACHE_FAILS_CLOSED proves that when the registry is
// offline and no durable floor record exists for the project file, the method
// returns ErrRegistryOffline rather than silently succeeding with epoch 0.
//
// This validates BO-V8-2.b: cold cache must fail closed.
func TestEPOCH_FALLBACK_COLD_CACHE_FAILS_CLOSED(t *testing.T) {
	t.Parallel()

	const projectID = "proj-epoch-cold"
	const fileName = "secrets/api.enc.yaml"

	// Build a client with nil transport (offline from the start) and a cold disk
	// cache (no epoch records stored for this project).
	disk := newFakeDiskCache() // empty — cold cache
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      projectID,
		TrustAnchorKey: make([]byte, ed25519.PublicKeySize),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: nil, // offline
		DiskCache:      disk,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// Seed the admin-set cache so the offline path knows about the file.
	_ = c.SeedCache(context.Background(), projectID, coreregistry.AdminSet{
		ProjectID:       projectID,
		HeadCommit:      "seeded",
		ConfiguredFiles: map[string]string{fileName: fileName},
	})

	_, callErr := c.FetchRotationEpochs(context.Background(), projectID)
	if callErr == nil {
		t.Fatal("EPOCH_FALLBACK_COLD_CACHE_FAILS_CLOSED: expected error, got nil — " +
			"an offline cold-cache must not silently succeed with epoch-0")
	}
	if !errors.Is(callErr, coreregistry.ErrRegistryOffline) {
		t.Errorf("EPOCH_FALLBACK_COLD_CACHE_FAILS_CLOSED: error = %v; want wrapping ErrRegistryOffline", callErr)
	}
}

// ---- EPOCH_FALLBACK_DOES_NOT_SUPPRESS_R4b ------------------------------------

// TestEPOCH_FALLBACK_DOES_NOT_SUPPRESS_R4b proves that when the registry is
// offline but the disk cache holds a valid epoch > 0 (floor passes), the
// FetchRotationEpochs call returns a non-nil error wrapping ErrRegistryOffline
// together with a non-empty epoch map. This lets the doctor use-case detect
// that the result is stale and still evaluate the partial-rotation / forward-
// secrecy warning (R4b) against the served epochs.
//
// This validates BO-V8-2.d: stale-serve is NOT a skip-R4b path.
func TestEPOCH_FALLBACK_DOES_NOT_SUPPRESS_R4b(t *testing.T) {
	t.Parallel()

	const projectID = "proj-epoch-r4b"
	const fileName = "secrets/prod.enc.yaml"
	const cachedEpoch = uint64(3)

	// Disk holds a valid epoch=3 record for the file.
	disk := newFakeDiskCache()
	disk.setEpoch(projectID, fileName, cachedEpoch)

	// Build a client that first does an online fetch to set the floor to 3.
	onlineFT := &epochFakeTransport{
		verified:     true,
		epochs:       map[string]uint64{fileName: cachedEpoch},
		projectFiles: map[string]string{fileName: fileName},
	}
	client := buildEpochClient(t, onlineFT, disk)
	// Warm up the in-memory floor to 3.
	_, err := client.FetchRotationEpochs(context.Background(), projectID)
	if err != nil {
		t.Fatalf("warm-up: %v", err)
	}

	// Seed the admin-set cache so the offline path can discover the file name.
	if seedErr := client.SeedCache(context.Background(), projectID, coreregistry.AdminSet{
		ProjectID:       projectID,
		HeadCommit:      "seeded-head",
		ConfiguredFiles: map[string]string{fileName: fileName},
	}); seedErr != nil {
		t.Fatalf("SeedCache: %v", seedErr)
	}

	// Switch to offline.
	client.SetTransportForTest(nil)

	// Offline call: disk has epoch=3 which equals the floor (3 >= 3). The call
	// must return a non-empty map AND an ErrRegistryOffline error.
	epochs, offlineErr := client.FetchRotationEpochs(context.Background(), projectID)
	if offlineErr == nil {
		t.Fatal("EPOCH_FALLBACK_DOES_NOT_SUPPRESS_R4b: expected ErrRegistryOffline error, got nil — " +
			"stale-serve must carry the offline sentinel so callers know the data is cached")
	}
	if !errors.Is(offlineErr, coreregistry.ErrRegistryOffline) {
		t.Errorf("EPOCH_FALLBACK_DOES_NOT_SUPPRESS_R4b: error = %v; want wrapping ErrRegistryOffline", offlineErr)
	}
	if len(epochs) == 0 {
		t.Error("EPOCH_FALLBACK_DOES_NOT_SUPPRESS_R4b: epoch map is empty — " +
			"stale-serve must return a non-empty map so R4b logic can run")
	}
	if got := epochs[fileName]; got != cachedEpoch {
		t.Errorf("EPOCH_FALLBACK_DOES_NOT_SUPPRESS_R4b: epoch[%q] = %d, want %d",
			fileName, got, cachedEpoch)
	}
}

// ---- EPOCH_UNSIGNED_HEAD_DOES_NOT_FALL_BACK ----------------------------------

// TestEPOCH_UNSIGNED_HEAD_DOES_NOT_FALL_BACK proves that a signature-verification
// failure on the registry HEAD is a hard ErrUnsignedRegistry error and does NOT
// fall through to the offline cache. The cache fallback is reserved strictly for
// transport-unavailable conditions.
//
// This validates BO-V8-2.c: cache fallback is NEVER reached on !verified.
func TestEPOCH_UNSIGNED_HEAD_DOES_NOT_FALL_BACK(t *testing.T) {
	t.Parallel()

	const projectID = "proj-unsigned"
	const fileName = "secrets/db.enc.yaml"

	// Disk has a valid cached epoch that would be served if fallback were reached.
	disk := newFakeDiskCache()
	disk.setEpoch(projectID, fileName, 5)

	// Transport returns an unverified HEAD (verified=false).
	unsignedFT := &epochFakeTransport{
		verified:     false, // signature verification fails
		epochs:       map[string]uint64{fileName: 5},
		projectFiles: map[string]string{fileName: fileName},
	}

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      projectID,
		TrustAnchorKey: make([]byte, ed25519.PublicKeySize),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: unsignedFT,
		DiskCache:      disk,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// Seed the admin-set and epoch floor caches so the offline path would succeed
	// IF the fallback were reached. This proves the test is meaningful: if the
	// implementation incorrectly fell through, it would return a non-error result.
	_ = c.SeedCache(context.Background(), projectID, coreregistry.AdminSet{
		ProjectID:       projectID,
		HeadCommit:      "old-head",
		ConfiguredFiles: map[string]string{fileName: fileName},
	})

	_, callErr := c.FetchRotationEpochs(context.Background(), projectID)
	if callErr == nil {
		t.Fatal("EPOCH_UNSIGNED_HEAD_DOES_NOT_FALL_BACK: expected error, got nil — " +
			"an unverified HEAD must be a hard error, never a cache-fallback trigger")
	}
	if !errors.Is(callErr, coreregistry.ErrUnsignedRegistry) {
		t.Errorf("EPOCH_UNSIGNED_HEAD_DOES_NOT_FALL_BACK: error = %v; want wrapping ErrUnsignedRegistry", callErr)
	}
	// Confirm it does NOT wrap ErrRegistryOffline (which would mean fallback was reached).
	if errors.Is(callErr, coreregistry.ErrRegistryOffline) {
		t.Errorf("EPOCH_UNSIGNED_HEAD_DOES_NOT_FALL_BACK: error wraps ErrRegistryOffline — " +
			"the offline fallback was incorrectly reached on an unverified HEAD")
	}
}

// ---- EPOCH_STALE_SERVE_CARRIES_WARN ------------------------------------------

// TestEPOCH_STALE_SERVE_CARRIES_WARN proves that when the registry is offline
// and a valid floor-passing cached epoch is served, the return value carries an
// ErrRegistryOffline sentinel (the "stale WARN" signal the CLI layer renders as
// an INFO/WARN line). The epoch map must be non-empty and the error non-nil.
//
// This validates BO-V8-2.d: stale-serve carries the offline sentinel so the
// CLI render layer knows to emit the stale-cache warning.
func TestEPOCH_STALE_SERVE_CARRIES_WARN(t *testing.T) {
	t.Parallel()

	const projectID = "proj-stale-warn"
	const fileName = "secrets/service.enc.yaml"
	const onlineEpoch = uint64(7)

	disk := newFakeDiskCache()

	// Online first: establishes floor=7.
	onlineFT := &epochFakeTransport{
		verified:     true,
		epochs:       map[string]uint64{fileName: onlineEpoch},
		projectFiles: map[string]string{fileName: fileName},
	}
	client := buildEpochClient(t, onlineFT, disk)
	_, err := client.FetchRotationEpochs(context.Background(), projectID)
	if err != nil {
		t.Fatalf("online warm-up: %v", err)
	}

	// Seed the admin-set cache so the offline path can discover the file name.
	if seedErr := client.SeedCache(context.Background(), projectID, coreregistry.AdminSet{
		ProjectID:       projectID,
		HeadCommit:      "seeded-head",
		ConfiguredFiles: map[string]string{fileName: fileName},
	}); seedErr != nil {
		t.Fatalf("SeedCache: %v", seedErr)
	}

	// Go offline.
	client.SetTransportForTest(nil)

	// Offline call: disk has epoch=7 (written by write-through), floor=7 in memory.
	// cachedEpoch(7) >= floor(7): passes. Must return (non-empty map, ErrRegistryOffline).
	epochs, offlineErr := client.FetchRotationEpochs(context.Background(), projectID)
	if offlineErr == nil {
		t.Fatal("EPOCH_STALE_SERVE_CARRIES_WARN: expected ErrRegistryOffline, got nil — " +
			"a stale-serve must carry the offline sentinel")
	}
	if !errors.Is(offlineErr, coreregistry.ErrRegistryOffline) {
		t.Errorf("EPOCH_STALE_SERVE_CARRIES_WARN: error = %v; want wrapping ErrRegistryOffline", offlineErr)
	}
	if len(epochs) == 0 {
		t.Error("EPOCH_STALE_SERVE_CARRIES_WARN: epoch map is empty — " +
			"a floor-passing stale-serve must return a non-empty map")
	}
	if got := epochs[fileName]; got != onlineEpoch {
		t.Errorf("EPOCH_STALE_SERVE_CARRIES_WARN: epoch[%q] = %d, want %d",
			fileName, got, onlineEpoch)
	}
}
