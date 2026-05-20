//go:build windows

package countercache_test

// D10(f) — Windows sentinel tests.
// WINDOWS_SENTINEL_NOT_DEFINED_IN_UNIX_BUILD is exercised by cache_unix_test.go.

import (
	"context"
	"errors"
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/registry/countercache"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

const testRegistryURLWindows = "https://github.com/testorg/byreis-admins"

func newWindowsTestStore(t *testing.T) *countercache.Store {
	t.Helper()
	s, err := countercache.New(testRegistryURLWindows, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("countercache.New: %v", err)
	}
	return s
}

// TestWindows_LOAD_RETURNS_SENTINEL verifies every Load method returns
// ErrCounterCacheWindowsUnsupported on Windows.
func TestWindows_LOAD_RETURNS_SENTINEL(t *testing.T) {
	t.Parallel()
	s := newWindowsTestStore(t)
	ctx := context.Background()

	_, err := s.LoadHead(ctx, "proj")
	if !errors.Is(err, countercache.ErrCounterCacheWindowsUnsupported) {
		t.Errorf("LoadHead: expected ErrCounterCacheWindowsUnsupported, got: %v", err)
	}

	_, err = s.LoadCounter(ctx, "proj", "f")
	if !errors.Is(err, countercache.ErrCounterCacheWindowsUnsupported) {
		t.Errorf("LoadCounter: expected ErrCounterCacheWindowsUnsupported, got: %v", err)
	}

	_, err = s.LoadPending(ctx, "proj", "f")
	if !errors.Is(err, countercache.ErrCounterCacheWindowsUnsupported) {
		t.Errorf("LoadPending: expected ErrCounterCacheWindowsUnsupported, got: %v", err)
	}
}

// TestWindows_STORE_RETURNS_SENTINEL verifies every Store method returns
// ErrCounterCacheWindowsUnsupported on Windows.
func TestWindows_STORE_RETURNS_SENTINEL(t *testing.T) {
	t.Parallel()
	s := newWindowsTestStore(t)
	ctx := context.Background()

	err := s.StoreHead(ctx, "proj", "sha")
	if !errors.Is(err, countercache.ErrCounterCacheWindowsUnsupported) {
		t.Errorf("StoreHead: expected ErrCounterCacheWindowsUnsupported, got: %v", err)
	}

	err = s.StoreCounter(ctx, "proj", "f", 1)
	if !errors.Is(err, countercache.ErrCounterCacheWindowsUnsupported) {
		t.Errorf("StoreCounter: expected ErrCounterCacheWindowsUnsupported, got: %v", err)
	}

	bump := &countertypes.PendingBump{PendingCounter: 1, TargetArtifactSHA: "sha256:x"}
	err = s.StorePending(ctx, "proj", "f", bump)
	if !errors.Is(err, countercache.ErrCounterCacheWindowsUnsupported) {
		t.Errorf("StorePending: expected ErrCounterCacheWindowsUnsupported, got: %v", err)
	}

	err = s.ClearPending(ctx, "proj", "f")
	if !errors.Is(err, countercache.ErrCounterCacheWindowsUnsupported) {
		t.Errorf("ClearPending: expected ErrCounterCacheWindowsUnsupported, got: %v", err)
	}
}
