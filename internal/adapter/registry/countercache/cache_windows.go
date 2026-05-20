//go:build windows

package countercache

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// platformState holds Windows-specific state: the log-once guard for the
// Windows no-op warning.
type platformState struct {
	mu                sync.Mutex
	windowsLoggedOnce bool
}

// ErrCounterCacheWindowsUnsupported is returned by all persistence methods on
// Windows. Windows is not a supported release target for byreis write
// operations. Counter cache persistence is unavailable on Windows; the
// in-memory cache is the only cache for the process lifetime.
//
// This sentinel is defined exclusively in this windows-tagged file and does
// NOT exist in cache_unix.go. Cross-platform consumers use errors.Is.
var ErrCounterCacheWindowsUnsupported = errors.New(
	"counter cache persistence is unavailable on Windows; " +
		"use the Linux or macOS build of byreis for durable anti-rollback counters")

// readSecureFile on Windows returns ErrCounterCacheWindowsUnsupported.
func (s *Store) readSecureFile(_ context.Context, _ string) ([]byte, error) {
	s.logWindowsOnce()
	return nil, ErrCounterCacheWindowsUnsupported
}

// ensureRegistryDir on Windows returns ErrCounterCacheWindowsUnsupported.
func (s *Store) ensureRegistryDir(_ context.Context) error {
	return ErrCounterCacheWindowsUnsupported
}

// writeSecureFile on Windows returns ErrCounterCacheWindowsUnsupported.
func (s *Store) writeSecureFile(_ context.Context, _ string, _ []byte) error {
	return ErrCounterCacheWindowsUnsupported
}

// logWindowsOnce emits the Windows no-op warning exactly once per Store
// instance. Subsequent calls are silent.
func (s *Store) logWindowsOnce() {
	s.platformState.mu.Lock()
	defer s.platformState.mu.Unlock()
	if !s.platformState.windowsLoggedOnce {
		s.platformState.windowsLoggedOnce = true
		s.log.Info("counter cache persistence unavailable on Windows; using in-memory cache only")
	}
}

// The following are no-ops on Windows needed to satisfy unused-import rules.
var (
	_ = os.ErrNotExist
	_ = (*countertypes.PendingBump)(nil)
)
