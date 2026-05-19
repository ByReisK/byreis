// Package fs provides real filesystem, clock, and randomness adapters.
// These are the production implementations of the ports injected into core.
// Unit tests inject fakes; only integration/end-to-end tests use this package.
package fs

import (
	"context"
	"os"
	"time"
)

// Clock is the real-time clock adapter.
type Clock struct{}

// Now returns the current time.
func (Clock) Now() time.Time { return time.Now() }

// Filesystem is the real filesystem adapter implementing config.Filesystem.
type Filesystem struct{}

// ReadFile reads the named file.
func (Filesystem) ReadFile(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteFile writes data to the named file with the given permissions.
func (Filesystem) WriteFile(_ context.Context, path string, data []byte, perm uint32) error {
	return os.WriteFile(path, data, os.FileMode(perm))
}

// FileExists reports whether path exists as a regular file.
func (Filesystem) FileExists(_ context.Context, path string) (bool, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
