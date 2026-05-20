//go:build unix

package atomicwrite

// SetPreRenameHook installs a function that is called exactly once, immediately
// before the atomic rename. Intended exclusively for tests that need to inject
// a directory swap between the parent-inode snapshot and the rename syscall to
// exercise the inode re-check path. Pass nil to clear the hook.
//
// This symbol exists only in test binaries (it lives in a _test.go file).
func SetPreRenameHook(fn func()) {
	preRenameHook = fn
}
