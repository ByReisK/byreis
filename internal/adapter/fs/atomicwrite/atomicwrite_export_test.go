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

// SetPostRenameHook installs a function that is called exactly once, immediately
// after a successful unix.Renameat and before performAtomicRename returns the
// parent fd to the caller. This is a distinct hook from SetPreRenameHook
// (which fires pre-rename); this one models the dirSync window (the period
// between rename completion and fsync of the parent directory fd).
//
// Intended exclusively for tests that need to inject a directory swap between
// rename success and the dirSyncFd call, to prove the fd-thread closes the
// symlink-swap window. Pass nil to clear the hook.
//
// This symbol exists only in test binaries (it lives in a _test.go file).
func SetPostRenameHook(fn func()) {
	postRenameHook = fn
}

// SetNextTempSuffixHook installs a function that is called with the randomly
// generated temp-file suffix immediately before openExclTempFile attempts to
// open the file. This allows tests to observe or intercept the suffix to test
// EEXIST retry behavior and ELOOP fail-closed behavior.
//
// The hook receives the full temp filename (including the prefix). Pass nil to
// clear the hook. This symbol exists only in test binaries.
func SetNextTempSuffixHook(fn func(suffix string)) {
	nextTempSuffixHook = fn
}
