//go:build windows

package atomicwrite

// SetPreRenameHook installs a function that would be called immediately before
// the atomic rename. On Windows, performAtomicRename currently returns
// ErrAtomicWriteWindowsUnsupported before reaching the hook, so the hook is
// never invoked. This symbol is retained so that test code referencing it
// compiles on Windows; it will become meaningful when the Windows write-path
// slice is implemented.
//
// This symbol exists only in test binaries (it lives in a _test.go file).
func SetPreRenameHook(fn func()) {
	preRenameHook = fn
}

// SetPostRenameHook is the Windows stub for the post-rename test hook. On
// Windows, performAtomicRename returns ErrAtomicWriteWindowsUnsupported before
// any rename occurs, so the hook is never invoked. This symbol is retained for
// cross-platform test-file compilation.
func SetPostRenameHook(fn func()) {
	postRenameHook = fn
}

// SetNextTempSuffixHook is the Windows stub for the temp-suffix test hook.
// On Windows, the temp-create path is not reached (performAtomicRename returns
// ErrAtomicWriteWindowsUnsupported before temp creation). This symbol is
// retained for cross-platform test-file compilation.
func SetNextTempSuffixHook(fn func(suffix string)) {
	nextTempSuffixHook = fn
}
