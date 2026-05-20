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
