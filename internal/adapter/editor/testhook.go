//go:build testhook

package editor

import "github.com/ByReisK/byreis/internal/core/usecase"

// NewWithAfterWriteHook constructs a usecase.Editor that invokes hook
// immediately after writeWithNoFollow succeeds (plaintext is on disk) and
// before the editor binary is launched.
//
// This constructor is compiled only under the testhook build tag; it is absent
// from production binaries. Its sole purpose is to let panic-injection tests
// prove that the deferred cleanup in Edit covers the panic path: a hook that
// panics forces the deferred cleanup to run, and the test recovers and asserts
// the temp file/dir are gone and plainBuf is zeroized.
//
// The hook is stored in editorAdapter.postWriteHook, a field that is always
// present in the struct but is nil in all production constructors. Only this
// test-tagged constructor sets a non-nil value, so the panic-injection surface
// is unreachable without -tags testhook.
func NewWithAfterWriteHook(binPath, directive, tmpParent string, hook func()) usecase.Editor {
	return &editorAdapter{
		cmd:           binPath,
		extraArgs:     []string{directive},
		tmpParent:     tmpParent,
		postWriteHook: hook,
	}
}
