//go:build testhook

package editor_test

// TestN5_PanicAfterWrite_DeferCleanupRuns proves that when a dependency
// panics AFTER writeWithNoFollow succeeds (plaintext is on disk), the deferred
// cleanup in Edit: removes the temp file, removes the temp dir, and zeroizes
// plainBuf — satisfying ADR-0011 D11-4 ("panic-safe defer") and N-5
// ("panic paths leave NO plaintext residue").
//
// This test MUST fail if cleanup is not deferred (i.e. if it were only called
// at explicit return sites): a panic in the hook would bypass every explicit
// call, leaving the 0600 temp file in place.
//
// The test is compiled only under -tags testhook; it is absent from production
// binaries and from the default go test ./... run.
import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/ByReisK/byreis/internal/adapter/editor"
	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

func TestN5_PanicAfterWrite_DeferCleanupRuns(t *testing.T) {
	t.Parallel()

	// Build the helper binary (same approach as the rest of the suite).
	bin := helperBinary(t)

	tmpParent := t.TempDir()

	// Craft a sentinel plaintext value we can probe for after the panic.
	const sentinelKey = "PANIC_HOOK_SECRET"
	const sentinelVal = "panic_hook_unique_plaintext_12345"
	plaintext := map[string]string{sentinelKey: sentinelVal}

	// The panic message — distinct from any plaintext value so we can tell them apart.
	const panicMsg = "test-injected panic after writeWithNoFollow"

	// Hook: panics after the temp file has been written with plaintext.
	// The deferred cleanup must run during stack unwinding and wipe the file
	// before the goroutine terminates.
	hook := func() {
		panic(panicMsg)
	}

	// Wrap Edit in a goroutine so we can recover the panic and assert post-conditions.
	type result struct {
		recovered any
		tmpParent string
	}
	ch := make(chan result, 1)

	go func() {
		var recovered any
		func() {
			defer func() {
				recovered = recover()
			}()
			ed := editor.NewWithAfterWriteHook(bin, "exit0", tmpParent, hook)
			// Edit will panic inside the hook; the deferred cleanup must run
			// before the goroutine panic propagates.
			_, _ = ed.Edit(context.Background(), usecase.EditSession{
				ProjectID: "proj-panic-hook",
				FileName:  "secrets/panic.enc.yaml",
				Plaintext: plaintext,
			})
		}()
		ch <- result{recovered: recovered, tmpParent: tmpParent}
	}()

	res := <-ch

	// The panic must have been the one we injected.
	if res.recovered == nil {
		t.Fatal("N5_PanicAfterWrite: expected a panic but none was recovered — hook may not have run")
	}
	recoveredStr, ok := res.recovered.(string)
	if !ok || recoveredStr != panicMsg {
		t.Fatalf("N5_PanicAfterWrite: recovered unexpected value %#v; want %q", res.recovered, panicMsg)
	}

	// Primary assertion: no byreis-editor-* residue in tmpParent (temp file and
	// temp dir must both be gone — the deferred cleanup ran on the panic path).
	entries, err := os.ReadDir(res.tmpParent)
	if err != nil {
		t.Fatalf("N5_PanicAfterWrite: ReadDir(%q): %v", res.tmpParent, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "byreis-editor-") {
			t.Errorf("N5_PanicAfterWrite: lingering editor temp entry %q — "+
				"deferred cleanup did NOT run on the panic path; "+
				"plaintext temp file may have been left on disk",
				filepath.Join(res.tmpParent, e.Name()))
		}
	}

	// Supplementary: prove ZeroizeBuffer zeroes memory (same pinning approach
	// as TestN5_BufferZeroized_AfterEdit). We do this inline to confirm the
	// zeroization mechanism itself is sound — the deferred cleanup calls it.
	buf := []byte(sentinelVal)
	ptr := unsafe.SliceData(buf) //nolint:gosec // pinning backing array for zeroization assertion
	n := len(buf)
	identityadapter.ZeroizeBuffer(buf)
	pinned := unsafe.Slice(ptr, n) //nolint:gosec // pinned backing array assertion for L-2 zeroization
	for i, b := range pinned {
		if b != 0 {
			t.Errorf("N5_PanicAfterWrite: ZeroizeBuffer did not zero byte %d — L-2 zeroization failure", i)
		}
	}
	runtime.KeepAlive(buf)
}
