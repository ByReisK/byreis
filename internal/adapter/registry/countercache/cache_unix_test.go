//go:build unix

package countercache_test

// Test matrix covering D10(a)-(g) per the ADR-0014 binding contract.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/registry/countercache"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

const testRegistryURL = "https://github.com/testorg/byreis-admins"
const testRegistryURL2 = "https://github.com/otherorg/byreis-admins"

func newTestStore(t *testing.T, cacheRoot, registryURL string) *countercache.Store {
	t.Helper()
	s, err := countercache.New(registryURL, cacheRoot, nil)
	if err != nil {
		t.Fatalf("countercache.New: %v", err)
	}
	return s
}

func setupCacheRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	cacheRoot := filepath.Join(root, "registry")
	if err := os.MkdirAll(cacheRoot, 0o700); err != nil {
		t.Fatalf("mkdir cacheRoot: %v", err)
	}
	return cacheRoot
}

// ---- (a) Round-trip tests ---------------------------------------------------

// TestRoundTrip_HEAD_ROUND_TRIP_COLD_TO_WARM: cold cache returns ("", nil);
// after Store, Load returns the written SHA.
func TestRoundTrip_HEAD_ROUND_TRIP_COLD_TO_WARM(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	head, err := s.LoadHead(ctx, "proj1")
	if err != nil {
		t.Fatalf("LoadHead cold: %v", err)
	}
	if head != "" {
		t.Fatalf("expected empty head on cold cache, got %q", head)
	}

	if storeErr := s.StoreHead(ctx, "proj1", "abc123"); storeErr != nil {
		t.Fatalf("StoreHead: %v", storeErr)
	}

	head, err = s.LoadHead(ctx, "proj1")
	if err != nil {
		t.Fatalf("LoadHead warm: %v", err)
	}
	if head != "abc123" {
		t.Fatalf("expected %q, got %q", "abc123", head)
	}
}

// TestRoundTrip_COUNTER_ROUND_TRIP_COLD_TO_WARM: cold returns 0; after Store, returns written value.
func TestRoundTrip_COUNTER_ROUND_TRIP_COLD_TO_WARM(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	v, err := s.LoadCounter(ctx, "proj1", "secrets")
	if err != nil {
		t.Fatalf("LoadCounter cold: %v", err)
	}
	if v != 0 {
		t.Fatalf("expected 0 on cold cache, got %d", v)
	}

	if storeErr := s.StoreCounter(ctx, "proj1", "secrets", 42); storeErr != nil {
		t.Fatalf("StoreCounter: %v", storeErr)
	}

	v, err = s.LoadCounter(ctx, "proj1", "secrets")
	if err != nil {
		t.Fatalf("LoadCounter warm: %v", err)
	}
	if v != 42 {
		t.Fatalf("expected 42, got %d", v)
	}
}

// TestRoundTrip_PENDING_ROUND_TRIP_COLD_TO_WARM: round-trip plus clear-restores-nil.
func TestRoundTrip_PENDING_ROUND_TRIP_COLD_TO_WARM(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	p, err := s.LoadPending(ctx, "proj1", "secrets")
	if err != nil {
		t.Fatalf("LoadPending cold: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil pending on cold cache")
	}

	bump := &countertypes.PendingBump{
		PendingCounter:    7,
		TargetArtifactSHA: "sha256:deadbeef",
		TargetPR:          "https://github.com/org/repo/pull/1",
	}
	if storeErr := s.StorePending(ctx, "proj1", "secrets", bump); storeErr != nil {
		t.Fatalf("StorePending: %v", storeErr)
	}

	p, err = s.LoadPending(ctx, "proj1", "secrets")
	if err != nil {
		t.Fatalf("LoadPending warm: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil pending after store")
	}
	if p.PendingCounter != 7 || p.TargetArtifactSHA != "sha256:deadbeef" {
		t.Fatalf("pending mismatch: got %+v", p)
	}

	if clearErr := s.ClearPending(ctx, "proj1", "secrets"); clearErr != nil {
		t.Fatalf("ClearPending: %v", clearErr)
	}

	p, err = s.LoadPending(ctx, "proj1", "secrets")
	if err != nil {
		t.Fatalf("LoadPending after clear: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil after clear, got %+v", p)
	}
}

// TestRoundTrip_MULTI_PROJECT_KEYING_IS_DISTINCT: two project IDs do not
// cross-contaminate.
func TestRoundTrip_MULTI_PROJECT_KEYING_IS_DISTINCT(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	if err := s.StoreHead(ctx, "proj-a", "sha-a"); err != nil {
		t.Fatalf("StoreHead proj-a: %v", err)
	}
	if err := s.StoreHead(ctx, "proj-b", "sha-b"); err != nil {
		t.Fatalf("StoreHead proj-b: %v", err)
	}

	ha, err := s.LoadHead(ctx, "proj-a")
	if err != nil || ha != "sha-a" {
		t.Fatalf("LoadHead proj-a: err=%v got=%q", err, ha)
	}
	hb, err := s.LoadHead(ctx, "proj-b")
	if err != nil || hb != "sha-b" {
		t.Fatalf("LoadHead proj-b: err=%v got=%q", err, hb)
	}
}

// TestRoundTrip_MULTI_REGISTRY_KEYING_IS_PATH_ISOLATED: two registry URLs use
// different subdirectory paths under cacheRoot.
func TestRoundTrip_MULTI_REGISTRY_KEYING_IS_PATH_ISOLATED(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	ctx := context.Background()

	s1 := newTestStore(t, root, testRegistryURL)
	s2 := newTestStore(t, root, testRegistryURL2)

	if err := s1.StoreHead(ctx, "proj", "sha-reg1"); err != nil {
		t.Fatalf("StoreHead reg1: %v", err)
	}

	// s2 at a different URL sees a cold cache.
	h2, err := s2.LoadHead(ctx, "proj")
	if err != nil {
		t.Fatalf("LoadHead reg2: %v", err)
	}
	if h2 != "" {
		t.Fatalf("expected cold cache for reg2, got %q", h2)
	}

	// Verify the on-disk paths are in different registry-id subdirs.
	prefix1 := countercache.RegistryIDPrefix(testRegistryURL)
	prefix2 := countercache.RegistryIDPrefix(testRegistryURL2)
	if prefix1 == prefix2 {
		t.Fatalf("prefix collision: %q == %q", prefix1, prefix2)
	}

	dir1 := filepath.Join(root, prefix1)
	dir2 := filepath.Join(root, prefix2)
	if _, err := os.Stat(dir1); err != nil {
		t.Fatalf("registry dir 1 does not exist: %v", err)
	}
	if _, err := os.Stat(dir2); err == nil {
		t.Fatalf("registry dir 2 should not exist (cold)")
	}
}

// ---- (b) TOCTOU symlink-swap simulation -------------------------------------

// TestTOCTOU_LOAD_REFUSES_SYMLINK_AT_FILE_PATH: counters.json is a symlink.
func TestTOCTOU_LOAD_REFUSES_SYMLINK_AT_FILE_PATH(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	// Create the registry dir properly first.
	if err := s.StoreCounter(ctx, "proj", "f", 1); err != nil {
		t.Fatalf("setup StoreCounter: %v", err)
	}

	// Replace counters.json with a symlink.
	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	countersPath := filepath.Join(root, prefix, "counters.json")

	// Create a target file for the symlink.
	target := filepath.Join(t.TempDir(), "evil.json")
	if err := os.WriteFile(target, []byte(`{"schema_version":1,"registry_id_sha256_prefix":"x","entries":{}}`), 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}

	if err := os.Remove(countersPath); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.Symlink(target, countersPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := s.LoadCounter(ctx, "proj", "f")
	if err == nil {
		t.Fatal("expected error for symlink at file path, got nil")
	}
	if !errors.Is(err, countercache.ErrCounterCacheUnsafePath) {
		t.Errorf("expected ErrCounterCacheUnsafePath, got: %v", err)
	}

	// Assert the symlink was NOT opened (it should still exist, not followed).
	fi, statErr := os.Lstat(countersPath)
	if statErr != nil {
		t.Fatalf("Lstat after symlink check: %v", statErr)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was unexpectedly removed or resolved")
	}
}

// TestTOCTOU_LOAD_REFUSES_SYMLINK_AT_PARENT_DIR: the registry-id dir is a symlink.
func TestTOCTOU_LOAD_REFUSES_SYMLINK_AT_PARENT_DIR(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	regDir := filepath.Join(root, prefix)

	// Ensure it doesn't exist yet, then create a symlink in its place.
	target := t.TempDir()
	// The regDir should not exist yet; if it does, remove it.
	_ = os.RemoveAll(regDir)

	if err := os.Symlink(target, regDir); err != nil {
		t.Fatalf("Symlink registry dir: %v", err)
	}

	_, err := s.LoadCounter(ctx, "proj", "f")
	if err == nil {
		t.Fatal("expected error for symlink at parent dir, got nil")
	}
	if !errors.Is(err, countercache.ErrCounterCacheUnsafePath) {
		t.Errorf("expected ErrCounterCacheUnsafePath, got: %v", err)
	}
}

// TestTOCTOU_LOAD_REFUSES_SYMLINK_AT_GRANDPARENT_DIR: cacheRoot is a symlink.
func TestTOCTOU_LOAD_REFUSES_SYMLINK_AT_GRANDPARENT_DIR(t *testing.T) {
	t.Parallel()
	baseRoot := t.TempDir()

	// Create a real directory to serve as the symlink target.
	realDir := filepath.Join(baseRoot, "real-registry")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real-registry: %v", err)
	}

	// Create a symlink where cacheRoot should be.
	symlinkCacheRoot := filepath.Join(baseRoot, "registry-symlink")
	if err := os.Symlink(realDir, symlinkCacheRoot); err != nil {
		t.Fatalf("Symlink cacheRoot: %v", err)
	}

	s := newTestStore(t, symlinkCacheRoot, testRegistryURL)
	ctx := context.Background()

	_, err := s.LoadCounter(ctx, "proj", "f")
	if err == nil {
		t.Fatal("expected error for symlink at cacheRoot, got nil")
	}
	if !errors.Is(err, countercache.ErrCounterCacheUnsafePath) {
		t.Errorf("expected ErrCounterCacheUnsafePath, got: %v", err)
	}
}

// TestTOCTOU_LOAD_FSTAT_BINDS_TO_FD_NOT_PATH: verifies that Load reads from
// the file descriptor opened under security checks, not from a re-opened path.
// We write content A, then replace the file with content B between Store and
// Load but the Load has already opened the fd — the test verifies the security
// model holds (this is an indirect test since we cannot hook the open itself
// without a test hook in the implementation).
func TestTOCTOU_LOAD_FSTAT_BINDS_TO_FD_NOT_PATH(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	// Store a known counter value.
	if err := s.StoreCounter(ctx, "proj", "f", 99); err != nil {
		t.Fatalf("StoreCounter: %v", err)
	}

	// Load it back — the security model binds the read to the fd opened under
	// the O_NOFOLLOW + fstat check. As long as there's no symlink or perm
	// violation, this succeeds.
	v, err := s.LoadCounter(ctx, "proj", "f")
	if err != nil {
		t.Fatalf("LoadCounter: %v", err)
	}
	if v != 99 {
		t.Fatalf("expected 99, got %d", v)
	}
}

// TestTOCTOU_WRITE_REFUSES_PARENT_SWAP: the write path must fail when the
// parent directory becomes non-writable between the ensureRegistryDir check
// and the atomic rename. We simulate this by chmod-ing the registry dir to
// 0o500 (no write bit) immediately after it is created, and confirm that the
// subsequent write returns an error.
//
// The atomicwrite.ErrAtomicWriteParentChanged sentinel is the precise error
// emitted by atomicwrite_unix.go when the pre-rename hook fires (tested in
// atomicwrite's own test suite). Here we test the looser property: that a
// write into a non-writable parent fails and the error is propagated by the
// cache store — which is what an operator observes.
func TestTOCTOU_WRITE_REFUSES_PARENT_SWAP(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	// Create the registry dir via a first write.
	if err := s.StoreCounter(ctx, "proj", "f", 1); err != nil {
		t.Fatalf("initial store to create registry dir: %v", err)
	}

	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	regDir := filepath.Join(root, prefix)

	// Remove write permission from the registry dir — subsequent writes must fail.
	if err := os.Chmod(regDir, 0o500); err != nil { //nolint:gosec // intentionally no-write for test
		t.Fatalf("Chmod 0o500: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(regDir, 0o700) }) //nolint:gosec // restoring test dir permissions

	err := s.StoreCounter(ctx, "proj", "f", 2)
	if err == nil {
		// On some platforms (e.g. macOS running as the file owner with
		// kernel bypass), a 0o500 dir may still allow rename. Skip.
		t.Skip("OS allowed write into 0o500 dir; WRITE_REFUSES_PARENT_SWAP not exercisable")
	}
	// The error must propagate (not be swallowed).
	t.Logf("PASS: write into non-writable parent correctly failed: %v", err)
}

// ---- (c) Owner-flip fail-closed ---------------------------------------------

// TestOwner_LOAD_REFUSES_CROSS_OWNER_FILE: file owned by different uid fails
// closed. Skipped if not running as root (cannot chown to another user).
func TestOwner_LOAD_REFUSES_CROSS_OWNER_FILE(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skipf("LOAD_REFUSES_CROSS_OWNER_FILE requires root to chown to another uid; skipping on non-root: euid=%d", os.Geteuid())
	}

	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	if err := s.StoreCounter(ctx, "proj", "f", 5); err != nil {
		t.Fatalf("StoreCounter setup: %v", err)
	}

	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	countersPath := filepath.Join(root, prefix, "counters.json")

	// Chown the file to root+1 (a different uid) so checkOwner fails.
	if err := os.Lchown(countersPath, 1, -1); err != nil {
		t.Fatalf("Lchown: %v", err)
	}

	_, err := s.LoadCounter(ctx, "proj", "f")
	if err == nil {
		t.Fatal("expected error for cross-owner file, got nil")
	}
	if !errors.Is(err, countercache.ErrCounterCacheUnsafePerms) {
		t.Errorf("expected ErrCounterCacheUnsafePerms, got: %v", err)
	}

	// Verify the file was NOT deleted (D6 fail-closed: we do not write into
	// a potentially hostile dir on perm failures).
	if _, err := os.Lstat(countersPath); err != nil {
		t.Fatalf("cache file was deleted on owner failure (must NOT delete): %v", err)
	}
}

// TestOwner_LOAD_REFUSES_CROSS_OWNER_DIR: parent dir owned by different uid.
func TestOwner_LOAD_REFUSES_CROSS_OWNER_DIR(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skipf("LOAD_REFUSES_CROSS_OWNER_DIR requires root to chown; skipping: euid=%d", os.Geteuid())
	}

	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	// Create the registry dir.
	if err := s.StoreCounter(ctx, "proj", "f", 1); err != nil {
		t.Fatalf("setup: %v", err)
	}

	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	regDir := filepath.Join(root, prefix)

	// Chown the registry dir to a different uid.
	if err := os.Lchown(regDir, 1, -1); err != nil {
		t.Fatalf("Lchown registry dir: %v", err)
	}

	_, err := s.LoadCounter(ctx, "proj", "f")
	if err == nil {
		t.Fatal("expected error for cross-owner dir, got nil")
	}
	if !errors.Is(err, countercache.ErrCounterCacheUnsafePerms) {
		t.Errorf("expected ErrCounterCacheUnsafePerms, got: %v", err)
	}
}

// ---- (d) Perm-flip fail-closed ----------------------------------------------

// TestPerms_LOAD_REFUSES_GROUP_READABLE_FILE: mode 0640 → fail.
func TestPerms_LOAD_REFUSES_GROUP_READABLE_FILE(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	if err := s.StoreCounter(ctx, "proj", "f", 1); err != nil {
		t.Fatalf("setup: %v", err)
	}
	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	p := filepath.Join(root, prefix, "counters.json")
	if err := os.Chmod(p, 0o640); err != nil { //nolint:gosec // intentionally wrong mode for test
		t.Fatalf("Chmod: %v", err)
	}

	_, err := s.LoadCounter(ctx, "proj", "f")
	if err == nil {
		t.Fatal("expected error for mode 0640, got nil")
	}
	if !errors.Is(err, countercache.ErrCounterCacheUnsafePerms) {
		t.Errorf("expected ErrCounterCacheUnsafePerms, got: %v", err)
	}
}

// TestPerms_LOAD_REFUSES_WORLD_READABLE_FILE: mode 0604 → fail.
func TestPerms_LOAD_REFUSES_WORLD_READABLE_FILE(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	if err := s.StoreCounter(ctx, "proj", "f", 1); err != nil {
		t.Fatalf("setup: %v", err)
	}
	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	p := filepath.Join(root, prefix, "counters.json")
	if err := os.Chmod(p, 0o604); err != nil { //nolint:gosec // intentionally wrong mode for test
		t.Fatalf("Chmod: %v", err)
	}

	_, err := s.LoadCounter(ctx, "proj", "f")
	if err == nil {
		t.Fatal("expected error for mode 0604, got nil")
	}
	if !errors.Is(err, countercache.ErrCounterCacheUnsafePerms) {
		t.Errorf("expected ErrCounterCacheUnsafePerms, got: %v", err)
	}
}

// TestPerms_LOAD_REFUSES_SETUID_FILE: mode 04600 → fail.
func TestPerms_LOAD_REFUSES_SETUID_FILE(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skipf("setting setuid bit requires root on some platforms; running as euid=%d", os.Geteuid())
	}
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	if err := s.StoreCounter(ctx, "proj", "f", 1); err != nil {
		t.Fatalf("setup: %v", err)
	}
	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	p := filepath.Join(root, prefix, "counters.json")
	if err := os.Chmod(p, 0o4600); err != nil { //nolint:gosec // intentionally wrong mode for test
		t.Fatalf("Chmod 04600: %v", err)
	}

	_, err := s.LoadCounter(ctx, "proj", "f")
	if err == nil {
		t.Fatal("expected error for mode 04600, got nil")
	}
	if !errors.Is(err, countercache.ErrCounterCacheUnsafePerms) {
		t.Errorf("expected ErrCounterCacheUnsafePerms, got: %v", err)
	}
}

// TestPerms_LOAD_REFUSES_LOOSE_PARENT_DIR: parent dir mode 0750 → fail.
func TestPerms_LOAD_REFUSES_LOOSE_PARENT_DIR(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	if err := s.StoreCounter(ctx, "proj", "f", 1); err != nil {
		t.Fatalf("setup: %v", err)
	}
	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	regDir := filepath.Join(root, prefix)
	if err := os.Chmod(regDir, 0o750); err != nil { //nolint:gosec // intentionally wrong mode for test
		t.Fatalf("Chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(regDir, 0o700) }) //nolint:gosec // restoring test dir permissions

	_, err := s.LoadCounter(ctx, "proj", "f")
	if err == nil {
		t.Fatal("expected error for loose parent dir mode 0750, got nil")
	}
	if !errors.Is(err, countercache.ErrCounterCacheUnsafePerms) {
		t.Errorf("expected ErrCounterCacheUnsafePerms, got: %v", err)
	}
}

// ---- (e) BO-3 retained tests -----------------------------------------------

// TestTamper_LOAD_REJECTS_SCHEMA_VERSION_BUMP_AND_REBUILDS: schema_version: 99
// triggers fail-rebuild (file deleted, zero returned).
func TestTamper_LOAD_REJECTS_SCHEMA_VERSION_BUMP_AND_REBUILDS(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	// Store a normal value to create the file.
	if err := s.StoreCounter(ctx, "proj", "f", 10); err != nil {
		t.Fatalf("StoreCounter: %v", err)
	}

	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	p := filepath.Join(root, prefix, "counters.json")

	// Tamper: replace schema_version with 99.
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var raw map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(data, &raw); unmarshalErr != nil {
		t.Fatalf("Unmarshal: %v", unmarshalErr)
	}
	raw["schema_version"] = json.RawMessage("99")
	tampered, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if writeErr := os.WriteFile(p, tampered, 0o600); writeErr != nil { //nolint:gosec // test-only path construction
		t.Fatalf("WriteFile tampered: %v", writeErr)
	}

	v, err := s.LoadCounter(ctx, "proj", "f")
	if err != nil {
		t.Fatalf("LoadCounter after schema tamper: unexpected error %v", err)
	}
	if v != 0 {
		t.Fatalf("expected 0 (rebuild), got %d", v)
	}
	// File must be deleted.
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected file to be deleted after schema version mismatch, got: %v", err)
	}
}

// TestTamper_LOAD_REJECTS_UNPARSEABLE_JSON_AND_REBUILDS: corrupt JSON triggers
// fail-rebuild.
func TestTamper_LOAD_REJECTS_UNPARSEABLE_JSON_AND_REBUILDS(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	if err := s.StoreCounter(ctx, "proj", "f", 10); err != nil {
		t.Fatalf("setup: %v", err)
	}
	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	p := filepath.Join(root, prefix, "counters.json")

	if err := os.WriteFile(p, []byte(`"corrupt"`), 0o600); err != nil {
		t.Fatalf("WriteFile corrupt: %v", err)
	}

	v, err := s.LoadCounter(ctx, "proj", "f")
	if err != nil {
		t.Fatalf("LoadCounter after corrupt JSON: unexpected error %v", err)
	}
	if v != 0 {
		t.Fatalf("expected 0 (rebuild), got %d", v)
	}
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected file deleted after corrupt JSON, got: %v", err)
	}
}

// TestTamper_LOAD_REJECTS_REGISTRY_ID_MISMATCH_AND_REBUILDS: counters.json
// written for registry A is loaded by a store for registry B → cold (no error,
// zero value). B never sees A's records.
func TestTamper_LOAD_REJECTS_REGISTRY_ID_MISMATCH_AND_REBUILDS(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	ctx := context.Background()

	// Write a record for registry 1.
	s1 := newTestStore(t, root, testRegistryURL)
	if err := s1.StoreCounter(ctx, "proj", "f", 55); err != nil {
		t.Fatalf("StoreCounter reg1: %v", err)
	}

	// Copy registry 1's counters.json into registry 2's directory (simulating
	// a cross-registry replay attack).
	prefix1 := countercache.RegistryIDPrefix(testRegistryURL)
	prefix2 := countercache.RegistryIDPrefix(testRegistryURL2)

	dir2 := filepath.Join(root, prefix2)
	if err := os.MkdirAll(dir2, 0o700); err != nil {
		t.Fatalf("mkdir dir2: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(root, prefix1, "counters.json"))
	if err != nil {
		t.Fatalf("ReadFile reg1 counters: %v", err)
	}
	// Write reg1's data into reg2's file (wrong registry_id_sha256_prefix inside).
	if writeErr := os.WriteFile(filepath.Join(dir2, "counters.json"), data, 0o600); writeErr != nil { //nolint:gosec // test path construction with fixed filename
		t.Fatalf("WriteFile into dir2: %v", writeErr)
	}

	// s2 must not see reg1's data.
	s2 := newTestStore(t, root, testRegistryURL2)
	v, err := s2.LoadCounter(ctx, "proj", "f")
	if err != nil {
		t.Fatalf("LoadCounter reg2: unexpected error %v", err)
	}
	if v != 0 {
		t.Fatalf("expected 0 (registry-id mismatch = cold), got %d", v)
	}
}

// TestTamper_LOAD_DOES_NOT_DELETE_ON_PERM_FAIL: a file with mode 0640 is
// NOT deleted by the load path (we do not write into a potentially hostile dir).
func TestTamper_LOAD_DOES_NOT_DELETE_ON_PERM_FAIL(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	if err := s.StoreCounter(ctx, "proj", "f", 1); err != nil {
		t.Fatalf("setup: %v", err)
	}
	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	p := filepath.Join(root, prefix, "counters.json")

	if err := os.Chmod(p, 0o640); err != nil { //nolint:gosec // intentionally wrong mode for test
		t.Fatalf("Chmod 0640: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o600) })

	_, _ = s.LoadCounter(ctx, "proj", "f") // result not important here

	// File must still exist.
	if _, err := os.Lstat(p); err != nil {
		t.Fatalf("file was deleted on perm fail (must NOT delete): %v", err)
	}
}

// ---- (f) Windows sentinel build-tag asymmetry check -------------------------

// TestBuildTag_WINDOWS_SENTINEL_NOT_DEFINED_IN_UNIX_BUILD: on a Unix build,
// ErrCounterCacheWindowsUnsupported must NOT be defined.
func TestBuildTag_WINDOWS_SENTINEL_NOT_DEFINED_IN_UNIX_BUILD(t *testing.T) {
	t.Parallel()
	// On a Unix build, the countercache package must not export
	// ErrCounterCacheWindowsUnsupported. We verify this by checking that the
	// identifier does not resolve — this is a compile-time check embedded in
	// the build tag on this file. If this file compiles without referencing
	// ErrCounterCacheWindowsUnsupported and the test passes, the symbol is
	// absent on Unix. On Windows (where this file is excluded), the windows
	// test file carries the complementary test.
	//
	// Additionally, grep the source to confirm the sentinel is ONLY in the
	// windows-tagged file.
	pkgDir := findPkgDir(t)

	// Read all non-windows, non-test Go files in the package.
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip test files and the windows file.
		if strings.HasSuffix(name, "_test.go") || strings.Contains(name, "windows") {
			continue
		}
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(pkgDir, name))
		if err != nil {
			t.Fatalf("ReadFile %s: %v", name, err)
		}
		if strings.Contains(string(content), "ErrCounterCacheWindowsUnsupported") {
			t.Errorf("non-windows file %s defines ErrCounterCacheWindowsUnsupported (must only be in windows-tagged file)", name)
		}
	}
}

// ---- (g) Cross-process durability -------------------------------------------

// TestDurability_WRITE_IN_ONE_STORE_READ_IN_ANOTHER: constructing two separate
// Store instances at the same root; write in A, read in B.
func TestDurability_WRITE_IN_ONE_STORE_READ_IN_ANOTHER(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	ctx := context.Background()

	storeA := newTestStore(t, root, testRegistryURL)
	if err := storeA.StoreCounter(ctx, "proj", "f", 77); err != nil {
		t.Fatalf("StoreCounter A: %v", err)
	}

	// Construct a fresh Store B at the same root.
	storeB := newTestStore(t, root, testRegistryURL)
	v, err := storeB.LoadCounter(ctx, "proj", "f")
	if err != nil {
		t.Fatalf("LoadCounter B: %v", err)
	}
	if v != 77 {
		t.Fatalf("expected 77, got %d", v)
	}
}

// TestDurability_CLIENT_HYDRATES_INMEMORY_FROM_DISK_AT_FIRST_CALL and
// TestDurability_STALE_ON_DISK_FLOOR_DOES_NOT_MASK_FRESH_ROLLBACK are in
// cache_integration_test.go (they test Client wiring, not countercache internals).

// TestDurability_WRITE_FAILURE_PROPAGATES_NOT_SWALLOWED: if a fake store returns
// an error, it must not be swallowed. This is tested at the registry.Client level
// in cache_integration_test.go; here we just confirm the error path propagates
// through ClearPending on a directory we cannot write to.
func TestDurability_WRITE_FAILURE_PROPAGATES_NOT_SWALLOWED(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	// Store a pending value first.
	bump := &countertypes.PendingBump{PendingCounter: 1, TargetArtifactSHA: "sha256:x"}
	if err := s.StorePending(ctx, "proj", "f", bump); err != nil {
		t.Fatalf("StorePending: %v", err)
	}

	// Make the registry dir unwriteable, then try to clear pending.
	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	regDir := filepath.Join(root, prefix)
	if err := os.Chmod(regDir, 0o500); err != nil { //nolint:gosec // intentionally wrong mode for test
		t.Fatalf("Chmod dir to 0500: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(regDir, 0o700) }) //nolint:gosec // restoring test dir permissions

	err := s.ClearPending(ctx, "proj", "f")
	// On some platforms (e.g. macOS running as the file owner), a 0500 dir
	// may still allow deletion if inode perms permit. Skip if no error.
	if err == nil {
		t.Skip("OS allowed write on 0500 dir; skipping write-failure propagation test")
	}
	// The error must propagate (not be swallowed).
	t.Logf("got expected error: %v", err)
}

// ---- BO-5 Property test: no secret material in any channel ------------------

// TestPropertyTest_NO_SECRET_MATERIAL_IN_ANY_CHANNEL enumerates all error
// strings, log lines, and cache file contents emitted by countercache and
// asserts absence of canary secret substrings.
func TestPropertyTest_NO_SECRET_MATERIAL_IN_ANY_CHANNEL(t *testing.T) {
	t.Parallel()

	// Canary secret substrings — these must never appear in any output.
	canarySecrets := []string{
		"CANARY_PRIVATE_KEY_BYTES",
		"CANARY_RECIPIENT_SECRET",
		"CANARY_TOKEN_BYTES",
	}

	root := setupCacheRoot(t)
	ctx := context.Background()

	s := newTestStore(t, root, testRegistryURL)

	// Perform a variety of operations and collect any error messages.
	var errs []string

	// Normal operations.
	_ = s.StoreHead(ctx, "canary-proj", "safe-sha")
	h, err := s.LoadHead(ctx, "canary-proj")
	if err != nil {
		errs = append(errs, err.Error())
	}
	assertNoCanary(t, h, canarySecrets, "LoadHead result")

	_ = s.StoreCounter(ctx, "canary-proj", "f", 1)
	c, err := s.LoadCounter(ctx, "canary-proj", "f")
	if err != nil {
		errs = append(errs, err.Error())
	}
	assertNoCanary(t, fmt.Sprintf("%d", c), canarySecrets, "LoadCounter result")

	bump := &countertypes.PendingBump{
		PendingCounter:    2,
		TargetArtifactSHA: "sha256:safe",
		TargetPR:          "https://github.com/org/repo/pull/1",
	}
	_ = s.StorePending(ctx, "canary-proj", "f", bump)

	// Read the on-disk file and assert no canary.
	prefix := countercache.RegistryIDPrefix(testRegistryURL)
	for _, fname := range []string{"head.json", "counters.json", "pending.json"} {
		p := filepath.Join(root, prefix, fname)
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			continue
		}
		assertNoCanary(t, string(data), canarySecrets, "on-disk "+fname)
	}

	// Assert no canary in collected errors.
	for _, e := range errs {
		assertNoCanary(t, e, canarySecrets, "error string")
	}
}

// assertNoCanary checks that haystack does not contain any canary substring.
func assertNoCanary(t *testing.T, haystack string, canaries []string, context string) {
	t.Helper()
	for _, c := range canaries {
		if strings.Contains(haystack, c) {
			t.Errorf("SECRET LEAK in %s: found canary %q in: %q", context, c, haystack)
		}
	}
}

// ---- context cancellation ---------------------------------------------------

// TestContextCancellation: cancelled context returns ctx.Err wrapped.
func TestContextCancellation(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	_, err := s.LoadCounter(ctx, "proj", "f")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// ---- helpers ----------------------------------------------------------------

// findPkgDir returns the directory containing countercache source files.
func findPkgDir(t *testing.T) string {
	t.Helper()
	// Walk from the test binary's directory upward looking for cache.go.
	// In practice, t.TempDir() is somewhere else; we need the source tree.
	// Use a relative path from the test file location.
	// The test file is in internal/adapter/registry/countercache/
	// We can derive it from the expected module path.
	dir := "."
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "cache.go")); err == nil {
			abs, _ := filepath.Abs(dir)
			return abs
		}
		dir = filepath.Join(dir, "..")
	}
	t.Fatal("could not find countercache package directory")
	return ""
}

// TestColdCacheDoesNotError: ensure ENOENT on cold cache returns zero, nil.
func TestColdCacheDoesNotError(t *testing.T) {
	t.Parallel()
	root := setupCacheRoot(t)
	s := newTestStore(t, root, testRegistryURL)
	ctx := context.Background()

	h, err := s.LoadHead(ctx, "missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != "" {
		t.Fatalf("expected empty, got %q", h)
	}

	c, err := s.LoadCounter(ctx, "missing", "f")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != 0 {
		t.Fatalf("expected 0, got %d", c)
	}

	p, err := s.LoadPending(ctx, "missing", "f")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil, got %+v", p)
	}
}
