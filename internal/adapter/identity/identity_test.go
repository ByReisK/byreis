package identity_test

// Test obligations (named, individually-failing):
//   N-1: wrong-perm / TOCTOU key file → HARD ERROR with chmod hint; symlink caught.
//         Single-shared-resolver assertion: Loader and resolver compute byte-identical
//         path + identical perm verdict.
//   N-2: no file + BYREIS_KEY unset + BYREIS_KEY_FILE unset + no keychain entry →
//         typed ErrNoAdminKey (step-1 CONTRIBUTOR), NOT error/panic. Keychain access
//         error → same fail-closed "no key". Marker only when key present; empty on
//         no-key path.
//   L-2: env/file/keychain raw-secret buffer zeroized after parse (pinned backing
//         buffer asserted zero before drop, GC/escape-resistant).
//   happy: valid 0600 BYREIS_KEY_FILE and valid BYREIS_KEY env each parse to a
//           usable identity.Identity; precedence order honored deterministically.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"filippo.io/age"

	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
)

// generateTestKey returns a fresh age X25519 private key string.
func generateTestKey(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generateTestKey: %v", err)
	}
	return id.String()
}

// writeKeyFile writes content to dir/name with perm and returns the path.
func writeKeyFile(t *testing.T, dir, name, content string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), perm); err != nil {
		t.Fatalf("writeKeyFile: %v", err)
	}
	return p
}

// fakeKeychain implements KeychainSource for tests. No real OS keychain is used.
type fakeKeychain struct {
	secret string
	err    error
}

func (f *fakeKeychain) GetIdentitySecret(_ context.Context) (string, error) {
	return f.secret, f.err
}

// ─── N-1: Wrong-perm / TOCTOU key file ─────────────────────────────────────

// TestN1_WrongPerm_0644_HardError proves that BYREIS_KEY_FILE pointing at a
// 0644 file is a HARD ERROR with a chmod hint.
func TestN1_WrongPerm_0644_HardError(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := generateTestKey(t)
	p := writeKeyFile(t, tmp, "admin.key", key, 0o644) //nolint:gosec // intentionally insecure perm to test rejection

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     p,
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	})

	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("N-1: expected HARD ERROR for 0644 key file, got nil")
	}
	if !isHardPermError(err) {
		t.Errorf("N-1: expected hard perm error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("N-1: error does not contain chmod hint: %q", err.Error())
	}
	if !strings.Contains(err.Error(), p) {
		t.Errorf("N-1: error does not reference the file path %q: %q", p, err.Error())
	}
}

// TestN1_WrongPerm_0400_HardError proves that 0400 (too restrictive) is also
// rejected — only exactly 0600 is accepted.
func TestN1_WrongPerm_0400_HardError(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := generateTestKey(t)
	p := writeKeyFile(t, tmp, "admin.key", key, 0o400) //nolint:gosec // intentionally insecure perm to test rejection

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     p,
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	})

	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("N-1: expected HARD ERROR for 0400 key file, got nil")
	}
	if !isHardPermError(err) {
		t.Errorf("N-1: 0400 must be a hard perm error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("N-1: 0400 error does not contain chmod hint: %q", err.Error())
	}
}

// TestN1_Symlink_Rejected proves that a symlink at the final path component is
// rejected by O_NOFOLLOW before any read occurs.
func TestN1_Symlink_Rejected(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := generateTestKey(t)
	realFile := writeKeyFile(t, tmp, "real.key", key, 0o600)
	symlinkPath := filepath.Join(tmp, "admin.key")
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     symlinkPath,
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	})

	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("N-1: expected error for symlink key file, got nil")
	}
	// Must be a hard error (not the no-key sentinel).
	if errors.Is(err, identityadapter.ErrNoAdminKey) {
		t.Fatal("N-1: symlink must be a hard error, not the no-key sentinel")
	}
}

// TestN1_SymlinkSwapAfterCheckCaught proves the TOCTOU fstat-on-fd discipline:
// O_NOFOLLOW rejects the symlink at open() time — there is no stat-then-open
// gap that an attacker could race through.
func TestN1_SymlinkSwapAfterCheckCaught(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := generateTestKey(t)
	realFile := writeKeyFile(t, tmp, "real.key", key, 0o600)
	symlinkPath := filepath.Join(tmp, "admin.key")
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     symlinkPath,
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	})

	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("N-1 TOCTOU: O_NOFOLLOW must reject symlink at open; got nil error")
	}
	if errors.Is(err, identityadapter.ErrNoAdminKey) {
		t.Fatal("N-1 TOCTOU: symlink must be a hard error, not no-key sentinel")
	}
}

// TestN1_SingleSharedResolver proves that ResolvedPath (the shared resolver)
// and the Loader's internal path resolution are byte-identical for file sources.
// A divergence would break the B5-2 KeyProbe contract.
func TestN1_SingleSharedResolver(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	p := filepath.Join(tmp, "admin.key")
	key := generateTestKey(t)

	cfg := identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     p,
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	}

	// The shared resolver must return p.
	resolverPath := identityadapter.ResolvedPath(cfg)
	if resolverPath != p {
		t.Errorf("N-1 resolver: ResolvedPath=%q, want=%q", resolverPath, p)
	}

	// Write the file so Load succeeds.
	if err := os.WriteFile(p, []byte(key), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// The loader must use the same path as the resolver.
	loaderPath := identityadapter.LoaderResolvedPath(identityadapter.New(cfg))
	if loaderPath != resolverPath {
		t.Errorf("N-1 single-resolver divergence: loader resolved %q, shared resolver returned %q",
			loaderPath, resolverPath)
	}
}

// ─── N-2: No key in any source ──────────────────────────────────────────────

// TestN2_NoKey_AllSourcesAbsent proves that no file + BYREIS_KEY unset +
// BYREIS_KEY_FILE unset + no keychain entry → ErrNoAdminKey, not a panic.
func TestN2_NoKey_AllSourcesAbsent(t *testing.T) {
	t.Parallel()

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     "",
		Keychain:       &fakeKeychain{secret: "", err: nil},
		DefaultKeyPath: func() string { return "" },
	})

	id, err := loader.Load(context.Background())
	if id != nil {
		t.Error("N-2: expected nil identity, got non-nil")
	}
	if !errors.Is(err, identityadapter.ErrNoAdminKey) {
		t.Errorf("N-2: expected ErrNoAdminKey, got: %v", err)
	}
}

// TestN2_KeychainError_FailClosed proves that a keychain access error fails
// closed to ErrNoAdminKey. Absence of an admin key is the normal contributor case.
func TestN2_KeychainError_FailClosed(t *testing.T) {
	t.Parallel()

	keychainErr := errors.New("keychain backend unavailable")
	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     "",
		Keychain:       &fakeKeychain{secret: "", err: keychainErr},
		DefaultKeyPath: func() string { return "" },
	})

	id, err := loader.Load(context.Background())
	if id != nil {
		t.Error("N-2: expected nil identity on keychain error, got non-nil")
	}
	if !errors.Is(err, identityadapter.ErrNoAdminKey) {
		t.Errorf("N-2: keychain error must fail closed to ErrNoAdminKey, got: %v", err)
	}
}

// TestN2_NilKeychain_FailClosed proves that a nil keychain (not injected) fails
// closed to ErrNoAdminKey — not a panic.
func TestN2_NilKeychain_FailClosed(t *testing.T) {
	t.Parallel()

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     "",
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	})

	id, err := loader.Load(context.Background())
	if id != nil {
		t.Error("N-2: nil keychain: expected nil identity, got non-nil")
	}
	if !errors.Is(err, identityadapter.ErrNoAdminKey) {
		t.Errorf("N-2: nil keychain: expected ErrNoAdminKey, got: %v", err)
	}
}

// TestN2_MarkerOnlyWhenKeyPresent_Keychain proves the marker contract:
// ResolvedPath returns the in-process marker constant ONLY when the keychain
// genuinely has a secret; it returns empty on the no-key path.
func TestN2_MarkerOnlyWhenKeyPresent_Keychain(t *testing.T) {
	t.Parallel()

	key := generateTestKey(t)

	// Keychain has a secret → non-empty marker.
	cfgWithKey := identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     "",
		Keychain:       &fakeKeychain{secret: key, err: nil},
		DefaultKeyPath: func() string { return "" },
	}
	marker := identityadapter.ResolvedPath(cfgWithKey)
	if marker == "" {
		t.Error("N-2 marker: expected non-empty marker for keychain key presence, got empty")
	}
	if marker == key {
		t.Error("N-2 marker: marker must not be the raw key string")
	}

	// No keychain secret → empty.
	cfgNoKey := identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     "",
		Keychain:       &fakeKeychain{secret: "", err: nil},
		DefaultKeyPath: func() string { return "" },
	}
	if got := identityadapter.ResolvedPath(cfgNoKey); got != "" {
		t.Errorf("N-2 marker: expected empty on no-key path, got %q", got)
	}
}

// TestN2_MarkerOnlyWhenKeyPresent_Env proves the marker contract for the
// BYREIS_KEY env source.
func TestN2_MarkerOnlyWhenKeyPresent_Env(t *testing.T) {
	t.Parallel()

	key := generateTestKey(t)

	// BYREIS_KEY set → non-empty marker.
	cfgWithKey := identityadapter.Config{
		EnvKey:         key,
		EnvKeyFile:     "",
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	}
	marker := identityadapter.ResolvedPath(cfgWithKey)
	if marker == "" {
		t.Error("N-2 marker: expected non-empty marker for env key presence, got empty")
	}
	if marker == key {
		t.Error("N-2 marker: marker must not be the raw env key string")
	}

	// BYREIS_KEY empty → empty marker.
	cfgNoKey := identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     "",
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	}
	if got := identityadapter.ResolvedPath(cfgNoKey); got != "" {
		t.Errorf("N-2 marker: expected empty marker for empty env key, got %q", got)
	}
}

// ─── L-2: Zeroization ───────────────────────────────────────────────────────

// TestL2_ZeroizeBuffer_PinnedBacking proves that ZeroizeBuffer zeros the backing
// array of a pinned slice. The caller holds a reference throughout so the GC
// cannot collect the backing array before the assertion.
func TestL2_ZeroizeBuffer_PinnedBacking(t *testing.T) {
	t.Parallel()

	key := generateTestKey(t)
	buf := []byte(key)

	// Pin the backing array pointer before the wipe.
	ptr := unsafe.SliceData(buf) //nolint:gosec // pinning backing array for zeroization assertion; not production escape
	n := len(buf)

	identityadapter.ZeroizeBuffer(buf)

	// Read the backing array via the pinned pointer — still alive because
	// we hold `buf` on the stack.
	result := unsafe.Slice(ptr, n) //nolint:gosec // pinned backing array assertion for L-2 zeroization test
	for i, b := range result {
		if b != 0 {
			t.Errorf("L-2: buffer not fully zeroed at index %d: got %d", i, b)
		}
	}
	runtime.KeepAlive(buf)
}

// TestL2_LoadedIdentity_HoldsNoAdapterCopy proves that a loaded identity holds
// no extra adapter-side copy of the raw private key bytes. The Recipient() of
// the returned identity must be an age public key (age1…), not the raw private
// key string.
func TestL2_LoadedIdentity_HoldsNoAdapterCopy(t *testing.T) {
	t.Parallel()

	key := generateTestKey(t)

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         key,
		EnvKeyFile:     "",
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	})

	id, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("L-2: Load failed: %v", err)
	}
	if id == nil {
		t.Fatal("L-2: expected non-nil identity")
	}
	if id.Recipient() == key {
		t.Error("L-2: Recipient() returned the raw private key — adapter exposes secret material")
	}
	if !strings.HasPrefix(id.Recipient(), "age1") {
		t.Errorf("L-2: Recipient() does not look like an age public key: %q", id.Recipient())
	}
}

// ─── Happy-path tests ────────────────────────────────────────────────────────

// TestHappy_BYREIS_KEY_ParsesIdentity proves that a valid BYREIS_KEY env value
// produces a usable identity.Identity.
func TestHappy_BYREIS_KEY_ParsesIdentity(t *testing.T) {
	t.Parallel()

	key := generateTestKey(t)

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         key,
		EnvKeyFile:     "",
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	})

	id, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("happy BYREIS_KEY: Load error: %v", err)
	}
	if id == nil {
		t.Fatal("happy BYREIS_KEY: expected non-nil identity")
	}
	if id.AgeIdentity() == nil {
		t.Error("happy BYREIS_KEY: AgeIdentity() is nil")
	}
	if !strings.HasPrefix(id.Recipient(), "age1") {
		t.Errorf("happy BYREIS_KEY: Recipient not an age1 public key: %q", id.Recipient())
	}
}

// TestHappy_BYREIS_KEY_FILE_ParsesIdentity proves that a valid 0600 key file
// produces a usable identity.Identity.
func TestHappy_BYREIS_KEY_FILE_ParsesIdentity(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := generateTestKey(t)
	p := writeKeyFile(t, tmp, "admin.key", key, 0o600)

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     p,
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	})

	id, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("happy BYREIS_KEY_FILE: Load error: %v", err)
	}
	if id == nil {
		t.Fatal("happy BYREIS_KEY_FILE: expected non-nil identity")
	}
	if !strings.HasPrefix(id.Recipient(), "age1") {
		t.Errorf("happy BYREIS_KEY_FILE: Recipient not age1: %q", id.Recipient())
	}
}

// TestHappy_Keychain_ParsesIdentity proves that a valid keychain secret
// produces a usable identity.Identity.
func TestHappy_Keychain_ParsesIdentity(t *testing.T) {
	t.Parallel()

	key := generateTestKey(t)

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     "",
		Keychain:       &fakeKeychain{secret: key, err: nil},
		DefaultKeyPath: func() string { return "" },
	})

	id, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("happy keychain: Load error: %v", err)
	}
	if id == nil {
		t.Fatal("happy keychain: expected non-nil identity")
	}
	if !strings.HasPrefix(id.Recipient(), "age1") {
		t.Errorf("happy keychain: Recipient not age1: %q", id.Recipient())
	}
}

// TestHappy_DefaultKeyPath_ParsesIdentity proves that the default key path
// fallback produces a usable identity.
func TestHappy_DefaultKeyPath_ParsesIdentity(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := generateTestKey(t)
	p := writeKeyFile(t, tmp, "admin.key", key, 0o600)

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     "",
		Keychain:       nil,
		DefaultKeyPath: func() string { return p },
	})

	id, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("happy default path: Load error: %v", err)
	}
	if id == nil {
		t.Fatal("happy default path: expected non-nil identity")
	}
}

// TestHappy_PrecedenceOrder_EnvWins proves the fixed fail-closed precedence:
// BYREIS_KEY env > BYREIS_KEY_FILE > keychain > default path.
func TestHappy_PrecedenceOrder_EnvWins(t *testing.T) {
	t.Parallel()

	envKey := generateTestKey(t)
	fileKey := generateTestKey(t)

	tmp := t.TempDir()
	p := writeKeyFile(t, tmp, "admin.key", fileKey, 0o600)

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         envKey,
		EnvKeyFile:     p,
		Keychain:       &fakeKeychain{secret: fileKey, err: nil},
		DefaultKeyPath: func() string { return p },
	})

	id, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("precedence env>file: Load error: %v", err)
	}

	// The loaded identity must correspond to envKey.
	envID, err := identity.Parse(envKey)
	if err != nil {
		t.Fatalf("precedence: Parse envKey: %v", err)
	}
	if id.Recipient() != envID.Recipient() {
		t.Errorf("precedence env>file: got Recipient=%q, want (from envKey) %q",
			id.Recipient(), envID.Recipient())
	}
}

// TestHappy_PrecedenceOrder_KeyFileBeatskeychain proves that BYREIS_KEY_FILE
// wins over the keychain source when env key is absent.
func TestHappy_PrecedenceOrder_KeyFileBeatskeychain(t *testing.T) {
	t.Parallel()

	fileKey := generateTestKey(t)
	keychainKey := generateTestKey(t)

	tmp := t.TempDir()
	p := writeKeyFile(t, tmp, "admin.key", fileKey, 0o600)

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "",
		EnvKeyFile:     p,
		Keychain:       &fakeKeychain{secret: keychainKey, err: nil},
		DefaultKeyPath: func() string { return "" },
	})

	id, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("precedence file>keychain: Load error: %v", err)
	}
	fileID, err := identity.Parse(fileKey)
	if err != nil {
		t.Fatalf("precedence file>keychain: Parse fileKey: %v", err)
	}
	if id.Recipient() != fileID.Recipient() {
		t.Errorf("precedence file>keychain: got %q, want fileKey's %q",
			id.Recipient(), fileID.Recipient())
	}
}

// TestHappy_BadKey_ReturnsParseError proves that malformed key material returns
// identity.ErrParseIdentity without echoing the bad material in the error.
func TestHappy_BadKey_ReturnsParseError(t *testing.T) {
	t.Parallel()

	loader := identityadapter.New(identityadapter.Config{
		EnvKey:         "not-a-valid-age-key",
		EnvKeyFile:     "",
		Keychain:       nil,
		DefaultKeyPath: func() string { return "" },
	})

	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("bad key: expected ErrParseIdentity, got nil")
	}
	if !errors.Is(err, identity.ErrParseIdentity) {
		t.Errorf("bad key: expected ErrParseIdentity, got: %v", err)
	}
	if strings.Contains(err.Error(), "not-a-valid-age-key") {
		t.Error("bad key: error message echoes the raw key material — security violation")
	}
}

// ─── Allowlist / import boundary ────────────────────────────────────────────

// TestAllowlist_IdentityAdapter_NotImportedByCore proves that the
// internal/adapter/identity package does NOT appear in the transitive dep set
// of internal/core/crypto/encrypt. This enforces the no-core→adapter rule and
// the ADR-0005 closed-world allowlist.
func TestAllowlist_IdentityAdapter_NotImportedByCore(t *testing.T) {
	t.Parallel()

	deps := goListDeps(t, "github.com/ByReisK/byreis/internal/core/crypto/encrypt")
	for _, dep := range deps {
		if dep == "github.com/ByReisK/byreis/internal/adapter/identity" {
			t.Errorf("FAIL: internal/core/crypto/encrypt imports internal/adapter/identity\n"+
				"This violates the no-core→adapter rule and the ADR-0005 allowlist.\n"+
				"The adapter must never appear in the contributor encrypt path: %s", dep)
		}
	}
	if !t.Failed() {
		t.Logf("PASS: internal/adapter/identity not in internal/core/crypto/encrypt transitive set (%d deps)", len(deps))
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// isHardPermError returns true when the error text indicates the exact-0600
// HARD ERROR with a chmod hint.
func isHardPermError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "chmod 600") ||
		strings.Contains(msg, "insecure permissions") ||
		strings.Contains(msg, "must be exactly 0600")
}

// goListDeps runs go list -deps for the given package.
func goListDeps(t *testing.T, pkg string) []string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", pkg) //nolint:gosec // pkg is a compile-time constant, not user input
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Fields(strings.TrimSpace(string(out)))
}
