package signingkey_test

// Test matrix — signingkey adapter (security-relevant: admin Ed25519 signing key source)
//
// Source-1 (BYREIS_SIGN_KEY env):
//   SK-E-1: valid 64-byte base64-std value → success, returns exactly 64 bytes
//   SK-E-2: bad base64 (not valid base64) → error, NOT ErrNoSigningKey, no fallthrough
//   SK-E-3: base64-std of wrong length (32 bytes) → error, NOT ErrNoSigningKey, no fallthrough
//   SK-E-4: whitespace-trimmed value → success (encoded bytes decoded correctly)
//
// Source-2 (BYREIS_SIGN_KEY_FILE):
//   SK-F-1: valid 0600 file with exactly 64 bytes → success
//   SK-F-2: file with 0644 perm → hard perm error (NOT ErrNoSigningKey), no fallthrough
//   SK-F-3: file with 0400 perm → hard perm error (NOT ErrNoSigningKey)
//   SK-F-4: symlink at final path component → rejected by O_NOFOLLOW (hard error)
//   SK-F-5: file with trailing whitespace/newline → trimmed to 64 bytes, success
//   SK-F-6: file with wrong length after trim → length error
//   SK-F-7: file absent → ErrNoSigningKey (soft, not hard)
//
// Source-3 (injected keychain):
//   SK-K-1: keychain returns 64 bytes → success, result is a COPY (fresh buffer)
//   SK-K-2: keychain success → keychain-returned slice is ZEROED after copy
//   SK-K-3: keychain access error → wraps ErrNoSigningKey, DOES NOT fall through to source-4
//   SK-K-4: keychain returns nil/empty → falls through to source-4 (default path)
//
// Source-4 (DefaultKeyPath):
//   SK-D-1: default path points to valid 0600 64-byte file → success
//   SK-D-2: default path points to absent file → ErrNoSigningKey (soft)
//   SK-D-3: DefaultKeyPath returns "" → ErrNoSigningKey
//
// All-absent:
//   SK-ALL-1: no env, no file, no keychain, no default path → ErrNoSigningKey
//
// ctx cancellation:
//   SK-CTX-1: cancelled context before first source checked → error wraps context.Canceled
//
// Precedence (no fallthrough from source-1 failure):
//   SK-P-1: bad env key + valid file configured → error from source-1, NOT success from file
//   SK-P-2: keychain error (non-nil error) + valid default path → ErrNoSigningKey (no fallthrough)

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/adapter/signingkey"
)

// ─── helpers ────────────────────────────────────────────────────────────────

// freshKey returns a fresh 64-byte Ed25519 private key (all non-zero for clarity).
func freshKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// validBase64Key encodes a 64-byte key as base64-std (no padding issues expected
// for 64 bytes: 64 * 4/3 = 85.33 → 88 chars with padding).
func validBase64Key(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// writeSignKeyFile writes rawKey to dir/name with the given perm and returns path.
func writeSignKeyFile(t *testing.T, dir, name string, rawKey []byte, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, rawKey, perm); err != nil {
		t.Fatalf("writeSignKeyFile: %v", err)
	}
	return p
}

// fakeKeychain implements KeychainSigningSource. No real OS keychain is touched.
type fakeKeychain struct {
	key []byte
	err error
}

func (f *fakeKeychain) GetSigningKey(_ context.Context) ([]byte, error) {
	return f.key, f.err
}

// noopDefaultPath is a func() string returning "" — signals no default path.
func noopDefaultPath() string { return "" }

// ─── Source-1: BYREIS_SIGN_KEY env ─────────────────────────────────────────

func TestSK_E1_EnvKey_Valid_Success(t *testing.T) {
	t.Parallel()

	key := freshKey(t)
	encoded := validBase64Key(key)

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     encoded,
		EnvSignKeyFile: "",
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	got, err := src.ProvideKey(context.Background())
	if err != nil {
		t.Fatalf("SK-E-1: expected success, got error: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("SK-E-1: expected 64 bytes, got %d", len(got))
	}
	if !bytes.Equal(got, key) {
		t.Error("SK-E-1: returned key does not match the original 64-byte key")
	}
}

func TestSK_E2_EnvKey_BadBase64_Error(t *testing.T) {
	t.Parallel()

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "!!! not valid base64 !!!",
		EnvSignKeyFile: "",
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	got, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-E-2: expected error for bad base64 env key, got nil")
	}
	if got != nil {
		t.Error("SK-E-2: expected nil key on error")
	}
	// Must NOT be the no-signing-key sentinel: bad base64 is a hard decode error.
	if errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Error("SK-E-2: bad base64 must NOT return ErrNoSigningKey — it must be a distinct decode error")
	}
	// Error must contain a helpful hint about what BYREIS_SIGN_KEY expects.
	if !strings.Contains(err.Error(), "BYREIS_SIGN_KEY") {
		t.Errorf("SK-E-2: error should reference BYREIS_SIGN_KEY, got: %v", err)
	}
}

func TestSK_E3_EnvKey_WrongLength_Error_NoFallthrough(t *testing.T) {
	t.Parallel()

	// 32 bytes encodes to valid base64 but wrong length after decode.
	short := make([]byte, 32)
	for i := range short {
		short[i] = byte(i + 1)
	}
	encoded := base64.StdEncoding.EncodeToString(short)

	tmp := t.TempDir()
	validKey := freshKey(t)
	filePath := writeSignKeyFile(t, tmp, "sign.key", validKey, 0o600)

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     encoded,
		EnvSignKeyFile: filePath, // must NOT be reached
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	got, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-E-3: expected error for wrong-length decoded env key, got nil")
	}
	if got != nil {
		t.Error("SK-E-3: expected nil key on error")
	}
	// Must NOT be ErrNoSigningKey.
	if errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Error("SK-E-3: wrong-length decoded env key must NOT return ErrNoSigningKey — must be a distinct length error")
	}
	// Must contain length information.
	if !strings.Contains(err.Error(), "32") {
		t.Errorf("SK-E-3: error should mention actual byte count 32, got: %v", err)
	}
	// Must NOT fall through to the valid file source.
	if !strings.Contains(err.Error(), "64") {
		t.Errorf("SK-E-3: error should mention expected byte count 64, got: %v", err)
	}
}

func TestSK_E4_EnvKey_WithLeadingTrailingWhitespace_Success(t *testing.T) {
	t.Parallel()

	key := freshKey(t)
	encoded := "  " + validBase64Key(key) + "\n"

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     encoded,
		EnvSignKeyFile: "",
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	got, err := src.ProvideKey(context.Background())
	if err != nil {
		t.Fatalf("SK-E-4: expected success with whitespace-padded value, got: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("SK-E-4: expected 64 bytes after whitespace trim, got %d", len(got))
	}
}

// ─── Source-2: BYREIS_SIGN_KEY_FILE ─────────────────────────────────────────

func TestSK_F1_KeyFile_Valid0600_Success(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := freshKey(t)
	p := writeSignKeyFile(t, tmp, "sign.key", key, 0o600)

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: p,
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	got, err := src.ProvideKey(context.Background())
	if err != nil {
		t.Fatalf("SK-F-1: expected success with 0600 file, got: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("SK-F-1: expected 64 bytes, got %d", len(got))
	}
	if !bytes.Equal(got, key) {
		t.Error("SK-F-1: returned key does not match file contents")
	}
}

func TestSK_F2_KeyFile_0644_HardPermError_NoFallthrough(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := freshKey(t)
	p := writeSignKeyFile(t, tmp, "sign.key", key, 0o644) //nolint:gosec // intentionally insecure perm to test rejection

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: p,
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	_, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-F-2: expected hard perm error for 0644 file, got nil")
	}
	// Must NOT be the soft ErrNoSigningKey sentinel.
	if errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Error("SK-F-2: 0644 file must be a HARD error, not ErrNoSigningKey")
	}
	// Must contain chmod hint (TOCTOU/CheckTrustFileTOCTOU enforcement).
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("SK-F-2: hard perm error must contain chmod hint, got: %v", err)
	}
}

func TestSK_F3_KeyFile_0400_HardPermError(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := freshKey(t)
	p := writeSignKeyFile(t, tmp, "sign.key", key, 0o400) //nolint:gosec // intentionally insecure perm to test rejection

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: p,
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	_, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-F-3: expected hard perm error for 0400 file, got nil")
	}
	if errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Error("SK-F-3: 0400 file must be a HARD perm error, not ErrNoSigningKey")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("SK-F-3: hard perm error must contain chmod hint, got: %v", err)
	}
}

func TestSK_F4_KeyFile_Symlink_Rejected_O_NOFOLLOW(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := freshKey(t)
	real := writeSignKeyFile(t, tmp, "real.key", key, 0o600)
	link := filepath.Join(tmp, "sign.key")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: link,
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	_, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-F-4: expected error for symlink key file (O_NOFOLLOW), got nil")
	}
	// Symlink rejection must be a HARD error, not the soft no-key sentinel.
	if errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Error("SK-F-4: symlink rejection must be a HARD error, not ErrNoSigningKey")
	}
}

func TestSK_F5_KeyFile_TrailingNewline_Trimmed_Success(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := freshKey(t)
	// Append a trailing newline that editors commonly add.
	content := append(key, '\n')
	p := writeSignKeyFile(t, tmp, "sign.key", content, 0o600)

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: p,
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	got, err := src.ProvideKey(context.Background())
	if err != nil {
		t.Fatalf("SK-F-5: expected success after whitespace trim, got: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("SK-F-5: expected 64 bytes after trim, got %d", len(got))
	}
	if !bytes.Equal(got, key) {
		t.Error("SK-F-5: trimmed key does not match original 64-byte key")
	}
}

func TestSK_F6_KeyFile_WrongLengthAfterTrim_Error(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	// 32 bytes: valid file, 0600, wrong length.
	short := make([]byte, 32)
	for i := range short {
		short[i] = byte(i + 1)
	}
	p := writeSignKeyFile(t, tmp, "sign.key", short, 0o600)

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: p,
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	_, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-F-6: expected error for 32-byte file, got nil")
	}
	if errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Error("SK-F-6: wrong-length file must NOT return ErrNoSigningKey — distinct length error required")
	}
	// The error must mention the expected size (64) to be actionable.
	if !strings.Contains(err.Error(), "64") {
		t.Errorf("SK-F-6: error should mention expected byte count 64, got: %v", err)
	}
}

func TestSK_F7_KeyFile_Absent_ErrNoSigningKey_Soft(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	absent := filepath.Join(tmp, "nonexistent-sign.key")

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: absent,
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	_, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-F-7: expected error for absent file, got nil")
	}
	// Absent file is the SOFT not-configured sentinel, not a hard error.
	if !errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Errorf("SK-F-7: absent file must return ErrNoSigningKey (soft), got: %v", err)
	}
}

// ─── Source-3: injected keychain ─────────────────────────────────────────────

func TestSK_K1_Keychain_Success_FreshBuffer_Copy(t *testing.T) {
	t.Parallel()

	key := freshKey(t)
	// The fakeKeychain returns a slice; we keep the original reference.
	keychainSlice := make([]byte, 64)
	copy(keychainSlice, key)
	kc := &fakeKeychain{key: keychainSlice}

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: "",
		Keychain:       kc,
		DefaultKeyPath: noopDefaultPath,
	})

	got, err := src.ProvideKey(context.Background())
	if err != nil {
		t.Fatalf("SK-K-1: expected success from keychain, got: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("SK-K-1: expected 64 bytes, got %d", len(got))
	}
	if !bytes.Equal(got, key) {
		t.Error("SK-K-1: returned key does not match keychain key")
	}
	// The result must be a distinct allocation from keychainSlice.
	// Use unsafe to compare backing-array pointers.
	gotPtr := unsafe.SliceData(got)          //nolint:gosec // pointer comparison for copy-assertion; pinned, not escaped
	srcPtr := unsafe.SliceData(key)          //nolint:gosec // pointer comparison for copy-assertion
	_ = srcPtr                               // suppress unused warning; key and got must differ
	kcPtr := unsafe.SliceData(keychainSlice) //nolint:gosec // pointer comparison for copy-assertion
	if gotPtr == kcPtr {
		t.Error("SK-K-1: result shares backing array with keychain slice — not a fresh copy")
	}
	runtime.KeepAlive(got)
	runtime.KeepAlive(keychainSlice)
}

func TestSK_K2_Keychain_Success_SourceSliceZeroed(t *testing.T) {
	t.Parallel()

	key := freshKey(t)
	// Provide a pinned slice as the "keychain returned" buffer.
	// We need to observe whether ProvideKey zeroizes it.
	keychainBuf := make([]byte, 64)
	copy(keychainBuf, key)

	// Pin the backing array address before ProvideKey is called.
	ptr := unsafe.SliceData(keychainBuf) //nolint:gosec // pinning backing array for zeroization assertion
	n := len(keychainBuf)

	kc := &fakeKeychain{key: keychainBuf}

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: "",
		Keychain:       kc,
		DefaultKeyPath: noopDefaultPath,
	})

	got, err := src.ProvideKey(context.Background())
	if err != nil {
		t.Fatalf("SK-K-2: expected success, got: %v", err)
	}
	// Suppress "got unused" warning — we need got to prevent GC of the result.
	_ = got

	// The backing array of keychainBuf must be all-zero after ProvideKey returns
	// (ZeroizeBuffer was called on the keychain-returned slice).
	backing := unsafe.Slice(ptr, n) //nolint:gosec // pinned backing array assertion for zeroization test
	for i, b := range backing {
		if b != 0 {
			t.Errorf("SK-K-2: keychain source slice not zeroed at index %d: got %d", i, b)
		}
	}
	runtime.KeepAlive(keychainBuf)
}

func TestSK_K3_Keychain_Error_WrapsErrNoSigningKey_NoFallthrough(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := freshKey(t)
	defaultPath := writeSignKeyFile(t, tmp, "sign.key", key, 0o600)

	keychainErr := errors.New("OS keychain backend unavailable")
	kc := &fakeKeychain{key: nil, err: keychainErr}

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: "",
		Keychain:       kc,
		DefaultKeyPath: func() string { return defaultPath }, // must NOT be reached
	})

	_, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-K-3: expected error on keychain failure, got nil")
	}
	// Keychain access failure wraps ErrNoSigningKey (fail-closed to not-configured).
	if !errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Errorf("SK-K-3: keychain error must wrap ErrNoSigningKey (fail-closed), got: %v", err)
	}
	// But MUST NOT fall through to the valid default path file.
	// We verify by checking the error contains the keychain failure context, not a file error.
	if !strings.Contains(err.Error(), "keychain") {
		t.Errorf("SK-K-3: error should reference keychain failure, got: %v", err)
	}
}

func TestSK_K4_Keychain_Empty_FallsThrough_ToDefaultPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := freshKey(t)
	defaultPath := writeSignKeyFile(t, tmp, "sign.key", key, 0o600)

	// Keychain returns nil/empty → no entry, should fall through to default path.
	kc := &fakeKeychain{key: nil, err: nil}

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: "",
		Keychain:       kc,
		DefaultKeyPath: func() string { return defaultPath },
	})

	got, err := src.ProvideKey(context.Background())
	if err != nil {
		t.Fatalf("SK-K-4: expected success via fallthrough to default path, got: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("SK-K-4: expected 64 bytes from default path, got %d", len(got))
	}
	if !bytes.Equal(got, key) {
		t.Error("SK-K-4: key from default path does not match expected key")
	}
}

// ─── Source-4: DefaultKeyPath ────────────────────────────────────────────────

func TestSK_D1_DefaultKeyPath_Valid_Success(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := freshKey(t)
	p := writeSignKeyFile(t, tmp, "admin-sign.key", key, 0o600)

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: "",
		Keychain:       nil,
		DefaultKeyPath: func() string { return p },
	})

	got, err := src.ProvideKey(context.Background())
	if err != nil {
		t.Fatalf("SK-D-1: expected success from default path, got: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("SK-D-1: expected 64 bytes, got %d", len(got))
	}
	if !bytes.Equal(got, key) {
		t.Error("SK-D-1: default path key does not match expected key")
	}
}

func TestSK_D2_DefaultKeyPath_AbsentFile_ErrNoSigningKey(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	absent := filepath.Join(tmp, "nonexistent-admin-sign.key")

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: "",
		Keychain:       nil,
		DefaultKeyPath: func() string { return absent },
	})

	_, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-D-2: expected ErrNoSigningKey for absent default path file, got nil")
	}
	if !errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Errorf("SK-D-2: absent default path file must return ErrNoSigningKey (soft), got: %v", err)
	}
}

func TestSK_D3_DefaultKeyPath_EmptyFunc_ErrNoSigningKey(t *testing.T) {
	t.Parallel()

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: "",
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	_, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-D-3: expected ErrNoSigningKey when DefaultKeyPath returns empty string, got nil")
	}
	if !errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Errorf("SK-D-3: expected ErrNoSigningKey, got: %v", err)
	}
}

// ─── All-absent ──────────────────────────────────────────────────────────────

func TestSK_ALL1_AllSourcesAbsent_ErrNoSigningKey(t *testing.T) {
	t.Parallel()

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: "",
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	got, err := src.ProvideKey(context.Background())
	if got != nil {
		t.Error("SK-ALL-1: expected nil key when no sources configured")
	}
	if !errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Errorf("SK-ALL-1: expected ErrNoSigningKey, got: %v", err)
	}
}

// ─── ctx cancellation ────────────────────────────────────────────────────────

func TestSK_CTX1_Cancelled_BeforeAnySource(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: "",
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	got, err := src.ProvideKey(ctx)
	if got != nil {
		t.Error("SK-CTX-1: expected nil key on cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("SK-CTX-1: expected error wrapping context.Canceled, got: %v", err)
	}
}

// ─── Precedence (no-fallthrough from source-1 failure) ──────────────────────

func TestSK_P1_BadEnvKey_NoFallthroughToFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := freshKey(t)
	filePath := writeSignKeyFile(t, tmp, "sign.key", key, 0o600)

	// bad env key (not valid base64) + valid file configured → must error, not succeed.
	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "!!! not base64 !!!",
		EnvSignKeyFile: filePath,
		Keychain:       nil,
		DefaultKeyPath: noopDefaultPath,
	})

	_, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-P-1: expected error from bad env key, got nil (did it fall through?)")
	}
	// Must not be success from the file.
	if errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Error("SK-P-1: must NOT return ErrNoSigningKey — it must be a distinct env decode error")
	}
}

func TestSK_P2_KeychainError_NoFallthroughToDefaultPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	key := freshKey(t)
	defaultPath := writeSignKeyFile(t, tmp, "sign.key", key, 0o600)

	kc := &fakeKeychain{key: nil, err: errors.New("keychain unavailable")}

	src := signingkey.New(signingkey.Config{
		EnvSignKey:     "",
		EnvSignKeyFile: "",
		Keychain:       kc,
		DefaultKeyPath: func() string { return defaultPath },
	})

	_, err := src.ProvideKey(context.Background())
	if err == nil {
		t.Fatal("SK-P-2: expected error on keychain failure, got nil")
	}
	// Must wrap ErrNoSigningKey (fail-closed) and must NOT be success from default path.
	if !errors.Is(err, signingkey.ErrNoSigningKey) {
		t.Errorf("SK-P-2: expected ErrNoSigningKey (fail-closed), got: %v", err)
	}
	// The error must reference keychain failure (not a file-read error).
	if !strings.Contains(err.Error(), "keychain") {
		t.Errorf("SK-P-2: error should reference keychain, got: %v", err)
	}
}

// ─── ZeroizeBuffer export smoke test ────────────────────────────────────────

// TestZeroizeBuffer_PinnedBacking verifies that ZeroizeBuffer (exported for tests
// from the identity adapter, used internally by signingkey) zeros the backing array.
// This is the same pattern as the identity adapter's L-2 test.
func TestZeroizeBuffer_PinnedBacking(t *testing.T) {
	t.Parallel()

	key := freshKey(t)
	buf := make([]byte, 64)
	copy(buf, key)

	ptr := unsafe.SliceData(buf) //nolint:gosec // pinning backing array for zeroization assertion
	n := len(buf)

	identityadapter.ZeroizeBuffer(buf)

	result := unsafe.Slice(ptr, n) //nolint:gosec // pinned backing array assertion
	for i, b := range result {
		if b != 0 {
			t.Errorf("ZeroizeBuffer: byte %d not zeroed: %d", i, b)
		}
	}
	runtime.KeepAlive(buf)
}
