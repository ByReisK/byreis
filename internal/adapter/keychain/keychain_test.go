package keychain_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/keychain"
	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// fakeModeProvider implements keychain.ModeProvider for tests.
type fakeModeProvider struct {
	m   mode.Mode
	err error
}

func (f *fakeModeProvider) CurrentMode(_ context.Context) (mode.Mode, error) {
	return f.m, f.err
}

// fakeKeychain implements keychain.KeyringClient for tests.
// It records whether Get was called.
type fakeKeychain struct {
	getCalls int
	token    string
	err      error
}

func (f *fakeKeychain) Get(service, account string) (string, error) {
	f.getCalls++
	return f.token, f.err
}

func (f *fakeKeychain) Set(service, account, secret string) error { return nil }
func (f *fakeKeychain) Delete(service, account string) error      { return nil }

// Test helpers for constructing a Store with injected fakes.
func newTestStore(mp keychain.ModeProvider, kr keychain.KeyringClient) *keychain.Store {
	return keychain.NewWithDeps(mp, kr)
}

// B-D5-SANITISE-TEST: MODE_DENIED_KEYCHAIN_NOT_QUERIED
// A CONTRIBUTOR mode caller must not cause any keychain read.
func TestGetRegistryWriteToken_ModeDenied_KeychainNotQueried(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{}
	s := newTestStore(&fakeModeProvider{m: mode.ModeContributor}, fk)

	_, err := s.GetRegistryWriteToken(context.Background(), "https://github.com/org/registry")
	if err == nil {
		t.Fatal("expected error for CONTRIBUTOR mode, got nil")
	}
	if !errors.Is(err, registryadapter.ErrRegistryWriteAuth) {
		t.Errorf("want errors.Is(err, ErrRegistryWriteAuth), got: %v", err)
	}
	if fk.getCalls != 0 {
		t.Errorf("keychain must NOT be queried in CONTRIBUTOR mode; got %d calls", fk.getCalls)
	}
	if !strings.Contains(err.Error(), "not ADMIN") {
		t.Errorf("error message should contain 'not ADMIN', got: %v", err)
	}
}

// B-D5-SANITISE-TEST: MODE_UNAVAILABLE_KEYCHAIN_NOT_QUERIED
// ModeProvider returning an error must fail-closed before any keychain read.
func TestGetRegistryWriteToken_ModeUnavailable_KeychainNotQueried(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{}
	mp := &fakeModeProvider{err: errors.New("detector failure")}
	s := newTestStore(mp, fk)

	_, err := s.GetRegistryWriteToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for mode unavailable, got nil")
	}
	if !errors.Is(err, registryadapter.ErrRegistryWriteAuth) {
		t.Errorf("want errors.Is(err, ErrRegistryWriteAuth), got: %v", err)
	}
	if fk.getCalls != 0 {
		t.Errorf("keychain must NOT be queried when mode is unavailable; got %d calls", fk.getCalls)
	}
	if !strings.Contains(err.Error(), "mode unavailable") {
		t.Errorf("error should mention 'mode unavailable', got: %v", err)
	}
}

// MODE_FORGED_UNKNOWN_FAIL_CLOSED
// An unrecognised Mode iota value must be treated as CONTRIBUTOR (fail closed).
func TestGetRegistryWriteToken_ModeForgedUnknown_FailClosed(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{}
	s := newTestStore(&fakeModeProvider{m: mode.Mode(99)}, fk)

	_, err := s.GetRegistryWriteToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for forged mode, got nil")
	}
	if !errors.Is(err, registryadapter.ErrRegistryWriteAuth) {
		t.Errorf("want errors.Is(err, ErrRegistryWriteAuth), got: %v", err)
	}
	if fk.getCalls != 0 {
		t.Errorf("keychain must NOT be queried for forged mode; got %d calls", fk.getCalls)
	}
}

// ADMIN_SLOT_EMPTY
// Admin mode but empty token must return ErrRegistryWriteAuth with "slot empty".
func TestGetRegistryWriteToken_AdminSlotEmpty(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{token: ""}
	s := newTestStore(&fakeModeProvider{m: mode.ModeAdmin}, fk)

	_, err := s.GetRegistryWriteToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty slot, got nil")
	}
	if !errors.Is(err, registryadapter.ErrRegistryWriteAuth) {
		t.Errorf("want errors.Is(err, ErrRegistryWriteAuth), got: %v", err)
	}
	if !strings.Contains(err.Error(), "slot empty") {
		t.Errorf("error should mention 'slot empty', got: %v", err)
	}
}

// ADMIN_SLOT_PRESENT
// Admin mode with a populated slot must return the token with nil error.
func TestGetRegistryWriteToken_AdminSlotPresent(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{token: "tok"}
	s := newTestStore(&fakeModeProvider{m: mode.ModeAdmin}, fk)

	got, err := s.GetRegistryWriteToken(context.Background(), "")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if got != "tok" {
		t.Errorf("expected token 'tok', got %q", got)
	}
}

// SUPER_SLOT_PRESENT
// ModeSuper with a populated slot must also succeed.
func TestGetRegistryWriteToken_SuperSlotPresent(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{token: "super-tok"}
	s := newTestStore(&fakeModeProvider{m: mode.ModeSuper}, fk)

	got, err := s.GetRegistryWriteToken(context.Background(), "")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if got != "super-tok" {
		t.Errorf("expected token 'super-tok', got %q", got)
	}
}

// KEYCHAIN_LOCKED
// A keychain returning "access denied" must map to ErrRegistryWriteAuth + "access denied".
func TestGetRegistryWriteToken_KeychainLocked(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{err: errors.New("access denied: keychain locked")}
	s := newTestStore(&fakeModeProvider{m: mode.ModeAdmin}, fk)

	_, err := s.GetRegistryWriteToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for locked keychain, got nil")
	}
	if !errors.Is(err, registryadapter.ErrRegistryWriteAuth) {
		t.Errorf("want errors.Is(err, ErrRegistryWriteAuth), got: %v", err)
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("error should mention 'access denied', got: %v", err)
	}
}

// KEYCHAIN_BACKEND_UNAVAILABLE
// A DBus/ENXIO-like error must map to ErrRegistryWriteAuth + "keychain unavailable".
func TestGetRegistryWriteToken_KeychainBackendUnavailable(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{err: errors.New("no DBus session bus")}
	s := newTestStore(&fakeModeProvider{m: mode.ModeAdmin}, fk)

	_, err := s.GetRegistryWriteToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for unavailable backend, got nil")
	}
	if !errors.Is(err, registryadapter.ErrRegistryWriteAuth) {
		t.Errorf("want errors.Is(err, ErrRegistryWriteAuth), got: %v", err)
	}
	if !strings.Contains(err.Error(), "keychain unavailable") {
		t.Errorf("error should mention 'keychain unavailable', got: %v", err)
	}
}

// CTX_CANCELLED_BEFORE_LOAD
// A cancelled context must surface ctx.Canceled before the keychain is queried.
func TestGetRegistryWriteToken_CtxCancelledBeforeLoad(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{token: "tok"}
	s := newTestStore(&fakeModeProvider{m: mode.ModeAdmin}, fk)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.GetRegistryWriteToken(ctx, "")
	if err == nil {
		t.Fatal("expected error for cancelled ctx, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want errors.Is(err, context.Canceled), got: %v", err)
	}
	if fk.getCalls != 0 {
		t.Errorf("keychain must NOT be queried after ctx cancel; got %d calls", fk.getCalls)
	}
}

// B-D5-SANITISE-TEST: NO_TOKEN_IN_ANY_ERROR_TEXT
// Across all failure paths, no error message must contain a token-like string.
// This covers the sanitised-cause paths (where the underlying go-keyring error
// text is surfaced after sanitisation).
func TestGetRegistryWriteToken_NoTokenInAnyErrorText(t *testing.T) {
	t.Parallel()

	// Control matrix of synthetic tokens that must never appear in error messages.
	syntheticTokens := []string{
		"ghp_SECRET_TOKEN_12345678901234567890",
		"byreis-secret-credential-xyz",
		"BYPASS_TOKEN_SUPER_SECRET",
	}

	cases := []struct {
		name string
		mp   *fakeModeProvider
		fk   *fakeKeychain
	}{
		{
			name: "mode_denied",
			mp:   &fakeModeProvider{m: mode.ModeContributor},
			fk:   &fakeKeychain{token: ""},
		},
		{
			name: "mode_unavailable",
			mp:   &fakeModeProvider{err: errors.New("mode error")},
			fk:   &fakeKeychain{token: ""},
		},
		{
			name: "slot_empty",
			mp:   &fakeModeProvider{m: mode.ModeAdmin},
			fk:   &fakeKeychain{token: ""},
		},
		{
			name: "keychain_locked",
			mp:   &fakeModeProvider{m: mode.ModeAdmin},
			fk:   &fakeKeychain{err: errors.New("access denied")},
		},
		{
			name: "backend_unavailable",
			mp:   &fakeModeProvider{m: mode.ModeAdmin},
			fk:   &fakeKeychain{err: errors.New("DBus unavailable")},
		},
	}

	for _, tok := range syntheticTokens {
		for _, tc := range cases {
			tc := tc
			tok := tok
			t.Run(tc.name+"/"+tok[:10], func(t *testing.T) {
				t.Parallel()
				// Inject the token into the fakeKeychain as if it were present.
				fk := &fakeKeychain{token: tok, err: tc.fk.err}
				s := newTestStore(tc.mp, fk)

				_, err := s.GetRegistryWriteToken(context.Background(), "")
				if err == nil {
					// success is only valid for admin+slot_present — all the test
					// cases above are failure paths so nil is not expected.
					return
				}
				errText := err.Error()
				if strings.Contains(errText, tok) {
					t.Errorf("[%s] token %q must not appear in error text: %q",
						tc.name, tok, errText)
				}
			})
		}
	}
}

// B-D5-SANITISE-TEST: sanitiser strips path/token-like substrings from raw
// go-keyring errors. This tests that the sanitiser applied inside the adapter
// strips token-like content from the underlying error before it crosses the
// adapter boundary.
func TestSanitiseKeychainError_StripsTokenLikeContent(t *testing.T) {
	t.Parallel()

	// Simulate a go-keyring backend that embeds a token in its error message
	// (pathological but possible on some backends that echo the service/account).
	syntheticToken := "ghp_SYNTHETIC_SECRET_12345678"
	fk := &fakeKeychain{err: fmt.Errorf("keychain error: secret=%s path=/etc/passwd", syntheticToken)}
	s := newTestStore(&fakeModeProvider{m: mode.ModeAdmin}, fk)

	_, err := s.GetRegistryWriteToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if strings.Contains(err.Error(), syntheticToken) {
		t.Errorf("sanitiser must strip token from underlying error; found %q in: %v", syntheticToken, err)
	}
	if strings.Contains(err.Error(), "/etc/passwd") {
		t.Errorf("sanitiser must strip path from underlying error; found '/etc/passwd' in: %v", err)
	}
}

// richFakeKeychain is a richer fake KeyringClient that supports per-method
// error injection (used by the sibling-sanitiser tests).
type richFakeKeychain struct {
	getCalls    int
	getErr      error
	getToken    string
	setErr      error
	deleteErr   error
	deleteCalls int
}

func (f *richFakeKeychain) Get(_, _ string) (string, error) {
	f.getCalls++
	return f.getToken, f.getErr
}

func (f *richFakeKeychain) Set(_, _, _ string) error {
	return f.setErr
}

func (f *richFakeKeychain) Delete(_, _ string) error {
	f.deleteCalls++
	return f.deleteErr
}

// TestKeychainSiblingMethods_NoMaterialInErrorText proves that GetToken,
// SetToken, DeleteToken, and GetIdentitySecret never include token-like
// material in their returned error text, including when the service/account
// arguments themselves are token-shaped (Amendment A2/A3 pins).
func TestKeychainSiblingMethods_NoMaterialInErrorText(t *testing.T) {
	t.Parallel()

	// sensitiveLeakShape represents one case where the backend error or the
	// caller-supplied service/account arg contains sensitive material that must
	// NOT appear in the returned error text.
	type sensitiveLeakShape struct {
		name string
		// sensitiveInErr is token-like material embedded by the fake keyring in its
		// error message. Empty when the leak vector is the arg, not the error.
		sensitiveInErr string
		// sensitiveInArgs is a token-shaped service/account arg (Amendment A2/A3).
		// Empty when the leak vector is the error, not the arg.
		sensitiveInArgs string
	}
	shapes := []sensitiveLeakShape{
		{
			name:           "path_in_error",
			sensitiveInErr: "/home/user/.config/byreis/identity.key",
		},
		{
			name:           "base64ish_token_in_error",
			sensitiveInErr: "ghp_BASE64AAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			name:           "hex_token_in_error",
			sensitiveInErr: "abcdef0123456789abcdef0123456789ab",
		},
		{
			name:           "dbus_address_in_error",
			sensitiveInErr: "unix:path=/tmp/dbus-ABCDEFGHij,guid=cafebabe12345678",
		},
		{
			name:           "percent_q_escaped_material_in_error",
			sensitiveInErr: `secret=VERYLONGSECRETTOKEN1234567890`,
		},
		{
			// Amendment A2/A3: service arg is itself token-shaped.
			name:            "token_shaped_service_arg",
			sensitiveInArgs: "ghp_TOKEN_IN_SERVICE_NAME_1234567890AB",
		},
		{
			// Amendment A3: account arg is itself token-shaped (hex-like).
			name:            "token_shaped_account_arg",
			sensitiveInArgs: "abcdef0123456789abcdef0123456789ab",
		},
	}

	for _, shape := range shapes {
		shape := shape

		// Build the error the keyring backend will return.
		// For arg-leak shapes the keyring error is generic (non-sensitive).
		backendErr := func() error {
			if shape.sensitiveInErr != "" {
				return fmt.Errorf("backend err: %s", shape.sensitiveInErr)
			}
			return fmt.Errorf("backend: generic keychain failure")
		}

		// Choose which arg to pass as service/account.
		argVal := func() string {
			if shape.sensitiveInArgs != "" {
				return shape.sensitiveInArgs
			}
			return "normal-service"
		}

		t.Run(shape.name+"/GetToken", func(t *testing.T) {
			t.Parallel()
			fk := &richFakeKeychain{getErr: backendErr()}
			s := keychain.NewWithKeychainOnly(fk)
			_, err := s.GetToken(context.Background(), argVal(), argVal())
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			errText := err.Error()
			if shape.sensitiveInErr != "" && strings.Contains(errText, shape.sensitiveInErr) {
				t.Errorf("error text must not contain sensitive err material %q; got: %q",
					shape.sensitiveInErr, errText)
			}
			if shape.sensitiveInArgs != "" && strings.Contains(errText, shape.sensitiveInArgs) {
				t.Errorf("error text must not contain token-shaped arg %q; got: %q",
					shape.sensitiveInArgs, errText)
			}
		})

		t.Run(shape.name+"/SetToken", func(t *testing.T) {
			t.Parallel()
			fk := &richFakeKeychain{setErr: backendErr()}
			s := keychain.NewWithKeychainOnly(fk)
			err := s.SetToken(context.Background(), argVal(), argVal(), "value")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			errText := err.Error()
			if shape.sensitiveInErr != "" && strings.Contains(errText, shape.sensitiveInErr) {
				t.Errorf("error text must not contain sensitive err material %q; got: %q",
					shape.sensitiveInErr, errText)
			}
			if shape.sensitiveInArgs != "" && strings.Contains(errText, shape.sensitiveInArgs) {
				t.Errorf("error text must not contain token-shaped arg %q; got: %q",
					shape.sensitiveInArgs, errText)
			}
		})

		t.Run(shape.name+"/DeleteToken", func(t *testing.T) {
			t.Parallel()
			fk := &richFakeKeychain{deleteErr: backendErr()}
			s := keychain.NewWithKeychainOnly(fk)
			err := s.DeleteToken(context.Background(), argVal(), argVal())
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			errText := err.Error()
			if shape.sensitiveInErr != "" && strings.Contains(errText, shape.sensitiveInErr) {
				t.Errorf("error text must not contain sensitive err material %q; got: %q",
					shape.sensitiveInErr, errText)
			}
			if shape.sensitiveInArgs != "" && strings.Contains(errText, shape.sensitiveInArgs) {
				t.Errorf("error text must not contain token-shaped arg %q; got: %q",
					shape.sensitiveInArgs, errText)
			}
		})

		t.Run(shape.name+"/GetIdentitySecret", func(t *testing.T) {
			t.Parallel()
			// GetIdentitySecret uses fixed internal service/account so only
			// the backend error leak applies (no caller-supplied arg vector).
			if shape.sensitiveInErr == "" {
				t.Skip("arg-leak shape not applicable to GetIdentitySecret (uses fixed slot)")
			}
			fk := &richFakeKeychain{getErr: backendErr()}
			s := keychain.NewWithKeychainOnly(fk)
			_, err := s.GetIdentitySecret(context.Background())
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			errText := err.Error()
			if strings.Contains(errText, shape.sensitiveInErr) {
				t.Errorf("error text must not contain sensitive err material %q; got: %q",
					shape.sensitiveInErr, errText)
			}
		})
	}
}

// TestKeychainSiblingMethods_PreserveErrNotFound proves that GetToken,
// DeleteToken, and GetIdentitySecret return their documented zero-values on
// not-found (per Amendment A3: the contracts are ("",nil), nil, and ("",nil)
// respectively, NOT an errors.Is chain check).
func TestKeychainSiblingMethods_PreserveErrNotFound(t *testing.T) {
	t.Parallel()

	t.Run("GetToken/not_found", func(t *testing.T) {
		t.Parallel()
		fk := &richFakeKeychain{getErr: keychain.ErrNotFound}
		s := keychain.NewWithKeychainOnly(fk)
		tok, err := s.GetToken(context.Background(), "svc", "acc")
		if err != nil {
			t.Errorf("GetToken not-found: want (nil error), got: %v", err)
		}
		if tok != "" {
			t.Errorf("GetToken not-found: want empty string, got %q", tok)
		}
	})

	t.Run("DeleteToken/not_found_is_idempotent", func(t *testing.T) {
		t.Parallel()
		fk := &richFakeKeychain{deleteErr: keychain.ErrNotFound}
		s := keychain.NewWithKeychainOnly(fk)
		err := s.DeleteToken(context.Background(), "svc", "acc")
		if err != nil {
			t.Errorf("DeleteToken not-found: want nil, got: %v", err)
		}
	})

	t.Run("GetIdentitySecret/not_found", func(t *testing.T) {
		t.Parallel()
		fk := &richFakeKeychain{getErr: keychain.ErrNotFound}
		s := keychain.NewWithKeychainOnly(fk)
		secret, err := s.GetIdentitySecret(context.Background())
		if err != nil {
			t.Errorf("GetIdentitySecret not-found: want (nil error), got: %v", err)
		}
		if secret != "" {
			t.Errorf("GetIdentitySecret not-found: want empty string, got %q", secret)
		}
	})
}

// Tests for the generic TokenStore methods (GetToken, SetToken, DeleteToken).
// These also must be real go-keyring calls, not panics.
func TestStore_GetToken_UsesKeyring(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{token: "my-token"}
	s := keychain.NewWithKeychainOnly(fk)

	tok, err := s.GetToken(context.Background(), "service", "account")
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if tok != "my-token" {
		t.Errorf("want 'my-token', got %q", tok)
	}
}

func TestStore_GetToken_NotFound_ReturnsEmptyNil(t *testing.T) {
	t.Parallel()
	// go-keyring returns keyring.ErrNotFound for absent entries; Store must map
	// to ("", nil) for the general TokenStore contract.
	fk := &fakeKeychain{err: keychain.ErrNotFound}
	s := keychain.NewWithKeychainOnly(fk)

	tok, err := s.GetToken(context.Background(), "service", "account")
	if err != nil {
		t.Fatalf("GetToken absent: expected nil, got: %v", err)
	}
	if tok != "" {
		t.Errorf("GetToken absent: expected empty string, got %q", tok)
	}
}

func TestStore_SetToken_UsesKeyring(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{}
	s := keychain.NewWithKeychainOnly(fk)

	if err := s.SetToken(context.Background(), "svc", "acc", "val"); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
}

func TestStore_DeleteToken_UsesKeyring(t *testing.T) {
	t.Parallel()
	fk := &fakeKeychain{}
	s := keychain.NewWithKeychainOnly(fk)

	if err := s.DeleteToken(context.Background(), "svc", "acc"); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
}

func TestStore_GetIdentitySecret_Empty_ReturnsNil(t *testing.T) {
	t.Parallel()
	// ErrNotFound must map to ("", nil) for identity source.
	fk := &fakeKeychain{err: keychain.ErrNotFound}
	s := keychain.NewWithKeychainOnly(fk)

	secret, err := s.GetIdentitySecret(context.Background())
	if err != nil {
		t.Fatalf("GetIdentitySecret absent: expected nil, got: %v", err)
	}
	if secret != "" {
		t.Errorf("expected empty string, got %q", secret)
	}
}
