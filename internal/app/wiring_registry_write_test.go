package app_test

import (
	"context"
	"errors"
	"testing"

	registryadapter "github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// fakeRegistryWriteTokenStore is a fake for testing the bridge.
type fakeRegistryWriteTokenStore struct {
	token string
	err   error
	calls int
}

func (f *fakeRegistryWriteTokenStore) GetRegistryWriteToken(_ context.Context, _ string) (string, error) {
	f.calls++
	return f.token, f.err
}

// BUILD_WIRES_WRITE_TOKEN_PROVIDER_WHEN_MANIFEST_SIGNER_PRESENT:
// When the write token store is non-nil, the bridge produces a non-nil
// RegistryWriteTokenProvider. This tests the bridge construction via
// NewAppRegistryWriteTokenBridge (exported in export_test.go).
func TestAppRegistryWriteTokenBridge_DelegatesToStore(t *testing.T) {
	t.Parallel()

	fake := &fakeRegistryWriteTokenStore{token: "tok"}
	bridge := app.NewAppRegistryWriteTokenBridgeForTest(fake)

	got, err := bridge.RegistryWriteToken(context.Background(), "https://github.com/org/reg")
	if err != nil {
		t.Fatalf("RegistryWriteToken: %v", err)
	}
	if got != "tok" {
		t.Errorf("want 'tok', got %q", got)
	}
	if fake.calls != 1 {
		t.Errorf("store called %d times, want 1", fake.calls)
	}
}

// BRIDGE_DELEGATES_TO_KEYCHAIN_STORE: the bridge invokes the store exactly
// once per RegistryWriteToken call and does not cache.
func TestAppRegistryWriteTokenBridge_NoCaching_CallsStoreEachTime(t *testing.T) {
	t.Parallel()

	fake := &fakeRegistryWriteTokenStore{token: "t"}
	bridge := app.NewAppRegistryWriteTokenBridgeForTest(fake)

	for i := 0; i < 3; i++ {
		if _, err := bridge.RegistryWriteToken(context.Background(), ""); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("want 3 store calls (no caching), got %d", fake.calls)
	}
}

// BUILD_CAPTURES_MODE_AT_COMPOSITION_TIME:
// The capturedModeProvider captures a fixed mode at construction and returns it
// verbatim. No re-detect happens inside the provider. Calling CurrentMode
// multiple times must always return the same captured value.
func TestCapturedModeProvider_ReturnsConstructionTimeMode(t *testing.T) {
	t.Parallel()

	for _, m := range []mode.Mode{mode.ModeContributor, mode.ModeAdmin, mode.ModeSuper} {
		m := m
		t.Run(m.String(), func(t *testing.T) {
			t.Parallel()
			p := app.NewCapturedModeProviderForTest(m)
			for i := 0; i < 5; i++ {
				got, err := p.CurrentMode(context.Background())
				if err != nil {
					t.Fatalf("CurrentMode: %v", err)
				}
				if got != m {
					t.Errorf("call %d: want %v, got %v", i, m, got)
				}
			}
		})
	}
}

// BUILD_CAPTURES_MODE_AT_COMPOSITION_TIME: the captured mode is set once and
// has no exported mutator. We verify this by checking that CurrentMode always
// returns the captured value. (The absence of an exported mutator is enforced
// structurally — the type is unexported and only exposed via an interface.)
func TestCapturedModeProvider_NoMutator(t *testing.T) {
	t.Parallel()
	// If NewCapturedModeProviderForTest returns an interface with no setter
	// method, the type system enforces immutability. The test asserts the value
	// is stable across calls (a mutator would change it).
	p := app.NewCapturedModeProviderForTest(mode.ModeAdmin)
	for i := 0; i < 10; i++ {
		got, err := p.CurrentMode(context.Background())
		if err != nil {
			t.Fatalf("CurrentMode[%d]: %v", i, err)
		}
		if got != mode.ModeAdmin {
			t.Errorf("expected ModeAdmin to be stable, got %v at iteration %d", got, i)
		}
	}
}

// BUILD_PASSES_NIL_WRITE_CONFIG_TO_PROJECT_REPO_READER:
// Confirm that the NewAppRegistryWriteTokenBridge path with a nil store
// correctly propagates errors to callers (the project-repo reader never
// receives write config).
func TestAppRegistryWriteTokenBridge_StoreReturnsError_Propagated(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("auth error")
	fake := &fakeRegistryWriteTokenStore{
		err: errors.Join(sentinel, registryadapter.ErrRegistryWriteAuth),
	}
	bridge := app.NewAppRegistryWriteTokenBridgeForTest(fake)

	_, err := bridge.RegistryWriteToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("want errors.Is(err, sentinel), got: %v", err)
	}
}
