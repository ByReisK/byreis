package usecase_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/ByReisK/byreis/internal/core/usecase"
)

// --- fakes ---

type fakeTrustAnchorStore struct {
	exists    bool
	anchor    usecase.TrustAnchor
	readErr   error
	writeErr  error
	written   *usecase.TrustAnchor
	existsErr error
}

func (f *fakeTrustAnchorStore) AnchorExists(_ context.Context) (bool, error) {
	return f.exists, f.existsErr
}

func (f *fakeTrustAnchorStore) ReadAnchor(_ context.Context) (usecase.TrustAnchor, error) {
	return f.anchor, f.readErr
}

func (f *fakeTrustAnchorStore) WriteAnchor(_ context.Context, a usecase.TrustAnchor) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.written = &a
	return nil
}

type fakeSignerProbe struct {
	fp  string
	err error
}

func (f *fakeSignerProbe) RegistrySignerFingerprint(_ context.Context, _ string) (string, error) {
	return f.fp, f.err
}

type fakeConfirmPrompter struct {
	err error
}

func (f *fakeConfirmPrompter) ConfirmSignerFingerprint(_ context.Context, _ string) error {
	return f.err
}

type fakeConfigWriter struct {
	written map[string][]byte
	err     error
}

func (f *fakeConfigWriter) ReadFile(_ context.Context, path string) ([]byte, error) {
	data, ok := f.written[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func (f *fakeConfigWriter) WriteFile(_ context.Context, path string, data []byte, _ uint32) error {
	if f.err != nil {
		return f.err
	}
	if f.written == nil {
		f.written = make(map[string][]byte)
	}
	f.written[path] = data
	return nil
}

func (f *fakeConfigWriter) FileExists(_ context.Context, path string) (bool, error) {
	_, ok := f.written[path]
	return ok, nil
}

// --- REQ-B-005 tests ---

// TestInit_FirstInit_InteractiveConfirm verifies that on first init (no
// existing pin), the prompter is called and the signer is pinned.
func TestInit_FirstInit_InteractiveConfirm(t *testing.T) {
	t.Parallel()

	ts := &fakeTrustAnchorStore{exists: false}
	sp := &fakeSignerProbe{fp: "aabbccdd"}
	pr := &fakeConfirmPrompter{err: nil}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		Prompter:     pr,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	res, err := u.Init(context.Background(), usecase.InitInput{
		RegistryURL: "https://example.com/registry",
		ProjectID:   "myproj",
		ConfigDir:   "/tmp/proj",
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !res.PinWritten {
		t.Error("expected PinWritten=true on first init")
	}
	if res.SignerFingerprint != "aabbccdd" {
		t.Errorf("expected fingerprint aabbccdd, got %q", res.SignerFingerprint)
	}
	if ts.written == nil || ts.written.SignerFingerprint != "aabbccdd" {
		t.Error("expected trust anchor to be written with correct fingerprint")
	}
}

// TestInit_FirstInit_AcceptSigner verifies that --accept-signer bypasses the
// interactive prompt.
func TestInit_FirstInit_AcceptSigner(t *testing.T) {
	t.Parallel()

	ts := &fakeTrustAnchorStore{exists: false}
	sp := &fakeSignerProbe{fp: "aabbccdd"}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	res, err := u.Init(context.Background(), usecase.InitInput{
		RegistryURL:  "https://example.com/registry",
		ProjectID:    "myproj",
		ConfigDir:    "/tmp/proj",
		AcceptSigner: "aabbccdd",
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !res.PinWritten {
		t.Error("expected PinWritten=true")
	}
}

// TestInit_NonInteractive_WithoutAcceptSigner_FailsClosed verifies that
// --non-interactive without --accept-signer fails closed.
func TestInit_NonInteractive_WithoutAcceptSigner_FailsClosed(t *testing.T) {
	t.Parallel()

	ts := &fakeTrustAnchorStore{exists: false}
	sp := &fakeSignerProbe{fp: "aabbccdd"}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "myproj",
		ConfigDir:      "/tmp/proj",
		NonInteractive: true,
		// AcceptSigner: NOT set
	})
	if !errors.Is(err, usecase.ErrSignerNotAccepted) {
		t.Errorf("expected ErrSignerNotAccepted, got %v", err)
	}
	// Assert no side effect: nothing written.
	if ts.written != nil {
		t.Error("trust anchor must not be written when non-interactive without --accept-signer")
	}
	if len(cw.written) != 0 {
		t.Error("project config must not be written on ErrSignerNotAccepted")
	}
}

// TestInit_AcceptSigner_Mismatch verifies that --accept-signer with a wrong
// fingerprint fails closed.
func TestInit_AcceptSigner_Mismatch_FailsClosed(t *testing.T) {
	t.Parallel()

	ts := &fakeTrustAnchorStore{exists: false}
	sp := &fakeSignerProbe{fp: "aabbccdd"}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL:  "https://example.com/registry",
		ProjectID:    "myproj",
		ConfigDir:    "/tmp/proj",
		AcceptSigner: "wrongfp",
	})
	if !errors.Is(err, usecase.ErrSignerNotAccepted) {
		t.Errorf("expected ErrSignerNotAccepted, got %v", err)
	}
	if len(cw.written) != 0 {
		t.Error("project config must not be written on accept-signer mismatch")
	}
}

// TestInit_ErrSignerChanged verifies that a different signer in the existing
// pin returns ErrSignerChanged and writes nothing.
func TestInit_ErrSignerChanged(t *testing.T) {
	t.Parallel()

	ts := &fakeTrustAnchorStore{
		exists: true,
		anchor: usecase.TrustAnchor{SignerFingerprint: "oldpin"},
	}
	sp := &fakeSignerProbe{fp: "newkey"}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL: "https://example.com/registry",
		ProjectID:   "myproj",
		ConfigDir:   "/tmp/proj",
	})
	if !errors.Is(err, usecase.ErrSignerChanged) {
		t.Errorf("expected ErrSignerChanged, got %v", err)
	}
	if len(cw.written) != 0 {
		t.Error("project config must not be written on ErrSignerChanged")
	}
}

// TestInit_RegistryVerifyFail_NoSideEffect is the named obligation:
// registry signature-verify failure during init writes NO .byreis.yaml and NO pin.
func TestInit_RegistryVerifyFail_NoSideEffect(t *testing.T) {
	t.Parallel()

	ts := &fakeTrustAnchorStore{exists: false}
	sp := &fakeSignerProbe{err: errors.New("commit is unsigned")}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL: "https://example.com/registry",
		ProjectID:   "myproj",
		ConfigDir:   "/tmp/proj",
	})
	if !errors.Is(err, usecase.ErrRegistryVerifyFailed) {
		t.Errorf("expected ErrRegistryVerifyFailed, got %v", err)
	}
	// No side effects: trust anchor not written, project config not written.
	if ts.written != nil {
		t.Error("trust anchor must NOT be written on registry verify failure")
	}
	if len(cw.written) != 0 {
		t.Error("project config must NOT be written on registry verify failure")
	}
}

// TestInit_NetworkRoundTrips_Bounded is the REQ-A-001 deterministic sub-assertion:
// the init call graph contains exactly ONE network round-trip (the signer probe)
// and no key/identity/decrypt step. This is NOT a wall-clock test.
func TestInit_NetworkRoundTrips_Bounded(t *testing.T) {
	t.Parallel()

	rounds := 0
	ts := &fakeTrustAnchorStore{exists: false}
	sp := &fakeSignerProbe{fp: "abcdef"}
	pr := &fakeConfirmPrompter{}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:    ts,
		SignerProbe:   sp,
		Prompter:      pr,
		ConfigWriter:  cw,
		NetworkRounds: &rounds,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	_, err = u.Init(context.Background(), usecase.InitInput{
		RegistryURL:  "https://example.com/registry",
		ProjectID:    "myproj",
		ConfigDir:    "/tmp/proj",
		AcceptSigner: "abcdef",
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Exactly one network round-trip (the signer probe).
	if rounds != 1 {
		t.Errorf("expected exactly 1 network round-trip, got %d", rounds)
	}
}

// TestInit_SubsequentInit_PinMatches verifies that when the existing pin
// matches the registry signer, init succeeds and does NOT re-write the pin.
func TestInit_SubsequentInit_PinMatches(t *testing.T) {
	t.Parallel()

	ts := &fakeTrustAnchorStore{
		exists: true,
		anchor: usecase.TrustAnchor{SignerFingerprint: "matching-fp"},
	}
	sp := &fakeSignerProbe{fp: "matching-fp"}
	cw := &fakeConfigWriter{}

	u, err := usecase.NewInitializer(usecase.InitDeps{
		TrustStore:   ts,
		SignerProbe:  sp,
		ConfigWriter: cw,
	})
	if err != nil {
		t.Fatalf("NewInitializer: %v", err)
	}

	res, err := u.Init(context.Background(), usecase.InitInput{
		RegistryURL: "https://example.com/registry",
		ProjectID:   "myproj",
		ConfigDir:   "/tmp/proj",
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if res.PinWritten {
		t.Error("expected PinWritten=false on subsequent init with matching pin")
	}
	if ts.written != nil {
		t.Error("trust anchor must not be re-written when pin already matches")
	}
}
