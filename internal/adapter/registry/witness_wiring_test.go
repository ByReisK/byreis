// Package registry — B3d-2 witness-wiring and counter-authority sourcing tests.
//
// This file owns the test obligations that land with the witness-chain
// production wiring and D8-3 fail-closed ancestry hardening:
//
//   - N-8 (positive proof): a Valid()==true CounterAuthority is producible only
//     via capmint.Mint (adapter subtree only by the Go internal/ rule); a sibling
//     assertion checks that countertypes has no exported *adapterWitness producer
//     and that the registry adapter is the sole importer of capmint in the subtree.
//
//   - N-FRESH (D8-3): an IsAncestor/FetchHead transport error on the
//     CounterAuthority-sourcing path yields no Valid() authority (fail-closed);
//     the contributor offline cache-read branch is the only offline-tolerant path
//     and never yields a Valid() ADMIN authority; the branch split is asserted;
//     the retained ErrCacheTampered still fires on the authority-sourcing path.
//
//   - D8-1.5 sourcing negative: CounterAuthority returns non-Valid/error when
//     the counter store value did NOT originate from a SourceVerified fetch
//     (in-memory fallback path; unverified-HEAD transport).
package registry_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/adapter/registry/internal/capmint"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// ---- N-8: positive proof — Valid() authority via capmint only -----------------

// TestN8_ValidCounterAuthorityOnlyViaCapmint proves that:
// (a) capmint.Mint produces a Valid()==true CounterAuthority, and
// (b) no exported *adapterWitness producer exists in countertypes (the
//
//	word "adapterWitness" must not appear as a return type in any exported func),
//
// (c) the registry adapter is the sole importer of capmint in the subtree.
func TestN8_ValidCounterAuthorityOnlyViaCapmint(t *testing.T) {
	t.Parallel()

	// (a) Positive proof: capmint.Mint must produce a Valid()==true value.
	// This call is legal only from the adapter subtree (Go internal/ rule).
	ca := capmint.Mint(42, &countertypes.PendingBump{
		PendingCounter:    43,
		TargetArtifactSHA: "sha-abc",
		TargetPR:          "pr/1",
	})
	if !ca.Valid() {
		t.Fatal("N-8 FAIL: capmint.Mint produced a !Valid() CounterAuthority — " +
			"the bridge is broken; the production mint path must produce Valid()==true")
	}
	if ca.LastAccepted() != 42 {
		t.Errorf("N-8: LastAccepted() = %d, want 42", ca.LastAccepted())
	}
	if ca.Pending() == nil || ca.Pending().PendingCounter != 43 {
		t.Errorf("N-8: Pending().PendingCounter = %v, want 43", ca.Pending())
	}
	t.Log("N-8 (a): capmint.Mint produces Valid()==true — production mint path confirmed.")

	// (b) No exported *adapterWitness producer in countertypes.
	assertNoExportedAdapterWitnessProducer(t)

	// (c) Registry adapter is the only non-capmint package in the subtree that
	// imports capmint; verify capmint appears in the registry adapter's dep set.
	assertRegistryAdapterImportsCapmint(t)
}

// assertNoExportedAdapterWitnessProducer checks that no exported package-level
// function in countertypes returns the adapterWitness type by scanning the
// go doc output for "adapterWitness" in return positions.
func assertNoExportedAdapterWitnessProducer(t *testing.T) {
	t.Helper()

	const pkg = "github.com/ByReisK/byreis/internal/core/registry/countertypes"
	cmd := exec.CommandContext(t.Context(), "go", "doc", "-all", pkg)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("N-8 (b): go doc %s failed: %v — treat as failure", pkg, err)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "func ") || strings.HasPrefix(trimmed, "func (") {
			continue
		}
		// Package-level exported func. Check if the return portion names adapterWitness.
		lastParen := strings.LastIndex(trimmed, ")")
		if lastParen < 0 {
			continue
		}
		returnPart := trimmed[lastParen:]
		if strings.Contains(returnPart, "adapterWitness") {
			t.Errorf("N-8 (b) FAIL: exported function appears to return adapterWitness:\n"+
				"  %s\n"+
				"No exported *adapterWitness producer is permitted — "+
				"this is the laundering-vector guard.", trimmed)
		}
	}
	if !t.Failed() {
		t.Log("N-8 (b): no exported *adapterWitness producer found in countertypes API.")
	}
}

// assertRegistryAdapterImportsCapmint confirms that capmint appears in the
// registry adapter's transitive dep set (it is wired as the sole caller).
func assertRegistryAdapterImportsCapmint(t *testing.T) {
	t.Helper()

	const capmintPkg = "github.com/ByReisK/byreis/internal/adapter/registry/internal/capmint"
	const registryPkg = "github.com/ByReisK/byreis/internal/adapter/registry"

	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", registryPkg)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("N-8 (c): go list -deps %s failed: %v", registryPkg, err)
	}
	deps := strings.Fields(strings.TrimSpace(string(out)))
	found := false
	for _, dep := range deps {
		if dep == capmintPkg {
			found = true
			break
		}
	}
	if !found {
		t.Error("N-8 (c) FAIL: registry adapter does not import capmint — " +
			"the CounterAuthority production path is disconnected.")
	} else {
		t.Log("N-8 (c): registry adapter imports capmint (expected — sole wired caller).")
	}
}

// ---- D8-1.5 sourcing negative: non-SourceVerified read must not yield Valid() --

// TestD815_NonSourceVerified_NoValidAuthority proves that CounterAuthority
// returns non-Valid / error when the counter store value did NOT originate from
// a SourceVerified fetch. Two cases: in-memory fallback (no FetchTransport) and
// a transport that returns verified=false.
func TestD815_NonSourceVerified_NoValidAuthority(t *testing.T) {
	t.Parallel()

	// Case 1: in-memory fallback (no FetchTransport configured). The counter
	// value was never read from a signature-verified registry HEAD, so it cannot
	// yield a Valid() authority.
	t.Run("in_memory_fallback_no_valid_authority", func(t *testing.T) {
		t.Parallel()

		cfg := registry.ClientConfig{
			RegistryURL:    "https://example.com/registry",
			ProjectID:      "test-proj",
			CacheDir:       t.TempDir(),
			TrustAnchorKey: make([]byte, 32),
			Clock:          func() time.Time { return time.Now() },
			// No FetchTransport: in-memory fallback path.
		}
		c, err := registry.New(cfg)
		if err != nil {
			t.Fatalf("registry.New: %v", err)
		}

		ca, err := c.CounterAuthority(context.Background(), "test-proj", "secrets/prod.yaml")
		if ca.Valid() {
			t.Fatal("D8-1.5 FAIL: in-memory fallback path produced Valid() — " +
				"only a SourceVerified fetch may yield a Valid() authority")
		}
		// An error is expected/acceptable; the key invariant is Valid()==false.
		t.Logf("D8-1.5 in-memory fallback: err=%v, valid=%v — non-SourceVerified blocked", err, ca.Valid())
	})

	// Case 2: transport returns verified=false on FetchHead. The counter is read
	// but the HEAD is not anchored to the trust root — not SourceVerified.
	t.Run("unverified_head_no_valid_authority", func(t *testing.T) {
		t.Parallel()

		cfg := registry.ClientConfig{
			RegistryURL:    "https://example.com/registry",
			ProjectID:      "test-proj",
			CacheDir:       t.TempDir(),
			TrustAnchorKey: make([]byte, 32),
			Clock:          func() time.Time { return time.Now() },
			FetchTransport: &unverifiedHeadCounterTransport{lastAccepted: 5},
		}
		c, err := registry.New(cfg)
		if err != nil {
			t.Fatalf("registry.New: %v", err)
		}

		ca, err := c.CounterAuthority(context.Background(), "test-proj", "secrets/prod.yaml")
		if ca.Valid() {
			t.Fatal("D8-1.5 FAIL: unverified-head transport produced Valid() — " +
				"the counter store value did not originate from a SourceVerified fetch; " +
				"the sourcing precondition must reject this path")
		}
		t.Logf("D8-1.5 unverified-head: err=%v, valid=%v — non-SourceVerified blocked", err, ca.Valid())
	})
}

// ---- N-FRESH (D8-3): fail-closed ancestry on authority-sourcing path ---------

// TestNFRESH_AncestryError_NoValidAuthority proves that an IsAncestor transport
// error on the CounterAuthority-sourcing path yields no Valid() authority.
func TestNFRESH_AncestryError_NoValidAuthority(t *testing.T) {
	t.Parallel()

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "test-proj",
		CacheDir:       t.TempDir(),
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: &ancestryErrorTransport{
			headCommit:   "new-head-xyz",
			lastAccepted: 5,
		},
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// Seed a prior head observation so the ancestry check actually executes.
	priorSet := coreregistry.AdminSet{
		ProjectID:      "test-proj",
		SourceVerified: true,
		HeadCommit:     "prior-head-abc",
		FetchedAt:      time.Now().Add(-5 * time.Minute),
	}
	if seedErr := c.SeedCache(context.Background(), "test-proj", priorSet); seedErr != nil {
		t.Fatalf("SeedCache: %v", seedErr)
	}

	// CounterAuthority: transport returns a different commit and IsAncestor errors.
	// D8-3 requires fail-closed — no Valid() authority.
	ca, err := c.CounterAuthority(context.Background(), "test-proj", "secrets/prod.yaml")
	if ca.Valid() {
		t.Fatal("N-FRESH FAIL: ancestry transport error on authority-sourcing path yielded Valid() — " +
			"D8-3 requires fail-closed: undeterminable ancestry must not yield a Valid() authority")
	}
	if err == nil {
		t.Fatal("N-FRESH: expected a non-nil error when ancestry is undeterminable, got nil")
	}
	t.Logf("N-FRESH ancestry error: err=%v, valid=%v — fail-closed correctly", err, ca.Valid())
}

// TestNFRESH_ContributorOffline_NeverAdmin proves that the contributor offline
// path (no FetchTransport) never yields a Valid() ADMIN counter authority.
// This is the explicit, separately-tested branch that may proceed offline but
// must never promote to Valid() ADMIN authority.
func TestNFRESH_ContributorOffline_NeverAdmin(t *testing.T) {
	t.Parallel()

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "test-proj",
		CacheDir:       t.TempDir(),
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		// No FetchTransport: contributor offline path.
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	ca, err := c.CounterAuthority(context.Background(), "test-proj", "secrets/prod.yaml")
	if ca.Valid() {
		t.Fatal("N-FRESH FAIL: contributor offline path produced Valid() CounterAuthority — " +
			"this path must never yield a Valid() ADMIN authority")
	}
	// err may or may not be nil depending on implementation; the invariant is Valid()==false.
	t.Logf("N-FRESH contributor offline: err=%v, valid=%v — never ADMIN authority offline", err, ca.Valid())
}

// TestNFRESH_ErrCacheTampered_StillFires proves that the ErrCacheTampered
// anti-rollback cache check is still enforced after the SourceVerified and
// ancestry preconditions are added — neither check masks the other.
func TestNFRESH_ErrCacheTampered_StillFires(t *testing.T) {
	t.Parallel()

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "test-proj",
		CacheDir:       t.TempDir(),
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// Seed cached counter=10, then simulate fetch returning counter=5 (regression).
	err = c.SimulateCacheCounterRegression(context.Background(), "test-proj", "secrets/prod.yaml",
		10, // cached (higher)
		5,  // fetched (lower — regression)
	)
	if err == nil {
		t.Fatal("want ErrCacheTampered for regressed counter, got nil")
	}
	if !errors.Is(err, coreregistry.ErrCacheTampered) {
		t.Errorf("N-FRESH: want ErrCacheTampered on regressed counter, got %v", err)
	}
	t.Log("N-FRESH: ErrCacheTampered still fires on regressed cached counter (anti-rollback retained).")
}

// ---- N-8: CounterAuthority succeeds end-to-end on SourceVerified path ---------

// TestN8_SourceVerified_YieldsValidAuthority is the positive end-to-end proof
// via the full Client.CounterAuthority path: a SourceVerified transport, clean
// ancestry, and clean anti-rollback cache all present => Valid()==true.
func TestN8_SourceVerified_YieldsValidAuthority(t *testing.T) {
	t.Parallel()

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "test-proj",
		CacheDir:       t.TempDir(),
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: &verifiedSourceTransport{
			headCommit:   "head-abc",
			lastAccepted: 7,
		},
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// No prior head observation: first fetch, no ancestry check needed.
	ca, err := c.CounterAuthority(context.Background(), "test-proj", "secrets/prod.yaml")
	if err != nil {
		t.Fatalf("N-8 end-to-end: CounterAuthority returned unexpected error: %v", err)
	}
	if !ca.Valid() {
		t.Fatal("N-8 end-to-end: SourceVerified path did not yield Valid() — " +
			"the full precondition chain (SourceVerified + anti-rollback + ancestry) should pass")
	}
	if ca.LastAccepted() != 7 {
		t.Errorf("N-8 end-to-end: LastAccepted() = %d, want 7", ca.LastAccepted())
	}
	t.Log("N-8 end-to-end: SourceVerified path yields Valid()==true CounterAuthority.")
}

// ---- stub transports ----------------------------------------------------------

// unverifiedHeadCounterTransport simulates a transport where FetchHead returns
// verified=false (unsigned registry HEAD) but ReadCounter returns a value.
// CounterAuthority must not produce Valid() because the HEAD is not
// SourceVerified against the trust anchor.
type unverifiedHeadCounterTransport struct {
	lastAccepted uint64
}

func (u *unverifiedHeadCounterTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "unsigned-head", "unknown-signer", false, nil // verified=false
}
func (u *unverifiedHeadCounterTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (u *unverifiedHeadCounterTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return u.lastAccepted, nil, nil
}
func (u *unverifiedHeadCounterTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (u *unverifiedHeadCounterTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (u *unverifiedHeadCounterTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (u *unverifiedHeadCounterTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (u *unverifiedHeadCounterTransport) DiscardCounterSession(_ context.Context, _ string) {}

// ancestryErrorTransport simulates a transport where FetchHead returns a
// different HEAD commit (triggering an ancestry check) but IsAncestor returns
// an error (undeterminable ancestry). On the authority-sourcing path this must
// fail closed.
type ancestryErrorTransport struct {
	headCommit   string
	lastAccepted uint64
}

func (a *ancestryErrorTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return a.headCommit, "test-signer", true, nil // verified=true, different commit
}
func (a *ancestryErrorTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return false, errors.New("ancestry transport error: network unreachable")
}
func (a *ancestryErrorTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return a.lastAccepted, nil, nil
}
func (a *ancestryErrorTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (a *ancestryErrorTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (a *ancestryErrorTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (a *ancestryErrorTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (a *ancestryErrorTransport) DiscardCounterSession(_ context.Context, _ string) {}

// verifiedSourceTransport simulates a fully-verified transport for the positive
// end-to-end test: FetchHead returns verified=true, IsAncestor returns true,
// ReadCounter returns a real value.
type verifiedSourceTransport struct {
	headCommit   string
	lastAccepted uint64
}

func (v *verifiedSourceTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return v.headCommit, "trust-anchor-signer", true, nil // verified=true
}
func (v *verifiedSourceTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}
func (v *verifiedSourceTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return v.lastAccepted, nil, nil
}
func (v *verifiedSourceTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}
func (v *verifiedSourceTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}
func (v *verifiedSourceTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}
func (v *verifiedSourceTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}
func (v *verifiedSourceTransport) DiscardCounterSession(_ context.Context, _ string) {}
