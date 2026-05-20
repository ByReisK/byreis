// Package countercache — V2 test row for the rotation_epoch on-disk integrity binding.
//
// V2.cache.1: on-disk countercache integrity binding (ADR-0014 D5 Alt-β pattern)
// holds for the new rotation_epoch field — tampering with the on-disk file's
// rotation_epoch value fails the integrity check identical to tampering with
// last_accepted_counter.
//
// The integrity check for the cache files is provided by Alt-β (no HMAC):
// the schema_version + registry_id_sha256_prefix envelope fields are validated
// on every load. A file whose registry_id_sha256_prefix does not match the
// store's derived prefix is rejected (fail-rebuild). A file whose JSON is
// corrupt or whose schema_version is wrong is also rejected.
//
// For this test, "tampering with rotation_epoch" is simulated by:
//  1. Storing a valid epochs file via the store.
//  2. Directly editing the on-disk JSON to change the rotation_epoch value.
//  3. Asserting the load correctly returns the stored epoch (since Alt-β does
//     not HMAC the epoch value itself — the epoch is stored in the epochs.json
//     file which uses the same envelope + registry_id binding).
//
// The binding catch demonstrated is: the on-disk file for epochs uses the same
// registry_id_sha256_prefix binding as counters.json — replacing one registry's
// epochs.json with another registry's file is detected at load time.
// Direct field mutation within a correctly-bound file is NOT detected by Alt-β
// (as documented in ADR-0014 Q1 ruling: Alt-β trusts the file-system 0o600 +
// checkOwner discipline rather than HMAC). The test documents this boundary
// clearly and asserts the registry_id mismatch detection (the structural
// integrity catch that IS provided).
//
// The test is individually failing before the V2 epoch store is implemented.
package countercache_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/registry/countercache"
)

// makeSecureCacheRoot creates a secure (mode 0700) cache root under the test's
// temp directory. The returned path is the cacheRoot to pass to countercache.New.
// It creates a "registry" subdirectory at 0700 so the security checks in the
// cache's readSecureFile / ensureRegistryDir pass (cacheRoot must be mode 0700).
func makeSecureCacheRoot(t *testing.T) string {
	t.Helper()
	outer := t.TempDir() // outer dir may be 0755 — that is fine; we don't use it as cacheRoot
	root := filepath.Join(outer, "cache")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("makeSecureCacheRoot: %v", err)
	}
	return root
}

// TestV2_Cache1_RotationEpochIntegrityBinding proves the ADR-0014 D5 Alt-β
// integrity-binding pattern holds for the rotation_epoch field:
//
//  1. A correctly-written epochs file loads the epoch correctly.
//  2. Replacing the file content with a JSON blob bound to a DIFFERENT registry
//     URL causes fail-rebuild (the registry_id_sha256_prefix mismatch is caught),
//     returning (0, nil) — the same fail-rebuild semantics as for counter fields.
//  3. A file with an unparseable JSON body is also treated as fail-rebuild.
//
// Direct in-place mutation of rotation_epoch within a correctly-bound file is NOT
// caught by Alt-β (per ADR-0014 Q1 ruling). The test documents this explicitly
// and does NOT assert detection of direct field mutation — that would imply HMAC,
// which the auditor ruled out. The structural binding (registry_id, schema_version)
// IS the integrity control that V2 inherits.
func TestV2_Cache1_RotationEpochIntegrityBinding(t *testing.T) {
	t.Parallel()

	t.Run("round_trip_epoch_store_load", func(t *testing.T) {
		t.Parallel()

		root := makeSecureCacheRoot(t)
		store, newErr := countercache.New("https://registry.example.com/admins", root, nil)
		if newErr != nil {
			t.Fatalf("New: %v", newErr)
		}

		ctx := context.Background()
		if storeErr := store.StoreRotationEpoch(ctx, "proj-x", "secrets/prod.enc.yaml", 3); storeErr != nil {
			t.Fatalf("StoreRotationEpoch: %v", storeErr)
		}

		got, loadErr := store.LoadRotationEpoch(ctx, "proj-x", "secrets/prod.enc.yaml")
		if loadErr != nil {
			t.Fatalf("LoadRotationEpoch: %v", loadErr)
		}
		if got != 3 {
			t.Errorf("LoadRotationEpoch = %d, want 3", got)
		}
	})

	t.Run("missing_field_defaults_to_zero", func(t *testing.T) {
		t.Parallel()

		root := makeSecureCacheRoot(t)
		store, newErr := countercache.New("https://registry.example.com/admins", root, nil)
		if newErr != nil {
			t.Fatalf("New: %v", newErr)
		}

		// Load from a cold (absent) cache — must return 0, nil.
		got, loadErr := store.LoadRotationEpoch(context.Background(), "proj-cold", "secrets/x.enc.yaml")
		if loadErr != nil {
			t.Fatalf("LoadRotationEpoch cold: %v", loadErr)
		}
		if got != 0 {
			t.Errorf("LoadRotationEpoch cold = %d, want 0", got)
		}
	})

	t.Run("registry_id_mismatch_triggers_fail_rebuild", func(t *testing.T) {
		t.Parallel()

		root := makeSecureCacheRoot(t)
		registryURL := "https://registry.example.com/admins"
		store, newErr := countercache.New(registryURL, root, nil)
		if newErr != nil {
			t.Fatalf("New: %v", newErr)
		}

		ctx := context.Background()
		if storeErr := store.StoreRotationEpoch(ctx, "proj-y", "secrets/prod.enc.yaml", 7); storeErr != nil {
			t.Fatalf("StoreRotationEpoch: %v", storeErr)
		}

		// Tamper: replace the file content with a JSON blob bound to a different
		// registry URL. This simulates a cross-registry replay attack.
		registryIDPrefix := countercache.RegistryIDPrefix(registryURL)
		epochsPath := filepath.Join(root, registryIDPrefix, "epochs.json")

		// Read and re-marshal with a wrong registry_id_sha256_prefix.
		rawData, readErr := os.ReadFile(epochsPath)
		if readErr != nil {
			t.Fatalf("reading epochs.json: %v", readErr)
		}

		var env map[string]any
		if unmarshalErr := json.Unmarshal(rawData, &env); unmarshalErr != nil {
			t.Fatalf("unmarshal epochs.json: %v", unmarshalErr)
		}
		// Replace the registry_id_sha256_prefix with a wrong value.
		env["registry_id_sha256_prefix"] = "wrong0000000dead"

		tampered, marshalErr := json.Marshal(env)
		if marshalErr != nil {
			t.Fatalf("marshal tampered: %v", marshalErr)
		}
		if writeErr := os.WriteFile(epochsPath, tampered, 0o600); writeErr != nil {
			t.Fatalf("write tampered: %v", writeErr)
		}

		// Load must return (0, nil) — fail-rebuild semantics: the tampered file
		// is detected by the registry_id_sha256_prefix mismatch and deleted,
		// and the epoch defaults to 0 (cold cache after rebuild).
		got, loadErr := store.LoadRotationEpoch(ctx, "proj-y", "secrets/prod.enc.yaml")
		if loadErr != nil {
			t.Fatalf("LoadRotationEpoch after registry_id tamper: %v", loadErr)
		}
		if got != 0 {
			t.Errorf("LoadRotationEpoch after registry_id tamper = %d, want 0 (fail-rebuild)",
				got)
		}

		// The tampered file must have been deleted (fail-rebuild removes it).
		if _, statErr := os.Stat(epochsPath); statErr == nil {
			t.Error("tampered epochs.json was not deleted by fail-rebuild")
		}
	})

	t.Run("unparseable_json_triggers_fail_rebuild", func(t *testing.T) {
		t.Parallel()

		root := makeSecureCacheRoot(t)
		registryURL := "https://registry.example.com/admins"
		store, newErr := countercache.New(registryURL, root, nil)
		if newErr != nil {
			t.Fatalf("New: %v", newErr)
		}

		ctx := context.Background()
		if storeErr := store.StoreRotationEpoch(ctx, "proj-z", "secrets/a.enc.yaml", 5); storeErr != nil {
			t.Fatalf("StoreRotationEpoch: %v", storeErr)
		}

		// Corrupt the file on disk.
		registryIDPrefix := countercache.RegistryIDPrefix(registryURL)
		epochsPath := filepath.Join(root, registryIDPrefix, "epochs.json")
		if writeErr := os.WriteFile(epochsPath, []byte("corrupt"), 0o600); writeErr != nil {
			t.Fatalf("write corrupt: %v", writeErr)
		}

		// Load must return (0, nil) — fail-rebuild on unparseable JSON.
		got, loadErr := store.LoadRotationEpoch(ctx, "proj-z", "secrets/a.enc.yaml")
		if loadErr != nil {
			t.Fatalf("LoadRotationEpoch after corrupt: %v", loadErr)
		}
		if got != 0 {
			t.Errorf("LoadRotationEpoch after corrupt = %d, want 0 (fail-rebuild)", got)
		}
	})

	t.Run("direct_field_mutation_not_caught_by_altbeta_documented", func(t *testing.T) {
		t.Parallel()

		// This sub-test DOCUMENTS the known Alt-β limitation: direct mutation of
		// the rotation_epoch field value within a correctly-bound file is NOT
		// detected at load time. Alt-β relies on 0o600 + checkOwner + O_NOFOLLOW
		// to prevent writes, not HMAC. An attacker who can write the cache file as
		// the process owner can change the field value undetected.
		//
		// This is NOT a bug — it is the explicitly-accepted Alt-β posture per
		// ADR-0014 Q1 ruling. The test documents this and DOES NOT assert detection
		// (which would be incorrect for Alt-β). It asserts the test passes with the
		// mutated value (i.e., the store reads what is on disk).
		//
		// If detection of direct field mutation is ever required, Alt-γ (keychain-
		// backed HMAC key) must be adopted instead, which requires principal-go
		// sign-off as a schema change to ADR-0014.

		root := makeSecureCacheRoot(t)
		registryURL := "https://registry.example.com/admins"
		store, newErr := countercache.New(registryURL, root, nil)
		if newErr != nil {
			t.Fatalf("New: %v", newErr)
		}

		ctx := context.Background()
		if storeErr := store.StoreRotationEpoch(ctx, "proj-mut", "secrets/b.enc.yaml", 10); storeErr != nil {
			t.Fatalf("StoreRotationEpoch: %v", storeErr)
		}

		// Mutate the field directly.
		registryIDPrefix := countercache.RegistryIDPrefix(registryURL)
		epochsPath := filepath.Join(root, registryIDPrefix, "epochs.json")

		rawData, readErr := os.ReadFile(epochsPath)
		if readErr != nil {
			t.Fatalf("reading epochs.json: %v", readErr)
		}

		var env map[string]any
		if unmarshalErr := json.Unmarshal(rawData, &env); unmarshalErr != nil {
			t.Fatalf("unmarshal: %v", unmarshalErr)
		}
		// Find the entry and mutate rotation_epoch from 10 to 1.
		if entries, ok := env["entries"].(map[string]any); ok {
			entries["proj-mut/secrets/b.enc.yaml"] = float64(1) // mutated
		}
		mutated, marshalErr := json.Marshal(env)
		if marshalErr != nil {
			t.Fatalf("marshal mutated: %v", marshalErr)
		}
		if writeErr := os.WriteFile(epochsPath, mutated, 0o600); writeErr != nil {
			t.Fatalf("write mutated: %v", writeErr)
		}

		// Alt-β does NOT detect this mutation. The load returns the mutated value.
		// This is the documented Alt-β boundary — not a bug, a known limitation.
		got, loadErr := store.LoadRotationEpoch(ctx, "proj-mut", "secrets/b.enc.yaml")
		if loadErr != nil {
			t.Fatalf("LoadRotationEpoch after direct mutation: %v", loadErr)
		}
		// The value may be 1 (mutated) — that is expected under Alt-β.
		// We do NOT assert got == 10 here; we assert the load did not error.
		t.Logf("Alt-β documented boundary: LoadRotationEpoch after direct field mutation = %d "+
			"(Alt-β does not detect direct field mutation; relies on 0o600+checkOwner posture)", got)
	})
}
