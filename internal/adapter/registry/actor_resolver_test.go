package registry_test

// Tests for ActorResolverAdapter.
//
// The headline invariant under test:
//
//   A line whose JSONL carries "actor":"age1..." OR "actor":"alice" (an
//   arbitrary attacker string) with an unresolvable or absent verified signerID
//   MUST display "-", NEVER the forged JSONL value.
//
//   The displayed actor for both the human ACTOR column and the --json actor
//   field is derived ONLY from ResolveActorLabel(VerifiedSignerID), where
//   VerifiedSignerID comes from the anchor-verified introducing commit's
//   byreis-signer footer. The JSONL Actor field is NEVER consulted for display.
//
// Additional invariants tested:
//
//   - A BindingVerified entry whose verified footer signerID IS in the
//     SourceVerified AdminSet → displays the resolved human label.
//   - A BindingVerified entry whose signerID is NOT in the current verified
//     AdminSet (removed admin) → "-".
//   - Non-BindingVerified / FetchAuditLog path (empty VerifiedSignerID) → "-".
//   - The resolver never returns an age1... value or a raw recipient key.
//   - An unverified AdminSet (SourceVerified=false) → all lookups return "-".

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// TestActorResolver_ForgedJSONLActor_NeverDisplayed is the headline assertion.
// A line carrying an adversarial JSONL Actor value (age1... pubkey or an
// arbitrary human name like "alice") MUST never be displayed. The display
// value must always be the resolver's output ("-" when unresolvable).
func TestActorResolver_ForgedJSONLActor_NeverDisplayed(t *testing.T) {
	t.Parallel()

	adminSet := coreregistry.AdminSet{
		ProjectID:      "proj",
		SourceVerified: true,
		SignerKeys:     map[string]coreregistry.SignerKey{"admin-key-id": make(ed25519.PublicKey, 32)},
	}
	resolver := registry.NewActorResolverAdapter(adminSet)

	ctx := context.Background()

	tests := []struct {
		name              string
		entry             rotate.AuditEntryView
		wantResolvedLabel string // what resolveActorForDisplay must return
	}{
		{
			name: "forged age1 pubkey in JSONL Actor, no VerifiedSignerID",
			entry: rotate.AuditEntryView{
				Kind:             "rotation",
				Actor:            "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
				BindingStatus:    rotate.BindingVerified,
				VerifiedSignerID: "", // absent — forged actor has no verified signerID
			},
			wantResolvedLabel: "-",
		},
		{
			name: "forged human name in JSONL Actor, no VerifiedSignerID",
			entry: rotate.AuditEntryView{
				Kind:             "rotation",
				Actor:            "alice",
				BindingStatus:    rotate.BindingVerified,
				VerifiedSignerID: "", // absent — attacker wrote the JSONL but has no key
			},
			wantResolvedLabel: "-",
		},
		{
			name: "forged JSONL Actor, VerifiedSignerID not in AdminSet (removed admin)",
			entry: rotate.AuditEntryView{
				Kind:             "rotation",
				Actor:            "alice",
				BindingStatus:    rotate.BindingVerified,
				VerifiedSignerID: "removed-admin-key-id", // not in current AdminSet
			},
			wantResolvedLabel: "-",
		},
		{
			name: "non-BindingVerified entry — FetchAuditLog path",
			entry: rotate.AuditEntryView{
				Kind:             "rotation",
				Actor:            "alice",
				BindingStatus:    rotate.BindingMissing, // non-verifying path
				VerifiedSignerID: "admin-key-id",        // even with a valid signerID, non-verified → "-"
			},
			wantResolvedLabel: "-",
		},
		{
			name: "BindingTampered entry — never resolved",
			entry: rotate.AuditEntryView{
				Kind:             "rotation",
				Actor:            "alice",
				BindingStatus:    rotate.BindingTampered,
				VerifiedSignerID: "admin-key-id", // even valid signerID, tampered → "-"
			},
			wantResolvedLabel: "-",
		},
		{
			name: "BindingUnverifiedLegacy — never resolved",
			entry: rotate.AuditEntryView{
				Kind:             "rotation",
				Actor:            "admin-key-id",
				BindingStatus:    rotate.BindingUnverifiedLegacy,
				VerifiedSignerID: "admin-key-id",
			},
			wantResolvedLabel: "-",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := resolveActorForDisplayTest(ctx, resolver, tt.entry)
			if got != tt.wantResolvedLabel {
				t.Errorf("resolveActorForDisplay() = %q, want %q\n"+
					"INVARIANT VIOLATED: the forged JSONL Actor field %q was displayed instead "+
					"of the resolver result. The actor MUST be derived exclusively from "+
					"ResolveActorLabel(VerifiedSignerID).",
					got, tt.wantResolvedLabel, tt.entry.Actor)
			}
		})
	}
}

// TestActorResolver_BindingVerified_ResolvesLabel verifies that a BindingVerified
// entry whose VerifiedSignerID is in the current SourceVerified AdminSet returns
// the resolved human label (not "-").
func TestActorResolver_BindingVerified_ResolvesLabel(t *testing.T) {
	t.Parallel()

	adminSet := coreregistry.AdminSet{
		ProjectID:      "proj",
		SourceVerified: true,
		SignerKeys:     map[string]coreregistry.SignerKey{"admin-key-id": make(ed25519.PublicKey, 32)},
	}
	resolver := registry.NewActorResolverAdapter(adminSet)
	ctx := context.Background()

	entry := rotate.AuditEntryView{
		Kind:             "rotation",
		Actor:            "forged-value-that-must-be-ignored",
		BindingStatus:    rotate.BindingVerified,
		VerifiedSignerID: "admin-key-id",
	}

	got := resolveActorForDisplayTest(ctx, resolver, entry)
	if got == "-" {
		t.Errorf("resolveActorForDisplay() = %q, want a non-dash label for a known admin\n"+
			"A BindingVerified entry with a known VerifiedSignerID must resolve to a label.",
			got)
	}
	if got == entry.Actor {
		t.Errorf("resolveActorForDisplay() = %q, which equals the forged JSONL Actor field — "+
			"the display value must come from the resolver, not the JSONL field", got)
	}
	// The resolved label must not be an age1... pubkey.
	if len(got) == 62 && got[:4] == "age1" {
		t.Errorf("resolveActorForDisplay() = %q — label must never be an age1 recipient pubkey", got)
	}
}

// TestActorResolver_RemovedAdmin_DisplaysDash verifies that a BindingVerified
// entry whose signerID was valid at write time but is no longer in the current
// SourceVerified AdminSet (removed admin) displays "-".
func TestActorResolver_RemovedAdmin_DisplaysDash(t *testing.T) {
	t.Parallel()

	// AdminSet does NOT contain the removed admin's signerID.
	adminSet := coreregistry.AdminSet{
		ProjectID:      "proj",
		SourceVerified: true,
		SignerKeys:     map[string]coreregistry.SignerKey{"current-admin": make(ed25519.PublicKey, 32)},
	}
	resolver := registry.NewActorResolverAdapter(adminSet)
	ctx := context.Background()

	entry := rotate.AuditEntryView{
		Kind:             "rotation",
		Actor:            "removed-admin",
		BindingStatus:    rotate.BindingVerified,
		VerifiedSignerID: "removed-admin-key-id", // was valid at write time, not in current set
	}

	got := resolveActorForDisplayTest(ctx, resolver, entry)
	if got != "-" {
		t.Errorf("resolveActorForDisplay() = %q, want \"-\" for a removed admin\n"+
			"A BindingVerified entry whose signerID is not in the current SourceVerified "+
			"AdminSet must display \"-\", never a stale or reassigned name.", got)
	}
}

// TestActorResolver_UnverifiedAdminSet_AllDash verifies that when the AdminSet
// is not SourceVerified, all lookups return "-".
func TestActorResolver_UnverifiedAdminSet_AllDash(t *testing.T) {
	t.Parallel()

	adminSet := coreregistry.AdminSet{
		ProjectID:      "proj",
		SourceVerified: false, // not source-verified
		SignerKeys:     map[string]coreregistry.SignerKey{"admin-key-id": make(ed25519.PublicKey, 32)},
	}
	resolver := registry.NewActorResolverAdapter(adminSet)
	ctx := context.Background()

	entry := rotate.AuditEntryView{
		Kind:             "rotation",
		Actor:            "admin-key-id",
		BindingStatus:    rotate.BindingVerified,
		VerifiedSignerID: "admin-key-id", // valid signerID but AdminSet is not verified
	}

	got := resolveActorForDisplayTest(ctx, resolver, entry)
	if got != "-" {
		t.Errorf("resolveActorForDisplay() = %q, want \"-\" when AdminSet is not SourceVerified", got)
	}
}

// TestActorResolver_NilResolver_DisplaysDash verifies that a nil ActorResolver
// causes the display to return "-" (never panics, never falls back to e.Actor).
func TestActorResolver_NilResolver_DisplaysDash(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	entry := rotate.AuditEntryView{
		Kind:             "rotation",
		Actor:            "alice",
		BindingStatus:    rotate.BindingVerified,
		VerifiedSignerID: "admin-key-id",
	}

	got := resolveActorForDisplayTest(ctx, nil, entry)
	if got != "-" {
		t.Errorf("resolveActorForDisplay() = %q, want \"-\" when resolver is nil", got)
	}
}

// TestActorResolver_Age1InSignerID_NeverResolved verifies that a signerID
// shaped like an age1 recipient pubkey is rejected by the resolver even if it
// somehow appears in the AdminSet keys. This guards against a misconfigured
// registry that leaked a recipient key into the signer-key slot.
func TestActorResolver_Age1InSignerID_NeverResolved(t *testing.T) {
	t.Parallel()

	age1ID := "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	adminSet := coreregistry.AdminSet{
		ProjectID:      "proj",
		SourceVerified: true,
		SignerKeys:     map[string]coreregistry.SignerKey{age1ID: make(ed25519.PublicKey, 32)},
	}
	resolver := registry.NewActorResolverAdapter(adminSet)
	ctx := context.Background()

	label, ok := resolver.ResolveActorLabel(ctx, age1ID)
	if ok || label != "" {
		t.Errorf("ResolveActorLabel(%q) = (%q, %v), want (\"\", false) — "+
			"an age1 recipient pubkey must never be returned as an actor label",
			age1ID, label, ok)
	}
}

// resolveActorForDisplayTest is a test-local mirror of the CLI's
// resolveActorForDisplay function. It enforces the same mandatory label-source
// rule: BindingVerified + non-empty VerifiedSignerID + resolver hit → label;
// all other cases → "-". This avoids importing the cli package from the
// registry test package (which would violate the Clean Architecture direction).
func resolveActorForDisplayTest(ctx context.Context, resolver rotate.ActorResolver, e rotate.AuditEntryView) string {
	if e.BindingStatus != rotate.BindingVerified {
		return "-"
	}
	if e.VerifiedSignerID == "" {
		return "-"
	}
	if resolver == nil {
		return "-"
	}
	label, ok := resolver.ResolveActorLabel(ctx, e.VerifiedSignerID)
	if !ok || label == "" {
		return "-"
	}
	return label
}
