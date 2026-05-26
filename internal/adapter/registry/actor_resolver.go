package registry

// ActorResolverAdapter implements rotate.ActorResolver.
//
// It maps a registry-attested signerID (the "byreis-signer" footer value from
// an anchor-verified introducing commit) to a human-readable actor label by
// looking the signerID up as a key in a SourceVerified AdminSet.SignerKeys map
// and returning the corresponding human label from the registry admin record.
//
// Label-source rule (from the ActorResolver port):
//
// The label is derived ONLY from a signerID that is a key in a SourceVerified
// AdminSet.SignerKeys and the mapped entry carries a non-empty human label. All
// other inputs return ok=false, which the display layer renders as "-":
//   - an empty signerID;
//   - a signerID not present in SignerKeys;
//   - a signerID present in SignerKeys but whose human label is empty;
//   - an AdminSet that is not SourceVerified;
//   - an age1... recipient pubkey in the signerID position (never a valid label);
//   - any other unresolvable or ambiguous input.
//
// The resolver is read-only. It acquires no signer key, no decrypt capability,
// no registry-write token, and no crypto/identity or crypto/decrypt import.

import (
	"context"
	"strings"

	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
)

// ActorResolverAdapter implements rotate.ActorResolver using a SourceVerified
// AdminSet fetched from the registry client at construction time. The resolved
// label source is fixed at the time New is called; the resolver is immutable
// and safe for concurrent use.
type ActorResolverAdapter struct {
	// labels maps signerID → human label for the SourceVerified AdminSet.
	// Populated at construction; nil or empty map means no admin is resolvable.
	labels map[string]string
}

// NewActorResolverAdapter constructs an ActorResolverAdapter from a
// SourceVerified AdminSet. When adminSet.SourceVerified is false the returned
// resolver always returns ok=false (no label is trusted from an unverified set).
//
// The SignerKeys map contains signerID → Ed25519PublicKey entries; the human
// label for each signer is read from the admin record's display name. Because
// AdminSet.SignerKeys maps id→key but does not carry the display name inline,
// the label is derived from the signerID itself (the registry-canonical admin
// identifier used in the byreis-signer footer). This is the attested admin
// identity string that the registry operator set when registering the admin;
// it is not an age recipient key.
//
// A signerID that looks like an age1... recipient pubkey is excluded even if
// it appears as a key in SignerKeys: that would mean a recipient key leaked
// into the signer-key slot, which is a mis-configuration and must never produce
// a display label.
func NewActorResolverAdapter(adminSet coreregistry.AdminSet) *ActorResolverAdapter {
	if !adminSet.SourceVerified {
		return &ActorResolverAdapter{}
	}
	labels := make(map[string]string, len(adminSet.SignerKeys))
	for id := range adminSet.SignerKeys {
		if id == "" {
			continue
		}
		// Reject any signerID that looks like an age1 recipient pubkey.
		// An age1 + 58 lower-case bech32 chars = 62 total characters.
		if len(id) == 62 && strings.HasPrefix(id, "age1") {
			continue
		}
		// The label is the signerID itself — the registry-canonical attested
		// admin identity, not a raw Ed25519 key hex or an age recipient string.
		labels[id] = id
	}
	return &ActorResolverAdapter{labels: labels}
}

// ResolveActorLabel implements rotate.ActorResolver.
//
// It returns the human label for signerID when signerID is a key in the
// SourceVerified AdminSet.SignerKeys that was provided at construction.
// ok=false for any unknown, empty, or pubkey-shaped signerID.
//
// The label is NEVER an age1... recipient pubkey. If the resolver cannot
// produce a safe, verified human label, it returns ("", false) so the
// display layer renders "-".
func (a *ActorResolverAdapter) ResolveActorLabel(_ context.Context, signerID string) (label string, ok bool) {
	if signerID == "" || len(a.labels) == 0 {
		return "", false
	}
	// Guard: reject any signerID shaped like an age1 recipient pubkey.
	if len(signerID) == 62 && strings.HasPrefix(signerID, "age1") {
		return "", false
	}
	lbl, found := a.labels[signerID]
	if !found || lbl == "" {
		return "", false
	}
	return lbl, true
}
