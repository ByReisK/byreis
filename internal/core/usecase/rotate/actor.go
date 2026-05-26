package rotate

import "context"

// ActorResolver is the consumer-defined port that maps a registry-attested
// signer identity to a human-readable actor label for the audit-log display.
// The git-side resolution (locating the introducing commit, parsing its footer,
// looking the signerID up in the verified registry admin record) lives in the
// adapter and is mapped to this port; no core → adapter edge is introduced.
//
// MANDATORY LABEL-SOURCE RULE:
//
// The actor label is derived ONLY from the byreis-signer footer signerID of an
// anchor-verified introducing commit, resolved as a key in a SourceVerified
// AdminSet.SignerKeys to its verified-registry human label. Every other source —
// an age1... recipient pubkey, contributor-supplied data, git author/committer,
// env/flag, or the raw signerID hex echoed as-is — is FORBIDDEN and MUST resolve
// to ok=false (caller displays "-"). ok=false also covers: unknown/absent
// signerID, non-SourceVerified AdminSet, present signerID with no human label,
// and legacy/pre-binding lines. Never fall back to a stale/unverified cache to
// recover a name.
type ActorResolver interface {
	// ResolveActorLabel maps a registry-attested signerID (the byreis-signer
	// footer value, == an AdminSet.SignerKeys key) to a human label sourced from
	// the verified registry admin record. ok=false → caller displays "-". The
	// label MUST NEVER be an age1... recipient pubkey, never contributor-supplied,
	// never git-author, never env/flag, never the raw signerID hex.
	ResolveActorLabel(ctx context.Context, signerID string) (label string, ok bool)
}
