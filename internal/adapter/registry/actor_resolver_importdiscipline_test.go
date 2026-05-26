package registry_test

// actor_resolver_importdiscipline_test.go enforces that actor_resolver.go
// does NOT directly import internal/core/crypto/identity or
// internal/core/crypto/decrypt.
//
// The ActorResolver adapter is read-only: it maps a signerID from an
// anchor-verified commit footer to a human label by looking it up in a
// SourceVerified AdminSet.SignerKeys map. It must never acquire a private
// key or decrypt capability. This check is file-level (AST import block),
// not package-level, because the registry adapter package legitimately
// imports identity and decrypt via other files (rotation_phase1.go). The
// actor_resolver.go file itself must import neither.

import (
	"testing"
)

// TestActorResolverAdapter_NoIdentityImport_InFile asserts that the specific
// file actor_resolver.go does NOT directly import crypto/identity.
// The ActorResolverAdapter is read-only and must have no compile-time route
// to private-key material; an identity import in the actor-display file is
// a security regression.
func TestActorResolverAdapter_NoIdentityImport_InFile(t *testing.T) {
	t.Parallel()
	assertFileDoesNotImport(t, "actor_resolver.go", identityPkg,
		"actor_resolver.go must not import crypto/identity — "+
			"the ActorResolver is read-only and must never acquire a private-key capability")
}

// TestActorResolverAdapter_NoDecryptImport_InFile asserts that the specific
// file actor_resolver.go does NOT directly import crypto/decrypt.
// The actor display path is write-only-safe: no decrypt capability may be
// reachable from it.
func TestActorResolverAdapter_NoDecryptImport_InFile(t *testing.T) {
	t.Parallel()
	assertFileDoesNotImport(t, "actor_resolver.go", decryptPkg,
		"actor_resolver.go must not import crypto/decrypt — "+
			"the ActorResolver is read-only; a decrypt import defeats the write-only guarantee")
}
