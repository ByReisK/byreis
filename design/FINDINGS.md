# Crypto Spike — Findings

**Phase:** SPIKE · **Date:** 2026-05-19 · **Status:** model decided, pending reis-crypto-auditor review
**Scope:** validate (or kill) byreis's asymmetric-access value proposition with running code.

## Decision

Model B (native format) is chosen. Model A is NOT needed. SOPS data-key indirection is removed entirely.
`go test -race ./spike/...` is green: contributor-without-private-key works, all six attack tests fail
closed, plus forged-signature and AEAD-tamper defenses.

## Why B over A

- Contributor holds only public keys — proven. ContributorEncrypt takes no identity/private param;
  a reflection test statically forbids age.Identity, *age.X25519Identity, AdminIdentity (incl.
  slices/maps) in its signature and forbids private fields on Recipient. PLAN.md §4/§5 contradiction
  (SOPS needs a private key to mutate a file) does not exist in B: no shared data key, each value is
  its own independent multi-recipient age ciphertext.
- Every admin decrypts every value — proven (admin x value cross product).
- Removed recipient loses access — proven (re-encrypt to reduced set; removed admin gets ErrDecrypt;
  remaining admin still decrypts).
- Structural integrity — signed manifest verifies; six attacks fail closed.
- Model A also satisfies the contributor property but keeps SOPS interop at the cost of a two-format
  system + admin-only merge that re-derives the data key. B is simpler and strictly stronger on the
  core promise. Fall back to A only if SOPS interop becomes a hard requirement (it is not).

## Format spec to carry into PLAN.md v2

FormatVersion = "byreis.native.v1". Artifact = {format_version, counter (uint64 monotonic per file),
values: map[name]->age ciphertext (multi-recipient to ALL admin pubkeys, no data key),
manifest: {format_version, counter, sorted_keys, recipient_set (sha256(pubkey)[:16] sorted),
value_digests map[name]->sha256(ct) hex, signature Ed25519 over deterministic canonical encoding}}.

Normative rules (re-implement under TDD in internal/core, do not lift this spike):
1. Canonical signing bytes hand-rolled & deterministic (fixed field order, 0x1e/0x1f separators,
   sorted keys & fingerprints). Map iteration order must never reach the signer.
2. Verify fails closed in order: format version -> manifest/artifact version&counter agreement ->
   strict counter monotonicity (>lastCounter) -> key-set equality -> per-key ct digest ->
   recipient-set equality vs registry -> signature last. Any failure is hard error.
3. Digest binds ciphertext to key NAME via canonical encoding (defeats ciphertext-swap).
4. Counter is per-secrets-file, last-accepted persisted registry/audit side; replay = counter<=last.

Manifest-signer question (DESIGN input, not a blocker): contributor has no private key so cannot
sign. Resolution: contributor submission is UNSIGNED (structure still fully digest-committed; all
tamper attacks still caught); admin signs manifest at review/merge with registry-trusted admin key;
file of record is always admin-signed. VerifyArtifact(nil) validates unsigned submission structure;
with key it requires+checks signature; both fail closed. Auditor must review this trust decision.

## Costs

- SOPS interop lost. byreis files no longer SOPS-readable/editable. Mitigation: optional admin-only
  one-way `byreis export --sops`. Recommend PLAN.md drop "SOPS-compatible" headline, reposition as
  "SOPS-inspired, age-native". The asymmetric model is fundamentally incompatible with SOPS's
  symmetric data-key design — keeping both is the source of the original contradiction.
- File size ~1.6 KB/value at 10 recipients (~160 KB for 100 keys), ~linear in keys x recipients.
- Performance: contributor hot path (submit = 1 key, ~10 recipients) ~4 ms (negligible). Full
  re-encrypt/rotation 100 keys x 10 recipients ~2.4 s encrypt / ~140 ms decrypt-all (rare admin
  batch op, acceptable; parallelizable). Decrypt ~1.4 ms/value regardless of corpus size.

## Residual risks (for reis-crypto-auditor / reis-threat-modeler)

1. Unsigned contributor submissions: authenticity until merge rests on PR/review + repo
   signed-commit/branch-protection boundary. Confirm sufficient; document in PLAN.md §6.
2. Counter authority: anti-replay needs lastCounter in a trustworthy home (registry/audit), not the
   mutable project repo. DESIGN must pin this.
3. Recipient-set source of truth must come from the verified admin registry, not the artifact.
4. No per-value AAD beyond age defaults; key name bound via signed digest instead — auditor confirm
   equivalence for §6 threats.
5. Encoding: spike uses JSON; PLAN.md v2 should pick YAML for diffs but canonical SIGNING bytes stay
   the hand-rolled encoding, independent of file serialization.
6. Spike code is throwaway; real impl TDD'd fresh in internal/core; nothing lifted verbatim.

Model decision: B (native, no data key, per-value multi-recipient age, signed structural manifest,
monotonic counter). Model A rejected. Ready for reis-crypto-auditor review. Not validated until
auditor (+ reis-threat-modeler for the new submission surface) signs off.
