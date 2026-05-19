# ADR-0001 — Signed manifest canonical encoding & Ed25519 signing model

Status: Proposed (revised — closes auditor H-2, M-2; post-DESIGN TM-D3 artifact-SHA
preimage cross-reference added) · Date: 2026-05-19 · Owner: reis-principal-go
Encodes: C-1, C-2, C-3, C-7, T7, T9, plus the AEAD-freshness clause (auditor H-2) and
the `format_version` charset constraint (auditor M-2). Normative spec lives in DESIGN.md §3.
The artifact-SHA preimage (TM-D3) is normatively defined in DESIGN.md §3.5 and is
cross-referenced from the signing model below (the unsigned→signed `S_signed`
relationship is part of "what is signed and what the next reader pins").

## Decision

The bytes Ed25519 signs are a hand-rolled, deterministic byte stream (NOT JSON/YAML
marshalling), with fixed field order, `0x1f` unit / `0x1e` record separators, internally
sorted key names and recipient fingerprints, signature excluded. Fields, in order:
`format_version, registry_project_id (C-2), logical_file_name (C-2), counter:uint64-BE (C-3),
{sorted key_name, per-key digest = sha256(key_name ‖ 0x00 ‖ ciphertext)}, {sorted full
32-byte recipient fingerprint hex (C-7)}`. The admin signs at merge over the exact reviewed
(pinned) bytes. Verification is the fixed fail-closed order in DESIGN §3.4 with no
nil-key/skip branch (C-1/T9).

### Artifact content SHA preimage & the unsigned→signed relationship (TM-D3)

The canonical signed *byte stream* above (what Ed25519 signs) is **distinct** from
the artifact **file content SHA** that git pins and `--expect`/`VerifyOfRecord`
step 4 compare. The latter is normatively defined in DESIGN §3.5: `sha256` over the
**exact, untransformed byte sequence of the artifact file** as fetched/pushed —
**zero normalization** (no YAML re-parse, no CRLF/whitespace/key-order
canonicalization). It is hashed once over the raw byte buffer at the boundary and
carried opaque; core/adapters MUST NOT canonicalize before hashing.

Signing changes the file bytes. The unsigned contributor artifact (`S_unsigned`,
what the contributor pushes and the reviewer pins via `--expect`) becomes the signed
file-of-record (`S_signed`) once the admin's Ed25519 `manifest_sig` is serialized
into it (and after any C-4 fresh whole-file re-encrypt, DESIGN §3.0/§4.2 step 3,
which itself changes the bytes). These are two distinct SHAs over two distinct byte
sequences. **`pending.target_artifact_sha` is the post-sign `S_signed`** — the bytes
the next reader pins at DESIGN §3.4 step 4 — recorded write-ahead so the post-merge
reader's `content_sha(file) == pending.target_artifact_sha` check holds against the
committed signed file (ADR-0006 step 2/3, DESIGN §3.5.3). Recording the pre-sign
`S_unsigned` is an explicit defect (negative test, DESIGN §7.2 D3).

### `format_version` is a constrained enum (auditor M-2 — T7)

`format_version` (field 1, the first signed field) MUST match the fixed regex
`^byreis\.native\.v[0-9]+$` (e.g. `byreis.native.v1`). It is **not** a free-form
string. Like all ids and key names, it is routed through the **same `0x1e`/`0x1f`
control-character rejection** before it reaches the canonical encoder: any
`format_version` containing `0x1e` or `0x1f`, or not matching the regex, is
rejected with `ErrFormatVersion` *before* any byte is emitted. This closes the
separator-injection gap where an unconstrained first field could smuggle a `US`
byte and shift every subsequent signed field's framing. The constraint holds for
**every** signed field: ids, file name, key names, fingerprint hex, and now
`format_version`.

### AEAD freshness — every value is a fresh independent ciphertext (auditor H-2)

This is a **binding** clause of the signing model:

- Each secret value is an **independent multi-recipient `age` ciphertext**
  produced by a **fresh `age.Encrypt`** call to the verified recipient set. There
  is no shared data key and no whole-file MAC (PLAN §4).
- **Re-encryption at merge (the C-4 stale-recipient path, DESIGN §4.2 step 3)
  MUST regenerate every value's ciphertext** from plaintext to the *current
  signature-verified recipient set* via a fresh `age.Encrypt`. It MUST NOT splice,
  re-wrap, or carry forward any prior ciphertext.
- **Ciphertext reuse across counter generations is forbidden.** A new
  file-of-record (new `counter`) is signed only over freshly-encrypted ciphertext
  for that generation. Reusing a prior generation's ciphertext bytes under a new
  counter is a defect (it would let a stale or attacker-influenced blob ride a
  fresh signature) and is a required negative test (DESIGN §7).

Rationale: the per-key digest binds `key_name ‖ 0x00 ‖ ciphertext`, so reusing an
old ciphertext under a new counter would still verify structurally; only the
freshness rule + the C-4 full re-encryption obligation prevents a stale-recipient
or replayed-blob ciphertext from being laundered through a new admin signature.

## Alternatives considered

- **JSON/YAML canonical marshalling as signed bytes.** Rejected: serializer map-order and
  whitespace nondeterminism become a verification flakiness = security hole; YAML has
  multiple valid encodings of the same data. The spike already proved a hand-rolled encoding
  is needed; we keep file serialization (YAML, for diffs) independent of signing bytes.
- **Normalizing the artifact file before computing its content SHA (rejected —
  TM-D3).** Any normalization (YAML re-parse, CRLF/whitespace/key-order
  canonicalization) before hashing would make the T1/T2 pin meaningless: an
  attacker could re-push semantically-equivalent but byte-different bytes and the
  pin would not detect it. The content SHA is over the exact untransformed file
  bytes (DESIGN §3.5); two "equivalent" files differing by one byte have different
  SHAs by design.
- **Protobuf/CBOR canonical form.** Rejected for v0.1: adds a dependency and codegen for a
  ~6-field structure; hand-rolled fixed encoding is auditable by eye and dependency-free.
- **Free-form `format_version` string.** Rejected (auditor M-2): an unconstrained
  first signed field is a separator-injection / framing-ambiguity surface; a fixed
  regex enum + the control-char rejection keeps every signed field safe.
- **Truncated 16-byte fingerprint (spike).** Rejected — C-7 requires full 32 bytes; 16-byte
  truncation lowers collision resistance for a security-set identifier.
- **`sha256(ciphertext)` digest not bound to key name (spike).** Rejected — enables
  ciphertext-swap-between-keys; we bind `key_name ‖ 0x00 ‖ ciphertext` (T7).
- **Re-wrap / splice prior ciphertext at re-encrypt time.** Rejected (auditor
  H-2): only a fresh `age.Encrypt` from plaintext to the verified recipient set
  guarantees the live file's confidentiality matches the *current* admin set and
  that no stale/attacker-influenced blob is carried across counter generations.

## Consequences

- Deterministic, dependency-free, eye-auditable signed bytes; reorder/swap/strip/transplant/
  downgrade all detectable (T7, C-2). Fail-closed verification with precise sentinel errors.
- The artifact file content SHA is a separate, normalization-free preimage
  (DESIGN §3.5); the next reader pins the post-sign `S_signed`, which is what the
  write-ahead records (ADR-0006). Re-marshalling before hashing, or recording the
  pre-sign `S_unsigned`, are explicit defects with negative tests (DESIGN §7.2 D3).
- `format_version`, key names, project id, file name, fingerprint hex containing
  `0x1e`/`0x1f` — or a `format_version` not matching `^byreis\.native\.v[0-9]+$` —
  MUST be rejected before encoding (`ErrFormatVersion` for the version,
  `ErrManifestMismatch` for ids/key names). Explicit input-validation obligation.
- Re-encryption at merge regenerates **every** value's ciphertext to the verified
  recipient set via fresh `age.Encrypt`; ciphertext is never reused across counter
  generations. Required negative test (DESIGN §7).
- The encoding is a hard compatibility surface: any future field change is a
  `format_version` bump (new `vN`) and a new ADR (it is signed, so it cannot change
  silently).
- Re-implemented fresh under TDD in `internal/core/crypto/manifest`; nothing lifted from
  `spike/`.
