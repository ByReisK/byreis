# ADR-0006 — Counter/audit store shape & write-ahead transactional bump-at-merge

Status: Proposed (revised — closes auditor H-1; post-DESIGN TM-D3 SHA-preimage
clause applied to step 4a/4b; B0-gate: `countertypes` type/ctor + sentinel
ownership landed — **SECURITY-RELEVANT (TM-D1), pending `reis-crypto-auditor`
sign-off before B0 closes; NOT self-certified**) · Date: 2026-05-19 · Owner:
reis-principal-go
Encodes: C-3, T3, REQ-B-004, REQ-C-001; `target_artifact_sha` follows the DESIGN
§3.5 preimage rule (TM-D3 — sha256 over the exact untransformed signed-file bytes,
zero normalization; the recorded SHA is the post-sign `S_signed` the next reader pins).
Revision note: the original "ordered sequence + detect-on-next-verify as ErrReplay"
self-heal claim was **non-implementable and false** (auditor H-1). The check never
fired: a correctly-merged-but-unbumped file has `signed_counter (= last+1) >
last_accepted`, which is exactly the OK predicate, so `ErrReplay` could not
distinguish it from a legitimate advance. This revision replaces it with a
**write-ahead pending-counter** protocol and a distinct terminal error.
TM-D3 note: `target_artifact_sha` is bound to the DESIGN §3.5 preimage and is the
**post-sign** `S_signed` (the bytes the next reader pins at DESIGN §3.4 step 4), not
the pre-sign unsigned `S_unsigned`; the protocol below is reordered so the
write-ahead records the SHA of the exact signed file-of-record bytes.

## Decision

### Type & error ownership (B0-gate decision — TM-D1, security-relevant)

`CounterAuthority` and `PendingBump` are the in-process domain view of the
two-record store below. They live in a **new pure isolated sub-package
`internal/core/registry/countertypes`** (the established `rectypes`-style
isolation wedge):

- The **only constructor is package-private** (`countertypes.newCounterAuthority`)
  and is reachable **only by the registry adapter** (`internal/adapter/registry`)
  that reads the signature-verified counter store + anti-rollback cache mirror.
  The **sole producer** of a valid value is therefore the `registry` port's
  `CounterAuthority(ctx, project, file)` method. This is a **compile-time
  type-shape constraint, NOT prose** — exactly the TM-D1 §2.0 wedge form, mirroring
  how `rectypes` mechanically isolates the recipient value types.
- `internal/core/crypto/verify` **imports `countertypes` and CONSUMES the opaque
  value** (reads fields via accessors / calls `Valid()`) at §3.4 step 4. It
  **cannot construct a valid one**: there is no exported constructor and no
  settable trust-bearing field; a zero-value / struct-literal is **not `Valid()`**
  and step 4 hard-errors on it. The previously exported `verify.NewCounterAuthority`
  is **REMOVED**.
- Because the type no longer lives in `verify`, the
  **`internal/core/registry → internal/core/crypto/verify` import is removed
  (gap 4a)**. The dependency now points `verify → countertypes` and
  `registry → countertypes` only; there is no cycle and no `registry`-on-`verify`
  edge.

**Sentinel ownership (B0-gate decision — no junk-drawer errors package, no
cross-package aliasing).** Each shared sentinel is defined **exactly once in its
semantic owner**; other packages **reference the canonical symbol** — `Err =
otherpkg.Err` re-alias vars are **forbidden**, and a catch-all `errors`
junk-drawer package is **explicitly rejected**:

- `ErrReplay`, `ErrCounterReconcile` → defined in
  `internal/core/registry/countertypes` (the counter authority is their semantic
  owner; they travel with the opaque type). `verify` and `registry` reference
  `countertypes.ErrReplay` / `countertypes.ErrCounterReconcile` directly.
- `ErrNoTrustedSigner` → stays in `internal/core/crypto/verify` (its semantic
  owner). The registry boundary (L-1) returns `verify.ErrNoTrustedSigner` **by
  reference**, never a `registry.ErrNoTrustedSigner` alias var.

**This Type & error ownership subsection is security-relevant (TM-D1). It is NOT
self-certified: `reis-crypto-auditor` (and `reis-threat-modeler` for TM-D1) MUST
sign off the `countertypes` construction/trust model before B0 closes.**

### Store shape

`last_accepted_counter` is per-`(project, file)` and its **sole authority** is a file
`counters/<project>/<file>.json` committed in the **admin registry repo** — so it
inherits the registry's signed-commit integrity and the client-pinned trust anchor
(DESIGN §4.1). The file holds **two** records, not one:

```json
{
  "project_id": "<id>",
  "file": "<logical file name>",
  "last_accepted_counter": <uint64>,      // committed: highest counter durably merged
  "last_pr": "<pr ref of the commit that set last_accepted_counter>",
  "updated_at": "<rfc3339>",
  "pending": {                            // present iff a merge is in flight; else null
    "pending_counter": <uint64>,          // == last_accepted_counter + 1
    "target_artifact_sha": "<full content SHA of the exact SIGNED file-of-record bytes — DESIGN §3.5 S_signed>",
    "target_pr": "<pr ref>",
    "intent_at": "<rfc3339>"
  }
}
```

`pending` is the **write-ahead intent**. `last_accepted_counter` is the **commit
record**. Both live in the signed registry repo; both are mirrored into the local
cache monotonic + integrity-tagged (a regressed cached `last_accepted_counter` is
`ErrCacheTampered` — anti-rollback offline). `pending` is **not** authority for
acceptance — only `last_accepted_counter` is.

`target_artifact_sha` is the DESIGN §3.5 preimage: `sha256` over the **exact,
untransformed byte sequence** of the **signed** file-of-record (zero normalization —
no YAML re-parse, no CRLF/whitespace/key-order canonicalization). It is the
post-sign `S_signed`, i.e. exactly the bytes the next reader pins at DESIGN §3.4
step 4 — never the pre-sign unsigned `S_unsigned` (TM-D3 / DESIGN §3.5.3).

### Write-ahead transactional protocol (strict order)

`Merge` for `(project, file)` executes in **exactly** this order; each step is a
hard gate (DESIGN §4.2 steps 4a–6). The signed file-of-record bytes are produced
**before** the write-ahead record so the recorded `target_artifact_sha` is the
post-sign `S_signed` (TM-D3 / DESIGN §3.5.3):

1. `last := LastAcceptedCounter(project,file)` from the signature-verified registry
   store; `next := last + 1`.
2. **PRODUCE SIGNED BYTES (no side effects yet):** build canonical bytes with
   `next` + C-2 ids over the **pinned** (post-C-4 re-encryption, DESIGN §3.0/§4.2
   step 3) artifact; Ed25519-sign → the signed file-of-record byte sequence.
   Compute `S_signed := content_sha(signed bytes)` per the DESIGN §3.5 preimage
   (sha256 over the exact untransformed signed bytes, zero normalization). No
   registry or secrets write has occurred yet.
3. **WRITE-AHEAD (registry-side, signed commit, BEFORE the secrets-repo merge):**
   `RecordPendingBump{pending_counter=next, target_artifact_sha=S_signed,
   target_pr}`. `target_artifact_sha` is the **post-sign** `S_signed` from step 2 —
   exactly the bytes step 4 commits and the next reader pins (DESIGN §3.4 step 4 /
   §3.5.3). This is a signed commit to the admin registry repo. It MUST be durable
   before step 4.
   - If a `pending` already exists for this `(project,file)`:
     - same `pending_counter` AND same `target_artifact_sha` (= the same
       `S_signed`) → **resume** (a prior attempt crashed after write-ahead;
       continue from step 4 with the already-produced signed bytes — re-derived
       deterministically over the same pinned artifact + same `next`).
     - any other mismatch → `ErrCounterReconcile` (terminal, manual; see below).
   - If step 2's C-4 re-encrypt changed the artifact after an earlier write-ahead
     (so `S_signed` differs from a previously recorded `target_artifact_sha`), the
     write-ahead is **rewritten** here with the new `S_signed` before the merge —
     the recorded intent always equals the exact signed bytes (DESIGN §3.5.3).
4. **MERGE (secrets repo):** `MergeSubmission(--expect sha, SignedBytes)` writes
   the signed file-of-record (whose `content_sha == S_signed`) to protected
   `secrets/**` + merges. Fails closed (`ErrArtifactMoved`) if the on-PR artifact
   SHA moved (T2). On failure the write-ahead `pending` is **left in place** (its
   presence + matching `S_signed` is what makes a retry a safe resume, not a
   reconcile).
5. **COMMIT-BUMP (registry-side, signed commit, AFTER merge lands):**
   `CommitBump{new last_accepted_counter = pending.pending_counter,
   last_pr = pending.target_pr}` AND **clear `pending` to null in the same commit**
   (single atomic registry commit: advance + clear). After this, no `pending`
   exists and `last_accepted_counter == next`.
6. Post-merge mandatory integrity check (DESIGN §4.2 step 7): live file MUST
   `VerifyOfRecord` and round-trip decrypt for **every** current recipient; failure
   surfaces (the live file is already committed at this point — this is a loud
   alarm + reconciliation hint, not a silent pass).

### Verify-time reconciliation decision (the check that MUST fire)

`VerifyOfRecord` step 4 (DESIGN §3.4 step 4) decides the counter outcome using
**both** records — `last_accepted_counter` and `pending` — fetched from the
signature-verified registry store (never the repo, C-3; the authority value is
produced ONLY by the registry port, DESIGN §2.0/§2.3 TM-D1). Let `sc` =
`signed_counter` of the file under verification, `la` = `last_accepted_counter`,
and `P` = the `pending` record (possibly null). `content_sha(file)` is the DESIGN
§3.5 preimage (sha256 over the exact untransformed committed file bytes), compared
against `P.target_artifact_sha` (= `S_signed`). The decision table is exhaustive
and fail-closed:

| Condition | Outcome |
|---|---|
| `sc <= la` | `ErrReplay` (a counter not strictly greater than committed authority — replayed/old file) |
| `sc == la + 1` AND `P != null` AND `P.pending_counter == sc` AND `P.target_artifact_sha == content_sha(file)` | **OK** — this is the legitimately-merged file whose commit-bump has not yet landed (the crash window). Verify SUCCEEDS for *this exact pinned artifact* and the caller (`merge` resume, or read of the just-merged file) MUST drive the commit-bump (step 5). A **read-only** verify caller MUST NOT write the commit-bump and MUST NOT synthesize a `pending` (DESIGN §7.2 L3). Any **other** artifact presented at `sc == la+1` falls to the next row. |
| `sc == la + 1` AND `P != null` AND `P.pending_counter == sc` AND `P.target_artifact_sha != content_sha(file)` | `ErrCounterReconcile` — a different artifact than the recorded write-ahead intent is claiming the pending counter (split-brain / attempted replay into the open slot). Terminal, manual. |
| `sc == la + 1` AND (`P == null` OR `P.pending_counter != sc`) | `ErrCounterReconcile` — a file signed with `last+1` exists with **no matching write-ahead intent and no committed bump**. This is the previously-undetectable "merged but unbumped, intent lost" / forged-advance state. Terminal, manual — **NOT auto-heal**. |
| `sc > la + 1` | `ErrCounterReconcile` — counter skipped ahead of authority (gap); never silently accepted. Terminal, manual. |

Key consequences of the table:

- A correctly-merged-but-unbumped file is **only** OK while its content SHA
  (DESIGN §3.5 preimage of the committed signed bytes) matches the still-present
  `pending.target_artifact_sha` (= `S_signed`). Because the write-ahead records the
  post-sign `S_signed` (step 3, TM-D3), the committed file's `content_sha` equals
  the recorded value exactly — the reader pins the same bytes that were signed and
  recorded, not the pre-sign unsigned bytes. The instant the commit-bump lands,
  `pending` is cleared and `la` becomes `sc`, so the same file re-verifies via
  row 1's complement (`sc == la`, OK by the of-record path's normal "equal to
  committed, signature still authoritative" — handled as the steady state:
  `sc <= la` is `ErrReplay` ONLY for `sc < la`; `sc == la` with a valid signature
  over the committed artifact is the normal live-read OK case).
  *(Implementation note: the steady-state live read has `sc == la`; treat
  `sc < la` as `ErrReplay`, `sc == la` as the committed-and-current OK path,
  `sc == la + 1` via the pending table, `sc > la + 1` as `ErrCounterReconcile`.)*
- The "intent lost" / "forged advance" state is now a **distinct terminal error**
  (`ErrCounterReconcile`), never confused with `ErrReplay` and never auto-healed.
- `ErrReplay` and `ErrCounterReconcile` are **distinguishable and both
  fail-closed**: `ErrReplay` = old/replayed file (`sc < la`);
  `ErrCounterReconcile` = the integrity of the counter authority itself is in
  question (manual operator action required, with a printed runbook hint).

### Resume vs. reconcile (crash-window behavior)

- Crash **after step 3, before step 4**: `pending` present (recording `S_signed`),
  secrets unmerged. Re-run `merge` → re-derive the same signed bytes
  deterministically (same pinned artifact + same `next`), recompute `S_signed`,
  step 3 finds matching `pending` (same counter + same `S_signed`) → resume.
  Live file untouched. Verify of the *old* live file: `sc <= la` path → it is the
  committed file, OK; no replay.
- Crash **after step 4, before step 5**: `pending` present, secrets merged.
  Re-run `merge` (or the post-merge verify) → row "OK, drive commit-bump" → step 5
  completes. The window is bounded and fail-closed; the merged file verifies as OK
  **only** because its content SHA (the §3.5 preimage of the committed signed
  bytes) matches the recorded post-sign `S_signed`.
- Lost/garbled `pending` with a merged `last+1` file (the bug this ADR fixes):
  → `ErrCounterReconcile`. Hard stop, manual. We do **not** guess.
- A **read-only** `VerifyOfRecord` caller hitting the OK row in the crash window
  does **not** write `CommitBump` and does **not** synthesize a `pending` (DESIGN
  §7.2 L3): only the `merge` resume path (or an explicit admin reconcile action)
  drives `CommitBump`, and only against a pre-existing matching signed `pending`.

### Operator reconciliation (manual, documented)

`ErrCounterReconcile` prints an actionable runbook hint (DESIGN §2.3 / §4.2):
the admin inspects the registry counter store history (signed commits), confirms
the true highest merged counter for `(project,file)`, and runs an explicit
`byreis admin counter reconcile --project <p> --file <f> --set <n> --pr <ref>`
(admin-mode-gated, audited, signed registry commit). There is **no automatic
heal**; the tool refuses to serve/deploy the file until reconciled.

## Alternatives considered

- **Original "ordered sequence, detect-on-next-verify as `ErrReplay`"
  (now rejected — auditor H-1).** Non-implementable: `next > last` is the OK
  predicate, so a merged-but-unbumped file is indistinguishable from a legitimate
  advance; `ErrReplay` never fires for it. Replaced by write-ahead intent + a
  distinct terminal error.
- **Recording the pre-sign unsigned `S_unsigned` in the write-ahead (rejected —
  TM-D3).** The next reader pins the *committed signed* file's bytes; signing
  changes the bytes, so a write-ahead keyed on `S_unsigned` would never match
  `content_sha(committed file)` and every legitimate crash-window read would
  spuriously fall to `ErrCounterReconcile`. The protocol therefore produces the
  signed bytes first (step 2) and records their `S_signed` (step 3), per the
  DESIGN §3.5.3 unsigned→signed relationship.
- **Counter in the project repo (spike convenience).** Rejected by C-3: the
  project repo is writable by the actor we defend against; trivially rolled back
  (T3).
- **External DB / service for the counter.** Rejected: violates zero-infra
  (PLAN §1/§9).
- **True 2-phase commit across two git repos.** Not achievable atomically across
  two repos without infra. Write-ahead intent + matching-SHA gate + distinct
  terminal error is fail-closed and infra-free; the only residual cost is a manual
  `ErrCounterReconcile` in a rare lost-intent crash window — which blocks, never
  accepts.
- **Auto-heal the unbumped window by writing the bump from the reader.** Rejected
  for the *intent-lost* case (any non-merge actor could forge an advance); the
  reader/merge resume MAY only complete a commit-bump when a matching signed
  `pending` intent exists (the resume path), never synthesize one. A read-only
  verify caller never writes (DESIGN §7.2 L3).
- **Counter derived from git commit count / timestamp.** Rejected: not monotonic
  under rebase/force-push; not an authority.

## Consequences

- Anti-replay authority is integrity-anchored to the same trust root as admin
  identity; the write-ahead `pending` record is itself a signed registry commit.
- The "merged but counter not advanced" state is now **detected and
  distinguished**: legitimate in-flight (matching pending+`S_signed` → OK + drive
  bump) vs. corrupt/forged (no matching intent → `ErrCounterReconcile`, terminal).
  The previously-false self-heal claim is removed.
- `target_artifact_sha` is the DESIGN §3.5 post-sign `S_signed` preimage; the
  reader pins the exact committed signed bytes, so the crash-window OK row matches
  by construction (TM-D3). Recording the pre-sign SHA is an explicit defect
  (negative test, DESIGN §7.2 D3).
- Merge is still not atomically transactional across two repos; the residual
  crash window is fail-closed and bounded, and is resumable (matching pending) or
  hard-stops (`ErrCounterReconcile`) — never silently accepts a replay or a gap.
- `merge` MUST treat a commit-bump failure as a non-final merge: re-running merge
  resumes from the matching `pending`; it never re-signs a new counter while a
  matching `pending` is open.
- `ErrCounterReconcile` (terminal, manual) and `ErrReplay` (replayed/old file)
  are **both defined in `internal/core/registry/countertypes`** (their semantic
  owner — they travel with the opaque `CounterAuthority`). `verify` and `registry`
  reference the canonical `countertypes.*` symbols; **no alias vars; no
  junk-drawer errors package** — see DESIGN §2.1 / §2.3. They are mutually
  exclusive by the decision table and both fail closed.
- `CounterAuthority`/`PendingBump` move to the pure isolated
  `internal/core/registry/countertypes` sub-package with a **package-private
  constructor** (sole producer = registry adapter; `verify` consumes opaque and
  cannot construct; `verify.NewCounterAuthority` removed). This **removes the
  `internal/core/registry → internal/core/crypto/verify` import (gap 4a)** and is
  enforced at compile time, not prose (TM-D1 / DESIGN §2.0 / §7.2 D1). This
  ownership/construction change is **security-relevant and pending
  `reis-crypto-auditor` sign-off before B0 closes — NOT self-certified.**
- BUILD test obligations (DESIGN §7): the full decision table is table-tested,
  including the three negative rows that MUST yield `ErrCounterReconcile` and the
  one OK-resume row; an explicit test asserts the old false-self-heal scenario now
  yields `ErrCounterReconcile`, not OK and not `ErrReplay`; the write-ahead records
  the post-sign `S_signed` and a test asserts a pre-sign `S_unsigned` recording is
  rejected and that the read-only verify caller writes no `CommitBump` / no
  synthesized `pending` (DESIGN §7.2 D3 / L3).

### Pre-Phase-3 obligation — `capmint.Mint → countertypes.newCounterAuthority` bridge (RECORDED; gates Phase 3, NOT B0)

Status at B0: `countertypes.newCounterAuthority` is package-private; the sole
intended caller is `internal/adapter/registry/internal/capmint.Mint`, which is
Go-`internal/`-restricted to the `internal/adapter/registry` subtree. At B0 both
`capmint.Mint` and the registry adapter stub panic; the type-shape constraint
(no exported ctor, no settable trust-bearing field, zero-value `!Valid()`) is
already operative and proven by the compile-fail §7.2-D1 test. The B0 gate is
satisfied by the type-shape alone; the bridge wiring is explicitly deferred.

**Obligation (owner = `reis-backend`; gating authority = `reis-principal-go`
Phase-3 design gate; security re-sign MANDATORY = `reis-crypto-auditor` +
`reis-threat-modeler` at Phase 3, not self-certified):** before Phase 3 closes,
the `capmint.Mint -> countertypes.newCounterAuthority` bridge MUST be implemented
such that the invariant **"only code rooted at `internal/adapter/registry` can
construct a `Valid()==true` CounterAuthority"** remains enforced by a
**mechanical, in-CI, fail-closed gate (a compile error or a build-breaking test
- NEVER grep/review/prose)**. The §7.2-D1 compile-fail test (capmint import is a
build error from any non-adapter package) MUST continue to pass unchanged, and a
positive test MUST prove the bridge actually produces a `Valid()` value through
`capmint.Mint` only.

The bridge mechanism is adjudicated as a **recorded Phase-3 design-gate
decision** (NOT decided now). Constraints each option MUST meet, per the
converged `reis-crypto-auditor` + `reis-threat-modeler` constraint text:

- **Option A (PREFERRED)** — `countertypes` exposes a restricted-by-name
  exported constructor (e.g. `New`/`Mint`) consumed only by `capmint`:
  admissible only if the §7.2-D1 test is extended with a belt-and-suspenders
  source/dep-scan assertion that the new exported constructor is NOT referenced
  from `verify`/`mode`/`usecase`/`cli`/tests, layered on top of (never
  replacing) the `capmint` Go-`internal/` rule. The reachability guarantee
  stays a compile/build property, not a doc.
- **Option B (CONSTRAINED)** — `countertypes` exposes the constructor via a
  registration var set by the adapter wiring: admissible only if there is **no
  `init()` side effect**, **no exported globally-mutable registration var** open
  to arbitrary callers, the set is a **one-shot single-writer guarded by
  `sync.Once`** if used at all, and post-set reachability is still gated by the
  `capmint` Go-`internal/` boundary. A registration path reachable by any
  importer is rejected on sight.
- **Option C** — another mechanism: admissible only if it does NOT break the
  Clean Architecture dependency rule (no `core -> adapter` edge; no
  `registry -> verify` re-introduction = gap 4a stays closed) and does NOT
  weaken the ADR-0005 closed-world allowlist (gap 4a / Submit allowlist
  unaffected), and still terminates in a mechanical fail-closed CI gate.

Acceptance at the Phase-3 gate: `reis-principal-go` selects exactly one option
against the constraints above; `reis-crypto-auditor` and `reis-threat-modeler`
re-sign the realised bridge (TM-D1) before Phase 3 ships. A bridge that reduces
the guarantee to grep/review, introduces an `init()`/open-mutable registration,
or breaks the dependency rule / ADR-0005 allowlist is CHANGES REQUIRED on sight
regardless of green tests.
