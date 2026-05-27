# byreis v0.6 release notes

v0.6 is the **audit-trail completion release**. It delivers two improvements
that together close the gap between what the v0.5 audit-binding verifier claimed
and what it could actually prove: contributor-side independent verification and
counter-monotonicity continuity enforcement.

The asymmetric-access guarantee is unchanged. Contributors still encrypt and
submit write-only; they cannot decrypt, and no v0.6 surface gives a non-key-holder
a route to a plaintext value. Access level remains derived from cryptographic
reality, never from a flag, an environment variable, or a config file.

## What's new

### `byreis audit verify` — contributor-accessible audit verification

A new top-level `byreis audit verify --project <id>` command performs the full
per-line binding walk and is available in all modes: Contributor, Admin, and
Super. A key-less contributor now needs only the pinned trust anchor (via
`init/trust.yaml`) and read access to the registry; no private key, no write
credential, and no decrypted secret is accessed or returned.

```
byreis audit verify --project <id>
byreis audit verify --project <id> --json
```

This is the asymmetric-compliance differentiator: the audit trail can now be
independently verified by any party who has read access to the registry,
without holding an admin key. The v0.5 admin-only boundary is retired.

The new verb is a sibling of `admin audit show`, not a relaxation of it. The
admin-only `audit show` (which decodes and renders plaintext-decoded audit
detail) is unchanged and remains admin-only. The all-modes `audit verify` verb
is confined to the read-only binding walk and cannot reach any plaintext path
by construction: it imports no identity or decrypt package, acquires no write
token, and makes no registry write.

**CI integration.** Use `byreis audit verify` as a tamper tripwire in CI:

```
byreis audit verify --project <id> --json || exit 1
```

The command exits non-zero on any tamper finding, offline condition, or
unverifiable registry HEAD. The `--json` flag emits a machine-readable binding
report with per-line status. There is no partial-verified-as-clean result.

### Counter-monotonicity continuity check

The verifier now asserts per-file counter continuity across the ordered
introducing-commit walk. The counter fields (`expected_previous_counter`,
`pending_counter`) are parsed from anchor-signed commit bodies — never from the
verified JSONL content — and checked in git-history order.

This closes the pre-binding prefix residual disclosed in v0.5 (ADR-0019 errata
E2): a principal holding the trust anchor key who rewrites the audit channel's
git history to back-position a fabricated anchor-signed line can no longer cause
that line to display as `legacy` rather than `TAMPERED`. A counter break — a
gap, a regression, or a forked predecessor value — marks the line `TAMPERED`
even when its content hash matches, because the break proves the ordered set of
introducing commits is not the genuine monotonic sequence.

The check spans the verified-HEAD checkpoint seam on incremental (warm-path)
walks: the seam predecessor's counter state is re-derived from the anchor-verified
cloned history at verification time, never from the checkpoint cache. A forged
checkpoint cannot inject a false counter seed and cannot mask a seam break; any
derivation failure forces a full cold re-walk.

The check is absent-vs-contradiction aware: a missing counter field in an
anchor-signed commit body is not treated as a tamper signal (many legitimate
commits predate the counter fields). Only a present-and-contradictory value
fails closed.

## Implementation notes

`byreis audit verify` reuses the existing `AuditVerifier` port, the binding
renderer, and the exit-code contract of `admin audit show --verify`. CI
consumers that already parse the `--json` output of `--verify` can consume the
new verb's output with no schema change.

The counter-monotonicity check is a second pass over the paired
(commits × lines) set after the content-hash phase. A counter break marks the
line `BindingTampered` even when the hash check already passed, because the two
checks are independent evidence of the same tamper event.

## Positioning and honesty disclosures

These statements bound what byreis does, deliberately:

- **Audit verification is now available to contributors.** `byreis audit verify`
  is permitted in all modes (Contributor, Admin, Super). A key-less party can
  now independently confirm the registry audit trail is untampered without
  holding an admin private key. The v0.5 admin-only restriction is superseded
  by this release.

- **The counter-monotonicity residual disclosed in v0.5 is now closed.**
  The pre-binding prefix residual described in v0.5 (an anchor-key-holding
  admin back-positioning a fabricated anchor-signed line so it displays as
  `legacy` rather than `TAMPERED`) is closed on both the cold full-history walk
  and the incremental (checkpoint-seam) warm path. A counter break → TAMPERED,
  regardless of content-hash outcome.

- **Decline and reject events are not covered by the audit-binding verifier.**
  Reject events are recorded host-locally at the time of rejection and are not
  written to the registry audit channel. The verifier therefore does not and
  cannot bind them; their absence from the channel is expected and is not a
  tamper signal.

- **Audit lines written before the binding era are shown as `legacy`, not
  `verified`.** Lines that predate per-line binding carry no `audit_entry_sha`
  field and cannot be retroactively bound. They are never displayed as
  `verified` and never as `TAMPERED`.

- **Reordering two lines introduced by the same single commit is below the
  per-commit binding granularity and is not detected.** The verifier binds each
  line to the commit that introduced it. Cross-commit reorders are detected;
  two lines from the same commit swapped within that commit's diff are a
  residual boundary of the per-commit approach.

- **The verifier is only as strong as the pinned trust anchor.** Every commit
  in the history walk is verified against the single pinned `TrustAnchorKey`.
  The `byreis-signer` commit footer is an attested label that identifies the
  signing tool; it is not an independent trust key. The residual that remains
  after v0.6 is that a principal holding the trust anchor key can author
  internally consistent history (the correct counter sequence, correct content
  hashes, correct signatures) — the trust root is the anchor, by design.

- **The verifier is read-only and zero-decrypt.** The audit channel is public.
  The verifier acquires no private key, no write credential, and returns no
  plaintext value. No v0.6 surface gives a non-key-holder a route to a
  plaintext value.

- **Verification fails closed under resource pressure.** An adversarially-large
  registry history, a registry that becomes unreachable mid-walk, or a context
  deadline causes the verifier to return a typed offline or timeout error and
  exit non-zero. There is no partial-verified-as-clean result and no silent
  truncation. Tamper-evidence is not weakened by resource pressure, but
  verification availability is not guaranteed against a hostile or unreachable
  registry.

- **GitHub-only.** byreis supports GitHub as its registry host. No other forge
  backend is supported in this release.

## Upgrading

Drop-in replacement for v0.5. No secrets-format change, no registry-schema
change, no environment variable change. Existing encrypted files, registries,
signed commits, and the two-variable `BYREIS_PROJECT` / `BYREIS_PROJECT_REPO`
contract are all unaffected. The `audit verify` verb is additive; existing
`admin audit show --verify` invocations continue to work identically.
