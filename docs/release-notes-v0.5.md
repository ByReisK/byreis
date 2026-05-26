# byreis v0.5 release notes

v0.5 is the **audit-binding release**. It makes the audit trail mean what the
security claim implies: every line recorded in the registry audit channel is now
bound to the signed commit that introduced it, so edits, deletes, reorders,
forged inserts, and cross-file splices are detectable at read time.

The asymmetric-access guarantee is unchanged. Contributors still encrypt and
submit write-only; they cannot decrypt, and no v0.5 surface gives a non-key-holder
a route to a plaintext value. Access level remains derived from cryptographic
reality, never from a flag, an environment variable, or a config file.

## What's new

### `byreis admin audit show --verify`

A new flag on the existing `audit show` command triggers per-line binding
verification of the registry audit channel:

```
byreis admin audit show --verify
```

The verifier walks the full git history of the audit channel file — not just the
current HEAD — and checks, for every binding-era line, that the `audit_entry_sha`
field matches what the signed commit that introduced that line actually recorded.
Lines that pass carry a `verified` marker; lines that were added in the binding era
but whose hash does not match carry a `TAMPERED` marker and cause the command to
exit non-zero with a typed `ErrAuditLogTampered` error.

The verifier detects:

- **Edits** to a binding-era line after it was committed.
- **Deletions** of a binding-era line that the git history shows should be present.
- **Reorders** of binding-era lines across different commits (each line is bound to
  the commit that introduced it; moving it to a different commit position is
  detected).
- **Forged inserts** — a new line injected into the audit file whose
  `audit_entry_sha` does not correspond to any legitimate commit in the chain.
- **Cross-file splices** — lines copied from one project's audit channel into
  another's (the binding includes the channel path, so the hash does not match in
  the destination file).

The command fails closed on any verification error: a tampered line is never
silently shown as clean, and an unverifiable state produces a non-zero exit with
an actionable error message rather than a partial result.

## Implementation notes

The git history walk uses the trust anchor already established for the registry:
every commit in the walk is signature-verified against the pinned `TrustAnchorKey`
before its tree is read. An unsigned or wrongly-signed commit in the audit channel's
history is itself a tamper signal and fails the walk closed.

Legacy lines (those written before this release, without an `audit_entry_sha` field)
are classified separately; see the honesty disclosures below for the precise boundary.

## Positioning and honesty disclosures

These statements bound what byreis does, deliberately:

- **Decline and reject events are not covered by the audit-binding verifier.** Reject
  events are recorded host-locally at the time of rejection and are not written to
  the registry audit channel. The verifier therefore does not and cannot bind them;
  their absence from the channel is expected and is not a tamper signal.

- **Audit lines written before this release are shown as `legacy`, not `verified`.**
  Lines that predate the per-line binding era carry no `audit_entry_sha` field and
  cannot be retroactively bound. The verifier classifies them as `legacy` (unverified
  but not tampered). They are never displayed as `verified` and never as `TAMPERED`
  because the binding infrastructure did not exist when they were written.

- **Reordering two lines introduced by the same single commit is below the
  per-commit binding granularity and is not detected.** The verifier binds each line
  to the commit that introduced it. Cross-commit reorders are detected; two lines
  from the same commit swapped within that commit's diff are a residual boundary of
  the per-commit approach.

- **The verifier is only as strong as the pinned trust anchor.** Every commit in the
  history walk is verified against the single pinned `TrustAnchorKey`. The
  `byreis-signer` commit footer is an attested label that identifies the signing
  tool; it is not an independent trust key. Rotating or compromising the trust anchor
  key is outside the scope of this verifier.

- **The audit-binding verifier is admin-only in v0.5.** The `--verify` flag is
  gated at the permission matrix to ADMIN and SUPER modes. Contributor-side audit
  verification is not in this release and is a planned follow-up; the compliance
  story is honestly bounded to admins holding a private key registered in the trust
  anchor chain.

- **Verification fails closed under resource pressure.** An adversarially-large
  registry history, a registry that becomes unreachable mid-walk, or a context
  deadline causes the verifier to return a typed offline or timeout error and exit
  non-zero. There is no partial-verified-as-clean result and no silent truncation.
  Tamper-evidence is not weakened by resource pressure, but verification availability
  is not guaranteed against a hostile or unreachable registry.

- **Pre-binding legacy lines carry a residual that cannot be closed without
  rewriting history.** Legacy lines are classified by anchor-signature and git-history
  position relative to the first binding-era commit. byreis does not verify
  counter-monotonicity continuity through the legacy region. A principal holding the
  trust anchor key who rewrites the audit channel's git history could position a
  fabricated anchor-signed line within the pre-binding prefix and it would display as
  `legacy`, not `TAMPERED`. This residual is confined to the pre-binding prefix and
  is exploitable only by a maximally-trusted principal (one who already holds the
  trust anchor). It does not affect the monotonic-counter anti-rollback layer that
  protects secret artifacts.

## Upgrading

Drop-in replacement for v0.4. No secrets-format change, no registry-schema change,
no environment variable change. Existing encrypted files, registries, signed commits,
and the two-variable `BYREIS_PROJECT` / `BYREIS_PROJECT_REPO` contract are all
unaffected. The `--verify` flag is additive; `audit show` without `--verify` behaves
identically to v0.4.
