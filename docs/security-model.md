# Security model

byreis has one defining property from which everything else follows:

!!! abstract "The invariant"
    **Access level is derived from cryptographic reality, never from a config
    file, a flag, or an environment variable.** If you can decrypt a project file
    and your public key is in the verified admin registry, you are an admin.
    Otherwise you are a contributor.

This page explains how that invariant is enforced.

## Asymmetric access

Secrets are encrypted with native [`age`](https://age-encryption.org/) in a
**per-recipient envelope** model: each value is independently encrypted to the
admins' public keys. There is **no shared symmetric data key**.

The consequence is the whole point of byreis:

- A **contributor** holds only public keys. They can encrypt a new value to the
  admins and add or replace a key in a project file — a write-only capability.
  They cannot decrypt anything, **not even a value they just submitted**.
- An **admin** holds a private key whose public half is registered. They can
  decrypt, read, edit, rotate, export, and run with the secrets.

This is why `--sops`-style interoperability is deliberately unsupported: SOPS uses
a single shared data key, which any key holder can use to read everything.
Adopting it would collapse the asymmetric guarantee. `byreis export` is the clean
plaintext escape hatch instead — and it only works for an admin.

## Mode detection (fail-closed)

byreis resolves your mode by checking, **in order**:

1. a private key file exists;
2. its file permissions are `0600` (otherwise byreis refuses to run);
3. it can actually **decrypt** a project file;
4. the corresponding public key is present in the **verified** admin registry.

Any failure downgrades to **contributor** — with a warning if a key is present
but does not grant admin. The default is always contributor; promotion is
explicit and audited. No flag, environment variable, config key, or tampered
cache can grant admin, because the decision is made from cryptographic facts, not
from declarations.

Every command is gated by this mode through a single permission matrix, and the
contributor-denied paths are *denied before they are attempted* — a contributor
invoking an admin verb never reaches the decrypt path at all.

## The build itself enforces the boundary

The asymmetric guarantee is not only a runtime check — it is structural. The
code path that a contributor compiles and runs (the encrypt / submit path) has
**no compile-time route** to any private-key or decryption capability. This is
enforced mechanically by a closed-world import gate in CI: if the contributor
build could even *link* against decryption code, the build fails. The import
graph is treated as a security boundary, not a style preference.

A non-skippable release gate additionally drives the real production wiring
end-to-end over real keys and real signed git history, proving admin reads
succeed and contributor reads are denied-not-attempted before any release ships.

## The two-repo trust model

byreis separates trust from ciphertext:

- The **admin registry repo** is the source of truth for who is an admin, their
  public keys, per-project configuration, and global policy. byreis fetches it
  read-only, caches it aggressively, and verifies its integrity through **signed
  commits** anchored to a pinned trust anchor.
- The **project secrets repo** holds only the pointer config and the encrypted
  files.

byreis never writes to the registry except through the explicit, audited
`admin add` / `admin remove` flow.

## Trustworthy audit trail

Every line on the audit channel is **bound to the anchor-verified commit that
introduced it**. The verifier detects:

- edited, deleted, or reordered entries;
- forged inserts and cross-file splices;
- counter regressions (anti-rollback / monotonicity continuity).

It **fails closed** on tamper, and **actor attribution is anchor-attested** —
derived from the signed introducing commit, never copied from the (forgeable) log
line. A removed admin's past entries attribute to a sentinel, not to a name an
attacker could spoof.

Anyone — including a key-less contributor — can run the full verification with
`byreis audit verify`. It performs zero decryption, and with `--json` returns a
non-zero exit on tamper, making it a drop-in CI integrity tripwire. A transient
verifier-side failure (for example a timed-out `git diff-tree`) is reported as a
retryable *inconclusive* result, distinct from a genuine *tamper* verdict, so a
flaky environment never produces a false tamper alarm — while any real content
divergence always denies.

## Consuming secrets without leaking them

The two consumption verbs are designed around exposure surface:

- **`byreis export`** emits plaintext to stdout for shell or dotenv consumers.
  Values are fully quoted and escaped (including `$` and backtick) so a hostile
  value cannot inject a command when the output is sourced or `eval`'d. Plaintext
  is refused to an interactive terminal by default — an accidental-dump guard,
  not a containment boundary.
- **`byreis run -- <cmd>`** injects secrets into a child process's environment so
  they **never touch disk or terminal scrollback**, and never the child's argv.

byreis is honest about what it cannot control once a child process holds the
environment: a descendant can re-export it, `/proc/<pid>/environ` is readable by
same-uid processes, and a core dump can capture it. byreis promises only that
*byreis itself* leaks nothing and that secrets never hit disk through byreis.

## Related reading

- **[Forward secrecy](forward-secrecy.md)** — what rotation does and does not
  guarantee about previously exposed values.
- **[Rotation runbook](rotation-runbook.md)** — operating recipient-set rotation.
- **[User guide](guide.md)** — the complete command and configuration reference.
