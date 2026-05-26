# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security problems.** Report privately via
GitHub's "Report a vulnerability" form:

  https://github.com/ByReisK/byreis/security/advisories/new

Please include a description, reproduction steps, affected version or commit,
and impact. We aim to acknowledge within a few days and will coordinate a fix
and disclosure timeline with you.

Do not include real secrets, private keys, or production data in a report.

## Supported versions

byreis releases stable binaries. Only the latest released version is actively
supported; there are no backported security releases.

| Version | Supported |
|---------|-----------|
| v0.5.x (latest) | yes |
| older releases  | no  |

## Threat model

### What byreis protects against

byreis enforces **asymmetric access**: contributors can encrypt and submit
secrets (write-only) but cannot decrypt them; only admins holding private keys
can read. Access level is derived from cryptographic reality — the presence and
usability of a private key registered in the admin registry — never from a config
flag, an environment variable, or a role assignment.

Encryption uses native `age` Model B (no shared SOPS data key). There is no
shared symmetric key that a contributor could obtain to decrypt values. A
contributor who submits a value immediately loses access to the plaintext;
there is no route in the codebase from the contributor path to a decryption
capability, and the import graph is structured to make this impossible at
compile time.

The registry audit channel records merge, rotation, and reversal events in a
signed file in the admin registry repo. From v0.5 onward, `byreis admin audit
show --verify` performs a per-line binding walk that detects edits, deletions,
reorders, forged inserts, and cross-file splices of binding-era audit lines.
Every commit in the walk is verified against the pinned trust anchor before its
tree is read.

Reports that demonstrate any of the following are highest priority:

- A contributor reading a plaintext secret value.
- A submission PR that can overwrite the live secrets file directly (bypassing
  the admin merge gate).
- Signed-record forgery or rollback of the registry.
- A registry trust bypass that promotes a non-admin to admin without
  cryptographic proof.
- An audit binding bypass that allows tampered lines to display as `verified`.

### What byreis does NOT protect against

**A compromised admin private key.** If an admin's private key is obtained by an
attacker, that attacker can decrypt any secret in any project the admin is a
recipient of, for as long as the key remains in the recipient set. byreis's
rotation procedure (`byreis rotate --remove`) changes the recipient set going
forward but cannot retroactively remove access to ciphertext already in git
history. See `docs/forward-secrecy.md` for the incident runbook.

**A compromised trust anchor key.** The admin registry's trust anchor is a
single pinned Ed25519 public key. The registry signed-commit verifier and the
audit binding verifier are only as strong as that anchor. A principal holding
the trust anchor key can author signed commits that the verifier accepts. byreis
does not provide a multi-party trust root.

**Audit lines written before v0.5.** Lines in the audit channel that predate the
per-line binding era carry no `audit_entry_sha` field and are classified as
`legacy` (unverified, not tampered). They are never displayed as `verified`. A
principal holding the trust anchor key who rewrites the git history in the
pre-binding prefix could position a fabricated line that displays as `legacy`.
This residual is confined to the pre-binding prefix.

**Reject and decline events in the audit channel.** Reject events are recorded
host-locally at the time of rejection and are not written to the registry audit
channel. The `--verify` audit walk does not cover them.

**Reordering two lines introduced by the same single commit.** The per-line
binding verifier detects cross-commit reorders; two lines from the same commit
swapped within that commit's diff are below the per-commit binding granularity
and are not detected.

**Verification under resource pressure.** An adversarially large registry
history or a registry that becomes unreachable mid-walk causes the verifier to
exit non-zero with a typed error. Tamper evidence is not weakened, but
verification availability is not guaranteed against a hostile or unreachable
registry.

**GitHub-only.** There is no GitLab provider. The git and PR operations depend
on the GitHub API.

**Windows.** byreis is buildable on Windows and the CLI functions, but Windows
is not a release binary target and is not tested on the release path.
