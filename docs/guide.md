# byreis user guide

This guide covers the full current feature set of byreis v0.5. It is written
for both contributors (who submit secrets but cannot read them) and admins (who
hold private keys and manage the secrets lifecycle).

## Contents

1. [The asymmetric access model](#1-the-asymmetric-access-model)
2. [Install](#2-install)
3. [Concepts and configuration](#3-concepts-and-configuration)
4. [Contributor workflow](#4-contributor-workflow)
5. [Admin workflow](#5-admin-workflow)
6. [Interactive TUI](#6-interactive-tui)
7. [CI usage](#7-ci-usage)
8. [Audit log and verification](#8-audit-log-and-verification)
9. [Security model and honest boundaries](#9-security-model-and-honest-boundaries)

---

## 1. The asymmetric access model

byreis's defining property: **contributors can submit secrets, but only admins
can read them.**

A contributor encrypts a value to the admin public keys sourced from the admin
registry and opens a pull request. The contributor never holds a private key and
cannot decrypt — not even the value they just submitted. An admin reviews the
decrypted value and merges it into the live secrets file.

Encryption uses native `age` Model B. There is no shared symmetric data key;
each ciphertext is addressed directly to the admin public keys. A keyless
contributor can produce ciphertext that only key-holders can open.

**Access level is derived from cryptographic reality, never from config or
flags.** byreis resolves your mode at startup by checking: does a private key
exist? Are its permissions 0600? Can it actually decrypt a project file? Is its
public key registered in the admin registry? Every failure downgrades the mode
to CONTRIBUTOR. Promotion to ADMIN is explicit, audited, and cryptographic —
you cannot set a flag to become an admin.

---

## 2. Install

### Pre-built binaries (recommended)

Download from the [Releases](https://github.com/ByReisK/byreis/releases) page.
Supported platforms: **linux/amd64**, **linux/arm64**, **darwin/amd64**,
**darwin/arm64**.

```bash
# Example: Linux amd64
curl -L https://github.com/ByReisK/byreis/releases/download/v0.5.0/byreis-linux-amd64 \
  -o /usr/local/bin/byreis
chmod +x /usr/local/bin/byreis
```

### From source

```bash
git clone https://github.com/ByReisK/byreis.git
cd byreis
make build    # produces ./bin/byreis
```

Or with `go install`:

```bash
go install github.com/ByReisK/byreis/cmd/byreis@latest
```

---

## 3. Concepts and configuration

### Two repos

byreis works across two Git repositories:

**Admin registry repo** (e.g. `myorg/byreis-admins`) — the source of truth for
who is an admin, admin public keys, per-project configuration, and global
policy. byreis fetches this read-only and caches it locally with signature
verification. You never write to it except through explicit `admin` commands.

**Project secrets repo** (e.g. `myorg/myapp-secrets`) — holds `.byreis.yaml`
(points at the registry) and encrypted `secrets/*.enc.yaml` files.

### Directories

| Path | Purpose |
|---|---|
| `~/.config/byreis/` | Configuration and trust anchors (must be 0700) |
| `~/.cache/byreis/` | Registry cache (TTL-based; offline fallback reads from here) |

### Environment variables

| Variable | Description |
|---|---|
| `BYREIS_REGISTRY` | Admin registry in `owner/repo` form |
| `BYREIS_PROJECT` | Slash-free logical project id (e.g. `myapp`) |
| `BYREIS_PROJECT_REPO` | Project secrets repo in `owner/repo` form (e.g. `myorg/myapp-secrets`) |
| `BYREIS_KEY` | Admin private key material (for CI decrypt) |
| `BYREIS_KEY_FILE` | Path to the admin private key file |
| `BYREIS_NON_INTERACTIVE` | Set to `1` to suppress all TUI and interactive prompts |
| `BYREIS_GITHUB_TOKEN` | GitHub token (also read from `GH_TOKEN`) |

`BYREIS_PROJECT` and `BYREIS_PROJECT_REPO` are distinct variables with distinct
meanings. `BYREIS_PROJECT` is the registry-path id (no slashes). A
`BYREIS_PROJECT` value that contains a slash is almost always an old-style
`owner/repo` value in the wrong variable; `byreis doctor` warns on this.

### `.byreis.yaml`

Created by `byreis init`. Points the project at its registry and holds the
pinned trust anchor fingerprint. Committed to the project secrets repo.

---

## 4. Contributor workflow

### Initialize a project

```bash
byreis init --project myapp --registry myorg/byreis-admins
```

On first run, byreis fetches the registry, displays the registry signer
fingerprint, and asks you to confirm it. Pass `--accept-signer <fp>` to confirm
non-interactively (required when `BYREIS_NON_INTERACTIVE=1`).

### Submit a secret

```bash
# Single key — value collected interactively (masked double-entry)
byreis submit --key DATABASE_URL

# Bulk — read all KEY=VALUE pairs from a .env file
byreis submit --file .env.production

# With a justification recorded in the PR
byreis submit --key STRIPE_API_KEY --justification "production payment key rotation"

# Non-interactive (CI, stdin value)
echo "the-value" | byreis submit --key DATABASE_URL --non-interactive
```

`submit` encrypts the value(s) to the admin public keys, pushes a branch named
`byreis/add-<key>-<timestamp>` (or `byreis/replace-*` for an existing key, or
`byreis/bulk-*` for `--file`), and opens a pull request against the project
secrets repo.

The contributor never holds or sees the plaintext after submission. There is no
decrypt capability on this path.

### Request access (to become a recipient)

If you want to be able to decrypt project secrets (i.e. to become an admin
recipient), open a request-access PR against the registry:

```bash
byreis request-access \
  --key age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --justification "team A onboarding for project foo" \
  --registry myorg/byreis-admins
```

This opens a PR from your own fork of the registry repo depositing a
`requests/<your-handle>.yaml` file with your proposed public key and
justification. An admin reviews and absorbs it via
`byreis rotate --add --from-request`. See `docs/request-access-runbook.md` for
the full procedure.

**Note:** this verb is contributor-only. If you are already an admin, you do not
open access requests; you use the rotation commands directly.

### Diagnostics

```bash
byreis doctor
```

Checks: config directory permissions, trust anchor permissions, your resolved
mode (CONTRIBUTOR or ADMIN) and the reason, registry connectivity and signature
validity, and branch protection status (advisory). Use
`--rotation-history` to report the per-file rotation epoch for every project
file.

---

## 5. Admin workflow

All admin commands require ADMIN mode: a usable private key (permissions 0600)
whose public key is registered in the admin registry. CONTRIBUTOR mode is
denied at the permission matrix before any network contact.

### Review a submission

```bash
byreis review --pr myorg/myapp-secrets#42
```

Fetches and decrypts the submission PR, displays each key's value and
add-vs-replace classification, and prints a `PinnedSHA`. Pass the `PinnedSHA`
to `--expect` when merging.

On an interactive terminal, `byreis review` opens the TUI review queue.

### Merge a submission

```bash
byreis admin merge \
  --pr myorg/myapp-secrets#42 \
  --expect <PinnedSHA> \
  --project myapp \
  --file secrets/production.enc.yaml
```

The `--expect` pin guards against a branch re-push between review and merge; if
the branch content changed after review, the pin does not match and merge fails.

A successful merge appends a signed merge event to the registry audit channel
in the same signed commit as the counter advance. The merge audit record is
fail-closed: if the registry write cannot complete (e.g. offline at merge time),
the command fails with a retry hint rather than silently dropping the record.

### Reject a submission or access request

```bash
byreis admin request reject \
  --pr myorg/myapp-secrets#42 \
  --reason "value does not meet the key-naming policy"
```

Closes the PR and posts the reason as a PR comment (visible to anyone who can
see the repository). Do not include secrets or sensitive details in the reason.
An already-merged PR is refused. An already-closed PR is an idempotent no-op.

### Read secrets

```bash
# Decrypt and print a single value
byreis get --project myapp --file secrets/production.enc.yaml --key DATABASE_URL

# Decrypt and print all values
byreis decrypt --project myapp --file secrets/production.enc.yaml

# Restrict output to specific keys
byreis decrypt --project myapp --file secrets/production.enc.yaml \
  --key DATABASE_URL --key STRIPE_API_KEY

# CI decrypt (headless; no TTY assumed)
byreis decrypt --project myapp --file secrets/production.enc.yaml --ci --json
```

Both `get` and `decrypt` run `VerifyOfRecord` (registry trust verification)
before any decrypt or key-load.

### Export to an env/dotenv stream

```bash
# Shell-sourceable export lines (set -a; source <(byreis export ...))
byreis export --project myapp --file secrets/production.enc.yaml --format env | cat

# .env file for godotenv / docker-compose env_file
byreis export --project myapp --file secrets/production.enc.yaml --format dotenv > app.env
```

`byreis export` is an admin-only command. Like `get` and `decrypt`, it decrypts
the secrets file with the admin private key, so a keyless contributor cannot run
it — it is denied at the permission matrix before any network contact or
key-load. It runs `VerifyOfRecord` first and decrypts the whole file fail-closed:
if any value cannot be decrypted, nothing is emitted.

`--format` selects the serialization shape:

- `env` emits one `export KEY="..."` line per value, intended to be `source`d or
  `eval`d by a shell.
- `dotenv` emits one `KEY="..."` line per value, for `.env` files consumed by
  godotenv, docker-compose `env_file`, and other quote-aware loaders.

Every value is always double-quoted and escaped — including `$` and backtick — so
a value round-trips exactly and a hostile secret value cannot inject a command
when the output is `source`d or `eval`d. The output targets quote-aware
consumers; raw `docker --env-file` (which does not process quotes or escapes) is
out of scope.

By default `byreis export` refuses to write plaintext to an interactive
terminal, so a decrypted file does not land in scrollback by accident. **This
TTY refusal is a convenience speed-bump against an accidental dump, not a
security boundary.** The security boundary is the admin private key. The moment
you pipe or redirect the output — `byreis export ... | cat`, `> app.env` — the
plaintext is yours to protect: it is now in your shell history, your CI logs,
and a file whose permissions you own. Treat exported plaintext with the same
care as any other decrypted secret.

#### Why there is no `--sops` flag

`byreis export` does not and will not support a `--sops` output format. byreis
uses a native age recipient model (see ADR-0001 and ADR-0003): secrets are
encrypted directly to each admin's public key, and there is **no shared
symmetric data key**. That absence is exactly what makes the access asymmetric —
a contributor can encrypt to the admins but holds no key that decrypts anything.
A SOPS-style export would have to reintroduce a shared symmetric data key on the
consumer side, which would defeat the asymmetric-access guarantee. If you are
migrating off SOPS, `byreis export --format env|dotenv` is the supported,
clean escape hatch into plaintext.

### Edit a secret in-place

```bash
byreis edit --project myapp --file secrets/production.enc.yaml
```

Decrypts the file, opens it in `$EDITOR`, re-encrypts and re-signs the result,
and writes it atomically. Any failure before the atomic rename leaves the live
file byte-identical.

### Rotate the recipient set

```bash
# Preview the plan without writing anything
byreis rotate --dry-run --project myapp

# Add a recipient
byreis rotate --project myapp --add age1xxxxxxxx...

# Remove a recipient (requires typed-fingerprint confirmation)
byreis rotate --project myapp --remove age1xxxxxxxx...

# Absorb an access-request PR
byreis rotate --project myapp --add --from-request myorg/byreis-admins#42

# Non-interactive (skips interactive confirm; requires --yes)
byreis rotate --project myapp --remove age1xxxxxxxx... --yes --non-interactive
```

Rotation re-encrypts every current secrets file to the new recipient set in a
strict two-phase commit. A project is never left half-rotated; an interrupted
run can be recovered via `byreis admin rotation reconcile`. See
`docs/rotation-runbook.md` and `docs/forward-secrecy.md` for the operator
procedures.

**Forward-secrecy notice:** removing a recipient re-encrypts current files to
the new set, but cannot retroactively scrub a removed recipient's access to
ciphertext already in git history. Values that a compromised recipient could
have read must be rotated out-of-band.

### Recover a partial rotation

```bash
byreis admin rotation reconcile --project myapp
```

Classifies partial rotation state (none / Phase-1-only / Phase-2-midflight /
inconsistent) and, when safe, reverts Phase-1 side effects in a single signed
registry commit. See `docs/rotation-runbook.md` for the full procedure.

### List access requests

```bash
byreis admin request list
```

Lists every open `request-access` PR in the admin registry. Read-only.

---

## 6. Interactive TUI

On an interactive TTY, `byreis submit` and `byreis review` open a bubbletea
TUI rather than the plain CLI path.

**submit TUI:** A masked-entry form. The contributor types the value; it is
masked and encrypted-to-admins without being displayed as plaintext.

**review TUI:** Opens a browsable list of pending submission PRs
(`byreis/add-*`, `byreis/replace-*`, `byreis/bulk-*` branches) with PR number,
key/action, author, and age. Select a row and press Enter to open the
submission detail and approve flow. Press `a`/`s` to toggle between the
submission-PR queue and the access-request triage view. A reject action is
available from the detail screen.

The TUI list view never decrypts. Decryption only happens when you explicitly
open a submission detail.

**Suppressing the TUI:**

```bash
BYREIS_NON_INTERACTIVE=1 byreis submit --key MY_KEY
byreis review --pr myorg/myapp-secrets#42 --json   # --json also suppresses TUI
```

The plain CLI path is always available. Automated, headless, and CI usage
should set `BYREIS_NON_INTERACTIVE=1`.

**Platform notes:** The interactive TUI targets linux and darwin. On Windows
byreis is buildable and the full CLI works, but the TUI is not a Windows target.

---

## 7. CI usage

### Contributor submit from CI

CI workflows typically run without an interactive TTY. Set
`BYREIS_NON_INTERACTIVE=1` to suppress the TUI and interactive prompts.

```bash
# .env file submit from CI
BYREIS_NON_INTERACTIVE=1 \
BYREIS_PROJECT=myapp \
BYREIS_PROJECT_REPO=myorg/myapp-secrets \
BYREIS_REGISTRY=myorg/byreis-admins \
BYREIS_GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }} \
  byreis submit --file .env.production
```

No admin private key is needed for submit. The CI workflow uses only a GitHub
token and the admin public keys from the registry (fetched automatically).

### Admin decrypt from CI

```bash
BYREIS_NON_INTERACTIVE=1 \
BYREIS_PROJECT=myapp \
BYREIS_PROJECT_REPO=myorg/myapp-secrets \
BYREIS_REGISTRY=myorg/byreis-admins \
BYREIS_KEY_FILE=/path/to/admin.key \
  byreis decrypt --file secrets/production.enc.yaml --ci --json
```

`BYREIS_KEY` may be used in place of `BYREIS_KEY_FILE` to pass the key material
directly (useful when the key is stored as a CI secret string).

The `--ci` flag on `decrypt` activates the headless entrypoint: no TTY assumed,
secrets are not masked (by design; ensure your CI logs are appropriately
protected).

---

## 8. Audit log and verification

### View the audit log

```bash
byreis admin audit show --project myapp
```

Displays the registry audit log for the project in chronological order. Entries
are sorted by append order. Entries whose event class is not recognized by this
version are shown as warning rows (forward-compatibility).

Contributors can read the raw audit file directly via git without running byreis:

```bash
git show audit/myapp.jsonl       # in the registry repo
git verify-commit HEAD
```

### Verify audit binding (v0.5+)

```bash
byreis admin audit show --project myapp --verify
```

The `--verify` flag performs a full per-line binding walk of the audit channel:
each JSONL line in the binding era is checked against the signed commit that
introduced it. Detected conditions include:

- **Edits** to a binding-era line after it was committed.
- **Deletions** of a binding-era line that git history shows should be present.
- **Reorders** of binding-era lines across different commits.
- **Forged inserts** — a new line whose `audit_entry_sha` does not match any
  legitimate commit in the chain.
- **Cross-file splices** — lines copied from one project's audit channel into
  another's.

The command fails closed on any verification error (exit non-zero, typed
`ErrAuditLogTampered`). Every commit in the walk is verified against the pinned
trust anchor before its tree is read.

With `--verify`, the ACTOR column is derived from the anchor-attested signer
identity in the signed introducing commit's `byreis-signer` footer, not from
the in-line JSONL field (which is adversarial input). Only `verified` entries
receive actor attribution; `legacy`, `missing`, and `TAMPERED` entries display
`-`.

### Honest audit boundaries

The audit verifier has the following residuals, stated plainly:

- **Reject/decline events are not covered.** Reject events are host-local and
  not written to the registry audit channel.
- **Legacy lines (pre-v0.5) are classified as `legacy`, not `verified`.** They
  cannot be retroactively bound.
- **Reordering two lines from the same single commit is not detected.** Cross-
  commit reorders are detected; same-commit reorders are below per-commit
  granularity.
- **The verifier is only as strong as the pinned trust anchor.** A principal
  holding the trust anchor key can author commits the verifier accepts.
- **The verifier is admin-only in v0.5.** Contributor-side verification is a
  planned follow-up.
- **Verification fails closed under resource pressure** (adversarially large
  history, unreachable registry, context deadline). Availability is not
  guaranteed against a hostile registry.

---

## 9. Security model and honest boundaries

### What byreis protects

- Contributors cannot read secret values — not even ones they submitted.
- There is no route in the code or import graph from the contributor (encrypt)
  path to a private-key or decrypt capability.
- The write path (submit) is isolated from the live secrets file: submissions
  are proposed artifacts in PRs, not direct writes.
- The admin registry trust anchor and counter store provide anti-rollback:
  a stale cache cannot resurrect a revoked admin.

### What byreis does not protect against

- A compromised admin private key. The holder can decrypt everything they are
  a recipient of, including historical ciphertext in git.
- The trust root is a single pinned Ed25519 anchor key. It is not a multi-party
  root.
- GitLab is not supported. Only GitHub is available.
- There is no `export --sops` and no SOPS-symmetric interoperation. The format
  is native-`age` Model B.

### Related reading

- `docs/forward-secrecy.md` — what `rotate --remove` does and does not
  guarantee about pre-rotation ciphertext.
- `docs/rotation-runbook.md` — recovering from a partial rotation.
- `docs/request-access-runbook.md` — the full contributor-onboarding procedure.
- `SECURITY.md` — the project security policy and vulnerability reporting.
