# byreis user guide

This guide covers the full current feature set of byreis v0.9.2. It is written
for both contributors (who submit secrets but cannot read them) and admins (who
hold private keys and manage the secrets lifecycle).

For a captured end-to-end run against real GitHub — real repos, real PRs, real
signed commits — see the [walkthrough](walkthrough.md).

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

### Counter file schema

The admin registry holds one counter file per project file, at
`counters/<project_id>/<file>.json`. byreis writes and reads this file during
`merge` and `rotate`. The JSON schema is:

```json
{
  "project_id":            "myapp",
  "file":                  "production",
  "last_accepted_counter": 0,
  "last_pr":               "myorg/myapp-secrets#42",
  "updated_at":            "2026-01-02T15:04:05Z",
  "rotation_epoch":        0,
  "pending":               null
}
```

Fields:

| Field | Type | Description |
|---|---|---|
| `project_id` | string | Slash-free logical project id (matches `BYREIS_PROJECT`) |
| `file` | string | Logical file name (basename without extension, e.g. `production`) |
| `last_accepted_counter` | integer | Monotonically increasing merge counter; starts at 0 |
| `last_pr` | string | `owner/repo#N` of the last accepted merge PR |
| `updated_at` | string | RFC 3339 timestamp of the last accepted merge |
| `rotation_epoch` | integer | Rotation epoch; incremented by `rotate`. Absent (or `0`) before any rotation |
| `pending` | object or null | Write-ahead intent for an in-flight merge; null when no merge is in progress |

The `pending` sub-object (non-null only during an in-flight merge):

| Field | Type | Description |
|---|---|---|
| `pending_counter` | integer | The counter value being committed (`last_accepted_counter + 1`) |
| `target_artifact_sha` | string | SHA-256 of the artifact being merged (replay defence) |
| `target_pr` | string | `owner/repo#N` of the PR being merged |
| `intent_at` | string | RFC 3339 timestamp when the pending intent was written |
| `parent_commit_sha` | string | Registry HEAD SHA at the time the pending intent was written (replay anchor) |

byreis uses `DisallowUnknownFields` when reading the file: extra JSON keys cause
a hard error. Do not add non-schema fields manually.

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

### Run a command with the secrets injected

```bash
# Run a child process with every value in the file injected into its environment
byreis run --project myapp --file secrets/production.enc.yaml -- ./deploy.sh

# Anything after `--` is the child command, exec'd directly (no shell)
byreis run --project myapp --file secrets/production.enc.yaml -- printenv DATABASE_URL

# For shell features (pipes, `$VAR`, globbing) you must spawn the shell yourself
byreis run --project myapp --file secrets/production.enc.yaml -- sh -c 'echo "$DATABASE_URL" | wc -c'
```

`byreis run -- <cmd>` is an admin-only command; it decrypts with the admin
private key, so a keyless contributor is denied at the permission matrix before
any decrypt or child spawn. Like `get`, `decrypt`, and `export`, the denial
happens before any network contact, identity load, or decrypt attempt. It runs
`VerifyOfRecord` first and decrypts the whole file fail-closed: if any value
cannot be decrypted, no child is spawned and nothing is run.

#### Environment-only injection, never argv

byreis injects every decrypted value into the child process's environment only —
never the argv (a process's argv is world-readable via `ps`, so a secret placed
there would leak to every user on the host). The secrets never touch disk via
byreis and exist only for the child's lifetime; when the child exits, byreis
holds no plaintext.

#### `exec`, not a shell

byreis execs the command after `--` directly — it does NOT interpret `$VAR`, run
a shell, or perform glob/pipe/redirect expansion. The argument vector you write
after `--` is exactly the argument vector the child receives. If you want shell
behavior, run `byreis run -- sh -c '...'` (which you then own). This is a
deliberate design boundary: execing argv directly means a secret value can never
be reinterpreted by byreis as a shell command.

#### Environment-override behavior

A byreis-injected variable overrides an inherited parent-environment variable of
the same name — injected-wins. If your shell already exports `DATABASE_URL` and
the secrets file also defines `DATABASE_URL`, the child sees the decrypted value
from the file, not the inherited one.

#### Inherited stdio, no pty

byreis inherits the child's stdin, stdout, and stderr directly — it allocates no
pty and never captures or filters the child's output. The child sees the real
terminal, and its exit code (including signal termination as `128 + signal`) is
passed straight through as byreis's own exit code.

#### Honest residual-exposure disclosure

`byreis run` is the security-aligned consumption pattern (the same model as
`op run` and `doppler run`): byreis promises only that byreis itself leaks
nothing and that secrets never hit disk via byreis. Once the child holds the
environment, that promise ends. byreis CANNOT protect against the following, and
you must account for them yourself:

- **The child and all its descendants inherit the environment.** Any same-uid
  process can read an injected secret via `/proc/<pid>/environ` for as long as
  the child (or a descendant) is alive.
- **A sub-child can re-expose a secret via its own argv.** If a process started
  by the child copies an inherited secret into its OWN argv, that value becomes
  readable via `ps` — byreis controls only the argv of the direct child it
  spawns, not what descendants do with the inherited environment.
- **A child core dump or crash reporter can capture the environment.** A child
  that crashes may write a core dump, or a crash reporter may capture its memory,
  and either can include the injected secrets.
- **A SIGKILL of byreis itself orphans the child with the secrets still set.**
  If the byreis process is force-killed (SIGKILL), the child it spawned is
  reparented (to init) and keeps the injected secrets in its environment until it
  exits — byreis cannot forward a signal it never receives.

If any of these are in your threat model, restrict the secret to the narrowest
possible child, disable core dumps for that process, and treat the injected
environment as plaintext you now own — the same care you would give any other
decrypted secret.

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

### Plugin-backed admin identities (YubiKey)

byreis supports admin identities backed by hardware security tokens via the age
plugin protocol. **Only `age-plugin-yubikey` is certified in this release.**
TPM, FIDO2, and Secure Enclave are admitted by format but are not certified or
tested; treat them as unsupported unless you are deliberately experimenting.

#### Enrolling a YubiKey identity

1. Install `age-plugin-yubikey` from its official release page on your admin
   machine.

2. Generate a new key slot on your YubiKey:
   ```bash
   age-plugin-yubikey --generate
   ```
   The tool prints an `age1yubikey1…` recipient string (the public identity you
   register) and an `AGE-PLUGIN-YUBIKEY-1…` identity string (the private-side
   handle you keep).

3. Register the `age1yubikey1…` recipient string in your admin registry entry
   (the `admins.yaml` field for your identity — the same field used for a plain
   `age1…` X25519 public key). Commit and push the registry change through the
   normal admin workflow.

4. Run `byreis doctor` to confirm the registry now shows the plugin recipient
   and that your identity resolves to ADMIN mode with the plugin key.

#### What contributors install

Contributors submitting to a project with plugin-backed admins need
`age-plugin-yubikey` on PATH but do NOT need a YubiKey. The plugin binary
handles the age recipient protocol on the contributor's machine during
encryption; the YubiKey hardware is needed only at the admin's machine during
decryption.

If the binary is absent when a contributor runs `byreis submit`, the command
fails immediately with an error naming the missing binary and an install hint,
before any secret value is collected. Install `age-plugin-yubikey` from the
official repository to resolve this.

#### Linux prerequisite: `pcscd`

On Linux, `age-plugin-yubikey` requires the `pcscd` smart card daemon to be
running when the YubiKey is touched during decryption. Start it with:

```bash
sudo systemctl start pcscd
```

The contributor path does NOT touch the YubiKey and is not affected by `pcscd`.
Only the admin decrypt path — and the startup mode-probe on an admin machine
configured with a plugin identity — requires `pcscd`. If it is absent, the
mode-probe fails closed and byreis downgrades to CONTRIBUTOR mode with a warning.

#### Version skew

Recipient strings (the `age1yubikey1…` string in the registry) do not encode
the plugin version. If you re-enroll a token slot, the new recipient string
differs from the old one. The old string in the registry becomes stale; update
the registry entry to use the new string and rotate so existing files are
re-encrypted to the new recipient. `byreis doctor` does not automatically detect
this skew.

#### PATH trust and no code-signature verification

byreis invokes `age-plugin-*` binaries from your PATH and cannot verify their
authenticity; a hostile binary earlier on PATH sees the file key — install
plugins from trusted sources only. This applies on the contributor encrypt path
as well as the admin decrypt path: a malicious plugin on a contributor's machine
can observe the plaintext file key as it passes through the recipient protocol.
Always obtain `age-plugin-yubikey` from the official repository and verify the
download.

---

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
