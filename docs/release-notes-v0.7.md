# byreis v0.7 release notes

v0.7 ships `byreis export`, the admin-only plaintext export verb. It is the
supported migration relief valve for operators who need to move secrets out of
byreis into another system: decrypt the live file of record to a shell-sourceable
or dotenv-compatible stream, without ever bypassing the asymmetric-access model.

The asymmetric-access guarantee is unchanged. `byreis export` is an admin-only
command — it decrypts the secrets file with the admin private key, so a keyless
contributor cannot run it. Contributor access remains write-only and
cryptographically enforced; no v0.7 surface changes the contributor permission
matrix.

## What's new

### `byreis export` — admin-only plaintext export

`byreis export` decrypts a project's live file-of-record and serializes every
value as a shell-env or dotenv stream to stdout.

```
byreis export --project <id> --file <name> --format env    > app.env
byreis export --project <id> --file <name> --format dotenv > .env
```

The two supported formats are:

- `env` — emits one `export KEY="..."` line per value. The resulting stream is
  intended to be sourced with `source` or `set -a; source <(byreis export ...)`,
  making every key available as an exported shell variable.

- `dotenv` — emits one `KEY="..."` line per value. Compatible with `.env`
  conventions, `docker-compose env_file`, and any library that reads `.env`
  files, such as `godotenv`.

Both formats double-quote every value and apply shell-safe escaping (including
`$` and backtick characters) so a secret value cannot inject a shell command
when the output is sourced or eval'd.

#### Admin-only gate

`byreis export` is denied at the permission matrix for CONTRIBUTOR mode. The
denial happens before any network contact, identity load, or decrypt attempt —
the same fail-closed ordering that `get` and `decrypt` follow. A contributor
running the command receives a clear permission-denied error.

#### VerifyOfRecord-first, whole-file decrypt

The export verb reuses the shipped admin-read decrypt use-case. VerifyOfRecord
runs before any decrypt or identity load. If any value in the file cannot be
decrypted, the command exits non-zero and nothing is written to stdout. There is
no partial or best-effort path: export is all-or-nothing.

The audit trail records an `op=export` event so a bulk export is distinguishable
from a single-key `decrypt` in the admin audit log.

#### TTY speed-bump

By default `byreis export` refuses to write plaintext to an interactive terminal
— a first-run operator running the command without a pipe would otherwise see
decrypted secrets land in terminal scrollback. This TTY refusal is a convenience
speed-bump against an accidental dump, not a security boundary. The security
boundary is the admin private key. Once you pipe or redirect the output — for
example `byreis export ... | cat` or `> app.env` — stdout is non-interactive and
the plaintext is yours to protect.

#### `--sops` deliberately unsupported

`byreis export` does not and will not support a `--sops` output format. byreis
uses a native age recipient model (see ADR-0001 and ADR-0003): there is no shared
symmetric data key, ciphertext is addressed directly to each admin public key, and
keyless contributors can submit secrets that only key-holders can open.
A SOPS-style export would have to reintroduce a shared symmetric data key on the
consumer side, which would defeat the asymmetric-access guarantee.

`byreis export --format env|dotenv` is the supported, clean escape hatch into plaintext.
For operators migrating off SOPS or moving secrets into a different system,
`env` or `dotenv` format is the correct tool.

## What is NOT in v0.7

The following are carried forward to a future release and are not available in
v0.7:

- **No `--json` flag.** Machine-readable structured output for export is not
  implemented. Env/dotenv formats are the only output shapes.
- **No `--force` flag.** There is no override for the TTY refusal; piping or
  redirecting is the designated path.
- **No `--key` filter.** Export always decrypts and emits the whole file.
  Per-key filtering is not supported in this release.
- **No GitLab support.** byreis is GitHub-only in v0.7. GitLab support is not
  planned for this release.

## Upgrading

Drop-in replacement for v0.6. No secrets-format change, no registry-schema
change, no environment variable change. Existing encrypted files, registries,
signed commits, and the two-variable `BYREIS_PROJECT` / `BYREIS_PROJECT_REPO`
contract are all unaffected. The `export` verb is additive; all existing commands
continue to work identically.
