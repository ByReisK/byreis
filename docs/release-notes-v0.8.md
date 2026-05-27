# byreis v0.8 release notes

v0.8 ships `byreis run`, the admin-only process-injection verb. It decrypts a
project's live file-of-record and runs a command with every value injected into
that command's environment — the secrets are handed to a single child process
and never leave the byreis process by any other channel. This is the
security-aligned consumption pattern shared by `op run` and `doppler run`:
follow-on to v0.7 `export`, whose release explicitly recorded `op run`-style
injection as the sanctioned v0.8 candidate.

The asymmetric-access guarantee is unchanged. `byreis run -- <cmd>` is an
admin-only command — it decrypts with the admin private key, so a keyless
contributor is denied at the permission matrix before any decrypt or child
spawn. Contributor access remains write-only and cryptographically enforced; no
v0.8 surface changes the contributor permission matrix. There is no new crypto
and no secrets-format change: `run` rides the shipped admin-read decrypt path.

## What's new

### `byreis run` — admin-only process injection

`byreis run` decrypts a project's live file-of-record and runs the command after
`--` with every value injected into its environment.

```
byreis run --project <id> --file <name> -- ./deploy.sh
byreis run --project <id> --file <name> -- printenv DATABASE_URL
```

#### Admin-only gate

`byreis run -- <cmd>` is an admin-only command; it decrypts with the admin
private key, so a keyless contributor is denied at the permission matrix before
any decrypt or child spawn. The denial happens before any network contact,
identity load, or decrypt attempt — the same fail-closed ordering that `get`,
`decrypt`, and `export` follow. The whole file is decrypted fail-closed: if any
value cannot be decrypted, no child is spawned.

The audit trail records an `op=run` event so an injection run is distinguishable
from a single-key `decrypt` or a bulk `export` in the admin audit log. Only the
operation literal is recorded — never the child command's arguments or any
secret value.

#### Environment-only injection, never argv

byreis injects every decrypted value into the child process's environment only —
never the argv. A process's argv is world-readable via `ps`, so a secret placed
there would leak to every user on the host. The secrets never touch disk via
byreis and exist only for the child's lifetime.

#### `exec`, not a shell

byreis execs the command after `--` directly — it does NOT interpret `$VAR`, run
a shell, or expand globs, pipes, or redirects. The argument vector you write
after `--` is exactly the argument vector the child receives. If you want shell
behavior, run `byreis run -- sh -c '...'` (which you then own). Execing argv
directly means a secret value can never be reinterpreted by byreis as a shell
command — the shell-injection surface is eliminated at the boundary.

#### Environment-override behavior

A byreis-injected variable overrides an inherited parent-environment variable of
the same name — injected-wins. If the parent environment already defines a
variable that the secrets file also defines, the child sees the decrypted value
from the file, not the inherited one. (A collision between two byreis-internal
keys that map to the same environment variable name is still a hard error: no
child is spawned.)

#### Inherited stdio, no pty

byreis inherits the child's stdin, stdout, and stderr directly — it allocates no
pty and never captures or filters the child's output. The child sees the real
terminal. The child's exit code, including signal termination reported as
`128 + signal`, is passed straight through as byreis's own exit code.

#### Honest residual-exposure disclosure

byreis promises only that byreis itself leaks nothing and that secrets never hit
disk via byreis — the same model as `op run` and `doppler run`. Once the child
holds the environment, that promise ends. byreis CANNOT protect against the
following:

- The child and all its descendants inherit the environment, making an injected
  secret readable via `/proc/<pid>/environ` by same-uid processes for as long as
  the child or a descendant is alive.
- A sub-child that puts an inherited secret into its OWN argv re-exposes that
  value via `ps`. byreis controls only the argv of the direct child it spawns,
  not what descendants do with the inherited environment.
- A child core dump or crash reporter can capture the environment, including the
  injected secrets.
- If the byreis process itself is force-killed (SIGKILL), the child it spawned is
  reparented (to init) and keeps the injected secrets in its environment until it
  exits — byreis cannot forward a signal it never receives.

If any of these are in your threat model, restrict the secret to the narrowest
possible child, disable core dumps for that process, and treat the injected
environment as plaintext you now own.

## What is NOT in v0.8

The following are carried forward to a future release and are not available in
v0.8:

- **No `--key` filter.** `run` always decrypts and injects the whole file.
  Per-key subset injection is not supported in this release.
- **No shell interpretation.** byreis execs the post-`--` argv directly and will
  never interpret `$VAR`, run a shell, or expand globs/pipes/redirects on your
  behalf. Use `byreis run -- sh -c '...'` if you need a shell.
- **No `--strict-env` flag.** The v0.8 default is injected-wins (an injected
  variable overrides an inherited one of the same name); there is no opt-in mode
  that turns an inherited/injected collision into an error.
- **No GitLab support.** byreis is GitHub-only in v0.8. GitLab support is not
  planned for this release.

## Upgrading

Drop-in replacement for v0.7. No secrets-format change, no registry-schema
change, no environment variable change. Existing encrypted files, registries,
signed commits, and the two-variable `BYREIS_PROJECT` / `BYREIS_PROJECT_REPO`
contract are all unaffected. The `run` verb is additive; all existing commands
continue to work identically.
