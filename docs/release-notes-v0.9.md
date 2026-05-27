# byreis v0.9 release notes

v0.9 ships plugin-backed admin identities. An admin can register a YubiKey
identity and have contributors encrypt to it the same way they encrypt to any
other admin — offline, with no token required on the contributor's side. The
admin decrypts with their token present. The asymmetric-access guarantee is
unchanged: contributors write secrets, admins read them, and the boundary is
still cryptographic reality.

This release admits exactly one certified plugin: **age-plugin-yubikey**. Three
others — TPM, FIDO2, and Secure Enclave — are admitted by format (byreis will
not reject a well-formed `age1tpm1…` or `age1se1…` recipient string in the
registry) but are NOT certified or tested in v0.9. Treat them as unsupported
unless you are deliberately experimenting.

## What's new

### Plugin-backed admin identities

An admin enrolls a YubiKey with `age-plugin-yubikey` and registers the
resulting `age1yubikey1…` recipient string in the admin registry. From that
point forward, submitting contributors encrypt to it automatically — no
configuration change required on the contributor side.

The contributor-side change is deliberately minimal: contributors submitting to
a project with plugin-backed admins need `age-plugin-yubikey` on PATH but do
NOT need a YubiKey. The plugin binary handles the age recipient protocol on
the contributor's machine during encryption; the YubiKey hardware is only needed
at the admin's machine during decryption.

#### What the admin does

1. Enroll a YubiKey slot with `age-plugin-yubikey --generate` (or equivalent).
   The tool prints an `age1yubikey1…` recipient string and a `AGE-PLUGIN-YUBIKEY-1…`
   identity string.
2. Register the `age1yubikey1…` recipient string in the admin registry (the
   `admins.yaml` entry for your identity, same field as a plain `age1…` public
   key).
3. Run `byreis doctor` to confirm the registry now shows the plugin recipient
   and that your identity resolves to ADMIN mode.

No re-key of existing secrets is required. byreis encrypts new submissions to
every registered admin recipient — existing X25519 admins are not affected by
a new plugin recipient being added.

#### What contributors install

Contributors who submit to a project that includes a plugin admin need
`age-plugin-yubikey` on their PATH. Install it from the project's GitHub
Releases page. The binary is a standalone executable and requires no YubiKey
to be present.

If the binary is missing when a contributor runs `byreis submit`, the command
fails with a clear error naming the missing binary and an install hint, before
any secret value is collected.

#### Linux requirement: `pcscd`

On Linux, `age-plugin-yubikey` requires `pcscd` (the PC/SC smart card daemon)
to be running when the YubiKey is touched during decryption. The contributor
path does NOT touch the YubiKey and is not affected. Only the admin decrypt
path (and the startup mode-probe on a plugin-configured admin machine) requires
`pcscd`. If it is absent, the mode-probe fails closed and byreis downgrades to
CONTRIBUTOR mode with a warning; it does not hard-crash.

#### Mixed fleet

Registering a plugin admin does not require removing or re-keying existing
X25519 admins. New submissions are encrypted to all registered recipients. An
existing X25519 admin who has not yet enrolled a plugin identity can still
decrypt normally. Mixed X25519 + plugin fleets are the expected migration path.

#### Orphaned-subprocess residual

byreis bounds the time it waits for the plugin subprocess to complete a
cryptographic operation. If the timeout is reached, byreis fails the operation
and returns an error. The underlying plugin subprocess may continue to run
briefly after the timeout; it is a best-effort reap, not a guaranteed kill. This
residual is inherent to the age plugin protocol and applies equally to any
plugin-backed operation.

#### Security: PATH trust and no code-signature verification

byreis invokes `age-plugin-*` binaries from your PATH and cannot verify their
authenticity; a hostile binary earlier on PATH sees the file key — install
plugins from trusted sources only. This applies on the contributor encrypt path
as well as the admin decrypt path: a malicious plugin on a contributor's machine
can observe the plaintext file key as it passes through the recipient protocol.
Always obtain `age-plugin-yubikey` from the official repository and verify the
download.

## What is NOT in v0.9

The following are not available in v0.9:

- **No other certified plugins.** Only `age-plugin-yubikey` is certified and
  tested. TPM, FIDO2, and Secure Enclave are admitted by format but unsupported
  — do not rely on them in production.
- **No auto-install or managed plugin registry.** byreis does not download or
  manage plugin binaries. Install from a trusted source manually.
- **No TUI surface for plugin management.** Plugin enrollment and registration
  are done outside byreis with the `age-plugin-yubikey` CLI and the standard
  registry edit flow.
- **No Tier-2 KMS-wrapped identity or Tier-3 KMS-recipient / PGP backends.**
  These are explicitly out of scope.
- **No GitLab support.** byreis is GitHub-only in v0.9.

### Total-blockage edge case

If every admin in a project has a plugin identity and a contributor does not
have the corresponding plugin binary installed, every `byreis submit` will fail
with a binary-not-found error. This is the correct, documented behavior: the
error names the missing binary and provides an install hint. Install the binary
to unblock.

## Upgrading

Drop-in replacement for v0.8. No secrets-format change, no registry-schema
change, no environment variable change. Existing encrypted files, registries,
signed commits, and the `BYREIS_PROJECT` / `BYREIS_PROJECT_REPO` contract are
all unaffected.

Admins who want to register a plugin identity add a new `age1yubikey1…`
recipient string to their registry entry. Existing identities (X25519) continue
to work without change. Plugin support is purely additive.
