# Real-workflow walkthrough

This page is a captured end-to-end run of byreis against **real GitHub**, with
the released binary, real signed commits, real PRs, and the real artifacts that
were produced. It is not a synthetic example. Where a step is honestly *not yet*
demonstrable end-to-end on real GitHub today, the gap is called out plainly
rather than papered over.

The intent is to show what a real first deployment currently looks like — both
its working core (contributor encrypts to admins without holding any key) and
the rough edges that remain.

> All evidence below was produced by `byreis` against private GitHub repositories
> under the operator's own account; the fingerprints, age public keys, repo URLs,
> and PR URLs shown are the actual values. Token values and admin private keys
> are never shown.

---

## 1. The asymmetric guarantee, in one sentence

A **contributor** holds no private key. They can `byreis submit` a secret, which
opens a PR on the project repository carrying ciphertext encrypted to every
**admin**'s age public key. The contributor cannot decrypt it back, even on the
machine where they just encrypted it. Only an admin with the matching age
private key (and, where signing applies, the matching anchor signing key) can
read or rotate the secrets.

This page demonstrates that property by running both roles on real GitHub.

---

## 2. The two-repo model

byreis uses **two separate repositories** so the trust governance (who is an
admin) is structurally separated from the data (encrypted secrets).

```
+------------------------------+         +-----------------------------------+
| admin registry repo          |         | project secrets repo              |
| (e.g. myorg/byreis-admins)   |         | (e.g. myorg/my-app-secrets)       |
|                              |  read   |                                   |
|  - admins.yaml  (pubkeys)    | <-----+ |  - .byreis.yaml  (registry pin)   |
|  - policy.yaml               |         |  - secrets/*.enc.yaml             |
|  - projects/<id>.yaml        |         |                                   |
|  - counters/<id>/<file>.json |         |  branches:                        |
|                              |         |    main         (signed merges)   |
|  signed commits required     |         |    byreis/add-* (submission PRs)  |
+------------------------------+         +-----------------------------------+
```

The registry repo is the trust root. It is read-only from byreis's point of
view (admin changes go through an explicit `admin` flow). The project repo
holds the encrypted secrets and is where contributor submissions land as PRs.

---

## 3. Admin setup (one-time per organisation)

The admin generates two key pairs locally and registers their public material
in the admin registry repository.

| Key | Purpose | Where it lives |
|-----|---------|----------------|
| `age` keypair | encrypt/decrypt secrets | private file `0600`; public goes in `admins.yaml` |
| ed25519 SSH/anchor keypair | sign registry commits | private held by admin; public is the trust anchor |

A real `admins.yaml` from this walkthrough looks like:

```yaml
admins:
  - id: admin-nghiadaulau
    age_key: age1hk8c56qcys45gvp3pe8kjzx270dz9xlfxe8zvrjw9pscchqnx9wsdcec4a
    signer_key: vIoB5QtZbDAcOU5+PLPL74BJM8Sco+Yj2PreOoyzznI=
```

`age_key` is the age public recipient. `signer_key` is the ed25519 public key
that signs registry commits (base64). The admin pushes this file to the
registry repo on a signed commit so that every subsequent registry fetch can
verify the chain against the pinned anchor.

For this walkthrough the registry repo is
`https://github.com/nghiadaulau/byreis-demo-admins-v091b` and the project repo
is `https://github.com/nghiadaulau/byreis-demo-app-secrets-v091b` (both private
on real GitHub).

---

## 4. `byreis init` — pin the trust anchor

Every admin and every contributor runs `byreis init` once per project. The
command clones the registry, reads the **signer key from the registry's signed
HEAD**, and asks the operator to confirm the fingerprint out of band before
pinning it into `trust.yaml` (trust-on-first-use).

Non-interactive form, as captured from the actual run:

```text
$ BYREIS_NON_INTERACTIVE=1 \
  BYREIS_REGISTRY=nghiadaulau/byreis-demo-admins-v091b \
  BYREIS_PROJECT=demoapp \
  byreis init --accept-signer 4c83b37ba4d36f38d4a2c9d28f0a4d3bee120ac3b35318b9ad40260161cedfee

ok: trust anchor pinned (signer: 4c83b37ba4d36f38d4a2c9d28f0a4d3bee120ac3b35318b9ad40260161cedfee)
ok: project config written
```

The fingerprint that `--accept-signer` receives is the SHA-256 of the registry
HEAD's signing key.

> ## ⚠️ Verify the fingerprint **out of band**, not from the same git history
>
> The TOFU step is only as strong as the channel through which the operator
> obtains the expected fingerprint. **Do not** copy the fingerprint from
> `git log` of the registry repo and feed it back to `--accept-signer`; an
> attacker who controls the network at first init can present any HEAD they
> want and the fingerprint will match. Obtain the expected fingerprint from a
> different channel — the registry maintainer's signed release notes, a
> separately published static page, a phone call, or an out-of-band file.
> Once pinned, every subsequent fetch verifies HEAD's signature against the
> pinned key, so the window of trust establishment is exactly the first
> `init` call.

Interactive form prompts the operator to type the fingerprint back verbatim
before pinning — a deliberate friction so it cannot be reflexively accepted.

---

## 5. Contributor: keyless `submit` opens a real PR

The contributor runs `byreis submit` against the project repo. They hold no age
private key and need no GitHub privileges beyond a token that can open a PR.

```text
$ byreis submit DATABASE_URL --value 'postgres://demo:demo@localhost/demo'
add — PR opened: https://github.com/nghiadaulau/byreis-demo-app-secrets-v091b/pull/1
branch: byreis/add-DATABASE_URL-1779939862
```

That URL is a real PR on real GitHub. The submitted file (the ciphertext
landing on the `byreis/add-*` branch) looks like this — note the age stanza,
the signed-manifest envelope, and the recipient fingerprint:

```yaml
DATABASE_URL: |-
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAwSllZMDRCT0FrMnNOMEg4
  T1EzcUNkWi9xRDdRK1FobFp1ZWVBNFkxTUMwCitXNkpTTkJhbGdJaGxwWlNkNGtn
  eEl3MjJYN0F5ankrMVJ4VEJrVFlHMFUKLS0tIEM2UWd5S2lNL3N6Y0trYVZwMWIw
  VTVKN1EvYVUxd200cHBIUWhTZ2xQdjQKGnDzXIgzpZ0CffP/VfT8oHEBBqd7/a3o
  HOV8Gyrm/BmpHR+azNXdSnBD55dto1kiMYvIsk847w6GKOYi1jx2P8eNQA==
  -----END AGE ENCRYPTED FILE-----
byreis:
  format_version: byreis.native.v1
  project_id: demoapp
  file: production
  counter: 1
  recipients:
    - fp: 0241b6df33021c9dcbee0489c7ffb3e3d0b351c4c9c57c133daa78b2f795f86f
manifest_sig:
  signer: admin-nghiadaulau
  sig: 0d0e338eeaf469cedb75299701e067b5579a9b2b25902f08abfc6db83704600aac6519b510468ecd45aa288ce64f79df15a62146108b129fa9b20dd0d2a7900f
```

The contributor has produced this ciphertext using only the admin's public age
recipient (the `age_key` from `admins.yaml`). They never held any decrypt
material.

---

## 6. The asymmetric proof: contributor cannot decrypt

This is the property the whole product hinges on. The same contributor, on the
same machine that just produced the ciphertext above, asking byreis to read it
back:

```text
$ byreis get DATABASE_URL
error: command "get" is not permitted in CONTRIBUTOR mode: command not permitted in the current mode — this requires an admin key; see `byreis doctor` for your current mode
```

`byreis doctor` confirms the mode resolution:

```text
mode: CONTRIBUTOR
reason: no admin key or key cannot decrypt — contributor mode

[OK] config-dir: …has correct permissions (0700)
[OK] trust-anchor: …has correct permissions (0600)
[OK] mode: resolved mode: CONTRIBUTOR — no admin key or key cannot decrypt — contributor mode
```

The denial is not policy at the CLI layer — it is structural. The contributor's
process holds no `age.Identity` it could pass to `age.Decrypt`, and the encrypt
compilation unit is mechanically prevented (by an import allowlist test) from
ever reaching the decrypt path. Adding `--force` does not exist; there is no
flag that would unlock this.

---

## 7. Admin: decrypt, export, run

An admin, holding the matching `0600`-permission age private key, runs the
same `get` command and the read paths it implies:

```text
$ byreis get DATABASE_URL
DATABASE_URL=postgres://demo:demo@localhost/demo

$ byreis export --format env
export DATABASE_URL="postgres://demo:demo@localhost/demo"

$ byreis export --format dotenv
DATABASE_URL="postgres://demo:demo@localhost/demo"

$ byreis run -- env | grep DATABASE_URL
DATABASE_URL=postgres://demo:demo@localhost/demo
```

`run` injects the decrypted environment into a child process via
`exec.Command`'s `Env` (not a shell), so the plaintext never lands on argv,
disk, or the parent's environment.

---

## 8. Audit trail

Every admin promotion is recorded in the audit log on the project repo. From
the actual run:

```jsonl
{"kind":"mode.promotion","occurred_at":"2026-05-28T04:09:31Z","project_id":"demoapp","outcome":"ok","details":{"reason":"0600 key decrypts project file and public key is in a signature-verified registry","resolved_mode":"ADMIN"}}
{"kind":"mode.promotion","occurred_at":"2026-05-28T04:11:04Z","project_id":"demoapp","outcome":"ok","details":{"reason":"0600 key decrypts project file and public key is in a signature-verified registry","resolved_mode":"ADMIN"}}
…
```

The `reason` field is the literal joined truth byreis verified before
promoting: the key's permissions, the key's ability to decrypt a project file
(cryptographic reality, not a config flag), and the public key's presence in a
**signature-verified** registry. Any one of those three failing keeps the
process in CONTRIBUTOR mode.

---

## 9. The reviewer loop (review, merge, rotate)

The reviewer loop — admin runs `byreis review` on the open PR, then
`byreis admin merge` to fold the submission into the signed file-of-record on
`main` — is gated on the admin's git access to the project repo. The HTTPS
authentication used by byreis for git clones, fetches, and pushes goes through
the same header byreis injects for every authenticated GitHub operation.

The wire format of that header **changed in v0.9.2** to fix a real bug: v0.9.1
emitted `Authorization: Bearer <token>`, which GitHub's smart-HTTP service
rejects for personal-access tokens; v0.9.2 emits
`Authorization: Basic base64("x-access-token:<token>")`, which is the form
GitHub actually accepts.

This is verified in CI, not just in the demo:

- `TestS3_GitAuthSchemeIsBasicNotBearer` (release-blocking ship-gate) builds a
  real `git ls-remote` subprocess, points it at an `httptest.Server`, captures
  the `Authorization` header git actually sent, and asserts both that the
  scheme is `Basic` and that the decoded payload is `x-access-token:<token>`.

> ### Honest limitation — not yet demonstrable end-to-end from a fresh project
>
> A complete fresh-project run of contributor `submit` → admin `review` →
> `merge` against real GitHub is currently **not** captured here because the
> first admin merge needs a signed file-of-record on `main` to exist already,
> and there is no `byreis` verb today that produces that initial signed
> artifact on a project that has never been merged. This is the
> *fresh-project bootstrap UX gap* tracked for a follow-up cycle. The
> auth-scheme fix that previously blocked the reviewer loop on real GitHub is
> proven by the integration test above; the user-facing demonstration of
> review→merge end-to-end on real GitHub will land alongside the bootstrap
> fix.

When a project is already past first-merge, the reviewer flow runs as the
shipgate suite proves: an admin's mode detection authenticates to the private
GitHub registry, mode resolves ADMIN, the submission PR is enumerable, the
review use-case validates the canonical bytes, and the merge use-case re-signs
the new file-of-record and pushes it back. Rotation (`byreis rotate`) operates
on the same merged state to re-encrypt to an updated recipient set.

---

## 10. Known limitations and operator notes

### 10.1 Fresh-project bootstrap

A brand-new project with no prior signed file-of-record cannot have its first
admin merge run through `byreis admin merge` today — the merge use-case
requires an existing signed artifact to chain from, and `byreis init` only
pins the trust anchor, it does not create an initial artifact. This is a UX
gap, not a security gap (no asymmetry property is violated by the absence —
contributors can still encrypt; admins cannot yet merge until the gap is
closed). A focused mini-design for a `byreis admin bootstrap` verb (or an
opt-in mode of `init`) is on the roadmap.

### 10.2 `BYREIS_PROJECT_REPO` must be an `owner/repo` slug

Even though `BYREIS_REGISTRY` accepts a `file://` URL for testing, the
project-repo git provider currently only accepts the `owner/repo` slug form
expected by GitHub. A local `file://` value yields:

```text
error: project string must be owner/repo (e.g. myorg/my-secrets) — got "file:///tmp/…" — repo part must not contain '/'
```

This is fine for any real GitHub deployment but blocks fully-offline
demonstrations of the reviewer loop. The GitLab provider (a separate roadmap
item) will widen this surface; until then, all reviewer-loop testing happens
against real GitHub.

### 10.3 `byreis doctor` will always show CONTRIBUTOR for itself

`doctor` is in the contributor-allowed verb set, so its own decrypt-probe is
deliberately suppressed (to avoid an unnecessary key-touch every time you run
`doctor`). When a key file is configured but the probe is suppressed for this
particular verb, `doctor` emits:

```text
[INFO] mode: probe suppressed (doctor does not require admin); to verify admin mode try a key-using command
```

Run any admin verb (e.g. `byreis get --json`) to actually exercise the
promotion path.

### 10.4 `GITHUB_TOKEN` and `GH_TOKEN` are *not* scrubbed by byreis

byreis scrubs its own `BYREIS_*` secret env vars (`BYREIS_KEY`,
`BYREIS_KEY_FILE`, `BYREIS_SIGN_KEY`, `BYREIS_SIGN_KEY_FILE`,
`BYREIS_GITHUB_TOKEN`) from the process environment after reading them, so
any age plugin subprocess byreis spawns inherits an environment that no
longer contains those values. The non-byreis convention variables
`GITHUB_TOKEN` and `GH_TOKEN` are intentionally **not** touched — they
belong to the operator's broader shell environment. High-security operators
who treat these as sensitive should scope or unset them out of band on
machines that run age plugins from third parties.

### 10.5 Plugin recipients (`age-plugin-yubikey` and friends) — what works today

age-plugin-yubikey-backed admin identities ship as of v0.9.0 and are proven
end-to-end through the asymmetric ship-gate (`TestAsymmetryShipGate_Plugin*`):
a contributor with the plugin binary on PATH can encrypt offline to a
YubiKey-backed admin recipient, that admin can decrypt with their token, and
mode detection promotes correctly when the token is present. The
`age-plugin-tpm`, `age-plugin-fido2-hmac`, and `age-plugin-se` plugins are
format-admitted but **not certified** in this release; their bytes are
accepted by the registry validator but their UX is not tested.

> ## ⚠️ Plugin binary trust
>
> byreis invokes `age-plugin-*` binaries from your PATH and cannot verify
> their authenticity. A hostile binary earlier on PATH sees the file key
> during encrypt and the secret material during decrypt. This applies on
> both the contributor encrypt path and the admin decrypt path. Install
> plugins from trusted sources only and consider pinning their locations.
> On Linux, `age-plugin-yubikey` requires `pcscd` to be running for the
> YubiKey to be addressable during decrypt; the contributor encrypt path
> does not touch the YubiKey and is not affected by `pcscd`.

---

## 11. Evidence

Every transcript, the captured `admins.yaml`, the encrypted
`production.enc.yaml`, and the `audit.log` shown above live in
`design/v09_demo_evidence/` (git-ignored on the byreis source tree because it
contains operator-specific test artifacts). The real demo repositories
themselves remain on GitHub at:

- Registry: <https://github.com/nghiadaulau/byreis-demo-admins-v091b>
- Project: <https://github.com/nghiadaulau/byreis-demo-app-secrets-v091b>
- Open submission PR: <https://github.com/nghiadaulau/byreis-demo-app-secrets-v091b/pull/1>

Visit them to see the actual signed commits, the actual ciphertext file, and
the actual contributor PR; nothing here is mocked.
