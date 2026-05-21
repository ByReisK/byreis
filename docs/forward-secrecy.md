# Forward secrecy: what byreis rotation does, and what it cannot do

This runbook explains, in operator-facing terms, why **byreis rotation does
not provide forward secrecy over git history**, and what an operator must do
when a recipient's key material is suspected compromised. The warning emitted
by `byreis rotate --remove` and `byreis doctor --rotation-history` points
here for the runbook procedure; this file is the single canonical reference.

Read this end-to-end before performing an incident-response rotation. The
operational guidance in the "What you MUST do" section is the load-bearing
part: simply running `byreis rotate --remove` is **not** sufficient
remediation on its own.

## TL;DR

- `byreis rotate --remove <recipient>` re-encrypts every **current**
  secrets file to the new recipient set so that, *going forward*, the
  removed party can no longer decrypt new commits.
- It **does not** delete, rewrite, or otherwise expunge the **pre-rotation
  ciphertext** that already exists in past commits of the project
  repository.
- A party that retains both (a) their private key and (b) any clone, fork,
  mirror, or backup of the project repository can still decrypt every
  secrets file that was committed before the rotation.
- Therefore, when a recipient is compromised, the **values inside the
  secrets** (passwords, tokens, API keys, certificates) must be rotated
  **out-of-band**, at the upstream system that issued them, in addition
  to running `byreis rotate --remove`.

## Why byreis cannot provide forward secrecy here

byreis is built on two underlying properties that, between them, make
git-history forward secrecy structurally impossible to deliver at the
tool layer:

### 1. The `age` Model B cryptographic primitive

byreis encrypts secrets in native `age` Model B format. In this model,
each recipient holds a long-lived `age` identity (a private key) that
corresponds to a public recipient string. Ciphertext is addressed to a
**set of recipients** at encryption time, and any recipient holding the
matching identity can decrypt that ciphertext **at any future point**.

There is no key-erasure step at the `age` layer: the cryptographic
primitive itself has no notion of "this past ciphertext is no longer
decryptable because the identity has been retired". A retained identity
remains a valid decryption capability for any ciphertext ever addressed
to its recipient string, indefinitely. This is intentional in `age`'s
design (it is an envelope encryption scheme, not a forward-secret
session protocol), and it is the right design for the use case byreis
solves — but it does mean that key compromise is **retroactive** with
respect to all ciphertext the compromised identity was ever a recipient
of.

### 2. Git's append-only history

The project repository where byreis stores encrypted secrets is, by
construction, a git repository — and git history is append-only. Every
commit ever pushed to a clone, fork, or mirror remains accessible to
anyone with read access to that history. There is no in-band mechanism
in git for byreis to retroactively remove a past blob from every
existing copy of the repository: even a forced history rewrite on the
origin (`git filter-repo` / a force-push) does not reach the clones,
forks, mirrors, CI caches, build artifacts, or developer laptops that
already pulled the affected commits. Once a ciphertext blob has been
pushed, an operator must assume it is permanently retained by every
party with read access to the project repository.

### The combination

Put together: a party who once had read access to the project repo and
who retains their private `age` identity can, at any future point,
clone or check out a pre-rotation commit, run `age` against any
pre-rotation `secrets/*.enc.yaml`, and recover every plaintext value
that was committed under their recipient set. byreis rotation cannot
prevent this — and no honest tooling at this layer can claim to.

byreis does not provide forward secrecy over git history. Any
documentation, marketing, or operator-facing message that suggests
otherwise would be a lie of commission, and the project's stance is
that such a lie is operationally far worse than the limitation itself.

## What `byreis rotate --remove` actually does

When you run `byreis rotate --remove <recipient>`, byreis:

1. Computes a new recipient set R' by removing the named recipient from
   the current recipient set R.
2. Decrypts every current `secrets/*.enc.yaml` file under the project's
   `secrets/` tree using the running admin's own identity.
3. Re-encrypts every file under recipient set R' and writes the new
   ciphertext back to disk.
4. Advances the manifest counter, refreshes the manifest signature, and
   pushes the rotation as a single signed commit on the project repo
   (paired with a signed bump on the admin registry repo).
5. Emits an audit log entry recording the rotation event, including
   the recipient(s) removed.

After step 5, the **current HEAD** of the project repo no longer
contains ciphertext addressed to the removed recipient. From the next
commit forward, that recipient cannot decrypt new contributions or
edits.

What rotation does **not** do, by design:

- It does not rewrite history. Past commits still contain the
  pre-rotation ciphertext addressed to the pre-rotation recipient set.
- It does not invalidate the removed recipient's private key. That
  identity remains a valid `age` identity; only its membership in the
  current recipient set is changed.
- It does not reach into clones, forks, mirrors, CI runners, developer
  laptops, or backup snapshots. Every copy of the project repo
  retained outside the byreis-administered origin remains fully
  decryptable by the retained-identity party.
- It does not rotate the **values** inside the secrets. The passwords,
  tokens, and keys held inside the YAML stay the same. That step is on
  you, performed out-of-band against the systems that issued those
  values.

## What you MUST do when a recipient is compromised

If the removed recipient is a routine departure (someone leaving an org
on good terms, with no suspected key exfiltration), then running
`byreis rotate --remove` and refreshing the recipient set is the
expected lifecycle action and no further steps are required.

If the removed recipient is a **compromised party** — a leaked key, a
suspected insider threat, a stolen device, or a breached service
account — then the rotation alone is not remediation. You MUST also:

1. **Treat every secret value that was ever encrypted under the
   pre-rotation recipient set as compromised.** Inventory every
   `secrets/*.enc.yaml` file that the compromised recipient was ever a
   recipient of, across the full git history of the project repo (not
   just the current HEAD).

2. **Rotate the underlying values out-of-band, at the issuing system.**
   For each affected secret:
   - If it is a database password, rotate it in the database engine.
   - If it is an API token, revoke and re-issue it at the upstream
     provider (cloud console, GitHub PAT settings, etc.).
   - If it is a private TLS or signing key, revoke its certificate
     where applicable, generate a fresh key, and re-issue the
     certificate.
   - If it is an OAuth client secret, rotate it in the OAuth
     provider's console.
   - If it is a service-account key, rotate it at the cloud IAM
     layer.

   In every case the operative step is **at the upstream system**, not
   in the secrets file. Editing the YAML alone does not invalidate the
   compromised value at the system that accepts it.

3. **Commit the new values into byreis** in the normal way: a
   contributor `byreis submit` (or an admin direct edit, depending on
   workflow) for each affected file. The new values will be encrypted
   under the **post-rotation** recipient set R', which does not
   include the compromised party.

4. **Audit downstream usage.** Anything that ever consumed the
   compromised values from byreis — CI pipelines, deployed services,
   developer workstations — must be redeployed or restarted to pick
   up the new values. Until that happens, the compromised value is
   still live in those systems even though byreis no longer hands
   it out.

5. **Record the incident.** The byreis audit log will capture the
   `rotate --remove` event with the removed recipient set; the
   out-of-band value rotations should be recorded in your
   organisation's incident-response log so the full remediation chain
   is traceable.

## Frequently asked

**"Doesn't a force-push on the project repo remove the pre-rotation
commits?"** No, in the meaningful sense. A force-push can rewrite the
origin's history, but it cannot reach into existing clones, forks,
mirrors, build artifacts, or backups. Treat every party that ever had
clone access as still holding the pre-rotation history.

**"Can I just delete the affected `secrets/*.enc.yaml` files and start
over?"** Deletion is a future-only operation, identical in effect to
removing a recipient. The historical blobs remain reachable through
any commit that contained them. Out-of-band value rotation is the
only remediation that severs the link to the upstream systems.

**"Is this an `age` weakness?"** No. `age` (Model B) is doing exactly
what it documents: long-lived envelope encryption to a recipient set.
The lack of git-history forward secrecy is a property of layering
`age` over an append-only history, not a defect in `age`. Schemes
that **do** provide forward secrecy (e.g. session-keyed exchanges
with key-erasure ratchets) are not a good fit for the GitOps secrets
problem byreis solves, because they remove the property operators
actually want: that any current admin can decrypt any current secrets
file at any future point.

**"Why does byreis surface a warning at all if there is nothing it
can do?"** Because the operational gap between "I removed a recipient"
and "the compromised party can no longer reach the data" is the most
common incident-response mistake at this layer. The warning is the
honest signal that running the byreis command is the start of the
remediation, not the end of it.

## Recipient onboarding via `request-access`

The complementary "add a recipient" path uses the contributor verb
`byreis request-access` to open a PR against the registry repo with
the proposed pubkey, and the admin verb
`byreis rotate --add --from-request <PR>` to absorb the proposed key
into a rotation after a typed-fingerprint confirm. The onboarding flow
does not touch the forward-secrecy property of past ciphertext (it is
an additive `--add`), but a single rotation invocation MAY combine
`--add --from-request` with `--remove <old>` to onboard a replacement
key in one transaction — in which case the forward-secrecy warning
above applies to the removed recipient just as it does on a standalone
`--remove`. See `docs/request-access-runbook.md` for the contributor
and admin procedures, the state-machine matrix, and the public-registry
disclosure surface.

## Related reading

- `byreis doctor --rotation-history` shows the audit-log history of
  past rotations on the current project, including which recipients
  were removed at each rotation.
- `docs/request-access-runbook.md` — opening, reviewing, and absorbing
  contributor request-access PRs. The complementary onboarding path
  to this runbook's removal procedure.
- The native `age` format byreis uses for ciphertext is the upstream
  `age` Model B; the project's design rationale for choosing Model B
  is recorded in the public design notes and ADRs.
