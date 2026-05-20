<div align="center">

# byreis

**Send secrets. Not see them.**

Friendly GitOps secrets management with asymmetric access control — written in Go.

</div>

---

## What is byreis?

byreis lets a team manage secrets in plain git, with one defining twist:

> **Contributors can submit secrets, but only admins can read them.**

A contributor encrypts a value to the team's admin public keys and opens a pull
request. They never hold a private key, so they can add or update a secret but
can never decrypt one — not even the value they just submitted. An admin reviews
the decrypted value and merges.

```bash
# Contributor — write-only, no private key
byreis submit STRIPE_API_KEY --env dev
# → opens a PR with the encrypted value for an admin to review

# Admin — review the real value, then merge
byreis review --pr 1234
```

No server. No vendor backend. Just git and modern public-key encryption.

## Why?

Existing tooling forces a trade:

- **SOPS + age** — zero-infra and git-native, but symmetric: anyone with a key
  reads everything, and a keyless contributor cannot edit a shared environment
  file at all.
- **Server-based managers** — good UX, but require infrastructure or a vendor.
- **Kubernetes-only controllers** — not usable for plain local/CI workflows.

byreis fills the gap: the only zero-infra, plain-git tool where people who must
never *read* secrets can still safely *add and update* them, with friendly
errors and CI-native flows.

## Status

🚧 **Early development.** The architecture and the cryptographic access model are
settled and the project skeleton is in place; core commands are being
implemented. Interfaces and on-disk formats may still change before `v0.1`.

## Roadmap (high level)

**v0.1 — the spine**
- Crypto-derived access mode (admin vs contributor is decided by what you can
  cryptographically do, never by a config flag)
- `init`, `doctor`
- `submit` — keyless, write-only, opens a GitHub PR
- `review` / `merge` — admin decrypts, validates, and merges
- Admin read path: `get`, `decrypt`, `edit`
- Keyless CI submit + CI decrypt
- Offline-first admin registry with signature verification

**Later**
- Interactive TUI for admins
- `rotate`, `share`, `revoke`, self-service access requests
- GitLab support, bulk submit

## Admin registry requirements

The admin registry repository (the one pointed to by `.byreis.yaml` in each
project repo) **must** have the following branch-protection rules on `main`
before any `byreis admin merge` or counter-write operation is attempted:

- **Signed commits required (byreis-aware status check)** — the registry must
  run a byreis verifier as a CI gate on `main` that validates the
  `byreis-signer:` / `byreis-sig:` footer in each counter commit against the
  registry's signer roster. GitHub's native "Require signed commits"
  branch-protection rule is **not** the enforcement point and must not be
  relied on, because byreis embeds its Ed25519 signature in the commit
  message body (preserving the signer port abstraction) rather than in the
  commit object's `gpgsig` header.
- **Linear history** — no merge commits; rebase-only. Ensures counter
  monotonicity.
- **No force-push** — ordinary `git push --force` is rejected. byreis uses
  `--force-with-lease` (CAS) to detect concurrent writes; if the remote accepts
  force-pushes, the concurrent-write guard loses its effectiveness.
- **No branch deletion** — protects the history that signed-commit verification
  and anti-rollback checks rely on.

Counter writes (`WriteCounter` / `CommitCounter`) validate these requirements at
push time and surface `ErrRegistryWriteRejected` if the remote refuses the push.
If you see that error, verify the branch-protection configuration above.

## Contributing

byreis is in active early development and not yet ready for production use.
Issues and discussion are welcome. Please open an issue before sending a pull
request so the design direction can be discussed.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
