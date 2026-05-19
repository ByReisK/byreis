# byreis documentation (public)

This folder holds **user-facing documentation** intended for public release —
written for people who *use* byreis, not for people building it.

Planned contents (per `PLAN.md` §1/§9, written during/after BUILD):

- `quickstart.md` — install + first submit in under 2 minutes
- `user-guide.md` — contributor workflow (`init`, `submit`)
- `admin-guide.md` — admin workflow (`review`, `merge`, registry, bootstrap)
- `ci-integration.md` — keyless CI submit + CI decrypt
- `threat-model.md` — public-facing security model & what byreis does/doesn't protect
- `architecture.md` — high-level overview for evaluators

> **Internal engineering artifacts do not live here.** The normative design
> spec, ADRs, locked requirements, and the crypto-spike findings are in
> [`../design/`](../design/) (`DESIGN.md`, `adr/`, `REQUIREMENTS.md`,
> `FINDINGS.md`). Throwaway crypto-spike proof code is in `../spike/`
> (git-ignored). Keep this `docs/` tree clean and publishable.
