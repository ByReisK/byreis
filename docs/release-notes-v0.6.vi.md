# byreis v0.6 release notes

v0.6 là **audit-trail completion release**. Nó deliver hai cải tiến mà
cùng nhau close gap giữa cái audit-binding verifier v0.5 đã claim và
cái nó thực sự prove được: verification contributor-side độc lập và
enforcement counter-monotonicity continuity.

Asymmetric-access guarantee không thay đổi. Contributor vẫn encrypt và
submit write-only; họ không decrypt được, và không có v0.6 surface
nào cho một người không giữ key một route tới một plaintext value.
Mức access vẫn được derive từ thực tế cryptography, không bao giờ từ
một flag, một environment variable, hay một config file.

## Có gì mới

### `byreis audit verify` — audit verification contributor-accessible

Một command top-level mới `byreis audit verify --project <id>` thực
hiện full per-line binding walk và available trong mọi mode:
Contributor, Admin, và Super. Một contributor key-less giờ chỉ cần
pinned trust anchor (qua `init/trust.yaml`) và read access tới
registry; không có private key, không có write credential, và không
có secret đã decrypt nào được access hay return.

```
byreis audit verify --project <id>
byreis audit verify --project <id> --json
```

Đây là differentiator asymmetric-compliance: audit trail giờ có thể
được verify độc lập bởi bất kỳ party nào có read access tới registry,
mà không cần giữ một admin key. Boundary admin-only v0.5 retired.

Verb mới là một sibling của `admin audit show`, không phải một
relaxation của nó. Admin-only `audit show` (cái decode và render
audit detail decoded-plaintext) không thay đổi và vẫn admin-only.
Verb `audit verify` all-modes confined trong binding walk read-only
và không reach được bất kỳ plaintext path nào theo cấu trúc: nó
import không identity hay decrypt package nào, acquire không write
token, và không make registry write.

**CI integration.** Dùng `byreis audit verify` như một tamper
tripwire trong CI:

```
byreis audit verify --project <id> --json || exit 1
```

Command exit non-zero trên bất kỳ tamper finding, offline condition,
hay registry HEAD unverifiable nào. Flag `--json` emit một binding
report machine-readable với status per-line. Không có result
partial-verified-as-clean.

### Check counter-monotonicity continuity

Verifier giờ assert per-file counter continuity qua ordered
introducing-commit walk. Các field counter (`expected_previous_counter`,
`pending_counter`) được parse từ anchor-signed commit body — không
bao giờ từ verified JSONL content — và check theo git-history order.

Cái này close pre-binding prefix residual đã disclose trong v0.5
(ADR-0019 errata E2): một principal giữ trust anchor key rewrite
history của audit channel để back-position một dòng anchor-signed
fabricated không còn có thể làm dòng đó display là `legacy` thay
vì `TAMPERED`. Một counter break — một gap, một regression, hay
một forked predecessor value — mark dòng là `TAMPERED` kể cả khi
content hash của nó match, vì break prove ordered set của
introducing commit không phải sequence monotonic genuine.

Check span verified-HEAD checkpoint seam trên incremental (warm-path)
walk: seam predecessor counter state được re-derive từ
anchor-verified cloned history ở verification time, không bao giờ từ
checkpoint cache. Một checkpoint forged không thể inject một false
counter seed và không thể mask một seam break; bất kỳ derivation
failure nào force một full cold re-walk.

Check là absent-vs-contradiction aware: một field counter thiếu
trong một anchor-signed commit body không được đối xử như một tamper
signal (nhiều commit hợp lệ pre-date các field counter). Chỉ một
value present-and-contradictory fail closed.

## Implementation notes

`byreis audit verify` reuse port `AuditVerifier` hiện có, binding
renderer, và exit-code contract của `admin audit show --verify`. CI
consumer đã parse output `--json` của `--verify` có thể consume
output của verb mới mà không có schema change.

Check counter-monotonicity là một second pass trên paired
(commits × lines) set sau phase content-hash. Một counter break
mark dòng là `BindingTampered` kể cả khi content-hash check đã pass,
vì hai check là evidence độc lập của cùng một tamper event.

## Disclosure positioning và thẳng thắn

Các statement này bound cái byreis làm, có chủ ý:

- **Audit verification giờ available cho contributor.**
  `byreis audit verify` được permit trong mọi mode (Contributor,
  Admin, Super). Một party key-less giờ có thể independently confirm
  registry audit trail untampered mà không cần giữ một admin private
  key. Restriction admin-only v0.5 superseded bởi release này.

- **Residual counter-monotonicity disclose trong v0.5 giờ closed.**
  Pre-binding prefix residual mô tả trong v0.5 (một admin holding
  anchor-key back-position một dòng anchor-signed fabricated để nó
  display là `legacy` thay vì `TAMPERED`) closed trên cả cold
  full-history walk và incremental (checkpoint-seam) warm path. Một
  counter break → TAMPERED, bất kể outcome content-hash.

- **Decline và reject event không được cover bởi audit-binding
  verifier.** Reject event được record host-local ở thời điểm
  rejection và không được write vào audit channel của registry.
  Verifier do đó không và không thể bind chúng; absence của chúng
  từ channel là expected và không phải tamper signal.

- **Audit line được write trước binding era được show là `legacy`,
  không phải `verified`.** Các dòng pre-date per-line binding không
  mang field `audit_entry_sha` và không thể retroactively bind.
  Chúng không bao giờ display là `verified` và không bao giờ là
  `TAMPERED`.

- **Reorder hai dòng introduce bởi cùng một single commit dưới
  granularity binding per-commit và không được detect.** Verifier
  bind mỗi dòng với commit đã introduce nó. Cross-commit reorder
  được detect; hai dòng từ cùng một commit swap trong diff của
  commit đó là một residual boundary của approach per-commit.

- **Verifier chỉ mạnh bằng pinned trust anchor.** Mỗi commit trong
  history walk được verify đối với single pinned `TrustAnchorKey`.
  Footer commit `byreis-signer` là một label attested identify
  signing tool; nó không phải một trust key độc lập. Residual còn
  lại sau v0.6 là một principal giữ trust anchor key có thể author
  history internally consistent (sequence counter đúng, content
  hash đúng, signature đúng) — trust root là anchor, theo thiết kế.

- **Verifier là read-only và zero-decrypt.** Audit channel là
  public. Verifier acquire không private key, không write
  credential, và return không plaintext value. Không có v0.6
  surface nào cho một người không giữ key một route tới một
  plaintext value.

- **Verification fail closed dưới resource pressure.** Một history
  registry adversarially-lớn, một registry trở nên unreachable
  giữa walk, hay một context deadline làm verifier return một typed
  offline hay timeout error và exit non-zero. Không có result
  partial-verified-as-clean và không có silent truncation.
  Tamper-evidence không bị yếu đi bởi resource pressure, nhưng
  verification availability không guarantee đối với một registry
  thù địch hay unreachable.

- **GitHub-only.** byreis support GitHub là host registry của nó.
  Không có forge backend khác được support trong release này.

## Upgrade

Drop-in replacement cho v0.5. Không có thay đổi secrets-format,
không có thay đổi registry-schema, không có thay đổi environment
variable. Các file encrypted, registry, signed commit hiện có, và
contract hai-biến `BYREIS_PROJECT` / `BYREIS_PROJECT_REPO` đều
không bị ảnh hưởng. Verb `audit verify` là additive; invocation
`admin audit show --verify` hiện có tiếp tục hoạt động identical.
