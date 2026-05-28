# byreis v0.5 release notes

v0.5 là **audit-binding release**. Nó làm audit trail mang đúng nghĩa
như security claim implies: mỗi dòng record trong audit channel của
registry giờ được bind với signed commit đã introduce nó, nên edit,
delete, reorder, forged insert, và cross-file splice được detect ở
read time.

Asymmetric-access guarantee không thay đổi. Contributor vẫn encrypt và
submit write-only; họ không decrypt được, và không có v0.5 surface
nào cho một người không giữ key một route tới một plaintext value.
Mức access vẫn được derive từ thực tế cryptography, không bao giờ từ
một flag, một environment variable, hay một config file.

## Có gì mới

### `byreis admin audit show --verify`

Một flag mới trên command `audit show` hiện có trigger per-line
binding verification của audit channel registry:

```
byreis admin audit show --verify
```

Verifier walk full git history của audit channel file — không chỉ
HEAD hiện tại — và check, cho mỗi dòng binding-era, rằng field
`audit_entry_sha` match với cái signed commit đã introduce dòng đó
thực sự record. Các dòng pass mang marker `verified`; các dòng được
add trong binding era nhưng hash không match mang marker `TAMPERED`
và làm command exit non-zero với một typed `ErrAuditLogTampered`
error.

Verifier detect:

- **Edits** tới một dòng binding-era sau khi nó được commit.
- **Deletions** của một dòng binding-era mà git history cho thấy
  đáng lẽ có.
- **Reorders** của các dòng binding-era qua các commit khác nhau
  (mỗi dòng bound với commit đã introduce nó; di chuyển nó sang một
  vị trí commit khác được detect).
- **Forged inserts** — một dòng mới inject vào audit file mà
  `audit_entry_sha` không tương ứng với bất kỳ commit hợp lệ nào
  trong chain.
- **Cross-file splices** — dòng copy từ audit channel của một
  project sang của một project khác (binding include channel path,
  nên hash không match ở destination file).

Command fail closed trên bất kỳ verification error nào: một dòng
tampered không bao giờ silent shown là clean, và một state
unverifiable produce một exit non-zero với một error message
actionable thay vì một partial result.

## Implementation notes

Git history walk dùng trust anchor đã established cho registry: mỗi
commit trong walk là signature-verified đối với pinned
`TrustAnchorKey` trước khi tree của nó được đọc. Một commit unsigned
hay wrongly-signed trong history của audit channel tự nó là một
tamper signal và fail walk closed.

Các dòng legacy (cái write trước release này, không có field
`audit_entry_sha`) được classify riêng; xem các disclosure thẳng
thắn bên dưới cho boundary chính xác.

## Disclosure positioning và thẳng thắn

Các statement này bound cái byreis làm, có chủ ý:

- **Decline và reject event không được cover bởi audit-binding
  verifier.** Reject event được record host-local ở thời điểm
  rejection và không được write vào audit channel của registry.
  Verifier do đó không và không thể bind chúng; absence của chúng
  từ channel là expected và không phải tamper signal.

- **Audit line được write trước release này được show là `legacy`,
  không phải `verified`.** Các dòng pre-date binding era per-line
  không mang field `audit_entry_sha` và không thể retroactively
  bind. Verifier classify chúng là `legacy` (unverified nhưng không
  tampered). Chúng không bao giờ display là `verified` và không bao
  giờ là `TAMPERED` vì binding infrastructure không tồn tại khi
  chúng được write.

- **Reorder hai dòng introduce bởi cùng một single commit dưới
  granularity binding per-commit và không được detect.** Verifier
  bind mỗi dòng với commit đã introduce nó. Cross-commit reorder
  được detect; hai dòng từ cùng một commit swap trong diff của
  commit đó là một residual boundary của approach per-commit.

- **Verifier chỉ mạnh bằng pinned trust anchor.** Mỗi commit trong
  history walk được verify đối với single pinned `TrustAnchorKey`.
  Footer commit `byreis-signer` là một label attested identify
  signing tool; nó không phải một trust key độc lập. Rotate hay
  compromise trust anchor key nằm ngoài scope của verifier này.

- **Audit-binding verifier là admin-only trong v0.5.** Flag
  `--verify` bị gate ở permission matrix cho mode ADMIN và SUPER.
  Verification audit phía contributor không nằm trong release này
  và là một follow-up đã plan; compliance story bị bound thẳng
  thắn cho admin giữ một private key registered trong trust anchor
  chain.

- **Verification fail closed dưới resource pressure.** Một history
  registry adversarially-lớn, một registry trở nên unreachable
  giữa walk, hay một context deadline làm verifier return một typed
  offline hay timeout error và exit non-zero. Không có result
  partial-verified-as-clean và không có silent truncation.
  Tamper-evidence không bị yếu đi bởi resource pressure, nhưng
  verification availability không guarantee đối với một registry
  thù địch hay unreachable.

- **Các dòng legacy pre-binding mang một residual không close được
  mà không rewrite history.** Legacy line được classify bởi
  anchor-signature và git-history position relative to first
  binding-era commit. byreis không verify continuity
  counter-monotonicity qua legacy region. Một principal giữ trust
  anchor key rewrite history của audit channel có thể position một
  dòng anchor-signed fabricated trong pre-binding prefix và nó sẽ
  display là `legacy`, không phải `TAMPERED`. Residual này confined
  trong pre-binding prefix và exploitable chỉ bởi một principal
  trusted maximum (người đã giữ trust anchor). Nó không ảnh hưởng
  layer monotonic-counter anti-rollback protect các secret artifact.

### Actor attribution trong `audit show --verify`

Khi `--verify` được dùng, cột ACTOR và field JSON `actor` giờ được
derive từ identity signer anchor-attested record trong footer
`byreis-signer` của signed introducing commit, không phải từ field
JSONL in-line. Field JSONL `actor` là adversarial input từ
registry-write path và không bao giờ được dùng cho display.

Chỉ entry có binding status `verified` nhận actor attribution.
Entry là `legacy`, `missing`, hay `TAMPERED`, cũng như bất kỳ
invocation `audit show` nào không có `--verify`, display `-` cho
cột actor.

Một action bởi một admin since-removed hay rotated display `-`.
Resolver look up signerID đối với current `SourceVerified` admin
set ở thời điểm command; một signerID không còn present được đối
xử là unknown và không bao giờ display một name stale hay
reassigned.

Field JSONL `actor` in-line không bao giờ được dùng cho display.
Một registry-writer chỉ control các byte JSONL (nhưng không phải
một signing key registered) không thể làm một name forged xuất
hiện trong cột actor.

## Upgrade

Drop-in replacement cho v0.4. Không có thay đổi secrets-format,
không có thay đổi registry-schema, không có thay đổi environment
variable. Các file encrypted, registry, signed commit hiện có, và
contract hai-biến `BYREIS_PROJECT` / `BYREIS_PROJECT_REPO` đều
không bị ảnh hưởng. Flag `--verify` là additive; `audit show`
không có `--verify` behavior identical với v0.4.
