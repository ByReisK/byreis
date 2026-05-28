# byreis v0.4 release notes

v0.4 là **reviewer-loop release**. Nó close hai nửa của admin review flow
mà v0.3 chỉ show một nửa: một submission-PR queue thật, browse-được trong
TUI và một verb `reject` first-class (CLI và in-TUI). Cùng với loop, record
audit của một merge thành công giờ land durably trong signed file của
registry thay vì chỉ trên local machine của admin merge.

Asymmetric-access guarantee không thay đổi. Contributor vẫn encrypt và
submit write-only; họ không decrypt được, và không có v0.4 surface nào
cho một người không giữ key một route tới một plaintext value. Mức access
vẫn được derive từ thực tế cryptography, không bao giờ từ một flag, một
environment variable, hay một config file.

## Có gì mới

### Một submission-PR queue browse-được trong `byreis review`

`byreis review`, chạy trên một interactive terminal như một admin, giờ mở
một **list các submission PR đang pending** (các branch `byreis/add-*`,
`byreis/replace-*`, và `byreis/bulk-*`) với số PR, key/action, author,
và tuổi. Chọn một row và nhấn Enter để mở detail/approve flow no-plaintext
hiện có — không cần reference PR thủ công, không drop xuống CLI hay web
UI.

List view không bao giờ decrypt. Nó chỉ call read port bounded; đường duy
nhất decrypt là approve-detail flow explicit bạn opt vào per item, đó là
cùng đường decryption đã được audit của v0.3. List tự nó không bao giờ
construct key material và không bao giờ bind một plaintext value.

Queue **bounded**: tối đa 5 page / 200 result, với một tín hiệu truncation
visible, một loading indicator trên fetch chậm, và context-cancellation
được honor.

### `byreis admin request reject`

Một verb duy nhất close một request hay submission PR với một reason có
cấu trúc, từ bên trong byreis thay vì out-of-band `gh pr close`:

```
byreis admin request reject --pr <owner/repo#N> --reason "<text>"
```

PR được close, reason được post như một PR comment (nên contributor nhận
được feedback có cấu trúc), và một reject event được record trong audit
log. `--json` emit `{pr, status, reason, url}`. Verb là **ADMIN/SUPER
only**; một contributor invocation bị deny ở permission matrix trước
bất kỳ network contact nào.

`reject` là **PR-close-only**. Nó không bao giờ load một private key,
không bao giờ decrypt, không bao giờ advance một counter, và không bao
giờ write vào `admins.yaml`, `projects/*`, `policy.yaml`, hay counter
store. Nó validate PR type trước khi act: trỏ vào một PR có type không
match (source repo và branch prefix của nó phải đồng ý), nó từ chối và
close không gì. Một PR đã merge bị từ chối với một typed error (một
submission đã merge không bao giờ silent close); một PR đã close là
một idempotent no-op không có comment duplicate.

Reason được sanitize cho terminal safety (control byte và override
Unicode bidirectional/format — class Trojan-source — bị strip) trước
khi nó reach PR comment hay audit log, và nó length-cap. Free-text
reason **không bao giờ stored trong audit event** — chỉ độ dài byte
của nó được record — nên audit search và diff không leak được nó.

### In-TUI reject

Màn submission detail trong `byreis review` thêm một reject action. Nó
là một caller mỏng: nó collect một reason, show một confirm step, và
call **cùng** reject use-case như CLI verb. Nó không bao giờ construct
key material và không bao giờ đọc một plaintext value; abort confirm
không tạo call nào và return về detail view.

### Merge audit durable trong signed registry file

Một `byreis merge` thành công giờ append một signed merge event vào
`audit/<project>.jsonl` của registry, fetchable read-only, nên review
post-incident không còn depend on local machine của một admin cụ thể.
Record merge audit **đi cùng signed registry commit như counter
advance**: nó được write nếu và chỉ nếu `CommitBump` counter land.
Không bao giờ có một orphan audit entry trên một counter chưa advance,
và không bao giờ có một orphan unsigned line. Audit counter monotonic
nghiêm ngặt và subordinate to counter advance; merge concurrent được
serialize bằng một compare-and-swap push nên đúng một cái win. Audit
file auto-initialize trên merge đầu tiên.

Posture merge-audit là **fail-closed**: một signed registry commit
không thể retry offline, và một audit gap unattended worse hơn một
command failed. Nếu registry write không complete được (offline lúc
merge), command fail với một retry hint rõ ràng và một result mô tả
cái gì đã land, thay vì drop record.

#### Scope của merge-audit tamper-evidence (đọc cái này)

Channel merge-audit được protect bằng **HEAD commit signature** verify
đối với pinned trust anchor, cộng **monotonic counter** và
**compare-and-swap (CAS)** push. Cùng nhau chúng detect một HEAD
registry unsigned hay forged và cung cấp anti-rollback.

Nó **không phải** per-line tamper-detection. byreis **không** hôm nay
re-verify per-line integrity của `audit/<project>.jsonl` trên read:
per-entry hash là write-side provenance only, không có read path nào
recompute nó. Một key-less repository writer edit, reorder, hay delete
JSONL line dưới một HEAD validly-signed do đó **không** được byreis
detect. Đây là một **pre-existing, system-wide property của audit
channel** (nó đã áp dụng cho rotation audit từ v0.2), không phải cái gì
specific to merge-audit. Per-line read-side integrity binding qua
toàn bộ audit system (rotation và merge) là một follow-up tracked cho
một release sau v0.4.

## Behavior và configuration change: contract project hai-biến

v0.4 split project identity thành hai biến với ý nghĩa phân biệt:

- **`BYREIS_PROJECT`** giờ là **logical project id không có /** (ví dụ
  `myapp`). Nó được dùng cho registry path — admin set, policy,
  counter, và file `audit/<project>.jsonl`.
- **`BYREIS_PROJECT_REPO`** là **`owner/repo` slug** của project
  secrets repository (ví dụ `myorg/myapp`). GitHub git provider derive
  vị trí repo từ nó.

`byreis doctor` warn nếu `BYREIS_PROJECT` chứa một /, vì điều đó gần
như luôn nghĩa một value `owner/repo` đã được để nhầm biến.

### Note migration

Nếu trước đây bạn set `BYREIS_PROJECT=owner/repo` (form single-variable
v0.3.x), split nó: đặt `owner/repo` slug vào **`BYREIS_PROJECT_REPO`**
và đặt logical id không / vào **`BYREIS_PROJECT`**. Pass `--project`
để override per invocation. Một `BYREIS_PROJECT` vẫn chứa một / bị flag
bởi `byreis doctor`.

## Disclosure positioning và thẳng thắn

Các statement này bound cái byreis làm, có chủ ý:

- **Review TUI mở submission-PR queue mặc định; nhấn `a` để toggle
  sang access-request triage.** Submission queue là màn default mới;
  đường access-request-triage v0.3 được preserve, không remove — nó
  cách một keystroke.
- **`reject` là PR-close-only và không bao giờ chạm key material.**
  Nó close một PR và post một comment; nó không bao giờ load một key,
  decrypt, advance một counter, hay write bất kỳ trust state nào.
- **Merge-audit là HEAD-signature, monotonic-counter, và CAS protect
  — không phải per-line tamper-detection.** Một key-less repo writer
  edit JSONL line dưới một HEAD validly-signed không bị detect hôm
  nay; per-line read-side integrity là một follow-up tracked.
- **byreis là GitHub-only.** Không có GitLab provider và không có
  forge backend khác.
- **Không có `export --sops` và không có interop SOPS-symmetric.**
  Format là native-`age` Model B; một contributor key-less có thể
  encrypt tới admin nhưng không decrypt được, và không có shared
  data key để export.

## Upgrade

Drop-in replacement cho v0.3.1 với một configuration change: split
project identity thành `BYREIS_PROJECT` (logical id không /) và
`BYREIS_PROJECT_REPO` (`owner/repo` slug) theo note migration bên
trên. Không có thay đổi secrets-format. Các file encrypted, registry,
và signed commit hiện có không bị ảnh hưởng.
