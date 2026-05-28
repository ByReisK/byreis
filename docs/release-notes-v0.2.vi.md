# byreis v0.2 release notes

## Correction (thêm 2026-05-23)

Binary v0.2.0 không wire các use-case `submit` và `review` vào production
composition root. Code cho cả hai — bao gồm bulk flow headline
`submit --file` — đã ship trong binary và pass test, nhưng wiring runtime
nối các use-case đó với adapter của chúng thì thiếu. Kết quả là
`byreis submit` (single-key và `--file`) và `byreis review` trả về một
error "adapters not configured" ở runtime trong v0.2.0. Logic encryption
và review tự nó không thay đổi và correct; chỉ production wiring vắng
mặt. Cái này fix trong v0.3.x, ở đó `submit` và `review` được wire vào
production composition root và hoạt động end to end. Notes v0.2 gốc
được giữ bên dưới như đã publish.

## Có gì mới trong v0.2

v0.2 land admin key-rotation lifecycle và contributor onboarding flow
trên top của submit/review/merge spine v0.1. Asymmetric-access guarantee
không thay đổi: contributor vẫn encrypt-to-admins và không bao giờ đọc
được một value.

### Key rotation

- `byreis rotate` — rotation admin-only của recipient set của một
  project. Rotation re-encrypt mọi file secrets hiện tại tới recipient
  set mới trong một two-phase commit nên một project không bao giờ bị
  bỏ dở half-rotated; một run bị interrupt an toàn để re-run. Removing
  một recipient in một forward-secrecy warning: rotation re-encrypt các
  file hiện tại nhưng không retroactively scrub được access của một
  recipient đã removed tới ciphertext đã có trong git history, nên các
  value mà một recipient compromise có thể đã đọc phải được rotate
  out-of-band. Xem `docs/forward-secrecy.md` cho incident runbook.
- `--dry-run` preview chính xác file nào và recipient nào một rotation
  sẽ thay đổi mà không write gì.
- Rotation destructive yêu cầu gõ fingerprint của recipient set mới để
  confirm, nên một rotation fat-fingered không thể tiến hành
  unattended.
- `byreis admin rotation reconcile` detect và repair một project bị bỏ
  ở state partial rotation (ví dụ sau một run trước bị interrupt) bằng
  cách đưa mọi file secrets về một recipient set consistent duy nhất.

### Contributor onboarding

- `byreis request-access` — một contributor mở một pull request xin
  được add như một recipient. Contributor không bao giờ cần admin
  credential; request đi như một PR reviewable bình thường.
- `byreis rotate --add --from-request <PR>` — một admin lift một
  access request vào một rotation add người request, verify rằng
  recipient key đang được add thuộc về author của PR trước khi grant
  access. Cái này close loop từ "contributor xin" tới "admin grant"
  mà không cần copy-paste key thủ công.
- `byreis admin request list` — một admin list các access-request PR
  đang mở chờ triage.

### Audit và diagnostics

- `byreis doctor --rotation-history` — report rotation history của
  một project và flag một project partially rotated, để một operator
  confirm rotation state liếc qua một cái.
- `byreis admin audit show` — một view read-only của signed registry
  audit log cho các rotation event.

### Bulk submission

- `byreis submit --file <.env>` — submit nhiều cặp key/value từ một
  file `.env` duy nhất trong một flow, với một bước review per-key
  trước khi bất cứ gì được encrypt và commit. Single-key submission
  không thay đổi; đường encryption identical với v0.1.

## Giới hạn đã biết / defer sang v0.3

- `byreis admin request list` enumerate mọi access-request pull
  request đang mở và chưa result-capped. Trên một registry rất lớn
  list có thể page chậm.
- Signed registry audit log record một recipient đã removed bằng
  (non-secret) public key của họ. `byreis admin audit show` report
  số lượng removed-recipient only, không phải breakdown
  per-recipient.
- Audit-log read và signed registry audit file cover rotation event
  class trong v0.2. Merge event được record host-local only và chưa
  được append vào signed registry audit file; cái đó defer sang
  v0.3.
- Per-key value validation surface trong bước review `submit --file`
  là một placeholder và chưa wire vào một production validator. Đối
  xử với output của nó như advisory trong v0.2.

## Migration: thay đổi format counter-store

byreis v0.2 mở rộng counter store JSON phía registry với một field
mới record rotation epoch của mỗi file. Một khi một admin chạy v0.2
land rotation đầu tiên trong một project, counter store cho project
đó include field này, và một binary v0.1 sẽ không đọc được nó
(decoder v0.1 dùng posture strict-unknown-field rejection). Mọi
admin operator phải upgrade lên v0.2 trước khi rotation commit đầu
tiên land; không có rollback path từ một registry đã thấy bất kỳ
rotation nào. Counter store pre-rotation forward-compatible (v0.2
đọc v0.1 fine).
