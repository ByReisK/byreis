# Rotation runbook: recover một rotation dở dang và dùng `admin rotation reconcile`

Runbook này là thủ tục operator-facing để recover từ một invocation
`byreis rotate` failed hoặc bị interrupt. Error message phát ra từ một
rotation đáp xuống partial state trỏ tới đây cho các bước recovery; file
này là canonical reference duy nhất.

Đọc end-to-end **trước khi** chạy `byreis admin rotation reconcile` đối
với một project bạn nghi đang ở partial-rotation state. Bước classify là
read-only và an toàn để chạy bất kỳ lúc nào, nhưng các action recovery
mô tả bên dưới là admin-only và write vào registry; coi chúng là sự
kiện thay đổi production.

Cho câu hỏi liên quan về **forward secrecy qua git history** —
`byreis rotate --remove` guarantee gì và không guarantee gì về
ciphertext pre-rotation — xem `docs/forward-secrecy.md`. Hai runbook bổ
trợ nhau: cái này về recover một transaction partial; runbook
forward-secrecy về cái gì vẫn decryptable với một recipient đã removed
mà còn giữ key material và một clone của history.

## TL;DR

- Một invocation `byreis rotate` fail sau Phase 1 (branch + pending bump
  per-file đã write) nhưng trước Phase 2 (registry `CommitRotation` đã
  land) để hệ thống ở partial state recoverable được. Chạy
  `byreis admin rotation reconcile` classify state và, khi
  classification cho phép, revert side effect Phase-1 trong một signed
  registry commit duy nhất.
- Verb reconcile là **admin-only**. Một invocation từ contributor bị
  deny ở policy gate trước bất kỳ registry fetch nào, với exit code
  `permission-denied`.
- Verb reconcile là **classify-first**: một partial state không thể
  auto-revert an toàn (case Phase-2 mid-flight) surface một terminal
  error trỏ về runbook này và yêu cầu admin coordination thủ công.
  Không có auto-rollback cho Phase-2 mid-flight, theo thiết kế.
- Reconcile **không** ảnh hưởng forward-secrecy property của bất kỳ
  ciphertext nào. Nó revert attempt thay đổi recipient-set in-flight;
  nó không thay đổi cái gì một party retain-key decrypt được từ
  history.

## Khi nào invoke `byreis admin rotation reconcile`

Invoke verb này trong một trong hai tình huống:

1. **Sau một failure `byreis rotate`.** Khi một invocation `rotate` trả
   về error nhắc đến "rotation is in a partial state", "see rotation
   runbook", hoặc một exit class khác 0 dạng `counter-reconcile` hoặc
   `trust-error` từ một rotation path, hệ thống có thể đã commit side
   effect Phase-1 (một rotation branch trên project repo, pending bump
   per-file trong counter store của registry) mà không land được
   `CommitRotation` Phase-2 atomic finalize rotation. Chạy
   `byreis admin rotation reconcile --project <id>` để classify và,
   chỗ nào an toàn, revert.

2. **Chủ động trên một partial state nghi ngờ.** Nếu `byreis doctor`
   report một pending counter per-file đi trước committed counter
   per-file cho một project, hoặc nếu một rotation branch tên
   `byreis/rotate-<epoch>-*` có mặt trên project repo mà không có
   `CommitRotation` audit row match trong registry log, project có
   thể đang ở Phase-1-only partial state. Bước classify read-only và
   an toàn chạy bất kỳ lúc nào; nó sẽ report `NoPartial` nếu không có
   gì cần reverse.

## `byreis admin rotation reconcile` làm gì

Verb tiến hành qua hai stage:

### Stage 1 — Classify (read-only)

Reconciler fetch một view registry signature-verified, không stale (nó
không bao giờ đọc từ stale cache cho quyết định này) và fetch state hiện
tại của rotation branch của project repo (nếu có). Sau đó assign
partial state vào một trong bốn class:

- **`NoPartial`** — không có rotation đang in flight; không có gì để
  làm. Exit code `ok`. Verb trả về ngay với một success message.
- **`Phase1Only`** — side effect Phase-1 có mặt (rotation branch đã
  write, pending counter đã bump) nhưng không có `CommitRotation` nào
  land trong registry log. Cái này safely reversible: rotation chưa
  bao giờ đạt tới commit point, nên không có thay đổi recipient-set
  publish nào đã có hiệu lực.
- **`Phase2Midflight`** — evidence Phase-2 partial có mặt: một số file
  phía project xuất hiện đã committed vào main branch của project
  repo (rotation branch đã merge), nhưng `CommitRotation` row atomic
  finalize counter per-file trong registry chưa land; **hoặc**
  rotation branch của project đã merge nhưng counter-store + audit
  advance của registry chưa land trong cùng signed commit nó đáng lẽ.
  Class này **không** auto-revertable.
- **`InconsistentPartial`** — state quan sát được không khớp bất kỳ
  cái nào trong ba class trên (ví dụ một rotation branch có mặt nhưng
  pending per-file trên registry vắng, hoặc ngược lại). Đối xử như
  `Phase2Midflight` từ góc độ recovery: terminal, không auto-revert,
  yêu cầu coordination thủ công.

Stage 1 không bao giờ write. Nó được compose đối với một view registry
read-only và một probe project-repo read-only. Bước classify không
load write credential và không yêu cầu admin đang chạy giữ bất kỳ
write capability nào ngoài read capability đã implies bởi mode ADMIN.

### Stage 2 — Revert (chỉ trên `Phase1Only`)

Khi classification là `Phase1Only`, reconciler:

1. Build một reversal audit event ghi rotation epoch, delta recipient-set
   đã attempt, ref của rotation branch, và lý do reversal.
2. Issue một signed registry commit duy nhất **atomically**:
   - clear mọi pending counter per-file đã bị bump bởi Phase 1 về
     value pre-rotation, và
   - append reversal audit row vào audit log của registry.

   State cleared-pendings và reversal audit row land cùng nhau trong
   một signed commit. Một operator đọc registry log có thể tin cậy
   việc join: bạn sẽ không bao giờ quan sát một phantom reversal audit
   row mà không có counter reset đi kèm, hay một counter reset mà
   không có audit row của nó.

3. Attempt delete rotation branch từ project repo qua
   `git push origin --delete <branch-ref>`, retry dưới một budget
   compare-and-swap bounded.

Sau khi step 2 thành công, registry ở state pre-rotation consistent.
Step 3 là cosmetic cleanup của project repo: nếu nó fail sau khi
registry commit đã land, registry state **đã** consistent và cái duy
nhất còn lại là remove stale branch khỏi project repo. Verb surface
case này explicit (xem "Branch-delete budget exhausted" bên dưới).

Khi classification là `Phase2Midflight` hoặc `InconsistentPartial`,
reconciler **không** attempt revert. Nó trả về một terminal error trỏ
về runbook này và surface exit class `counter-reconcile`. Không có
action automatic thêm nào được thực hiện, và không có action automatic
thêm nào sẽ được attempt khi re-invoke: verb là idempotent trên các
terminal classification.

## Exit code

Exit code của verb tương ứng với các exit class chuẩn của project:

- **`ok`** — `NoPartial` (không có gì để làm) hoặc một reversal
  `Phase1Only` thành công. Verb hoàn thành sạch.
- **`permission-denied`** — caller không ở mode ADMIN. Verb bị deny ở
  policy gate trước bất kỳ registry fetch nào.
- **`counter-reconcile`** — classification là `Phase2Midflight` hoặc
  `InconsistentPartial`. Một terminal error đã trả về; xem
  "Phase-2 mid-flight recovery" bên dưới.
- **`trust-error`** — CAS registry bị reject sau khi bounded retry
  budget exhausted (registry contention), hoặc rotation-branch probe
  của project surface một missing branch ref ở chỗ cần một.
- **`auth-error`** — mode của admin đang chạy không derive được (ví
  dụ key không sẵn, file permission không phải `0600`, hoặc
  trust-path của registry chưa verified).

## Phase-2 mid-flight recovery (terminal class — thủ tục manual)

Khi `byreis admin rotation reconcile` classify state là
`Phase2Midflight` (hoặc `InconsistentPartial`), automatic recovery
dừng. **Không có auto-rollback** cho class này, và đó là một quyết
định thiết kế có chủ ý, không phải feature thiếu.

### Tại sao không có auto-rollback

Một state Phase-2 mid-flight nghĩa là một phần của project-side merge
của rotation đã có hiệu lực (rotation branch đã merge vào project
main, nên ciphertext mới visible với reader), trong khi
`CommitRotation` phía registry finalize counter per-file advance +
audit log entry chưa land atomic. Một automated recovery từ điểm này
sẽ bản thân nó phải là một trust-path write dưới pre-condition không
chắc chắn: nó sẽ cần (a) push `CommitRotation` thiếu forward để match
project-side merge, hoặc (b) revert project-side merge để match
registry commit thiếu. Cả hai option yêu cầu code recovery quyết định
unilaterally về intent của operator, đối với một observed state
inconsistent, trong khi giữ write capability trên một trust-path
resource. Position của project là **fail-closed beats fail-clever**
cho một primitive load-bearing thế này: behavior an toàn hơn là halt
automatic path và surface tình huống cho một con người, kể cả chi
phí là một bước recovery thủ công.

### Thủ tục recovery thủ công

Khi bạn quan sát một exit `Phase2Midflight` hay `InconsistentPartial`
từ `byreis admin rotation reconcile`:

1. **Dừng lại và coordinate.** Không re-run `rotate` hay `reconcile`
   đối với project này cho đến khi thủ tục manual hoàn thành. Mở một
   incident channel với ít nhất một administrator khác nằm trong
   recipient set **pre-rotation** (để họ đọc được các file ảnh hưởng
   độc lập với rotation vừa fail).

2. **Thiết lập ground truth.** Inspect cả hai phía của partial commit:
   - Trên project repo, identify rotation branch ref đã merged và
     confirm các file `secrets/*.enc.yaml` nào có ciphertext
     post-rotation tại main `HEAD` hiện tại.
   - Trên registry repo, inspect audit log và counter store. Confirm
     pending counter per-file nào (nếu có) đã được bump, và liệu một
     row `CommitRotation` partial có tồn tại không. Cross-check
     rotation epoch ở cả hai phía.

3. **Quyết định direction sửa.** Hoặc:
   - **Roll forward**: thủ công re-derive `CommitRotation` thiếu
     (rotation epoch, committed counter per-file, audit row) cho
     project-side merge đã có hiệu lực, và push signed commit đó vào
     registry. Verify state registry mới bằng chạy `byreis doctor`
     đối với project và confirm committed counter per-file match
     ciphertext của project-repo `HEAD`.
   - **Roll back**: revert project-side merge trên project repo
     (`git revert` của rotation merge commit, push như một commit
     mới trên main), và **độc lập** restore counter store của
     registry về value pre-rotation qua một signed registry commit
     bao gồm audit row phù hợp.

   Lựa chọn giữa roll-forward và roll-back phụ thuộc vào việc thay
   đổi recipient-set của rotation có còn được muốn hay không.
   Roll-forward thích hợp khi intent của rotation vẫn valid và công
   việc còn lại duy nhất là land phía registry của một thay đổi
   project đã merge. Roll-back thích hợp khi rotation tự nó nên được
   undone (ví dụ operator giờ tin rằng recipient delta sai, hay
   rotation là một phần của một aborted incident response).

4. **Surface recovery vào audit log.** Direction nào được chọn,
   registry commit land recovery phải mang một audit row identify
   recovery là một manual reconciliation, rotation epoch liên quan,
   và administrator đã thực hiện. Đừng thực hiện recovery dưới dạng
   một registry write "silent".

5. **Warn explicit.** Một manual recovery sai — ví dụ re-derive sai
   rotation epoch, hay skip counter advance per-file trên một
   roll-forward — có thể phá vỡ asymmetric-access invariant mà
   project depend on (thuộc tính contributor-can-write-but-not-
   read), vì nó sẽ để ciphertext của project repo address tới một
   recipient set mà registry không đồng ý tồn tại. Hai administrator
   phải verify commit recovery độc lập trước khi nó được push.

## Branch-delete budget exhausted

Khi một reversal `Phase1Only` land registry-side reversal commit sạch
nhưng project-repo branch delete tiếp theo fail sau khi bounded retry
budget, verb surface một error dạng:

    branch-delete CAS rejected after N retries; manual cleanup required
    via git push origin --delete <ref>

Error này là **cosmetic cleanup**, không phải một transactional
failure. Registry **đã** ở state pre-rotation consistent — pending
counter đã được clear và reversal audit row đã được append trong
cùng signed registry commit, và commit đó đã land trước khi
branch-delete được attempt. Công việc còn lại duy nhất là remove
stale rotation branch khỏi project repo.

Để hoàn thành cleanup, chạy chính xác command verb đã surface, ví dụ:

    git push origin --delete byreis/rotate-7-20260521t1200z

Nếu branch delete tiếp tục fail (thường vì project branch-protection
rule hay một concurrent reviewer đang giữa chừng nhìn rotation
branch), coordinate với reviewer của project repo và delete branch
qua ref-deletion path chuẩn của project. Bạn **không** cần re-run
`byreis admin rotation reconcile` sau đó; phía registry đã settle.

## Cân nhắc large-N rotation

Một project với số file secret rất lớn (lớn hơn nhiều case
day-to-day) trên nguyên tắc có thể tạo ra một partial state với danh
sách dài pending per-file để revert. Đến nay, project fixture và
integration test fixture chưa surface bất kỳ regression large-N nào —
không observed run nào đã vượt practical single-commit revert budget
— nhưng guidance vận hành là:

- Nếu `byreis admin rotation reconcile` report một classification
  `Phase1Only` với số lượng file rất lớn để revert, để verb chạy đến
  hoàn thành. Reversal là một signed registry commit bất kể số file;
  nó không fan out thành commit per-file.
- Nếu một classification `Phase2Midflight` surface đối với một
  project có số file rất lớn, thủ tục recovery manual mô tả bên
  trên áp dụng, nhưng operator coordination trở nên proportionally
  quan trọng hơn: hai administrator review commit recovery không
  còn là nice-to-have ở quy mô đó, nó là precondition.
- Hardening tương lai để batch reversal commit (hoặc thêm guardrail
  per-file-count trước khi reconcile tiến hành) được track như một
  hardening item trong reserved work của project; không gì về
  behavior verb hiện tại thay đổi cho đến khi hardening đó land.

## Hợp đồng atomicity same-commit

Hợp đồng transactional trung tâm của verb reconcile trên một reversal
`Phase1Only` là state cleared-pendings và reversal audit row land
**cùng nhau** trong một signed registry commit duy nhất. Hợp đồng này
load-bearing:

- Một operator đọc registry log có thể tin cậy việc join. Bạn sẽ
  không quan sát một phantom reversal audit row mà không có effect
  của nó (counter reset), và bạn sẽ không quan sát một counter reset
  mà không có audit row của nó.
- Một reader reproduce registry log offline (ví dụ khi verify audit
  history như một phần của security review) thấy reversal như một
  sự kiện atomic duy nhất, không phải hai bước có thể bị tear qua
  các intermediate state.
- Bounded CAS retry budget trên registry commit defend hợp đồng đối
  với concurrent registry write: một CAS rejection làm verb retry
  cùng composed commit, không bao giờ split reversal thành một
  counter reset trên một commit và một audit row trên một commit
  sau.

Bước branch-delete trên project repo cố ý **nằm ngoài** envelope
atomicity này. Nó là cosmetic post-cleanup; fail nó không corrupt
registry state.

## Nhắc về forward-secrecy

Kể cả sau một reversal `Phase1Only` sạch, các secret value đã từng
được encrypt dưới recipient set **pre-rotation** vẫn decryptable
được bởi bất kỳ ai giữ:

- một private key đã là member của recipient set pre-rotation đó, và
- bất kỳ retained clone, fork, mirror, hay backup nào của git
  history của project repo.

Reversal undo *attempt thay đổi recipient-set* đang in flight. Nó
**không** thay đổi forward-secrecy property của ciphertext quá khứ,
vì không rotation nào làm được: ciphertext pre-rotation vĩnh viễn
được retained bởi mọi party có read access tới project repo, và một
retained private key vẫn là một decryption capability valid vô thời
hạn. Xem `docs/forward-secrecy.md` cho thủ tục operator đầy đủ khi
một recipient bị nghi compromise; chạy reconcile verb này, một
mình, không phải một action incident-response.

## FAQ

**"`rotate` của tôi fail mid-flight và tôi nghĩ tôi đang ở
`Phase1Only` — tôi có thể chỉ re-run `rotate`?"** Không. Re-running
`rotate` đối với một project có pending per-file chưa clear sẽ fail
closed, vì rotation spine từ chối bắt đầu một rotation mới đối với
một project có một rotation trước đang in flight. Chạy
`byreis admin rotation reconcile` trước để clear partial state; chỉ
lúc đó re-run `rotate`.

**"Verb reconcile nói `NoPartial` nhưng `byreis doctor` report một
counter mismatch — giờ sao?"** Combination đó indicate
project-repo `HEAD` và registry ở steady state từ góc nhìn rotation
(không có rotation đang in flight) nhưng một counter drift khác có
mặt. Dùng `byreis doctor` cho diagnostic, không phải rotation
runbook; rotation reconcile path là cụ thể cho partial-rotation
recovery.

**"Tại sao verb yêu cầu một ADMIN identity cho bước classify
read-only?"** Vì bước classify cần một view registry
signature-verified, không stale, và capability đó bị gate cho ADMIN
trong mô hình mode của project. Bước classify tự nó không bao giờ
load write credential; policy gate là điểm denial rẻ nhất có thể và
chạy trước bất kỳ registry fetch nào.

**"Tôi có thể chạy `byreis admin rotation reconcile` đối với một
project arbitrary mà tôi không administer không?"** Không. Verb bị
gate cho project mà admin đang chạy là một registered admin của, và
registry trust path verify membership đó trước khi stage classify
tiến hành. Một invocation non-admin bị deny ở policy gate; một
invocation admin đối với một project không liên quan bị deny ở
registry trust.

## Đọc liên quan

- `docs/forward-secrecy.md` — `byreis rotate --remove` guarantee gì
  và không guarantee gì về ciphertext pre-rotation, và thủ tục
  remediation out-of-band khi một recipient bị compromise.
- `byreis doctor` — verb diagnostic chung; surface counter drift,
  unverified registry trust, và issue key/permission độc lập với
  rotation lifecycle.
- Audit log trên admin registry repo — canonical record của các sự
  kiện rotation, reversal, và recovery; bất kỳ manual recovery nào
  thực hiện dưới thủ tục bên trên PHẢI được reflect trong audit log.
