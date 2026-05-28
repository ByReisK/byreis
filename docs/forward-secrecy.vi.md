# Forward secrecy: byreis rotation làm gì, và không làm được gì

Runbook này giải thích, theo cách operator-facing, vì sao **byreis
rotation không cung cấp forward secrecy trên git history**, và một
operator phải làm gì khi key material của một recipient bị nghi
compromise. Warning emit bởi `byreis rotate --remove` và
`byreis doctor --rotation-history` trỏ về đây cho thủ tục runbook;
file này là canonical reference duy nhất.

Đọc end-to-end trước khi thực hiện một incident-response rotation.
Operational guidance trong section "Bạn PHẢI làm gì" là phần
load-bearing: chỉ chạy `byreis rotate --remove` **không** đủ
remediation tự nó.

## TL;DR

- `byreis rotate --remove <recipient>` re-encrypt mọi file secrets
  **hiện tại** tới recipient set mới sao cho, *từ đây trở đi*, party
  đã removed không decrypt được các commit mới nữa.
- Nó **không** delete, rewrite, hay expunge **ciphertext pre-rotation**
  đã tồn tại trong các commit quá khứ của project repository.
- Một party retain cả (a) private key của họ và (b) bất kỳ clone,
  fork, mirror, hay backup nào của project repository vẫn decrypt
  được mọi file secrets đã committed trước rotation.
- Do đó, khi một recipient bị compromise, **các value bên trong
  secrets** (password, token, API key, certificate) phải được rotate
  **out-of-band**, ở upstream system đã issue chúng, ngoài việc chạy
  `byreis rotate --remove`.

## Tại sao byreis không cung cấp forward secrecy ở đây

byreis xây trên hai thuộc tính nền mà giữa chúng làm forward
secrecy git-history về cấu trúc không deliver được ở tool layer:

### 1. Primitive cryptography age Model B

byreis encrypt secrets ở format native `age` Model B. Trong mô hình
này, mỗi recipient giữ một `age` identity long-lived (một private
key) tương ứng với một public recipient string. Ciphertext được
address tới một **set recipient** ở thời điểm encryption, và bất kỳ
recipient nào giữ identity match đều có thể decrypt ciphertext đó
**ở bất kỳ điểm tương lai nào**.

Không có bước key-erasure nào ở layer `age`: cryptographic primitive
tự nó không có khái niệm "ciphertext quá khứ này không decrypt được
nữa vì identity đã retired". Một identity retained vẫn là một
decryption capability valid cho bất kỳ ciphertext nào từng được
address tới recipient string của nó, vô thời hạn. Đây là chủ ý
trong thiết kế `age` (nó là một envelope encryption scheme, không
phải session protocol forward-secret), và nó là thiết kế đúng cho
use case byreis solve — nhưng nó nghĩa là key compromise là
**retroactive** đối với mọi ciphertext mà compromised identity từng
là recipient.

### 2. Git history append-only

Project repository nơi byreis lưu encrypted secrets, theo cấu trúc,
là một git repository — và git history là append-only. Mọi commit
đã từng push vào một clone, fork, hay mirror vẫn accessible với bất
kỳ ai có read access tới history đó. Không có cơ chế in-band nào
trong git để byreis retroactively remove một blob quá khứ khỏi mọi
bản copy hiện có của repository: kể cả một forced history rewrite
trên origin (`git filter-repo` / một force-push) không reach tới
các clone, fork, mirror, CI cache, build artifact, hay developer
laptop đã pull các commit ảnh hưởng. Một khi một ciphertext blob
đã push, một operator phải assume nó vĩnh viễn được retained bởi
mọi party có read access tới project repository.

### Combination

Đặt cùng nhau: một party đã từng có read access tới project repo
và retain `age` identity private vẫn có thể, ở bất kỳ điểm tương
lai nào, clone hay check out một commit pre-rotation, chạy `age`
đối với bất kỳ `secrets/*.enc.yaml` pre-rotation nào, và recover
mọi plaintext value đã committed dưới recipient set của họ. byreis
rotation không thể prevent điều này — và không có tool honest nào
ở layer này có thể claim được.

byreis không cung cấp forward secrecy trên git history. Bất kỳ
documentation, marketing, hay operator-facing message nào suggest
ngược lại sẽ là một lie of commission, và stance của project là
một lie như vậy là worse operational hơn nhiều so với chính
limitation đó.

## `byreis rotate --remove` thực sự làm gì

Khi bạn chạy `byreis rotate --remove <recipient>`, byreis:

1. Tính một recipient set mới R' bằng cách remove recipient được
   nêu tên khỏi recipient set hiện tại R.
2. Decrypt mọi file `secrets/*.enc.yaml` hiện tại dưới tree
   `secrets/` của project dùng identity của admin đang chạy.
3. Re-encrypt mọi file dưới recipient set R' và write ciphertext
   mới về disk.
4. Advance manifest counter, refresh manifest signature, và push
   rotation như một signed commit duy nhất trên project repo
   (paired với một signed bump trên admin registry repo).
5. Emit một audit log entry ghi rotation event, bao gồm (các)
   recipient đã removed.

Sau step 5, **HEAD hiện tại** của project repo không còn chứa
ciphertext address tới recipient đã removed. Từ commit tiếp theo
trở đi, recipient đó không decrypt được các đóng góp hay edit mới.

Cái rotation **không** làm, theo thiết kế:

- Nó không rewrite history. Các commit quá khứ vẫn chứa ciphertext
  pre-rotation address tới recipient set pre-rotation.
- Nó không invalidate private key của recipient đã removed.
  Identity đó vẫn là một `age` identity valid; chỉ membership của
  nó trong recipient set hiện tại thay đổi.
- Nó không reach vào clone, fork, mirror, CI runner, developer
  laptop, hay backup snapshot. Mọi bản copy của project repo
  retain ngoài origin do byreis administer vẫn fully decryptable
  bởi party có identity retain.
- Nó không rotate **value** bên trong secrets. Password, token,
  và key giữ bên trong YAML giữ nguyên. Bước đó là việc của bạn,
  thực hiện out-of-band đối với system đã issue các value đó.

## Bạn PHẢI làm gì khi một recipient bị compromise

Nếu recipient bị removed là một departure routine (ai đó rời org
on good terms, không nghi key exfiltration), thì chạy
`byreis rotate --remove` và refresh recipient set là lifecycle
action mong đợi và không cần bước nào thêm.

Nếu recipient bị removed là một **party bị compromise** — một key
leak, một insider threat nghi ngờ, một device bị đánh cắp, hay một
service account bị breach — thì rotation một mình không phải
remediation. Bạn PHẢI cũng:

1. **Đối xử với mọi secret value đã từng được encrypt dưới
   recipient set pre-rotation như đã compromise.** Inventory mọi
   file `secrets/*.enc.yaml` mà recipient compromise từng là một
   recipient của, qua git history đầy đủ của project repo (không
   chỉ HEAD hiện tại).

2. **Rotate các value cơ sở out-of-band, ở system issue.** Cho
   mỗi secret ảnh hưởng:
   - Nếu nó là một database password, rotate nó ở database engine.
   - Nếu nó là một API token, revoke và re-issue nó ở upstream
     provider (cloud console, GitHub PAT settings, v.v.).
   - Nếu nó là một private TLS hay signing key, revoke
     certificate của nó ở nơi áp dụng, generate một key fresh, và
     re-issue certificate.
   - Nếu nó là một OAuth client secret, rotate nó ở console của
     OAuth provider.
   - Nếu nó là một service-account key, rotate nó ở layer cloud
     IAM.

   Trong mọi case bước operative là **ở upstream system**, không
   phải trong file secrets. Edit YAML một mình không invalidate
   value compromise ở system accept nó.

3. **Commit các value mới vào byreis** theo cách bình thường: một
   contributor `byreis submit` (hoặc một admin edit trực tiếp, tùy
   workflow) cho mỗi file ảnh hưởng. Các value mới sẽ được encrypt
   dưới recipient set **post-rotation** R', không include party
   compromise.

4. **Audit downstream usage.** Bất cứ thứ gì từng consume các
   value compromise từ byreis — CI pipeline, service deployed,
   developer workstation — phải được redeploy hay restart để pick
   up value mới. Cho đến khi điều đó xảy ra, value compromise vẫn
   live trong các system đó dù byreis không còn hand it out.

5. **Record incident.** byreis audit log sẽ capture event
   `rotate --remove` với recipient set đã removed; các out-of-band
   value rotation nên được ghi trong incident-response log của tổ
   chức bạn để chain remediation đầy đủ trace được.

## FAQ

**"Một force-push trên project repo có remove các commit
pre-rotation không?"** Không, theo nghĩa có ý nghĩa. Một force-push
có thể rewrite history của origin, nhưng nó không reach vào các
clone, fork, mirror, build artifact, hay backup hiện có. Đối xử
với mọi party đã từng có clone access như vẫn giữ history
pre-rotation.

**"Tôi có thể chỉ delete các file `secrets/*.enc.yaml` ảnh hưởng
và bắt đầu lại không?"** Deletion là một future-only operation,
identical về effect với remove một recipient. Các historical blob
vẫn reachable qua bất kỳ commit nào chứa chúng. Out-of-band value
rotation là remediation duy nhất sever được link tới upstream
system.

**"Đây có phải một weakness của `age` không?"** Không. `age`
(Model B) đang làm chính xác cái nó document: long-lived envelope
encryption tới một recipient set. Việc thiếu git-history forward
secrecy là một thuộc tính của việc layer `age` trên một history
append-only, không phải defect trong `age`. Các scheme **có** cung
cấp forward secrecy (ví dụ session-keyed exchange với key-erasure
ratchet) không phù hợp với vấn đề GitOps secrets byreis solve, vì
chúng remove thuộc tính operator thực sự muốn: rằng bất kỳ admin
hiện tại nào cũng decrypt được bất kỳ file secrets hiện tại nào
ở bất kỳ điểm tương lai nào.

**"Tại sao byreis surface một warning nếu không có gì nó làm
được?"** Vì operational gap giữa "tôi đã remove một recipient" và
"party compromise không còn reach được data" là mistake
incident-response thường gặp nhất ở layer này. Warning là tín
hiệu honest rằng chạy command byreis là bắt đầu remediation,
không phải kết thúc nó.

## Onboarding recipient qua `request-access`

Đường bổ trợ "add một recipient" dùng contributor verb
`byreis request-access` để mở một PR đối với registry repo với
pubkey đề xuất, và admin verb
`byreis rotate --add --from-request <PR>` để absorb key đề xuất
vào một rotation sau một typed-fingerprint confirm. Flow onboarding
không chạm thuộc tính forward-secrecy của ciphertext quá khứ (nó
là một additive `--add`), nhưng một single rotation invocation
MAY combine `--add --from-request` với `--remove <old>` để
onboard một replacement key trong một transaction — trong case
đó forward-secrecy warning bên trên áp dụng cho recipient đã
removed như với một `--remove` standalone. Xem
`docs/request-access-runbook.md` cho thủ tục contributor và admin,
state-machine matrix, và public-registry disclosure surface.

## Đọc liên quan

- `byreis doctor --rotation-history` show lịch sử audit-log của
  các rotation quá khứ trên project hiện tại, bao gồm recipient
  nào đã removed ở mỗi rotation.
- `docs/request-access-runbook.md` — mở, review, và absorb các
  contributor request-access PR. Đường onboarding bổ trợ cho thủ
  tục removal của runbook này.
- Format native `age` byreis dùng cho ciphertext là upstream `age`
  Model B; project's design rationale chọn Model B được ghi trong
  public design note và ADR.
