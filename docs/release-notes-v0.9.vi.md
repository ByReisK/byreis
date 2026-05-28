# byreis v0.9 release notes

v0.9 ship admin identity backed bằng plugin. Một admin có thể register
một YubiKey identity và để contributor encrypt tới nó cùng cách họ
encrypt tới bất kỳ admin nào khác — offline, không cần token phía
contributor. Admin decrypt với token có mặt. Asymmetric-access
guarantee không thay đổi: contributor write secrets, admin read
chúng, và boundary vẫn là thực tế cryptography.

Release này admit đúng một plugin certified: **age-plugin-yubikey**.
Ba cái khác — TPM, FIDO2, và Secure Enclave — được admit theo format
(byreis sẽ không reject một recipient string `age1tpm1…` hay `age1se1…`
well-formed trong registry) nhưng KHÔNG certified hay test trong v0.9.
Đối xử với chúng như unsupported trừ khi bạn cố ý experiment.

## Có gì mới

### Admin identity backed bằng plugin

Một admin enroll một YubiKey với `age-plugin-yubikey` và register
recipient string `age1yubikey1…` kết quả trong admin registry. Từ điểm
đó trở đi, các contributor submit encrypt tới nó tự động — không cần
configuration change phía contributor.

Thay đổi phía contributor cố ý minimal: contributor submit tới một
project có admin backed bằng plugin cần `age-plugin-yubikey` trên
PATH nhưng KHÔNG cần YubiKey. Binary plugin xử lý giao thức age
recipient trên máy contributor lúc encryption; hardware YubiKey chỉ
cần ở máy admin lúc decryption.

#### Admin làm gì

1. Enroll một slot YubiKey với `age-plugin-yubikey --generate` (hay
   tương đương). Tool sẽ in một recipient string `age1yubikey1…` và
   một identity string `AGE-PLUGIN-YUBIKEY-1…`.
2. Register recipient string `age1yubikey1…` trong admin registry
   (entry `admins.yaml` cho identity của bạn, cùng field như một
   public key `age1…` thường).
3. Chạy `byreis doctor` để confirm registry giờ show plugin
   recipient và identity của bạn resolve về mode ADMIN.

Không cần re-key secrets hiện có. byreis encrypt các submission mới
tới mọi recipient admin đã register — các admin X25519 hiện có không
bị ảnh hưởng bởi một plugin recipient mới được add.

#### Contributor cài gì

Contributor submit tới một project bao gồm một plugin admin cần
`age-plugin-yubikey` trên PATH của họ. Cài nó từ trang GitHub
Releases của project. Binary là một executable standalone và không
cần YubiKey có mặt.

Nếu binary missing khi một contributor chạy `byreis submit`, command
fail với một error rõ ràng gọi tên binary thiếu và một install hint,
trước khi bất kỳ secret value nào được collect.

#### Yêu cầu Linux: `pcscd`

Trên Linux, `age-plugin-yubikey` yêu cầu `pcscd` (daemon PC/SC smart
card) chạy khi YubiKey được touch lúc decryption. Đường contributor
KHÔNG chạm YubiKey và không bị ảnh hưởng. Chỉ đường admin decrypt
(và mode-probe startup trên một máy admin configured plugin) yêu
cầu `pcscd`. Nếu nó vắng mặt, mode-probe fail closed và byreis
downgrade về mode CONTRIBUTOR với một warning; nó không hard-crash.

#### Fleet mixed

Register một plugin admin không yêu cầu remove hay re-key các admin
X25519 hiện có. Submission mới được encrypt tới mọi recipient đã
register. Một admin X25519 hiện có chưa enroll một plugin identity
vẫn decrypt được bình thường. Fleet mixed X25519 + plugin là
migration path mong đợi.

#### Residual orphaned-subprocess

byreis bound thời gian nó wait cho plugin subprocess complete một
cryptographic operation. Nếu timeout đạt tới, byreis fail operation
và return một error. Plugin subprocess cơ sở có thể tiếp tục chạy
ngắn sau timeout; đó là một best-effort reap, không phải một kill
guaranteed. Residual này inherent với giao thức age plugin và áp
dụng tương đương cho bất kỳ operation backed bằng plugin nào.

#### Security: PATH trust và không verify code-signature

byreis invoke binary `age-plugin-*` từ PATH của bạn và không verify
được authenticity của chúng; một binary có ý đồ xấu nằm sớm hơn
trên PATH thấy file key — chỉ cài plugin từ nguồn trusted. Cái này
áp dụng cho đường encrypt của contributor cũng như đường decrypt
của admin: một plugin độc hại trên máy contributor có thể quan sát
plaintext file key khi nó đi qua giao thức recipient. Luôn lấy
`age-plugin-yubikey` từ official repository và verify download.

## Cái KHÔNG có trong v0.9

Các cái sau không available trong v0.9:

- **Không có plugin certified nào khác.** Chỉ `age-plugin-yubikey`
  được certified và test. TPM, FIDO2, và Secure Enclave được admit
  theo format nhưng unsupported — đừng rely vào chúng trong
  production.
- **Không có auto-install hay managed plugin registry.** byreis
  không download hay manage binary plugin. Cài từ một nguồn trusted
  thủ công.
- **Không có TUI surface cho plugin management.** Plugin enrollment
  và registration được làm ngoài byreis với CLI `age-plugin-yubikey`
  và flow edit registry chuẩn.
- **Không có Tier-2 KMS-wrapped identity hay Tier-3
  KMS-recipient / PGP backend.** Các cái này explicitly out of
  scope.
- **Không có support GitLab.** byreis là GitHub-only trong v0.9.

### Edge case total-blockage

Nếu mọi admin trong một project có một plugin identity và một
contributor không có binary plugin tương ứng cài đặt, mọi
`byreis submit` sẽ fail với một error binary-not-found. Đây là
behavior đúng, đã document: error gọi tên binary thiếu và cung
cấp một install hint. Cài binary để unblock.

## Upgrade

Drop-in replacement cho v0.8. Không có thay đổi secrets-format,
không có thay đổi registry-schema, không có thay đổi environment
variable. Các file encrypted, registry, signed commit hiện có, và
contract `BYREIS_PROJECT` / `BYREIS_PROJECT_REPO` đều không bị ảnh
hưởng.

Admin muốn register một plugin identity add một recipient string
`age1yubikey1…` mới vào entry registry của họ. Identity hiện có
(X25519) tiếp tục hoạt động không có thay đổi. Plugin support
purely additive.
