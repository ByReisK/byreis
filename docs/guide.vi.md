# byreis user guide

Guide này bao trùm toàn bộ feature set hiện tại của byreis v0.9.2. Nó được viết
cho cả contributor (người submit secrets nhưng không đọc được) và admin
(người giữ private key và quản lý lifecycle của secrets).

Để xem một run end-to-end thật trên GitHub thật — repo thật, PR thật, signed
commit thật — xem [walkthrough](walkthrough.md).

## Mục lục

1. [Mô hình asymmetric access](#1-mo-hinh-asymmetric-access)
2. [Install](#2-install)
3. [Khái niệm và configuration](#3-khai-niem-va-configuration)
4. [Contributor workflow](#4-contributor-workflow)
5. [Admin workflow](#5-admin-workflow)
6. [TUI tương tác](#6-tui-tuong-tac)
7. [Dùng trong CI](#7-dung-trong-ci)
8. [Audit log và verification](#8-audit-log-va-verification)
9. [Mô hình bảo mật và các giới hạn thẳng thắn](#9-mo-hinh-bao-mat-va-cac-gioi-han-thang-than)

---

## 1. Mô hình asymmetric access

Thuộc tính định danh của byreis: **contributor có thể submit secrets, nhưng
chỉ admin mới đọc được.**

Một contributor encrypt một giá trị tới các public key của admin lấy từ admin
registry và mở một pull request. Contributor không bao giờ giữ private key và
không decrypt được — kể cả giá trị họ vừa submit. Một admin review giá trị đã
decrypt và merge nó vào file secrets live.

Encryption dùng native `age` Model B. Không có shared symmetric data key; mỗi
ciphertext được addressed trực tiếp tới các public key của admin. Một
contributor không có key có thể tạo ciphertext mà chỉ người giữ key mới mở
được.

**Mức access được derive từ thực tế cryptography, không bao giờ từ config hay
flag.** byreis resolve mode của bạn lúc startup bằng cách check: có private
key không? Permission của nó có phải 0600 không? Nó có thực sự decrypt được
một project file không? Public key của nó có register trong admin registry
không? Mỗi failure đều downgrade mode về CONTRIBUTOR. Promotion lên ADMIN là
explicit, có audit, và cryptography — bạn không thể set một flag để biến
thành admin.

---

## 2. Install

### Pre-built binary (recommended)

Tải từ trang [Releases](https://github.com/ByReisK/byreis/releases). Platform
được support: **linux/amd64**, **linux/arm64**, **darwin/amd64**,
**darwin/arm64**.

```bash
# Ví dụ: Linux amd64
curl -L https://github.com/ByReisK/byreis/releases/download/v0.5.0/byreis-linux-amd64 \
  -o /usr/local/bin/byreis
chmod +x /usr/local/bin/byreis
```

### Build từ source

```bash
git clone https://github.com/ByReisK/byreis.git
cd byreis
make build    # tạo ./bin/byreis
```

Hoặc với `go install`:

```bash
go install github.com/ByReisK/byreis/cmd/byreis@latest
```

---

## 3. Khái niệm và configuration

### Hai repo

byreis hoạt động trên hai Git repository:

**Admin registry repo** (ví dụ `myorg/byreis-admins`) — source of truth cho
việc ai là admin, public key của admin, configuration per-project, và global
policy. byreis fetch read-only và cache local với signature verification. Bạn
không bao giờ write vào nó trừ qua command `admin` explicit.

**Project secrets repo** (ví dụ `myorg/myapp-secrets`) — giữ `.byreis.yaml`
(trỏ tới registry) và các file encrypted `secrets/*.enc.yaml`.

### Thư mục

| Path | Mục đích |
|---|---|
| `~/.config/byreis/` | Configuration và trust anchor (phải là 0700) |
| `~/.cache/byreis/` | Cache của registry (TTL-based; offline fallback đọc từ đây) |

### Environment variables

| Biến | Mô tả |
|---|---|
| `BYREIS_REGISTRY` | Admin registry dạng `owner/repo` |
| `BYREIS_PROJECT` | Logical project id không có dấu / (ví dụ `myapp`) |
| `BYREIS_PROJECT_REPO` | Project secrets repo dạng `owner/repo` (ví dụ `myorg/myapp-secrets`) |
| `BYREIS_KEY` | Private key material của admin (cho CI decrypt) |
| `BYREIS_KEY_FILE` | Path tới file private key của admin |
| `BYREIS_NON_INTERACTIVE` | Set `1` để suppress mọi TUI và prompt tương tác |
| `BYREIS_GITHUB_TOKEN` | GitHub token (cũng đọc từ `GH_TOKEN`) |

`BYREIS_PROJECT` và `BYREIS_PROJECT_REPO` là hai biến phân biệt với ý nghĩa
phân biệt. `BYREIS_PROJECT` là id registry-path (không có /). Một giá trị
`BYREIS_PROJECT` có chứa / gần như chắc chắn là một giá trị `owner/repo` kiểu
cũ đặt nhầm biến; `byreis doctor` sẽ warn về việc này.

### Schema file counter

Admin registry giữ một file counter cho mỗi project file, tại
`counters/<project_id>/<file>.json`. byreis write và read file này trong lúc
`merge` và `rotate`. JSON schema:

```json
{
  "project_id":            "myapp",
  "file":                  "production",
  "last_accepted_counter": 0,
  "last_pr":               "myorg/myapp-secrets#42",
  "updated_at":            "2026-01-02T15:04:05Z",
  "rotation_epoch":        0,
  "pending":               null
}
```

Các field:

| Field | Type | Mô tả |
|---|---|---|
| `project_id` | string | Logical project id không có / (match `BYREIS_PROJECT`) |
| `file` | string | Logical file name (basename không extension, ví dụ `production`) |
| `last_accepted_counter` | integer | Merge counter monotonic tăng dần; bắt đầu ở 0 |
| `last_pr` | string | `owner/repo#N` của merge PR đã accept gần nhất |
| `updated_at` | string | Timestamp RFC 3339 của merge đã accept gần nhất |
| `rotation_epoch` | integer | Rotation epoch; tăng bởi `rotate`. Vắng (hoặc `0`) trước khi có rotation nào |
| `pending` | object hoặc null | Write-ahead intent cho một merge đang in-flight; null khi không có merge đang diễn ra |

Sub-object `pending` (chỉ non-null khi có in-flight merge):

| Field | Type | Mô tả |
|---|---|---|
| `pending_counter` | integer | Counter value đang được commit (`last_accepted_counter + 1`) |
| `target_artifact_sha` | string | SHA-256 của artifact đang được merge (replay defence) |
| `target_pr` | string | `owner/repo#N` của PR đang được merge |
| `intent_at` | string | Timestamp RFC 3339 khi pending intent được write |
| `parent_commit_sha` | string | HEAD SHA của registry tại thời điểm pending intent được write (replay anchor) |

byreis dùng `DisallowUnknownFields` khi đọc file này: JSON key thừa gây hard
error. Đừng tự tay thêm field ngoài schema.

### `.byreis.yaml`

Được tạo bởi `byreis init`. Trỏ project tới registry của nó và giữ fingerprint
của pinned trust anchor. Được commit vào project secrets repo.

---

## 4. Contributor workflow

### Initialize một project

```bash
byreis init --project myapp --registry myorg/byreis-admins
```

Lần chạy đầu, byreis fetch registry, hiển thị fingerprint của registry signer,
và yêu cầu bạn confirm. Truyền `--accept-signer <fp>` để confirm
non-interactively (bắt buộc khi `BYREIS_NON_INTERACTIVE=1`).

### Submit một secret

```bash
# Single key — giá trị nhập tương tác (masked double-entry)
byreis submit --key DATABASE_URL

# Bulk — đọc mọi cặp KEY=VALUE từ một file .env
byreis submit --file .env.production

# Kèm lý do được ghi vào PR
byreis submit --key STRIPE_API_KEY --justification "production payment key rotation"

# Non-interactive (CI, value qua stdin)
echo "the-value" | byreis submit --key DATABASE_URL --non-interactive
```

`submit` encrypt (các) value tới các public key của admin, push một branch tên
`byreis/add-<key>-<timestamp>` (hoặc `byreis/replace-*` cho key đã tồn tại,
hoặc `byreis/bulk-*` cho `--file`), và mở một pull request đối với project
secrets repo.

Contributor không bao giờ giữ hay thấy plaintext sau submission. Không có
capability decrypt nào trên đường này.

### Request access (để trở thành recipient)

Nếu bạn muốn có khả năng decrypt project secrets (tức trở thành admin
recipient), mở một request-access PR đối với registry:

```bash
byreis request-access \
  --key age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --justification "team A onboarding for project foo" \
  --registry myorg/byreis-admins
```

Cái này mở một PR từ fork riêng của bạn của registry repo, đặt vào một file
`requests/<your-handle>.yaml` với public key đề xuất và justification. Một
admin review và absorb nó qua `byreis rotate --add --from-request`. Xem
`docs/request-access-runbook.md` cho thủ tục đầy đủ.

**Lưu ý:** verb này chỉ dành cho contributor. Nếu bạn đã là admin, bạn không
mở access request; bạn dùng các rotation command trực tiếp.

### Diagnostics

```bash
byreis doctor
```

Kiểm tra: permission của config directory, permission của trust anchor, mode
đã resolve của bạn (CONTRIBUTOR hay ADMIN) và lý do, connectivity và signature
validity của registry, và branch protection status (advisory). Dùng
`--rotation-history` để report rotation epoch per-file cho mọi project file.

---

## 5. Admin workflow

Mọi admin command đều yêu cầu mode ADMIN: một private key dùng được (permission
0600) mà public key của nó register trong admin registry. Mode CONTRIBUTOR bị
deny ở permission matrix trước khi có bất kỳ contact network nào.

### Review một submission

```bash
byreis review --pr myorg/myapp-secrets#42
```

Fetch và decrypt PR submission, hiển thị value của mỗi key và phân loại
add-vs-replace, và in ra một `PinnedSHA`. Truyền `PinnedSHA` cho `--expect`
khi merge.

Trên interactive terminal, `byreis review` mở TUI review queue.

### Merge một submission

```bash
byreis admin merge \
  --pr myorg/myapp-secrets#42 \
  --expect <PinnedSHA> \
  --project myapp \
  --file secrets/production.enc.yaml
```

Pin `--expect` bảo vệ khỏi việc branch bị re-push giữa review và merge; nếu
nội dung branch thay đổi sau review, pin không match và merge fail.

Một merge thành công append một signed merge event vào audit channel của
registry trong cùng signed commit như counter advance. Record audit của merge
là fail-closed: nếu write registry không complete được (ví dụ offline lúc
merge), command fail với hint retry thay vì silently drop record.

### Reject một submission hoặc access request

```bash
byreis admin request reject \
  --pr myorg/myapp-secrets#42 \
  --reason "value does not meet the key-naming policy"
```

Đóng PR và post lý do làm PR comment (ai thấy repository đều thấy). Không kèm
secrets hay chi tiết nhạy cảm trong lý do. PR đã merge thì bị từ chối. PR đã
close thì là idempotent no-op.

### Đọc secrets

```bash
# Decrypt và in một value duy nhất
byreis get --project myapp --file secrets/production.enc.yaml --key DATABASE_URL

# Decrypt và in mọi value
byreis decrypt --project myapp --file secrets/production.enc.yaml

# Giới hạn output cho key cụ thể
byreis decrypt --project myapp --file secrets/production.enc.yaml \
  --key DATABASE_URL --key STRIPE_API_KEY

# CI decrypt (headless; không assume TTY)
byreis decrypt --project myapp --file secrets/production.enc.yaml --ci --json
```

Cả `get` và `decrypt` đều chạy `VerifyOfRecord` (registry trust verification)
trước bất kỳ decrypt hay key-load nào.

### Export ra một stream env/dotenv

```bash
# Dòng export shell-sourceable (set -a; source <(byreis export ...))
byreis export --project myapp --file secrets/production.enc.yaml --format env | cat

# File .env cho godotenv / docker-compose env_file
byreis export --project myapp --file secrets/production.enc.yaml --format dotenv > app.env
```

`byreis export` là command admin-only. Giống `get` và `decrypt`, nó decrypt
file secrets bằng private key của admin, nên một contributor không có key
không chạy được — nó bị deny ở permission matrix trước bất kỳ contact network
hay key-load nào. Nó chạy `VerifyOfRecord` trước và decrypt cả file
fail-closed: nếu bất kỳ value nào không decrypt được, không có gì được emit.

`--format` chọn shape serialization:

- `env` emit một dòng `export KEY="..."` cho mỗi value, để được `source` hoặc
  `eval` bởi một shell.
- `dotenv` emit một dòng `KEY="..."` cho mỗi value, cho file `.env` được
  consume bởi godotenv, docker-compose `env_file`, và các loader quote-aware
  khác.

Mọi value luôn được double-quote và escape — bao gồm cả `$` và backtick — nên
một value round-trip chính xác và một secret value có ý đồ xấu không inject
được command khi output bị `source` hoặc `eval`. Output nhắm tới các consumer
quote-aware; `docker --env-file` thô (không xử lý quote hay escape) ngoài
scope.

Mặc định `byreis export` từ chối write plaintext ra interactive terminal, nên
file đã decrypt không vô tình landing vào scrollback. **Việc từ chối TTY này
là một speed-bump tiện lợi chống dump vô ý, không phải security boundary.**
Security boundary là private key của admin. Khoảnh khắc bạn pipe hay redirect
output — `byreis export ... | cat`, `> app.env` — plaintext là của bạn để
protect: nó giờ ở trong shell history, CI log, và một file có permission của
bạn. Đối xử với exported plaintext cẩn thận như mọi secret đã decrypt khác.

#### Tại sao không có flag `--sops`

`byreis export` không và sẽ không support output format `--sops`. byreis dùng
mô hình native age recipient (xem ADR-0001 và ADR-0003): secrets được encrypt
trực tiếp tới public key của mỗi admin, và **không có shared symmetric data
key**. Sự vắng mặt đó chính là cái làm access trở nên asymmetric — một
contributor có thể encrypt tới các admin nhưng không giữ key nào decrypt được
cái gì cả. Một export kiểu SOPS sẽ phải reintroduce một shared symmetric data
key ở phía consumer, sẽ phá vỡ guarantee asymmetric-access. Nếu bạn đang
migrate khỏi SOPS, `byreis export --format env|dotenv` là escape hatch
supported, sạch, ra plaintext.

### Chạy một command với secrets được inject

```bash
# Chạy một child process với mọi value trong file được inject vào environment của nó
byreis run --project myapp --file secrets/production.enc.yaml -- ./deploy.sh

# Bất cứ thứ gì sau `--` là child command, được exec trực tiếp (không shell)
byreis run --project myapp --file secrets/production.enc.yaml -- printenv DATABASE_URL

# Cho shell feature (pipe, `$VAR`, globbing) bạn phải tự spawn shell
byreis run --project myapp --file secrets/production.enc.yaml -- sh -c 'echo "$DATABASE_URL" | wc -c'
```

`byreis run -- <cmd>` là command admin-only; nó decrypt bằng private key của
admin, nên một contributor không có key bị deny ở permission matrix trước
bất kỳ decrypt hay child spawn nào. Giống `get`, `decrypt`, và `export`,
việc deny xảy ra trước bất kỳ contact network, identity load, hay decrypt
attempt nào. Nó chạy `VerifyOfRecord` trước và decrypt cả file fail-closed:
nếu bất kỳ value nào không decrypt được, không child nào được spawn và không
gì được chạy.

#### Inject vào environment-only, không bao giờ argv

byreis inject mọi value đã decrypt vào environment của child process only —
không bao giờ vào argv (argv của một process là world-readable qua `ps`, nên
một secret đặt ở đó sẽ leak ra mọi user trên host). Secrets không bao giờ chạm
disk qua byreis và chỉ tồn tại trong vòng đời của child; khi child exit,
byreis không giữ plaintext nào.

#### `exec`, không phải shell

byreis exec command sau `--` trực tiếp — nó KHÔNG interpret `$VAR`, chạy
shell, hay làm glob/pipe/redirect expansion. Argument vector bạn viết sau `--`
chính xác là argument vector child nhận được. Nếu bạn muốn behavior shell,
chạy `byreis run -- sh -c '...'` (mà sau đó bạn owns). Đây là một design
boundary có chủ ý: exec argv trực tiếp nghĩa là một secret value không bao
giờ bị byreis reinterpret thành shell command.

#### Behavior environment-override

Một biến do byreis inject sẽ override một biến inherited từ parent-environment
cùng tên — injected-wins. Nếu shell của bạn đã export `DATABASE_URL` và file
secrets cũng define `DATABASE_URL`, child sẽ thấy value đã decrypt từ file,
không phải value inherited.

#### Inherited stdio, không pty

byreis inherit stdin, stdout, và stderr của child trực tiếp — nó không
allocate pty và không bao giờ capture hay filter output của child. Child thấy
terminal thật, và exit code của nó (bao gồm signal termination dạng `128 +
signal`) được pass thẳng qua làm exit code của byreis.

#### Disclosure thẳng thắn về residual-exposure

`byreis run` là pattern consume security-aligned (cùng mô hình với `op run`
và `doppler run`): byreis chỉ hứa rằng bản thân byreis không leak gì và
secrets không bao giờ chạm disk qua byreis. Khi child đã giữ environment,
lời hứa đó kết thúc. byreis KHÔNG protect được những cái sau, và bạn phải
tự lo:

- **Child và mọi descendant của nó inherit environment.** Bất kỳ process
  cùng-uid nào đều đọc được một secret đã inject qua `/proc/<pid>/environ`
  trong suốt vòng đời child (hoặc descendant) còn sống.
- **Một sub-child có thể re-expose một secret qua argv của chính nó.** Nếu
  một process được start bởi child copy một secret inherited vào CHÍNH argv
  của nó, value đó trở nên readable qua `ps` — byreis chỉ control được argv
  của direct child mình spawn, không control được những gì descendant làm
  với environment inherited.
- **Một core dump của child hoặc crash reporter có thể capture environment.**
  Một child crash có thể write core dump, hoặc crash reporter có thể capture
  memory của nó, và cả hai đều có thể include secrets đã inject.
- **Một SIGKILL với chính byreis sẽ orphan child với secrets vẫn còn set.**
  Nếu process byreis bị force-kill (SIGKILL), child mà nó spawn được
  reparent (về init) và giữ secrets đã inject trong environment cho đến khi
  nó exit — byreis không forward được một signal nó không bao giờ nhận.

Nếu bất kỳ cái nào trong số đó nằm trong threat model của bạn, restrict
secret xuống child hẹp nhất có thể, disable core dump cho process đó, và đối
xử với environment đã inject như plaintext bạn giờ owns — cùng mức cẩn thận
bạn dành cho mọi secret đã decrypt khác.

### Edit một secret tại chỗ

```bash
byreis edit --project myapp --file secrets/production.enc.yaml
```

Decrypt file, mở nó trong `$EDITOR`, re-encrypt và re-sign kết quả, và write
atomic. Bất kỳ failure nào trước atomic rename đều để lại file live
byte-identical.

### Rotate recipient set

```bash
# Xem plan mà không write gì
byreis rotate --dry-run --project myapp

# Add một recipient
byreis rotate --project myapp --add age1xxxxxxxx...

# Remove một recipient (yêu cầu typed-fingerprint confirmation)
byreis rotate --project myapp --remove age1xxxxxxxx...

# Absorb một access-request PR
byreis rotate --project myapp --add --from-request myorg/byreis-admins#42

# Non-interactive (skip interactive confirm; yêu cầu --yes)
byreis rotate --project myapp --remove age1xxxxxxxx... --yes --non-interactive
```

Rotation re-encrypt mọi file secrets hiện tại tới recipient set mới trong một
strict two-phase commit. Một project không bao giờ bị bỏ dở half-rotated;
một run bị interrupt có thể được recover qua `byreis admin rotation
reconcile`. Xem `docs/rotation-runbook.md` và `docs/forward-secrecy.md` cho
thủ tục operator.

**Notice forward-secrecy:** removing một recipient re-encrypt các file hiện
tại tới set mới, nhưng không retroactively scrub được access của một
recipient đã removed tới ciphertext đã có trong git history. Các value mà
một recipient bị compromise có thể đã đọc phải được rotate out-of-band.

### Recover một rotation dở dang

```bash
byreis admin rotation reconcile --project myapp
```

Phân loại trạng thái rotation dở dang (none / Phase-1-only /
Phase-2-midflight / inconsistent) và, khi an toàn, revert side effect của
Phase-1 trong một signed registry commit duy nhất. Xem
`docs/rotation-runbook.md` cho thủ tục đầy đủ.

### Admin identity backed bằng plugin (YubiKey)

byreis support admin identity backed bằng hardware security token qua giao
thức age plugin. **Trong release này chỉ `age-plugin-yubikey` được
certified.** TPM, FIDO2, và Secure Enclave được admit theo format nhưng
không certified hay test; coi như unsupported trừ khi bạn cố ý thử nghiệm.

#### Enroll một YubiKey identity

1. Cài `age-plugin-yubikey` từ trang official release của nó trên máy admin.

2. Generate một key slot mới trên YubiKey:
   ```bash
   age-plugin-yubikey --generate
   ```
   Tool sẽ in ra một recipient string `age1yubikey1…` (public identity bạn
   register) và một identity string `AGE-PLUGIN-YUBIKEY-1…` (handle phía
   private bạn giữ).

3. Register recipient string `age1yubikey1…` vào entry admin registry của
   bạn (field `admins.yaml` cho identity của bạn — cùng field dùng cho một
   public key X25519 `age1…` thường). Commit và push thay đổi registry qua
   admin workflow thông thường.

4. Chạy `byreis doctor` để confirm registry giờ show plugin recipient và
   identity của bạn resolve về mode ADMIN với plugin key.

#### Contributor cần cài gì

Contributor submit tới một project có admin backed bằng plugin cần
`age-plugin-yubikey` trên PATH nhưng KHÔNG cần YubiKey. Binary plugin xử lý
giao thức age recipient trên máy contributor lúc encryption; hardware
YubiKey chỉ cần ở máy admin lúc decryption.

Nếu binary vắng mặt khi contributor chạy `byreis submit`, command fail ngay
với error gọi tên binary thiếu và hint install, trước khi bất kỳ secret
value nào được collect. Cài `age-plugin-yubikey` từ official repository để
xử lý.

#### Prerequisite Linux: `pcscd`

Trên Linux, `age-plugin-yubikey` yêu cầu daemon smart card `pcscd` chạy khi
YubiKey được touch lúc decryption. Start nó với:

```bash
sudo systemctl start pcscd
```

Đường contributor KHÔNG chạm YubiKey và không bị ảnh hưởng bởi `pcscd`. Chỉ
đường admin decrypt — và mode-probe startup trên máy admin configured với
plugin identity — yêu cầu `pcscd`. Nếu vắng mặt, mode-probe fail closed và
byreis downgrade về mode CONTRIBUTOR với một warning.

#### Version skew

Recipient string (chuỗi `age1yubikey1…` trong registry) không encode plugin
version. Nếu bạn re-enroll một token slot, recipient string mới khác chuỗi
cũ. Chuỗi cũ trong registry trở nên stale; update entry registry để dùng
chuỗi mới và rotate để các file hiện tại được re-encrypt tới recipient mới.
`byreis doctor` không tự detect skew này.

#### PATH trust và không verify code-signature

byreis invoke binary `age-plugin-*` từ PATH của bạn và không verify được
authenticity của chúng; một binary có ý đồ xấu nằm sớm hơn trên PATH sẽ
thấy file key — chỉ cài plugin từ nguồn trusted. Cái này áp dụng cho đường
encrypt của contributor cũng như đường decrypt của admin: một plugin độc
hại trên máy contributor có thể quan sát plaintext file key khi nó đi qua
giao thức recipient. Luôn lấy `age-plugin-yubikey` từ official repository
và verify download.

---

### List access request

```bash
byreis admin request list
```

List mọi `request-access` PR đang mở trong admin registry. Read-only.

---

## 6. TUI tương tác

Trên TTY tương tác, `byreis submit` và `byreis review` mở một TUI bubbletea
thay vì đường CLI thường.

**submit TUI:** Một form masked-entry. Contributor gõ value; nó được mask và
encrypted-to-admins mà không hiển thị dưới dạng plaintext.

**review TUI:** Mở một list browse-được các submission PR đang pending
(branch `byreis/add-*`, `byreis/replace-*`, `byreis/bulk-*`) với số PR,
key/action, author, và tuổi. Chọn một dòng và nhấn Enter để mở submission
detail và flow approve. Nhấn `a`/`s` để toggle giữa submission-PR queue và
view triage access-request. Một action reject có sẵn từ màn detail.

TUI list view không bao giờ decrypt. Decryption chỉ xảy ra khi bạn explicit
mở một submission detail.

**Suppress TUI:**

```bash
BYREIS_NON_INTERACTIVE=1 byreis submit --key MY_KEY
byreis review --pr myorg/myapp-secrets#42 --json   # --json cũng suppress TUI
```

Đường CLI thường luôn có sẵn. Sử dụng automated, headless, và CI nên set
`BYREIS_NON_INTERACTIVE=1`.

**Lưu ý platform:** TUI tương tác nhắm tới linux và darwin. Trên Windows
byreis buildable và CLI đầy đủ chạy được, nhưng TUI không phải target
Windows.

---

## 7. Dùng trong CI

### Contributor submit từ CI

CI workflow điển hình chạy không có TTY tương tác. Set
`BYREIS_NON_INTERACTIVE=1` để suppress TUI và prompt tương tác.

```bash
# Submit file .env từ CI
BYREIS_NON_INTERACTIVE=1 \
BYREIS_PROJECT=myapp \
BYREIS_PROJECT_REPO=myorg/myapp-secrets \
BYREIS_REGISTRY=myorg/byreis-admins \
BYREIS_GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }} \
  byreis submit --file .env.production
```

Không cần admin private key cho submit. CI workflow chỉ dùng một GitHub
token và public key của admin từ registry (fetch tự động).

### Admin decrypt từ CI

```bash
BYREIS_NON_INTERACTIVE=1 \
BYREIS_PROJECT=myapp \
BYREIS_PROJECT_REPO=myorg/myapp-secrets \
BYREIS_REGISTRY=myorg/byreis-admins \
BYREIS_KEY_FILE=/path/to/admin.key \
  byreis decrypt --file secrets/production.enc.yaml --ci --json
```

`BYREIS_KEY` có thể dùng thay `BYREIS_KEY_FILE` để pass thẳng key material
(hữu ích khi key được lưu dạng CI secret string).

Flag `--ci` trên `decrypt` activate entrypoint headless: không assume TTY,
secrets không được mask (theo thiết kế; đảm bảo CI log của bạn được protect
đúng mức).

---

## 8. Audit log và verification

### Xem audit log

```bash
byreis admin audit show --project myapp
```

Hiển thị audit log của registry cho project theo thứ tự thời gian. Entry
được sort theo thứ tự append. Entry có event class mà version này không
recognize được show dưới dạng warning row (forward-compatibility).

Contributor đọc được file audit thô trực tiếp qua git mà không cần chạy
byreis:

```bash
git show audit/myapp.jsonl       # trong registry repo
git verify-commit HEAD
```

### Verify audit binding (v0.5+)

```bash
byreis admin audit show --project myapp --verify
```

Flag `--verify` thực hiện một walk per-line binding đầy đủ của audit
channel: mỗi dòng JSONL trong binding era được check đối với signed commit
đã introduce nó. Các điều kiện phát hiện được:

- **Edits** tới một dòng binding-era sau khi nó đã commit.
- **Deletions** của một dòng binding-era mà git history cho thấy đáng lẽ có.
- **Reorders** của các dòng binding-era qua nhiều commit.
- **Forged inserts** — một dòng mới mà `audit_entry_sha` của nó không match
  bất kỳ commit hợp lệ nào trong chain.
- **Cross-file splices** — dòng copy từ audit channel của project này sang
  của project khác.

Command fail closed trên bất kỳ verification error nào (exit khác 0, typed
`ErrAuditLogTampered`). Mỗi commit trong walk đều được verify với pinned
trust anchor trước khi tree của nó được đọc.

Với `--verify`, cột ACTOR được derive từ identity signer anchor-attested
trong footer `byreis-signer` của signed introducing commit, không phải từ
field JSONL in-line (đó là input adversarial). Chỉ entry `verified` mới
nhận actor attribution; entry `legacy`, `missing`, và `TAMPERED` hiển thị
`-`.

### Boundary thẳng thắn của audit

Verifier audit có các residual sau, nói thẳng:

- **Sự kiện reject/decline không được cover.** Sự kiện reject là host-local
  và không được write vào audit channel của registry.
- **Dòng legacy (pre-v0.5) được phân loại `legacy`, không `verified`.**
  Chúng không thể retroactively bind.
- **Reorder hai dòng từ cùng một single commit không phát hiện được.**
  Reorder cross-commit thì phát hiện được; reorder same-commit dưới mức
  granularity per-commit.
- **Verifier chỉ mạnh bằng pinned trust anchor.** Một principal giữ trust
  anchor key có thể author commit mà verifier accept.
- **Verifier là admin-only trong v0.5.** Verification phía contributor là
  follow-up đã plan.
- **Verification fail closed dưới áp lực resource** (history adversarially
  lớn, registry không tới được, context deadline). Availability không
  guarantee với một registry thù địch.

---

## 9. Mô hình bảo mật và các giới hạn thẳng thắn

### Cái byreis protect

- Contributor không đọc được secret value — kể cả cái họ đã submit.
- Không có route trong code hay import graph từ đường contributor (encrypt)
  tới private-key hay decrypt capability.
- Đường write (submit) bị isolate khỏi file secrets live: submission là
  artifact đề xuất trong PR, không phải direct write.
- Trust anchor của admin registry và counter store cung cấp anti-rollback:
  một cache stale không thể resurrect một admin đã revoke.

### Cái byreis không protect

- Một private key của admin bị compromise. Người giữ decrypt được mọi thứ
  họ là recipient, bao gồm ciphertext lịch sử trong git.
- Trust root là một anchor key Ed25519 pinned duy nhất. Nó không phải root
  multi-party.
- GitLab không được support. Chỉ có GitHub.
- Không có `export --sops` và không có interop SOPS-symmetric. Format là
  native-`age` Model B.

### Đọc liên quan

- `docs/forward-secrecy.md` — `rotate --remove` guarantee gì và không
  guarantee gì về ciphertext pre-rotation.
- `docs/rotation-runbook.md` — recover từ một rotation dở dang.
- `docs/request-access-runbook.md` — thủ tục onboarding contributor đầy đủ.
- `SECURITY.md` — security policy của project và vulnerability reporting.
