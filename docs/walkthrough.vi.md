# Walkthrough thực tế

Trang này là một bản capture end-to-end thật của byreis chạy trên **GitHub
thật**, với binary đã release, signed commit thật, PR thật, và các artifact
thật đã được sinh ra. Đây không phải ví dụ tổng hợp. Chỗ nào một bước
thẳng thắn là *chưa* demonstrable end-to-end trên GitHub thật hôm nay, lỗ
hổng đó được nêu rõ chứ không cover up.

Mục đích là show một first deployment thật hiện tại trông ra sao — cả lõi
hoạt động (contributor encrypt tới admin mà không giữ key nào) lẫn các
cạnh thô còn lại.

> Mọi evidence dưới đây được sinh bởi `byreis` đối với các private GitHub
> repository dưới tài khoản của operator; các fingerprint, age public key,
> URL repo, và URL PR được show là giá trị thật. Giá trị token và private
> key của admin không bao giờ được show.

---

## 1. Asymmetric guarantee, trong một câu

Một **contributor** không giữ private key nào. Họ có thể `byreis submit`
một secret, mở một PR trên project repository mang ciphertext encrypt tới
public key age của mọi **admin**. Contributor không decrypt nó lại được, kể
cả trên máy họ vừa encrypt. Chỉ admin với age private key tương ứng (và,
ở chỗ cần ký, anchor signing key tương ứng) mới đọc hay rotate được
secrets.

Trang này demo thuộc tính đó bằng cách chạy cả hai role trên GitHub thật.

---

## 2. Mô hình two-repo

byreis dùng **hai repository tách biệt** để trust governance (ai là admin)
được tách cấu trúc khỏi data (encrypted secrets).

```
+------------------------------+         +-----------------------------------+
| admin registry repo          |         | project secrets repo              |
| (e.g. myorg/byreis-admins)   |         | (e.g. myorg/my-app-secrets)       |
|                              |  read   |                                   |
|  - admins.yaml  (pubkeys)    | <-----+ |  - .byreis.yaml  (registry pin)   |
|  - policy.yaml               |         |  - secrets/*.enc.yaml             |
|  - projects/<id>.yaml        |         |                                   |
|  - counters/<id>/<file>.json |         |  branches:                        |
|                              |         |    main         (signed merges)   |
|  signed commits required     |         |    byreis/add-* (submission PRs)  |
+------------------------------+         +-----------------------------------+
```

Registry repo là trust root. Theo cách nhìn của byreis nó là read-only
(thay đổi admin đi qua flow `admin` explicit). Project repo giữ encrypted
secrets và là nơi submission của contributor đáp xuống dưới dạng PR.

---

## 3. Setup admin (một lần per tổ chức)

Admin generate hai keypair local và register material public của họ trong
admin registry repository.

| Key | Mục đích | Sống ở đâu |
|-----|---------|----------------|
| `age` keypair | encrypt/decrypt secrets | file private `0600`; public vào `admins.yaml` |
| ed25519 SSH/anchor keypair | sign registry commit | private do admin giữ; public là trust anchor |

Một `admins.yaml` thật từ walkthrough này trông như:

```yaml
admins:
  - id: admin-nghiadaulau
    age_key: age1hk8c56qcys45gvp3pe8kjzx270dz9xlfxe8zvrjw9pscchqnx9wsdcec4a
    signer_key: vIoB5QtZbDAcOU5+PLPL74BJM8Sco+Yj2PreOoyzznI=
```

`age_key` là age public recipient. `signer_key` là public key ed25519 ký
registry commit (base64). Admin push file này vào registry repo trên một
signed commit để mỗi lần fetch registry sau đó đều verify được chain với
pinned anchor.

Cho walkthrough này registry repo là
`https://github.com/nghiadaulau/byreis-demo-admins-v091b` và project repo là
`https://github.com/nghiadaulau/byreis-demo-app-secrets-v091b` (cả hai
private trên GitHub thật).

---

## 4. `byreis init` — pin trust anchor

Mọi admin và mọi contributor đều chạy `byreis init` một lần per project.
Command clone registry, đọc **signer key từ signed HEAD của registry**, và
yêu cầu operator confirm fingerprint out of band trước khi pin nó vào
`trust.yaml` (trust-on-first-use).

Dạng non-interactive, capture từ run thật:

```text
$ BYREIS_NON_INTERACTIVE=1 \
  BYREIS_REGISTRY=nghiadaulau/byreis-demo-admins-v091b \
  BYREIS_PROJECT=demoapp \
  byreis init --accept-signer 4c83b37ba4d36f38d4a2c9d28f0a4d3bee120ac3b35318b9ad40260161cedfee

ok: trust anchor pinned (signer: 4c83b37ba4d36f38d4a2c9d28f0a4d3bee120ac3b35318b9ad40260161cedfee)
ok: project config written
```

Fingerprint mà `--accept-signer` nhận là SHA-256 của signing key của
registry HEAD.

> ## ⚠️ Verify fingerprint **out of band**, không phải từ cùng git history
>
> Bước TOFU chỉ mạnh bằng channel mà operator lấy fingerprint mong đợi.
> **Đừng** copy fingerprint từ `git log` của registry repo rồi feed lại
> cho `--accept-signer`; một attacker control network lúc init lần đầu có
> thể present bất kỳ HEAD nào họ muốn và fingerprint vẫn match. Lấy
> fingerprint mong đợi từ một channel khác — signed release note của
> registry maintainer, một trang static publish riêng, một cuộc gọi điện,
> hay một file out-of-band. Một khi đã pin, mỗi fetch sau đều verify
> signature của HEAD với pinned key, nên window thiết lập trust chính
> xác là call `init` lần đầu.

Dạng interactive prompt operator gõ lại fingerprint verbatim trước khi
pin — một friction có chủ ý để không thể accept theo phản xạ.

---

## 5. Contributor: `submit` keyless mở một PR thật

Contributor chạy `byreis submit` đối với project repo. Họ không giữ age
private key nào và không cần GitHub privilege nào ngoài một token có thể
mở PR.

```text
$ byreis submit DATABASE_URL --value 'postgres://demo:demo@localhost/demo'
add — PR opened: https://github.com/nghiadaulau/byreis-demo-app-secrets-v091b/pull/1
branch: byreis/add-DATABASE_URL-1779939862
```

URL đó là một PR thật trên GitHub thật. File đã submit (ciphertext đáp
xuống branch `byreis/add-*`) trông như sau — chú ý age stanza,
signed-manifest envelope, và recipient fingerprint:

```yaml
DATABASE_URL: |-
  -----BEGIN AGE ENCRYPTED FILE-----
  YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSAwSllZMDRCT0FrMnNOMEg4
  T1EzcUNkWi9xRDdRK1FobFp1ZWVBNFkxTUMwCitXNkpTTkJhbGdJaGxwWlNkNGtn
  eEl3MjJYN0F5ankrMVJ4VEJrVFlHMFUKLS0tIEM2UWd5S2lNL3N6Y0trYVZwMWIw
  VTVKN1EvYVUxd200cHBIUWhTZ2xQdjQKGnDzXIgzpZ0CffP/VfT8oHEBBqd7/a3o
  HOV8Gyrm/BmpHR+azNXdSnBD55dto1kiMYvIsk847w6GKOYi1jx2P8eNQA==
  -----END AGE ENCRYPTED FILE-----
byreis:
  format_version: byreis.native.v1
  project_id: demoapp
  file: production
  counter: 1
  recipients:
    - fp: 0241b6df33021c9dcbee0489c7ffb3e3d0b351c4c9c57c133daa78b2f795f86f
manifest_sig:
  signer: admin-nghiadaulau
  sig: 0d0e338eeaf469cedb75299701e067b5579a9b2b25902f08abfc6db83704600aac6519b510468ecd45aa288ce64f79df15a62146108b129fa9b20dd0d2a7900f
```

Contributor đã sản xuất ciphertext này chỉ dùng age recipient public của
admin (`age_key` từ `admins.yaml`). Họ chưa bao giờ giữ decrypt material
nào.

---

## 6. Chứng minh asymmetric: contributor không decrypt được

Đây là thuộc tính cả product treo lên đó. Cùng contributor, trên cùng
máy vừa produce ciphertext bên trên, yêu cầu byreis đọc nó lại:

```text
$ byreis get DATABASE_URL
error: command "get" is not permitted in CONTRIBUTOR mode: command not permitted in the current mode — this requires an admin key; see `byreis doctor` for your current mode
```

`byreis doctor` confirm mode resolution:

```text
mode: CONTRIBUTOR
reason: no admin key or key cannot decrypt — contributor mode

[OK] config-dir: …has correct permissions (0700)
[OK] trust-anchor: …has correct permissions (0600)
[OK] mode: resolved mode: CONTRIBUTOR — no admin key or key cannot decrypt — contributor mode
```

Việc deny không phải policy ở layer CLI — nó là cấu trúc. Process của
contributor không giữ `age.Identity` nào để pass cho `age.Decrypt`, và
encrypt compilation unit bị ngăn cơ học (bằng một import allowlist test)
khỏi việc bao giờ với tới đường decrypt. Thêm `--force` không có; không
có flag nào unlock cái này.

---

## 7. Admin: decrypt, export, run

Một admin, giữ age private key tương ứng permission `0600`, chạy cùng
command `get` và các read path nó implies:

```text
$ byreis get DATABASE_URL
DATABASE_URL=postgres://demo:demo@localhost/demo

$ byreis export --format env
export DATABASE_URL="postgres://demo:demo@localhost/demo"

$ byreis export --format dotenv
DATABASE_URL="postgres://demo:demo@localhost/demo"

$ byreis run -- env | grep DATABASE_URL
DATABASE_URL=postgres://demo:demo@localhost/demo
```

`run` inject environment đã decrypt vào một child process qua `Env` của
`exec.Command` (không phải shell), nên plaintext không bao giờ đáp xuống
argv, disk, hay environment của parent.

---

## 8. Audit trail

Mọi admin promotion được ghi trong audit log trên project repo. Từ run
thật:

```jsonl
{"kind":"mode.promotion","occurred_at":"2026-05-28T04:09:31Z","project_id":"demoapp","outcome":"ok","details":{"reason":"0600 key decrypts project file and public key is in a signature-verified registry","resolved_mode":"ADMIN"}}
{"kind":"mode.promotion","occurred_at":"2026-05-28T04:11:04Z","project_id":"demoapp","outcome":"ok","details":{"reason":"0600 key decrypts project file and public key is in a signature-verified registry","resolved_mode":"ADMIN"}}
…
```

Field `reason` là sự thật joined byreis đã verify nguyên văn trước khi
promote: permission của key, khả năng của key decrypt một project file
(thực tế cryptography, không phải một config flag), và sự hiện diện của
public key trong một registry **signature-verified**. Bất kỳ một trong ba
cái đó fail thì process vẫn ở mode CONTRIBUTOR.

---

## 9. Reviewer loop (review, merge, rotate)

Reviewer loop — admin chạy `byreis review` trên PR đang mở, rồi
`byreis admin merge` để fold submission vào signed file-of-record trên
`main` — bị gate bởi git access của admin tới project repo. HTTPS
authentication mà byreis dùng cho git clone, fetch, và push đi qua cùng
header byreis inject cho mọi GitHub operation đã authenticate.

Wire format của header đó **thay đổi trong v0.9.2** để fix một bug thật:
v0.9.1 emit `Authorization: Bearer <token>`, mà smart-HTTP service của
GitHub reject cho personal-access token; v0.9.2 emit
`Authorization: Basic base64("x-access-token:<token>")`, đó là form GitHub
thực sự accept.

Cái này được verify trong CI, không chỉ trong demo:

- `TestS3_GitAuthSchemeIsBasicNotBearer` (ship-gate release-blocking)
  build một subprocess `git ls-remote` thật, trỏ nó vào một
  `httptest.Server`, capture header `Authorization` mà git thực sự send,
  và assert cả scheme là `Basic` lẫn decoded payload là
  `x-access-token:<token>`.

> ### Giới hạn thẳng thắn — chưa demonstrable end-to-end từ một project mới toanh
>
> Một run hoàn chỉnh fresh-project của contributor `submit` → admin
> `review` → `merge` đối với GitHub thật hiện tại **chưa** được capture ở
> đây vì admin merge đầu tiên cần một signed file-of-record trên `main`
> đã tồn tại sẵn, và không có verb `byreis` nào hôm nay produce ra signed
> artifact initial đó trên một project chưa từng được merge. Đây là *lỗ
> hổng UX bootstrap fresh-project* đang được track cho một cycle
> follow-up. Fix auth-scheme đã từng block reviewer loop trên GitHub
> thật được prove bằng integration test bên trên; demonstration
> user-facing review→merge end-to-end trên GitHub thật sẽ landing cùng
> với fix bootstrap.

Khi một project đã qua merge đầu tiên, flow reviewer chạy như shipgate
suite prove: mode detection của admin authenticate tới private GitHub
registry, mode resolve về ADMIN, submission PR enumerate được, review
use-case validate canonical bytes, và merge use-case re-sign
file-of-record mới và push lại. Rotation (`byreis rotate`) operate trên
cùng merged state để re-encrypt tới recipient set updated.

---

## 10. Giới hạn đã biết và ghi chú operator

### 10.1 Bootstrap fresh-project

Một project mới toanh không có signed file-of-record trước đó không thể
chạy admin merge đầu tiên qua `byreis admin merge` hôm nay — merge
use-case yêu cầu một signed artifact tồn tại để chain từ đó, và
`byreis init` chỉ pin trust anchor, nó không tạo artifact initial. Đây là
một lỗ hổng UX, không phải lỗ hổng bảo mật (không thuộc tính asymmetry
nào bị vi phạm bởi sự vắng mặt — contributor vẫn encrypt được; admin
chưa merge được cho đến khi lỗ hổng được đóng). Một mini-design tập
trung cho một verb `byreis admin bootstrap` (hoặc một opt-in mode của
`init`) nằm trên roadmap.

### 10.2 `BYREIS_PROJECT_REPO` phải là một slug `owner/repo`

Dù `BYREIS_REGISTRY` accept một URL `file://` cho test, git provider của
project-repo hiện tại chỉ accept dạng slug `owner/repo` GitHub mong đợi.
Một giá trị `file://` local yield:

```text
error: project string must be owner/repo (e.g. myorg/my-secrets) — got "file:///tmp/…" — repo part must not contain '/'
```

Cái này ổn với mọi deployment GitHub thật nhưng block các demonstration
fully-offline của reviewer loop. Provider GitLab (một item roadmap riêng)
sẽ mở rộng surface này; cho đến lúc đó, mọi test reviewer-loop xảy ra
đối với GitHub thật.

### 10.3 `byreis doctor` luôn show CONTRIBUTOR cho chính nó

`doctor` nằm trong tập verb contributor-allowed, nên decrypt-probe của
chính nó cố ý bị suppress (để tránh một key-touch không cần thiết mỗi
lần bạn chạy `doctor`). Khi một key file được configure nhưng probe bị
suppress cho verb cụ thể này, `doctor` emit:

```text
[INFO] mode: probe suppressed (doctor does not require admin); to verify admin mode try a key-using command
```

Chạy bất kỳ admin verb nào (ví dụ `byreis get --json`) để thực sự
exercise đường promotion.

### 10.4 `GITHUB_TOKEN` và `GH_TOKEN` *không* được scrub bởi byreis

byreis scrub các env var secret `BYREIS_*` của chính nó (`BYREIS_KEY`,
`BYREIS_KEY_FILE`, `BYREIS_SIGN_KEY`, `BYREIS_SIGN_KEY_FILE`,
`BYREIS_GITHUB_TOKEN`) khỏi environment của process sau khi đọc chúng,
nên bất kỳ age plugin subprocess nào byreis spawn inherit một
environment không còn các value đó. Các biến convention non-byreis
`GITHUB_TOKEN` và `GH_TOKEN` cố ý **không** bị chạm — chúng thuộc về
shell environment rộng hơn của operator. Operator high-security coi
chúng là nhạy cảm nên scope hoặc unset out of band trên máy chạy age
plugin từ third party.

### 10.5 Plugin recipient (`age-plugin-yubikey` và bạn bè) — cái gì hoạt động hôm nay

Admin identity backed bằng age-plugin-yubikey ship từ v0.9.0 và được
prove end-to-end qua asymmetric ship-gate (`TestAsymmetryShipGate_Plugin*`):
một contributor với binary plugin trên PATH có thể encrypt offline tới
một admin recipient backed bằng YubiKey, admin đó decrypt được với token
của mình, và mode detection promote đúng khi token có mặt. Plugin
`age-plugin-tpm`, `age-plugin-fido2-hmac`, và `age-plugin-se` được
format-admit nhưng **không certified** trong release này; bytes của
chúng được registry validator accept nhưng UX của chúng chưa được test.

> ## ⚠️ Trust plugin binary
>
> byreis invoke binary `age-plugin-*` từ PATH của bạn và không verify
> được authenticity của chúng. Một binary có ý đồ xấu nằm sớm hơn trên
> PATH thấy file key lúc encrypt và secret material lúc decrypt. Cái
> này áp dụng cho cả đường encrypt của contributor lẫn đường decrypt
> của admin. Cài plugin chỉ từ nguồn trusted và cân nhắc pin vị trí của
> chúng. Trên Linux, `age-plugin-yubikey` yêu cầu `pcscd` chạy để
> YubiKey addressable được lúc decrypt; đường encrypt của contributor
> không chạm YubiKey và không bị ảnh hưởng bởi `pcscd`.

---

## 11. Evidence

Mọi transcript, file `admins.yaml` đã capture, file
`production.enc.yaml` encrypted, và `audit.log` show ở trên sống trong
`design/v09_demo_evidence/` (git-ignored trên source tree byreis vì nó
chứa test artifact operator-specific). Các demo repository thật bản
thân vẫn nằm trên GitHub ở:

- Registry: <https://github.com/nghiadaulau/byreis-demo-admins-v091b>
- Project: <https://github.com/nghiadaulau/byreis-demo-app-secrets-v091b>
- Submission PR đang mở: <https://github.com/nghiadaulau/byreis-demo-app-secrets-v091b/pull/1>

Vào xem các signed commit thật, file ciphertext thật, và PR contributor
thật; không có gì ở đây là mock.
