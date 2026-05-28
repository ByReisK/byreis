# Request-access runbook: mở, review, và absorb access-request PR

Runbook này là thủ tục operator-facing cho verb contributor
`byreis request-access` và verb admin
`byreis rotate --add --from-request <PR>`. Cùng nhau chúng tạo thành
đường promotion in-band: một contributor đề xuất rằng age public key
của họ được add vào recipient set của một project; một admin review
đề xuất đó như một pull request đối với registry repo, rồi absorb
key đề xuất vào recipient set qua một rotation thường.

Hai verb giữ nguyên asymmetric-access invariant: contributor dùng
GitHub identity của chính mình và không acquire admin credential hay
registry-write key nào ở bất kỳ bước nào; admin dùng admin identity
keychain-backed sẵn có và không bao giờ re-derive một contributor
signing capability. Rotation absorb request là một
`rotate --add` thường với provenance của PR được ghi vào audit log.

Đọc end-to-end trước khi mở hay absorb một request-access PR.
State-machine matrix và bảng exit-code trong document này là
canonical reference cho quyết định accept/refuse của verb.

## TL;DR

- **Phía contributor**: `byreis request-access --key <age1...>
  --justification "..." --registry <owner/repo>` mở một PR đối với
  registry repo. PR add một single file ở
  `requests/<your-handle>.yaml` chứa pubkey đề xuất, GitHub login của
  bạn, và một justification free-text. PR mở từ fork riêng của bạn
  dùng GitHub identity của chính bạn; không có admin credential hay
  registry-write key nào được acquire.
- **Phía admin**: `byreis rotate --add --from-request <registry>#<number>
  --project <id>` fetch YAML của PR, chạy state-machine validation
  9-mode, in admin warning giải thích semantic byte-compare
  PR-author-vs-YAML, rồi fire confirm gate typed-fingerprint trước
  khi absorb pubkey đề xuất vào một rotation.
- **Quota**: tối đa 5 `request-access` PR đang mở per contributor
  identity per registry. Close các PR cũ trước khi mở mới.
- **Caveat registry public**: nếu registry repo là public, linkage
  `handle -> age_pubkey` đọc được public. Xem "Public-registry-repo
  disclosure surface" bên dưới.

## Thủ tục contributor

### Prerequisite

- Một GitHub identity với `read` access tới registry repo (shape
  chuẩn; registry adopter MAY configure access rộng hơn, xem section
  "Adopter configuration" bên dưới).
- Một personal fork của registry repo. Nếu bạn không có, tạo nó với
  `gh repo fork <registry>` trước khi chạy verb. Fork là
  source-of-record cho HEAD của PR; same-repo PR từ một contributor
  có registry-write access là một concern adopter-configuration (xem
  "Same-repo PR adopter footgun" bên dưới).
- Một `age` keypair. Verb chỉ lấy public key (`age1...`); private
  key không bao giờ rời máy bạn và không bao giờ được gửi tới
  registry.
- Một GitHub token trong `BYREIS_GITHUB_TOKEN` hay `GH_TOKEN`. Verb
  dùng cùng nguồn authentication như `byreis submit`; không cần
  keychain credential mới, và không có admin hay registry-write
  capability nào được acquire.

### Mở một request

Chạy, từ bất kỳ directory nào:

```
byreis request-access \
  --key age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --justification "team A onboarding for project foo" \
  --registry myorg/byreis-admins
```

Verb:

1. Từ chối nếu mode hiện tại của bạn là ADMIN hay SUPER (verb là
   contributor-only; admin không cần mở access request).
2. Đọc GitHub login của bạn từ token-bearer identity (hoặc accept
   một override `--handle <login>` explicit nếu bạn cần
   disambiguate).
3. Check quota open-PR đối với registry; từ chối với
   `ErrRequestAccessQuotaExceeded` nếu bạn đã có 5 hay nhiều hơn
   `request-access` PR đang mở.
4. Build một file `requests/<your-handle>.yaml` duy nhất với
   pubkey, handle, justification, và một timestamp RFC3339; verify
   YAML parse qua schema strict-decoder trước khi push bất cứ gì.
5. Tạo một branch tên
   `byreis/request-access-<handle>-<unix-time>` trên fork của bạn,
   commit file YAML với một commit message fixed-template (không có
   body operator-controlled), và mở một PR đối với default branch
   của registry.

Verb in URL PR khi thành công. Bước tiếp theo là admin review.

### Cái admin sẽ thấy và làm

Admin chạy `byreis rotate --add --from-request <registry>#<number>
--project <id>` đối với cùng project họ rotate bình thường. Tool
của admin fetch YAML của bạn ở PR HEAD, thực hiện state-machine
validation mô tả bên dưới, hiển thị admin warning giải thích semantic
byte-compare, rồi yêu cầu admin gõ đầy đủ 64-character SHA-256
fingerprint của pubkey đề xuất của bạn để confirm.

Nếu validation từ chối, admin thấy một sentinel error với hint trỏ
về action bạn cần thực hiện (ví dụ "close PR và reopen với một
commit set sạch", "regenerate qua `byreis request-access`"). Admin
KHÔNG cần merge registry PR trước khi chạy rotation; rotation commit
LÀ endorsement, và rotation audit row ghi URL PR, PR HEAD SHA, và
GitHub login đã validate của bạn làm bằng chứng provenance.

Nếu validation thành công và admin hoàn tất fingerprint confirmation,
pubkey của bạn được add vào recipient set của project trong một
single rotation transaction. Từ rotation tiếp theo trở đi, bạn
decrypt được secrets của project (subject to admin read-path
discipline thường của project).

### Update hay rotate pubkey của chính mình

Runbook bên trên cũng là thủ tục để replace pubkey của chính mình:
mở một `request-access` PR mới với pubkey mới; admin absorb nó qua
`rotate --add --from-request`, rồi độc lập remove key cũ qua
`rotate --remove <old-age1-key>` (fire forward-secrecy warning).
Combine hai intent vào một transaction duy nhất cũng được support
qua `rotate --replace <old>=<new>` sau khi key mới đã ở trong
recipient set.

## Thủ tục admin

### Prerequisite

- Mode ADMIN resolve cryptographically bởi `byreis` startup (admin
  private key có mặt, perm 0600, registered trong admin set). Verb
  bị denied-by-policy cho CONTRIBUTOR trước bất kỳ registry fetch
  nào.
- `BYREIS_GITHUB_TOKEN` (hay `GH_TOKEN`) với read access tới list
  PR của registry repo. Verb đọc thuần; không có write capability
  nào đối với registry repo được acquire qua verb này.
- Một flag `--project` identify project nào để rotate. Absorb một
  request-access PR đối với project A không thay đổi recipient set
  của project B; rotation là per-project.

### Chạy absorption

```
byreis rotate --add --from-request myorg/byreis-admins#42 \
  --project my-project-id
```

Verb:

1. Mode-gate trước: CONTRIBUTOR bị deny không có contact network.
2. Parse PR ref thành dạng `<owner>/<repo>#<number>`; reject value
   malformed.
3. Fetch PR HEAD SHA và nội dung `requests/<handle>.yaml` ở SHA đó
   qua một GitHub call read-only. HEAD SHA được pin cho re-check
   force-push-race ở step 5.
4. Chạy state-machine validation mô tả ở
   [State-machine matrix](#state-machine-matrix) bên dưới. Một
   refusal trả về sentinel match với hint actionable và exit không
   có Phase-1 work nào.
5. In block verbatim `RequestAccessAdminWarning` (xem
   [Admin warning](#admin-warning) bên dưới).
6. Hiển thị confirm prompt show PR author login, YAML handle,
   justification đã sanitize, và 16 ký tự đầu của SHA-256
   fingerprint của pubkey đề xuất. Admin phải gõ đầy đủ 64-char
   fingerprint để proceed; mismatch refuse với
   `ErrRotationFingerprintMismatch`.
7. Re-fetch PR HEAD SHA và assert byte-equal với value đã pin. Một
   drift nghĩa contributor đã push giữa plan và execute; verb từ
   chối với `ErrRequestAccessPRForcePushed`. Re-run để re-fetch và
   re-review content mới.
8. Tiến vào pipeline `rotate --add` Phase-1 / Phase-2 thường với
   pubkey đã validated inject vào add list. Rotation audit event
   ghi URL PR, PR HEAD SHA, YAML handle đã validated, và PR author
   login đã validated làm bằng chứng provenance.

### Admin warning

Verb in block này verbatim trước fingerprint-confirm prompt. Wording
chính xác là source of truth duy nhất trong code đã ship; runbook
này reproduce nó cho operator reference, nhưng emission live là
copy authoritative:

```
WARNING: this rotation absorbs a recipient pubkey from a contributor's
request-access PR. Before confirming:

  - The YAML's github_handle field is byte-compared to the PR opener's
    GitHub login (`pull_request.user.login`). It is NOT compared to
    the PR title, body, description, comments, or any commit-author email.
  - Visually verify the PR opener IS the human you intend to grant access
    to (run `gh pr view <PR>` to confirm the GitHub account is the
    intended contributor). A login byte-match alone is not a substitute
    for that visual check.
  - Commit-author divergence (a PR whose commits are authored by a
    different identity than the PR opener) AND force-push races between
    plan and execute are caught structurally, but the typed-fingerprint
    confirm below is your last line of defense — inspect the SHA-256
    fingerprint of the recipient and type the full 64-char value to
    proceed. Mismatch refuses the rotation.
```

### Cái tool catch cấu trúc vs cái bạn phải verify thủ công

Catch cấu trúc (bạn tin cậy được không cần inspect):

- PR closed, draft, merged, hay bot-authored bị refuse trước
  validation.
- YAML `github_handle` không match `pull_request.user.login`
  byte-equal (post-lowercase) bị refuse với
  `ErrRequestAccessIdentityMismatch`.
- Bất kỳ commit nào trên PR có author login diverges khỏi PR opener
  bị refuse với `ErrRequestAccessCommitAuthorDivergence`.
- Force-push giữa fetch và confirm (một content swap trên PR head
  branch) bị catch bởi HEAD SHA pin: SHA captured ở plan time được
  re-asserted byte-equal ở execute time, và bất kỳ drift nào bị
  refuse với `ErrRequestAccessPRForcePushed`.
- Fork-ownership transfer giữa fetch và confirm (một source swap,
  ở đó PR head branch trỏ tới cùng SHA nhưng fork repository đã đổi
  chủ) bị catch bởi một re-assertion byte-equal riêng của
  `pull_request.head.repo.owner.login` ở execute time; bất kỳ drift
  nào bị refuse với `ErrRequestAccessForkOwnershipChanged`. SHA pin
  một mình không đủ cho case này vì một fork đã transfer có thể
  retain content giống y; nên fork-owner login được check độc lập.
- YAML schema violation, field unknown, handle non-ASCII,
  justification trên 1000 byte, và pubkey `age1` malformed tất cả
  bị refuse ở decode time với `ErrRequestAccessSchemaInvalid`.
- File-set change ngoài `requests/<handle>.yaml` bị refuse với
  `ErrRequestAccessPRFilePathInvalid`.

Bạn PHẢI verify thủ công trước khi gõ fingerprint:

- Visually confirm PR opener (`gh pr view <PR>`) là con người bạn
  intend grant access cho. Các check cấu trúc prove rằng
  `pull_request.user.login` match YAML handle byte-for-byte, nhưng
  chúng không prove rằng GitHub account này thuộc về người bạn
  nghĩ.
- Confirm project ID trên flag `--project` của bạn là project bạn
  intend rotate. PR là project-agnostic; rotation là per-project.
- Confirm pubkey đề xuất là một cái contributor thực sự control
  (out-of-band: trao đổi fingerprint qua một side-channel trước
  khi họ mở PR là một pattern thường gặp ở quy mô).

## State-machine matrix

Bước validation accept đúng một PR shape và refuse mọi cái khác.
Matrix bên dưới là canonical reference; behavior live được assert
bởi test table-driven `request_test.go` row-by-row.

```yaml
# PR-state acceptance matrix cho `byreis rotate --add --from-request <PR>`
# Source-of-truth GitHub API fields:
#   pull_request.state                  ∈ {"open", "closed"}
#   pull_request.draft                  bool
#   pull_request.merged                 bool
#   pull_request.user.login             string (phải bằng yaml.github_handle byte-equal post-lowercase)
#   pull_request.head.sha               string (pin ở fetch-time, re-assert ở execute-time)
#   pull_request.head.repo.owner.login  string (pin cho fork-ownership-change detection)

accepted:
  - {state: open, draft: false, merged: false, user.login: <non-empty, non-"ghost">}

refused_with_sentinel:
  - condition: {state: closed, merged: true}
    sentinel: ErrRequestAccessPRStateInvalid
    hint: "this PR has already been merged; if you intend to re-rotate the same recipient, run rotate --add directly"
  - condition: {state: closed, merged: false}
    sentinel: ErrRequestAccessPRStateInvalid
    hint: "this PR has been closed; the contributor must reopen or open a new request-access PR"
  - condition: {state: open, draft: true}
    sentinel: ErrRequestAccessPRStateInvalid
    hint: "this PR is a draft; the contributor must mark it ready-for-review before admin absorption"
  - condition: {user.login: "ghost" OR ""}
    sentinel: ErrRequestAccessIdentityMismatch
    hint: "the PR author's GitHub account is deleted or anonymous; refuse the request"
  - condition: {yaml.github_handle != user.login (post-lowercase, post-ASCII-validation)}
    sentinel: ErrRequestAccessIdentityMismatch
    hint: "the YAML github_handle does not match the PR author's GitHub login"
  - condition: {any commit author.login != user.login}
    sentinel: ErrRequestAccessCommitAuthorDivergence
    hint: "the PR contains commits whose author differs from the PR opener; the contributor must close and reopen with a clean commit set"
  - condition: {head.sha at execute != head.sha at fetch}
    sentinel: ErrRequestAccessPRForcePushed
    hint: "the PR was force-pushed between plan and execute; re-run `byreis rotate --add --from-request <PR>` to re-fetch and review the new content"
  - condition: {head.repo.owner.login at execute != head.repo.owner.login at fetch}
    sentinel: ErrRequestAccessForkOwnershipChanged
    hint: "the contributor's fork ownership changed between plan and execute; re-run to re-evaluate"
  - condition: {files-changed contains anything outside requests/<handle>.yaml}
    sentinel: ErrRequestAccessPRFilePathInvalid
    hint: "the PR changes files outside the requests/ namespace; refuse"
  - condition: {YAML strict-decode fails (unknown field, duplicate key, malformed)}
    sentinel: ErrRequestAccessSchemaInvalid
    hint: "the YAML payload does not match the schema; the contributor must regenerate via `byreis request-access`"
  - condition: {YAML justification > 1000 bytes}
    sentinel: ErrRequestAccessSchemaInvalid
    hint: "justification exceeds 1000 bytes; the contributor must shorten and regenerate"
  - condition: {YAML github_handle contains non-ASCII or invalid GitHub login chars}
    sentinel: ErrRequestAccessSchemaInvalid
    hint: "github_handle must be ASCII-only and conform to GitHub's login alphabet ([A-Za-z0-9-]{1,39})"

advisory_only (NOT refused, log như warning):
  - condition: {PR has been closed-then-reopened}
    action: log warning, proceed nếu mọi state check khác pass
    hint: "visually verify the reopen reason via `gh pr view`"
```

## Exit code

Verb contributor (`byreis request-access`) và đường admin
(`byreis rotate --add --from-request`) share exit class chuẩn của
project:

- `ok` (`0`) — verb hoàn thành; PR opened (contributor) hay
  rotation absorbed (admin).
- `permission-denied` (`3`) — caller không ở mode required. Verb
  contributor deny ADMIN/SUPER; đường admin deny CONTRIBUTOR.
- `auth-error` (`4`) — GitHub token missing hay invalid; đường
  admin cũng surface cái này khi keychain identity của admin không
  load được hoặc admin nằm ngoài recipient set pre-rotation của
  project (một admin khác trong pre-rotation set phải chạy
  rotation).
- `counter-reconcile` (`6`) — đường admin quan sát một partial
  rotation state và từ chối start một rotation mới đối với nó.
  Chạy `byreis admin rotation reconcile` đối với project để
  recover; rồi re-run absorption.
- `trust-error` (`7`) — registry view stale hay unverified; refresh
  với `byreis registry refresh` và retry. Cũng surface trên rotation
  reversal probe defect (re-run `byreis admin rotation reconcile`).
- `decode-malformed` (`9`) — YAML payload fail schema strict-decode
  trên đường admin. Contributor phải regenerate qua
  `byreis request-access`.
- `general-error` (`1`) — mọi cái khác, bao gồm
  `ErrRequestAccessPRStateInvalid`, `ErrRequestAccessPRForcePushed`,
  `ErrRequestAccessForkOwnershipChanged`,
  `ErrRequestAccessQuotaExceeded`, và
  `ErrRotationFingerprintMismatch`. Mỗi cái đến với một hint
  actionable; hint identify bước operator tiếp theo.

## Public-registry-repo disclosure surface

Một số adopter configure admin registry repo như một public GitHub
repository (ví dụ để dùng GitHub Pages hoặc làm admin set visible
với external auditor). Cho những adopter đó, namespace `requests/`
cũng đọc được public: mỗi file `requests/<handle>.yaml` (bao gồm
GitHub handle của contributor và age public key) visible với bất
kỳ ai có browser.

Age public key bản thân theo cấu trúc là một public key; cryptographic
guarantee của `age` Model B không bị yếu đi bởi publication. Tuy
nhiên, **linkage** `<github-handle> -> <age public key>` trở thành
một fact public. Cho adopter coi recipient set của mình là
semi-confidential (ví dụ tổ chức không publicly disclose engineer
nào có access tới production), linkage này là một information
disclosure.

Nếu adopter của bạn ở category đó, guidance vận hành là:

- Configure registry repo như một PRIVATE GitHub repository. Verb
  hoạt động giống y đối với private registry; khác biệt duy nhất là
  ai browse được file của repo.
- Đối xử với access list của registry repo như một phần của
  asymmetric-access invariant: bất kỳ ai có thể đọc registry đều
  có thể đọc linkage pubkey-to-handle của mọi contributor và pubkey
  của mọi admin.
- Tool byreis không từ chối operate đối với một public registry;
  lựa chọn public-vs-private là của adopter, và tool surface notice
  này đúng một lần, ở đây trong runbook, thay vì một warning CLI lặp
  lại.

Nếu bạn không chắc về visibility của registry, chạy
`gh repo view <registry> --json visibility` trước khi mở một
`request-access` PR.

## Adopter configuration

### Same-repo PR adopter footgun

Flow request-access canonical assume contributor mở PR từ một fork
của registry repo. PR khi đó là một fork-PR: head repo là fork của
contributor, và contributor không có registry-write capability.

Một số adopter configure registry repo của họ sao cho mọi member
của organisation có push access (shape "small team, everyone is
trusted"). Trong configuration đó, một contributor với registry-repo
write access có thể mở một same-repo PR — push branch
`requests/<handle>.yaml` trực tiếp tới registry repo thay vì tới
một fork.

Tool byreis KHÔNG phân biệt fork-PR khỏi same-repo PR ở validation
layer: cả hai pass qua cùng state-machine matrix. Các check cấu
trúc vẫn effective:

- Check single-file scope refuse bất kỳ PR nào modify file ngoài
  `requests/<handle>.yaml`, nên một same-repo PR không smuggle được
  một recipient-set change vào một file riêng.
- Byte-compare PR-author-vs-YAML refuse bất kỳ PR nào có
  `user.login` không match `github_handle` của YAML, nên một
  same-repo PR không spoof được identity của contributor khác.

Tuy nhiên, adopter configuration canonical là "contributor có ZERO
registry-repo write; chỉ fork-PR path", vì configuration đó cũng
rule out direct branch manipulation của registry repo bởi non-admin
(một concern rộng hơn flow request-access). Để pin configuration
đó:

- Configure branch-protection của registry repo để require fork-PR
  review cho bất kỳ change nào tới path `requests/*`.
- Restrict push access registry-repo cho admin only; require
  contributor fork repo cho mọi change, bao gồm `request-access`.

Đây là registry-repo configuration choice, không phải byreis
setting. Behavior của tool không thay đổi cách nào; trust posture
của operator là biến.

### Tuning quota

Quota open-PR per-contributor (default 5) là một client-side
advisory limit enforce bởi verb `byreis request-access`. Nó không
phải server-side enforcement; một contributor chạy một `gh pr
create` unmodified trực tiếp đối với registry vẫn mở được PR
arbitrary nhiều. Quota calibrate cho case routine (một PR open per
in-flight pubkey rotation), không phải case adversarial.

Cho case adversarial, branch-protection rule của registry repo là
enforcement layer: configure chúng để require admin review trên
mọi path `requests/*`, và volume PR open trở nên cùng lắm là một
denial-of-service nuisance.

Quota check bản thân là một best-effort early-fail: giữa open-PR
count probe và actual PR creation (vài network round-trip), cùng
contributor — hoặc một invocation `byreis request-access` parallel
trên một máy khác dưới cùng account — có thể race PR thêm qua
limit. Server-side rate limit của GitHub và branch-protection rule
của registry là quota enforcer authoritative; client-side check tồn
tại để cho một error message sạch hơn trong case thường, không
phải bind một adversary.

## Đọc liên quan

- `docs/forward-secrecy.md` — `byreis rotate --remove` guarantee gì
  và không guarantee gì về ciphertext pre-rotation. Một
  request-access absorption là một additive `--add`; nó không chạm
  câu hỏi forward-secrecy trừ khi cùng rotation cũng remove một
  recipient.
- `docs/rotation-runbook.md` — recover từ một partial rotation qua
  `byreis admin rotation reconcile`, bao gồm classification
  Phase-1/Phase-2 và thủ tục recovery manual Phase-2 mid-flight.
  Một absorption rotation land một partial state surface qua cùng
  recovery path.
- `byreis doctor` — verb diagnostic chung; surface counter drift,
  unverified registry trust, và issue key/permission. Chạy trước
  khi mở hay absorb một request-access PR nếu có gì về recipient
  set của project trông unexpected.
