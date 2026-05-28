# Mô hình bảo mật

byreis có một thuộc tính định danh duy nhất mà mọi thứ khác đều suy ra từ đó:

!!! abstract "Invariant"
    **Mức access được derive từ thực tế cryptography, không bao giờ từ một
    config file, một flag, hay một environment variable.** Nếu bạn decrypt
    được một project file và public key của bạn nằm trong admin registry đã
    verify, bạn là admin. Ngược lại bạn là contributor.

Trang này giải thích invariant đó được enforce ra sao.

## Asymmetric access

Secrets được encrypt với native [`age`](https://age-encryption.org/) theo mô
hình **per-recipient envelope**: mỗi giá trị được encrypt độc lập tới các public
key của admin. **Không có shared symmetric data key**.

Hệ quả chính là điểm cốt lõi của byreis:

- Một **contributor** chỉ giữ public key. Họ có thể encrypt một giá trị mới
  tới các admin và add hoặc replace một key trong project file — một capability
  write-only. Họ không decrypt được gì cả, **kể cả một giá trị họ vừa submit**.
- Một **admin** giữ một private key mà nửa public của nó đã được register. Họ
  có thể decrypt, read, edit, rotate, export, và run với các secret đó.

Đây là lý do interop kiểu `--sops` cố ý không support: SOPS dùng một shared
data key duy nhất, ai có key cũng đọc được mọi thứ. Adopt nó sẽ làm sập
asymmetric guarantee. `byreis export` là escape hatch sạch ra plaintext thay
thế — và chỉ admin dùng được.

## Mode detection (fail-closed)

byreis resolve mode của bạn bằng cách check, **theo thứ tự**:

1. có file private key;
2. file permission là `0600` (nếu không byreis từ chối chạy);
3. nó thực sự **decrypt** được một project file;
4. public key tương ứng có trong admin registry đã **verify**.

Bất kỳ failure nào đều downgrade về **contributor** — kèm warning nếu có key
nhưng không grant admin. Mặc định luôn là contributor; promotion là explicit
và có audit. Không một flag, environment variable, config key, hay cache bị
tamper nào có thể grant admin được, vì quyết định dựa trên facts cryptography,
không phải declarations.

Mọi command đều bị gate bằng mode này qua một permission matrix duy nhất, và
các đường contributor-denied bị *từ chối trước khi được attempt* — một
contributor gọi một admin verb không bao giờ chạm đến đường decrypt.

## Build tự enforce boundary

Asymmetric guarantee không chỉ là runtime check — nó là cấu trúc. Code path mà
một contributor compile và run (đường encrypt / submit) **không có route
compile-time** nào tới private-key hoặc decryption capability. Điều này được
enforce cơ học bởi một closed-world import gate trong CI: nếu contributor
build chỉ cần *link* được vào code decrypt thôi, build cũng fail. Import graph
được coi là security boundary, không phải style preference.

Một release gate non-skippable bổ sung drive production wiring thật end-to-end
trên key thật và signed git history thật, chứng minh admin read thành công và
contributor read bị denied-not-attempted trước khi bất kỳ release nào ship.

## Mô hình two-repo trust

byreis tách trust khỏi ciphertext:

- **Admin registry repo** là source of truth cho việc ai là admin, public key
  của họ, configuration per-project, và global policy. byreis fetch nó
  read-only, cache aggressively, và verify integrity qua **signed commits**
  anchor tới một pinned trust anchor.
- **Project secrets repo** chỉ giữ config pointer và các file encrypted.

byreis không bao giờ write vào registry trừ qua flow `admin add` / `admin
remove` explicit, có audit.

## Audit trail đáng tin

Mỗi dòng trên audit channel được **bind với commit anchor-verified đã
introduce nó**. Verifier phát hiện:

- entries đã bị edit, delete, hoặc reorder;
- forged insert và cross-file splice;
- counter regression (anti-rollback / monotonicity continuity).

Nó **fail closed** khi có tamper, và **actor attribution là anchor-attested** —
derive từ signed introducing commit, không bao giờ copy từ (forgeable) log
line. Entries cũ của một admin đã removed sẽ attribute về một sentinel, không
phải về một cái tên mà attacker có thể spoof.

Bất kỳ ai — kể cả một contributor không có key — đều có thể chạy full
verification với `byreis audit verify`. Nó không decrypt gì cả, và với `--json`
trả về exit code khác 0 khi có tamper, biến nó thành CI integrity tripwire
cắm-vào-là-chạy. Một failure transient phía verifier (ví dụ một `git diff-tree`
timeout) được report là kết quả retryable *inconclusive*, phân biệt rõ với
verdict *tamper* thật sự, nên một môi trường flaky không bao giờ tạo false
tamper alarm — trong khi mọi content divergence thật đều luôn deny.

## Consume secrets mà không leak

Hai verb consume được thiết kế quanh exposure surface:

- **`byreis export`** emit plaintext ra stdout cho consumer dạng shell hoặc
  dotenv. Giá trị được quote và escape đầy đủ (bao gồm `$` và backtick) để một
  giá trị có ý đồ xấu không inject được command khi output bị source hoặc
  `eval`. Plaintext bị từ chối khi đầu ra là interactive terminal mặc định —
  một guard chống dump nhầm, không phải containment boundary.
- **`byreis run -- <cmd>`** inject secrets vào environment của một child
  process nên chúng **không bao giờ chạm disk hay terminal scrollback**, và
  không bao giờ chạm argv của child.

byreis thẳng thắn về cái nó không kiểm soát được khi một child process đã giữ
environment: một descendant có thể re-export, `/proc/<pid>/environ` đọc được
bởi các process cùng uid, và một core dump có thể capture nó. byreis chỉ hứa
*bản thân byreis* không leak gì và secrets không bao giờ chạm disk qua
byreis.

## Đọc liên quan

- **[Forward secrecy](forward-secrecy.md)** — rotation guarantee gì và không
  guarantee gì về các giá trị đã từng bị expose.
- **[Rotation runbook](rotation-runbook.md)** — vận hành rotation recipient-set.
- **[User guide](guide.md)** — reference đầy đủ về command và configuration.
