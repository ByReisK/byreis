# Tính năng

byreis được tổ chức quanh ràng buộc định danh của nó: **mức access được derive
từ thực tế cryptography**. Một contributor (không có private key) có thể write
nhưng không bao giờ read; một admin (giữ một private key đã register) có thể
read, edit, rotate, và consume. Các capability bên dưới được nhóm theo cách
tương tự.

## Contributor — write-only, không có private key

| Capability | Command |
| --- | --- |
| Submit một secret đơn lẻ (encrypt với public key của admin, mở một PR) | `byreis submit --key NAME` |
| Bulk submit mọi cặp từ một file `.env` | `byreis submit --file .env` |
| Verify audit trail — không cần key, read-only, không decrypt | `byreis audit verify` |
| Request access (in-band, có audit) | `byreis request-access` |
| Initialize một project / diagnose configuration | `byreis init`, `byreis doctor` |

- **Submit không bao giờ decrypt.** Contributor encrypt tới các recipient của
  admin và có thể add hoặc replace một key trực tiếp — nhưng không thể đọc bất
  kỳ giá trị nào, kể cả cái họ vừa submit.
- **`audit verify`** chạy verification per-line đầy đủ trên audit trail mà
  không cần private key và không decrypt. Với `--json` nó emit kết quả
  machine-readable và **exit code khác 0 khi bị tamper**, nên cắm thẳng vào CI
  pipeline làm tripwire được luôn.

## Admin — giữ một private key đã register

| Capability | Command |
| --- | --- |
| Đọc một giá trị / mọi giá trị | `byreis get`, `byreis decrypt` |
| Edit một secret tại chỗ | `byreis edit` |
| Export ra một stream `env` / `dotenv` | `byreis export --format env\|dotenv` |
| Chạy một child process với secrets được inject vào environment | `byreis run -- <cmd>` |
| Review và merge một submission | `byreis review`, `byreis admin merge` |
| Reject một submission hoặc access request | `byreis admin request reject` |
| List các access request đang mở | `byreis admin request list` |
| Inspect & verify audit trail với per-line binding | `byreis admin audit show --verify` |
| Rotate recipient set | `byreis rotate`, `byreis rotation-reconcile` |

### Consume secrets an toàn

byreis cho admin hai cách bổ trợ để *sử dụng* một secret đã decrypt:

- **`byreis export --format env|dotenv`** — emit các dòng `export KEY="..."`
  shell-sourceable hoặc một file dotenv. Giá trị luôn được quote và escape (bao
  gồm cả `$` và backtick) nên một giá trị có ý đồ xấu không inject được command
  khi source. Plaintext bị từ chối khi đầu ra là interactive terminal mặc định,
  để tránh vô tình dump vào scrollback.
- **`byreis run -- <cmd>`** — launch một child process duy nhất với mọi giá
  trị nằm trong environment của nó, nên secrets **không bao giờ chạm disk hay
  terminal scrollback**. byreis exec command sau `--` trực tiếp (không qua
  shell, không expand `$VAR`), giữ secrets ngoài argv của child, forward
  `SIGINT`/`SIGTERM`, và exit với exit code của child.

`--sops` export bị cố ý không support — xem [mô hình bảo mật](security-model.md)
để hiểu tại sao một shared symmetric data key sẽ phá vỡ asymmetric guarantee.

## Áp dụng cho cả hai role

- **Audit trail đáng tin.** Mỗi dòng audit-channel được bind với commit
  anchor-verified đã introduce nó; verifier phát hiện edits, deletes, reorders,
  forged inserts, cross-file splices, và counter regressions, và fail closed
  khi có tamper. Actor attribution là anchor-attested, không copy từ log line.
- **TUI tương tác.** Một terminal UI bubbletea cho submit form và review queue
  (submission PRs + access requests), kèm approve / reject ngay trong TUI — và
  một guarantee cứng là review UI không bao giờ bind giá trị plaintext đã
  decrypt.
- **Registry offline-first.** Network lỗi thì fall back về cache; cache cũ thì
  warn nhưng vẫn chạy. Integrity của registry được verify qua signed commits.
- **CLI thẳng thắn, thân thiện với máy.** Secrets được mask trong terminal và in
  thẳng khi pipe; `--json` cho output dạng máy đọc; exit code có ý nghĩa; error
  message kèm gợi ý fix actionable.
- **Cross-platform.** Linux và macOS, amd64 và arm64, ship dạng static binary
  mỗi release.

## Cái byreis cố ý *không* có

Đây là quyết định scope có chủ ý, không phải lỗ hổng:

- **Không có interop `--sops`** — vì nó sẽ reintroduce một shared symmetric
  data key và phá vỡ asymmetric access.
- **Không interpret shell trong `run`** — `byreis run` exec command của bạn
  trực tiếp; nếu muốn shell hãy tự spawn (`byreis run -- sh -c '...'`).
- **Không có server hay vendor backend** — byreis chỉ là plain git và
  public-key crypto.

Xem [release notes](release-notes-v0.8.md) cho lịch sử theo từng release.
