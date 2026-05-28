# byreis v0.3 release notes

## Có gì mới trong v0.3

v0.3 làm cho các flow day-to-day của contributor và admin thật end to end
và thêm một interactive terminal experience trên top. Asymmetric-access
guarantee không thay đổi: contributor vẫn encrypt-to-admins và không bao
giờ đọc được một value.

### Submit và review wired production

- `byreis submit` và `byreis review` giờ wired production đầy đủ và hoạt
  động end to end, bao gồm bulk `submit --file`. Cái này close gap
  v0.2.0 ở đó cả hai verb trả về error "adapters not configured" ở
  runtime vì các use-case chưa bao giờ được nối với adapter của chúng
  trong production composition root (xem Correction trong
  `docs/release-notes-v0.2.md`). Logic encryption và review đã correct
  trong v0.2; v0.3 wire nó vào production composition root nên nó chạy.

### TUI tương tác cho submit và review

- Trên một interactive terminal, `byreis submit` giờ launch một submit
  form masked-entry. Form giữ write-only affordance ở trung tâm: một
  contributor gõ một value, value được mask, và nó được
  encrypted-to-admins và submit như một pull request mà không bao giờ
  được display lại dạng plaintext.
- Trên một interactive terminal, `byreis review` giờ launch một admin
  review flow. Review flow là (a) một access-request triage queue list
  các access-request pull request đang mở chờ một decision, và (b)
  một single-PR submission detail view address bằng reference.

### Hardening v0.3 khác

- Các GitHub call `request-access` của contributor giờ đi qua một
  adapter port sạch, giữ network access của contributor write path
  sau một boundary duy nhất.
- Enumeration admin `request list` giờ bounded, nên một registry lớn
  không còn page không limit.

## Thẳng thắn và scope

byreis ship với một set guarantee narrow và machine-checkable có chủ
ý, và release notes nêu limit thẳng như feature.

- **TUI cover chỉ `submit` và `review`.** Rotation, decryption, key
  management, và audit vẫn là command CLI-only. Không có TUI cho các
  flow đó trong v0.3, theo thiết kế — đặc biệt đường plaintext
  decrypt ở lại trên CLI và không bao giờ render qua TUI.
- **CLI vẫn là source of truth và interface CI-native.** Mọi flow
  fully available trên CLI; TUI là một convenience layer trên các
  use-case `submit` và `review` và không bao giờ là cách duy nhất
  để làm gì. Mọi sử dụng automated, headless, hay CI nhắm tới CLI.
- **TUI review là access-request triage cộng single-PR detail,
  không phải submission-PR queue browse-được.** Review flow list các
  access-request pull request đang mở và show một submission PR
  duy nhất bằng reference; nó chưa enumerate hay browse được set
  đầy đủ submission pull request đang mở. Một submission-PR queue
  browse-được cần core surface mới và defer sang v0.4.
- **Behavioral delta từ v0.2.** Trong v0.2 các verb này luôn chạy
  đường CLI. Trong v0.3, trên một interactive terminal,
  `byreis submit` và `byreis review` launch TUI mặc định. Đây là
  một behavior change có chủ ý.
- **Sử dụng headless và non-interactive không thay đổi.** Với
  `--json`, với `BYREIS_NON_INTERACTIVE` set, với `TERM=dumb`, hay
  trên bất kỳ non-TTY pipe nào, TUI không bao giờ launch và đường
  CLI hiện tại chạy chính xác như trước. Output headless
  byte-identical với output CLI v0.2 cho các verb này.
- **Windows là chỉ đường CLI.** TUI tương tác nhắm tới linux và
  darwin; trên Windows byreis buildable và CLI đầy đủ chạy được,
  nhưng TUI không phải target Windows. Windows user nhận CLI
  experience.

## Thay đổi

- Command top-level `byreis merge` unimplemented bị remove; dùng
  `byreis admin merge`.

## Giới hạn đã biết / defer sang v0.4

- Một submission-PR queue browse-được trong TUI (enumerate và
  select qua mọi submission pull request đang mở) defer sang v0.4;
  nó yêu cầu core surface mới mà v0.3 cố ý không add.
- Signed registry merge-audit append (một feature phía registry
  write-side với crypto và threat review riêng) vẫn defer sang
  v0.4, như đã disclose trong notes v0.2.
