# byreis v0.7 release notes

v0.7 ship `byreis export`, verb plaintext export admin-only. Nó là supported
migration relief valve cho operator cần move secrets ra khỏi byreis sang
một system khác: decrypt file of record live ra một stream
shell-sourceable hay dotenv-compatible, mà không bao giờ bypass mô hình
asymmetric-access.

Asymmetric-access guarantee không thay đổi. `byreis export` là một
command admin-only — nó decrypt file secrets bằng admin private key,
nên một contributor keyless không chạy được. Contributor access vẫn
write-only và enforce cryptographically; không có v0.7 surface nào
thay đổi permission matrix contributor.

## Có gì mới

### `byreis export` — plaintext export admin-only

`byreis export` decrypt file-of-record live của một project và
serialize mọi value như một stream shell-env hay dotenv ra stdout.

```
byreis export --project <id> --file <name> --format env    > app.env
byreis export --project <id> --file <name> --format dotenv > .env
```

Hai format được support là:

- `env` — emit một dòng `export KEY="..."` cho mỗi value. Stream kết
  quả intended được source với `source` hay
  `set -a; source <(byreis export ...)`, làm mọi key available như
  một exported shell variable.

- `dotenv` — emit một dòng `KEY="..."` cho mỗi value. Compatible với
  convention `.env`, `docker-compose env_file`, và bất kỳ library
  nào đọc file `.env`, như `godotenv`.

Cả hai format double-quote mọi value và apply shell-safe escaping
(bao gồm ký tự `$` và backtick) nên một secret value không inject
được một shell command khi output bị source hay eval.

#### Gate admin-only

`byreis export` bị deny ở permission matrix cho mode CONTRIBUTOR.
Deny xảy ra trước bất kỳ network contact, identity load, hay decrypt
attempt nào — cùng ordering fail-closed mà `get` và `decrypt`
follow. Một contributor chạy command nhận một permission-denied
error rõ ràng.

#### VerifyOfRecord-first, decrypt whole-file

Verb export reuse decrypt use-case admin-read đã ship.
VerifyOfRecord chạy trước bất kỳ decrypt hay identity load nào. Nếu
bất kỳ value nào trong file không decrypt được, command exit
non-zero và không gì được write ra stdout. Không có path partial
hay best-effort: export là all-or-nothing.

Audit trail record một event `op=export` để một bulk export
distinguishable khỏi một `decrypt` single-key trong admin audit log.

#### TTY speed-bump

Mặc định `byreis export` từ chối write plaintext ra một interactive
terminal — một operator first-run chạy command không có pipe sẽ
thấy secrets đã decrypt land trong terminal scrollback. TTY
refusal này là một convenience speed-bump chống dump nhầm, không
phải security boundary. Security boundary là admin private key.
Khi bạn pipe hay redirect output — ví dụ `byreis export ... | cat`
hay `> app.env` — stdout là non-interactive và plaintext là của
bạn để protect.

#### `--sops` cố ý không support

`byreis export` không và sẽ không support output format `--sops`.
byreis dùng mô hình native age recipient (xem ADR-0001 và ADR-0003):
không có shared symmetric data key, ciphertext được address trực
tiếp tới mỗi admin public key, và contributor keyless có thể submit
secrets mà chỉ người giữ key mở được. Một export kiểu SOPS sẽ phải
reintroduce một shared symmetric data key ở phía consumer, sẽ phá
vỡ asymmetric-access guarantee.

`byreis export --format env|dotenv` là escape hatch supported,
sạch ra plaintext. Cho operator migrate khỏi SOPS hay move secrets
sang một system khác, format `env` hay `dotenv` là tool đúng.

## Cái KHÔNG có trong v0.7

Các cái sau được carry forward sang một release tương lai và
không available trong v0.7:

- **Không có flag `--json`.** Output structured machine-readable
  cho export chưa implement. Format env/dotenv là output shape
  duy nhất.
- **Không có flag `--force`.** Không có override cho TTY refusal;
  pipe hay redirect là path designated.
- **Không có filter `--key`.** Export luôn decrypt và emit whole
  file. Filter per-key không support trong release này.
- **Không có support GitLab.** byreis là GitHub-only trong v0.7.
  GitLab support không plan cho release này.

## Upgrade

Drop-in replacement cho v0.6. Không có thay đổi secrets-format,
không có thay đổi registry-schema, không có thay đổi environment
variable. Các file encrypted, registry, signed commit hiện có, và
contract hai-biến `BYREIS_PROJECT` / `BYREIS_PROJECT_REPO` đều
không bị ảnh hưởng. Verb `export` là additive; mọi command hiện
có tiếp tục hoạt động identical.
