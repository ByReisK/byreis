# Bắt đầu

Trang này dẫn bạn từ con số 0 đến một flow byreis hoạt động được: cài binary,
trỏ tới một registry, submit một secret với tư cách contributor, và đọc lại nó
với tư cách admin. Tham khảo đầy đủ ở **[user guide](guide.md)**.

## Cài đặt

=== "Pre-built binary"

    Tải binary cho platform của bạn từ trang
    [Releases](https://github.com/ByReisK/byreis/releases) (Linux và macOS,
    amd64 và arm64), rồi đặt vào `PATH`:

    ```bash
    # Ví dụ: Linux amd64
    curl -fsSL -o byreis \
      https://github.com/ByReisK/byreis/releases/latest/download/byreis-linux-amd64
    chmod +x byreis && sudo mv byreis /usr/local/bin/
    byreis version
    ```

=== "Build từ source"

    Yêu cầu Go 1.26+.

    ```bash
    go install github.com/ByReisK/byreis/cmd/byreis@latest
    byreis version
    ```

`byreis version`, `byreis --help`, và các command first-run đều chạy với zero
configuration — bạn chỉ cần một key và một registry khi bắt đầu submit hay đọc
secrets thật.

## Hai repository

byreis tách bạch *ai được trust* khỏi *cái gì được encrypt*:

- **Admin registry repo** (ví dụ `myorg/byreis-admins`) — source of truth cho
  việc ai là admin, public key của họ, config per-project, và policy. Được
  fetch read-only, cache lại, và verify integrity qua signed commits.
- **Project secrets repo** (ví dụ `myorg/my-app-secrets`) — chứa `.byreis.yaml`
  (trỏ tới registry) và các file encrypted `secrets/*.enc.yaml`.

Trỏ byreis tới registry của bạn một lần, thường là qua environment variables:

```bash
export BYREIS_REGISTRY=myorg/byreis-admins
export BYREIS_PROJECT=myapp                       # logical project id không có dấu /
export BYREIS_PROJECT_REPO=myorg/my-app-secrets   # GitHub owner/repo slug
```

## Initialize một project

Từ bên trong một project secrets repo, scaffold file `.byreis.yaml` nối project
tới registry:

```bash
byreis init
byreis doctor    # xác nhận resolved mode + configuration
```

`byreis doctor` là người bạn của bạn: nó báo xem byreis đang nhìn bạn như
**contributor** hay **admin**, và *vì sao* — bao gồm cả warning nếu một private
key tồn tại nhưng không grant admin (sai file permissions, hoặc public key của
bạn chưa được register).

## Contributor workflow — submit một secret

Một contributor **không cần private key**. Submit sẽ encrypt giá trị bằng các
public key của admin và mở một pull request.

```bash
# Single key — giá trị được nhập tương tác (masked, double-entry)
byreis submit --key STRIPE_API_KEY

# Bulk — đọc mọi cặp KEY=VALUE từ một file .env
byreis submit --file .env

# Kèm lý do được ghi vào PR
byreis submit --key STRIPE_API_KEY --reason "rotating the live key"
```

Bạn có thể verify integrity của audit trail bất kỳ lúc nào — không cần key:

```bash
byreis audit verify --json    # exit code khác 0 khi bị tamper là tripwire sạch cho CI
```

## Admin workflow — review, merge, và consume

Một admin giữ một private key mà nửa public của nó nằm trong registry đã verify.

```bash
# Review giá trị thật, đã decrypt, đằng sau một submission PR
byreis review --pr myorg/my-app-secrets#42

# Merge nó, pin nội dung mong đợi để không có gì thay đổi sau lưng bạn
byreis admin merge --pr myorg/my-app-secrets#42 --expect <pin> \
  --project myapp --file secrets/production.enc.yaml
```

Khi một secret đã được merge, bạn có thể đọc hoặc dùng nó:

```bash
# Đọc một giá trị
byreis get --project myapp --file secrets/production.enc.yaml --key STRIPE_API_KEY

# Export ra một stream shell-sourceable / dotenv
byreis export --project myapp --file secrets/production.enc.yaml --format env

# Chạy một process với mọi secret được inject vào environment của nó —
# không bao giờ chạm disk hay terminal scrollback (exec, không phải shell)
byreis run --project myapp --file secrets/production.enc.yaml -- ./server --port 8080
```

## Bước tiếp theo

- Xem mọi command, flag, và configuration value trong **[user guide](guide.md)**.
- Hiểu các guarantee trong **[mô hình bảo mật](security-model.md)**.
- Vận hành ở quy mô lớn? Đọc runbook **[rotation](rotation-runbook.md)** và
  **[access-request](request-access-runbook.md)**.
