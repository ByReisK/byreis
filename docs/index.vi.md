---
template: home.html
title: byreis — gửi secrets, không cần thấy secrets
hide:
  - navigation
  - toc
---

## Xem byreis hoạt động

```bash
# Contributor — write-only, không cần private key
byreis submit --key STRIPE_API_KEY

# Admin — review giá trị thật, rồi merge
byreis review --pr myorg/my-app-secrets#42
byreis admin merge --pr myorg/my-app-secrets#42 --expect <pin> \
  --project myapp --file secrets/production.enc.yaml

# Admin — đưa secrets vào process mà không bao giờ ghi xuống disk
byreis run --project myapp --file secrets/production.enc.yaml -- ./server
```

Mức access **được derive từ thực tế cryptography**, không bao giờ từ một config
flag hay environment variable. Nếu bạn decrypt được một project file và public
key của bạn nằm trong admin registry đã verify, bạn là admin. Ngược lại bạn là
contributor.

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } **Bắt đầu**

    ---

    Cài byreis, init một project, submit secret đầu tiên, rồi đọc nó với tư cách
    admin.

    [:octicons-arrow-right-24: Bắt đầu ngay](getting-started.md)

-   :material-feature-search:{ .lg .middle } **Tính năng**

    ---

    Toàn bộ capability theo role: contributor làm được gì, admin làm được gì, và
    các guarantee áp dụng cho cả hai.

    [:octicons-arrow-right-24: Xem tính năng](features.md)

-   :material-shield-key:{ .lg .middle } **Mô hình bảo mật**

    ---

    Asymmetric access hoạt động ra sao: native `age` encryption, mô hình
    two-repo trust, fail-closed mode detection, và audit trail đáng tin.

    [:octicons-arrow-right-24: Đọc mô hình](security-model.md)

-   :material-book-open-variant:{ .lg .middle } **Hướng dẫn sử dụng**

    ---

    Reference đầy đủ cho mọi workflow, command, configuration value, và
    environment variable.

    [:octicons-arrow-right-24: Mở guide](guide.md)

</div>

## Tại sao byreis?

Tooling hiện tại bắt bạn chọn đánh đổi:

- **SOPS + age** — zero-infra và git-native, nhưng *symmetric*: bất kỳ ai có key
  đều đọc được mọi thứ, và một contributor không có key thì hoàn toàn không
  edit nổi một shared environment file.
- **Server-based managers** — UX tốt, nhưng yêu cầu infrastructure hoặc một
  vendor.
- **Kubernetes-only controllers** — không dùng được cho workflow local thuần
  hay CI.

byreis lấp khoảng trống đó: là tool zero-infra plain-git duy nhất mà người
không bao giờ được *đọc* secrets vẫn có thể an toàn *add và update* secrets.

## Đi tiếp tới đâu

- Mới biết byreis? Bắt đầu ở **[Bắt đầu](getting-started.md)**.
- Đang đánh giá? Đọc **[Mô hình bảo mật](security-model.md)** và **[Tính năng](features.md)**.
- Đang vận hành byreis? Xem **[runbooks](rotation-runbook.md)** và
  **[user guide](guide.md)**.
- Thay đổi gần nhất nằm trong **[release notes](release-notes-v0.8.md)**.
