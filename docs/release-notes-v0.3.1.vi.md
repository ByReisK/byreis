# byreis v0.3.1 release notes

v0.3.1 là một patch release một-fix. Nó không thay đổi behavior cho
deployment configure đúng và không yếu đi security invariant nào;
asymmetric-access guarantee không thay đổi.

## Bug fix

- **Graceful fallback trên một `BYREIS_PROJECT` malformed.** Khi
  project identifier configure malformed (không phải `owner/repo` —
  ví dụ một segment path extra, hoặc không có dấu / nào cả),
  production composition root pass một git provider typed-nil qua các
  `nil`-provider guard gate đường review, merge, và submit. Kết quả
  là một runtime panic trên call privileged đầu tiên thay vì message
  "not configured" graceful intended. byreis giờ trả về một untyped
  nil explicit trên một provider-construction error, nên các đường
  đó fall back sạch và report một error actionable. Một regression
  test lock kết quả true-nil cho project string malformed.

Đây là một robustness fix cho một edge degraded-configuration; nó
không phải một security fix. Deployment với một `BYREIS_PROJECT`
valid không bị ảnh hưởng.

## Upgrade

Drop-in replacement cho v0.3.0. Không có thay đổi configuration,
format, hay workflow.
