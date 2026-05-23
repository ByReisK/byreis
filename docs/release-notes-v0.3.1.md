# byreis v0.3.1 release notes

v0.3.1 is a single-fix patch release. It changes no behaviour for correctly
configured deployments and weakens no security invariant; the asymmetric-access
guarantee is unchanged.

## Bug fix

- **Graceful fallback on a malformed `BYREIS_PROJECT`.** When the configured
  project identifier was malformed (not `owner/repo` — for example an extra
  path segment, or no slash at all), the production composition root passed a
  typed-nil git provider past the `nil`-provider guards that gate the review,
  merge, and submit paths. The result was a runtime panic on the first
  privileged call instead of the intended graceful "not configured" message.
  byreis now returns an explicit untyped nil on a provider-construction error,
  so those paths fall back cleanly and report an actionable error. A regression
  test locks the true-nil result for malformed project strings.

This is a robustness fix for a degraded-configuration edge; it is not a security
fix. Deployments with a valid `BYREIS_PROJECT` are unaffected.

## Upgrading

Drop-in replacement for v0.3.0. No configuration, format, or workflow changes.
