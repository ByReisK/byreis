// Package byreis is the public API façade for external integrations. It re-exports
// stable domain types and provides a façade over internal/core/usecase.
//
// No `any` in signatures without written reason (engineering standards).
// This is a stable surface — additions are reviewed for backward compatibility.
package byreis

// Version is the current byreis version string. Updated at build time via
// -ldflags "-X github.com/ByReisK/byreis/pkg/byreis.Version=<version>".
var Version = "dev"
