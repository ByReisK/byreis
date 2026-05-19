// Package usecase contains orchestration use-cases: Init, Doctor, Review,
// Merge, Get, Decrypt, Edit. These depend on the core ports only (mode, crypto,
// registry, git, audit, config, validator). No SDK imports.
//
// The Submit use-case lives in the dedicated sub-package
// internal/core/usecase/submit, not here. The split is structural, not prose:
// Decrypt/Edit/Merge live in this package (outside the submit sub-package), so
// they are off the contributor Submit import allowlist by construction. The
// allowlist gate targets internal/core/usecase/submit (the Submit compilation
// unit), not this parent package.
//
// This parent package may import internal/core/crypto/identity and
// internal/core/crypto/decrypt (the admin decrypt path). The submit sub-package
// must not, and the allowlist gate on that sub-package enforces it
// mechanically.
package usecase

// This file is intentionally minimal for now. Individual use-case types and
// constructors are defined in separate files within this package (review.go,
// merge.go, etc.) as the implementation is filled in.
//
// The Submit use-case lives at:
//   internal/core/usecase/submit/submit.go  (allowlist-gated sub-package)
//
// The ship-gate test file lives at:
//   internal/core/usecase/asymmetry_shipgate_test.go  (build tag: shipgate)
