// export_test.go exposes unexported helpers for black-box unit tests in
// package app_test. Nothing in this file is compiled into production binaries.
package app

// BaseBranchFromEnvForTest calls baseBranchFromEnvProd so that app_test
// package tests can exercise the env-reader + validator without exporting the
// production function.
var BaseBranchFromEnvForTest = baseBranchFromEnvProd

// ValidateBaseBranchForTest exposes validateBaseBranch for direct unit testing
// of inputs that cannot be set via t.Setenv (e.g. NUL bytes, which the OS
// rejects at the setenv(3) syscall level before userspace code can observe
// them through os.Getenv).
var ValidateBaseBranchForTest = validateBaseBranch
