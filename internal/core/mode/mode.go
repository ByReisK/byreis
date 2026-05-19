// Package mode implements crypto-derived mode detection and the command×mode
// permission policy matrix.
//
// Mode is determined by cryptographic reality, never by config or flags. The
// resolution order is strictly defined; any error fails closed to CONTRIBUTOR.
// The only hard error is an existing key file with wrong permissions.
//
// No age, no crypto/ed25519 import here — mode asks the encryption port
// "CanDecryptAny" via an injected KeyProbe interface.
package mode

import (
	"context"
	"errors"
)

// Mode represents the current operational mode.
type Mode int

const (
	// ModeContributor: no private key, or key not registered, or cannot decrypt.
	// All read/decrypt/admin commands are denied. This is the default.
	ModeContributor Mode = iota

	// ModeAdmin: private key present + 0600 + can decrypt + pubkey in verified
	// registry. All commands permitted.
	ModeAdmin
)

func (m Mode) String() string {
	switch m {
	case ModeAdmin:
		return "ADMIN"
	default:
		return "CONTRIBUTOR"
	}
}

// Command enumerates all byreis commands for the permission matrix.
type Command string

const (
	CommandVersion Command = "version"
	CommandInit    Command = "init"
	CommandDoctor  Command = "doctor"
	CommandSubmit  Command = "submit"
	CommandReview  Command = "review"
	CommandMerge   Command = "merge"
	CommandGet     Command = "get"
	CommandDecrypt Command = "decrypt"
	CommandEdit    Command = "edit"
)

// ErrKeyPermissions is a hard error returned when the private key file exists
// but has permissions other than 0600. byreis refuses to run any command (other
// than version) when this occurs. The error message includes the exact chmod fix.
var ErrKeyPermissions = errors.New(
	"admin key file has insecure permissions: must be exactly 0600 — " +
		"run: chmod 600 <path-to-key>")

// ErrPermissionDenied is returned by Policy.Allow when the current mode does
// not permit the requested command. It signals denied-by-policy, distinct from
// attempted-then-failed.
var ErrPermissionDenied = errors.New(
	"command not permitted in CONTRIBUTOR mode — " +
		"this requires an admin key; see `byreis doctor` for your current mode")

// KeyProbe is the consumer-defined port for checking key presence and decryption
// capability without touching identity material directly.
type KeyProbe interface {
	// KeyFilePath returns the path to the private key file, or "" if no key is
	// configured (BYREIS_KEY_FILE / BYREIS_KEY / default path).
	KeyFilePath(ctx context.Context) string

	// KeyFilePerms returns the file permission bits of the key file, or an error
	// if the file cannot be stat'd. Only called when KeyFilePath != "".
	KeyFilePerms(ctx context.Context) (uint32, error)

	// CanDecryptAny attempts to decrypt any single value from the provided
	// project's current secrets file using the configured key. Returns true if
	// decryption succeeds. Returns false (not an error) if the key is present but
	// cannot decrypt (e.g. key not in the recipient set).
	CanDecryptAny(ctx context.Context, projectID string) (bool, error)
}

// RegistryTrust is the consumer-defined port for querying the registry to check
// whether the current public key is a registered admin.
type RegistryTrust interface {
	// IsRegisteredAdmin returns true only if the current public key is found in
	// a SourceVerified registry fetch for the given project. Returns false (not an
	// error) if the key is not registered (emits a "key unregistered" warning via
	// the caller's logger). Returns an error on registry failure — which causes
	// fail-closed-to-contributor.
	IsRegisteredAdmin(ctx context.Context, projectID string) (bool, error)
}

// Clock is the consumer-defined port for time (injected; no real clock in unit
// tests per binding engineering standards).
type Clock interface {
	Now() interface{ Unix() int64 }
}

// Detector detects the current mode from cryptographic reality.
type Detector struct {
	Probe    KeyProbe
	Registry RegistryTrust
}

// Detect resolves the current mode in this strict order:
//
//  1. No key file → CONTRIBUTOR
//  2. Key file perms ≠ 0600 → hard error (ErrKeyPermissions), refuse to run
//  3. Cannot decrypt any project file → CONTRIBUTOR
//  4. Public key not in signature-verified registry → CONTRIBUTOR + warning
//  5. All checks pass → ADMIN (promotion written to audit log by caller)
//
// Any unexpected error → CONTRIBUTOR (fail closed). ErrKeyPermissions is the
// only case where an error is returned and the caller must refuse to run.
func (d *Detector) Detect(ctx context.Context, projectID string) (Mode, error) {
	panic("not implemented") // stub: real implementation pending
}

// Policy enforces the command×mode permission matrix. It is defined separately
// from Detector so it can be tested exhaustively for every (command × mode)
// pair, including the denied rows and all bypass attempts.
type Policy struct{}

// Allow returns nil if the command is permitted in the given mode, or
// ErrPermissionDenied if not. Bypass attempts (--mode admin flag, BYREIS_MODE
// env, mode: config key, forged SourceVerified) are never honoured — Allow takes
// the cryptographically-derived mode, not a user-supplied claim.
//
// This is the single enforcement point; ad-hoc per-command checks are forbidden.
func (p *Policy) Allow(m Mode, cmd Command) error {
	panic("not implemented") // stub: real implementation pending
}
