// Package mode implements crypto-derived mode detection and the command×mode
// permission policy matrix.
//
// Mode is determined by cryptographic reality, never by config or flags. The
// resolution order is strictly defined; any error fails closed to CONTRIBUTOR.
// The only hard error is an existing key file with wrong permissions.
//
// No age, no crypto/ed25519 import here — mode asks the encryption port
// "CanDecryptAny" via an injected KeyProbe interface, and asks the registry
// port whether the public key is a verified admin. The package has no UI,
// network, filesystem, or clock dependency of its own; every side-effecting
// capability is an injected, consumer-defined port so the access spine is
// fully reproducible under test.
package mode

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
)

// Mode represents the current operational access level. It is derived from
// cryptographic reality by the Detector and consumed by the Policy. It is never
// settable by a flag, environment variable, or config file.
type Mode int

const (
	// ModeContributor is the default and least-privileged mode: no usable
	// private key, or a key that cannot decrypt, or a key not vouched for by a
	// signature-verified registry. Read/decrypt/admin commands are denied.
	ModeContributor Mode = iota

	// ModeAdmin is reached only when a 0600 private key can decrypt a project
	// file AND its public key is present in a signature-verified, fresh
	// registry admin set. Promotion to this mode is audited.
	ModeAdmin

	// ModeSuper is the elevated admin role used for registry/governance
	// lifecycle actions. In the v0.1 command set it is a strict superset of
	// ModeAdmin's permissions (no v0.1 command is super-only); it exists so the
	// permission matrix is complete and stable as governance commands land.
	ModeSuper
)

func (m Mode) String() string {
	switch m {
	case ModeAdmin:
		return "ADMIN"
	case ModeSuper:
		return "SUPER"
	case ModeContributor:
		return "CONTRIBUTOR"
	default:
		// An unrecognised value is reported distinctly so a forged/uninitialised
		// mode is visible in diagnostics rather than masquerading as a known one.
		return "UNKNOWN"
	}
}

// Warning is a non-fatal advisory surfaced alongside a resolved mode so the CLI
// layer can tell the user why they were not promoted.
type Warning int

const (
	// WarningNone means no advisory applies.
	WarningNone Warning = iota

	// WarningKeyUnregistered means a usable key that can decrypt a project file
	// was found, but its public key is not present in a signature-verified
	// registry, so the user remains CONTRIBUTOR.
	WarningKeyUnregistered
)

func (w Warning) String() string {
	switch w {
	case WarningNone:
		return "none"
	case WarningKeyUnregistered:
		return "key-unregistered"
	default:
		return "none"
	}
}

// Result is the outcome of mode detection. It is a value type (return structs,
// accept interfaces) carrying the resolved mode and any advisory the CLI layer
// should surface to the user.
type Result struct {
	Mode    Mode
	Warning Warning
}

// Command enumerates all byreis v0.1 commands for the permission matrix.
type Command string

// Command constants enumerate all byreis v0.1 CLI verbs for the permission matrix.
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
// but its permissions are not exactly 0600. byreis refuses to run any command
// (other than version) when this occurs and never falls back to admin. The
// message carries the exact chmod fix so the CLI layer can surface an
// actionable hint.
var ErrKeyPermissions = errors.New(
	"admin key file has insecure permissions: must be exactly 0600 — " +
		"run: chmod 600 <path-to-key>")

// ErrPermissionDenied is returned by Policy.Allow when the current mode does
// not permit the requested command. It signals denied-by-policy, distinct from
// attempted-then-failed, so callers can reject before reaching any privileged
// code path.
var ErrPermissionDenied = errors.New(
	"command not permitted in the current mode — " +
		"this requires an admin key; see `byreis doctor` for your current mode")

// ErrDetectorMisconfigured is returned when the Detector is invoked without its
// required ports injected. A security path fails closed with a clear error
// rather than nil-panicking deep in the resolution chain.
var ErrDetectorMisconfigured = errors.New(
	"mode detector misconfigured: KeyProbe, RegistryTrust, Clock, and audit " +
		"sink must all be injected")

// ErrPromotionNotAudited is returned when an ADMIN promotion is otherwise
// warranted but cannot be durably recorded to the audit log. Promotion is
// security-relevant: an unrecordable promotion fails closed rather than
// silently granting elevated access.
var ErrPromotionNotAudited = errors.New(
	"admin promotion could not be written to the audit log; refusing to " +
		"promote without a durable audit record")

// KeyProbe is the consumer-defined port for checking key presence and
// decryption capability without this package ever touching identity material.
type KeyProbe interface {
	// KeyFilePath returns the path to the private key file, or "" if no key is
	// configured (BYREIS_KEY_FILE / BYREIS_KEY / default path).
	KeyFilePath(ctx context.Context) string

	// KeyFilePerms returns the file permission bits of the key file, or an
	// error if the file cannot be stat'd. Only called when KeyFilePath != "".
	KeyFilePerms(ctx context.Context) (uint32, error)

	// CanDecryptAny attempts to decrypt any single value from the given
	// project's current secrets file using the configured key. Returns true if
	// decryption succeeds; false (not an error) if the key is present but
	// cannot decrypt (e.g. not in the recipient set); an error on probe
	// failure, which fails closed to CONTRIBUTOR.
	CanDecryptAny(ctx context.Context, projectID string) (bool, error)
}

// RegistryTrust is the consumer-defined port for asking whether the current
// public key is a registered admin in a signature-verified, fresh registry.
type RegistryTrust interface {
	// IsRegisteredAdmin returns true ONLY if the current public key is found in
	// a SourceVerified, within-freshness-policy registry admin set for the
	// given project. It returns false (not an error) when the key is simply not
	// registered. It returns an error on registry failure OR when the only
	// available admin set is stale/unverified — in both cases the detector
	// fails closed to CONTRIBUTOR. A tampered cache that forges the
	// "verified" flag must therefore be rejected by the adapter implementing
	// this port, never reported as a registered admin.
	IsRegisteredAdmin(ctx context.Context, projectID string) (bool, error)
}

// Clock is the consumer-defined port for time. It is injected so unit tests
// never read a real clock (binding determinism standard).
type Clock interface {
	Now() interface{ Unix() int64 }
}

// Detector resolves the current mode from cryptographic reality. All
// side-effecting capabilities are injected via constructor fields.
type Detector struct {
	Probe    KeyProbe
	Registry RegistryTrust
	Clock    Clock
	Audit    audit.Logger
}

// Detect resolves the current mode in this strict, non-reorderable order:
//
//  1. No key file → CONTRIBUTOR
//  2. Key file perms ≠ 0600 (or unstattable) → hard error (ErrKeyPermissions),
//     refuse to run; never ADMIN
//  3. Cannot decrypt any project file (or probe error) → CONTRIBUTOR
//  4. Public key not in a signature-verified, fresh registry → CONTRIBUTOR
//     with WarningKeyUnregistered (registry error → CONTRIBUTOR, no warning)
//  5. All checks pass → ADMIN, and the promotion is written to the audit log;
//     if it cannot be durably audited, fail closed (ErrPromotionNotAudited)
//
// Any unexpected condition fails closed: CONTRIBUTOR, or a hard error for the
// permissions case. ADMIN is never the fallback for any error.
//
//nolint:cyclop // the resolution order is intentionally a flat, auditable chain
func (d *Detector) Detect(ctx context.Context, projectID string) (Result, error) {
	if d == nil || d.Probe == nil || d.Registry == nil || d.Clock == nil || d.Audit == nil {
		return Result{Mode: ModeContributor}, ErrDetectorMisconfigured
	}

	contributor := Result{Mode: ModeContributor, Warning: WarningNone}

	// Step 1: no key file → CONTRIBUTOR.
	keyPath := d.Probe.KeyFilePath(ctx)
	if keyPath == "" {
		return contributor, nil
	}

	// Step 2: perms must be exactly 0600, else HARD ERROR (refuse to run).
	// An unstattable key is treated as the perms case and also fails hard:
	// we will not continue past an ambiguous key on a security path.
	perms, err := d.Probe.KeyFilePerms(ctx)
	if err != nil {
		return Result{Mode: ModeContributor}, fmt.Errorf(
			"cannot verify permissions of key file %q: %w — %w",
			keyPath, err, ErrKeyPermissions)
	}
	// Compare only the permission bits; ignore type/setuid bits in the mode.
	if perms&0o777 != 0o600 {
		return Result{Mode: ModeContributor}, fmt.Errorf(
			"key file %q has mode %#o, want exactly 0600: %w",
			keyPath, perms&0o777, ErrKeyPermissions)
	}

	// Step 3: must be able to decrypt some project file. A probe error fails
	// closed to CONTRIBUTOR (never ADMIN, never a hard error here).
	canDecrypt, err := d.Probe.CanDecryptAny(ctx, projectID)
	if err != nil || !canDecrypt {
		return contributor, nil
	}

	// Step 4: public key must be in a signature-verified, fresh registry.
	// A registry error fails closed to CONTRIBUTOR with no advisory (we cannot
	// assert the key is unregistered if we could not consult the registry).
	registered, err := d.Registry.IsRegisteredAdmin(ctx, projectID)
	if err != nil {
		return contributor, nil
	}
	if !registered {
		return Result{Mode: ModeContributor, Warning: WarningKeyUnregistered}, nil
	}

	// Step 5: full chain satisfied → ADMIN, but only with a durable audit
	// record. An unrecordable promotion fails closed.
	ev := audit.Event{
		Kind:      audit.EventKindModePromotion,
		OccuredAt: nowTime(d.Clock),
		ProjectID: projectID,
		Outcome:   "ok",
		Details: map[string]string{
			"resolved_mode": ModeAdmin.String(),
			"reason":        "0600 key decrypts project file and public key is in a signature-verified registry",
		},
	}
	if err := d.Audit.Append(ctx, ev); err != nil {
		return Result{Mode: ModeContributor}, fmt.Errorf(
			"audit append failed: %w: %w", err, ErrPromotionNotAudited)
	}

	return Result{Mode: ModeAdmin, Warning: WarningNone}, nil
}

// nowTime adapts the minimal injected Clock (which yields only a Unix-second
// stamp) into the time.Time the audit event carries. Keeping the conversion
// here avoids widening the Clock port beyond what mode detection needs.
func nowTime(c Clock) time.Time {
	return time.Unix(c.Now().Unix(), 0).UTC()
}

// Policy enforces the command×mode permission matrix. It is a standalone unit
// (no detector dependency) so it can be tested exhaustively for every
// (command × mode) pair, including every denied cell and every bypass attempt.
type Policy struct{}

// matrix is the single source of truth for command permissions. A command is
// permitted in a mode iff its entry contains that mode. Any command or mode not
// represented here is denied (fail closed) — there is no default-allow path.
var matrix = map[Command]map[Mode]bool{
	CommandVersion: {ModeContributor: true, ModeAdmin: true, ModeSuper: true},
	CommandInit:    {ModeContributor: true, ModeAdmin: true, ModeSuper: true},
	CommandDoctor:  {ModeContributor: true, ModeAdmin: true, ModeSuper: true},
	CommandSubmit:  {ModeContributor: true, ModeAdmin: true, ModeSuper: true},
	CommandReview:  {ModeAdmin: true, ModeSuper: true},
	CommandMerge:   {ModeAdmin: true, ModeSuper: true},
	CommandGet:     {ModeAdmin: true, ModeSuper: true},
	CommandDecrypt: {ModeAdmin: true, ModeSuper: true},
	CommandEdit:    {ModeAdmin: true, ModeSuper: true},
}

// Allow returns nil if cmd is permitted in mode m, or an error wrapping
// ErrPermissionDenied otherwise. The mode argument is the cryptographically
// derived value from the Detector; there is deliberately no parameter for a
// flag, environment variable, or config-declared mode, so none of those
// channels can grant admin. This is the single enforcement point — ad-hoc
// per-command checks are forbidden.
func (p *Policy) Allow(m Mode, cmd Command) error {
	modes, known := matrix[cmd]
	if !known {
		return fmt.Errorf("unknown command %q: %w", cmd, ErrPermissionDenied)
	}
	if modes[m] {
		return nil
	}
	return fmt.Errorf(
		"command %q is not permitted in %s mode: %w",
		cmd, m, ErrPermissionDenied)
}
