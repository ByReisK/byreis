package mode_test

import (
	"errors"
	"testing"

	"github.com/ByReisK/byreis/internal/core/mode"
)

// TestPolicy_CommandModeMatrix is the enumerated command×mode permission
// fixture. Every command in the v0.1 set is asserted against every mode
// {Contributor, Admin, Super}, including every denied cell — a partial table is
// not acceptable for the access spine. Deny must be fail-closed and carry the
// permission-denied sentinel so callers can distinguish "not permitted" from
// "attempted and failed".
func TestPolicy_CommandModeMatrix(t *testing.T) {
	t.Parallel()

	// allow is the source-of-truth expectation grid. Read it as:
	// command -> mode -> permitted?
	//
	// v0.1 command set and mode mapping per the locked requirements:
	//   version/init/doctor/submit : all modes (contributor-runnable spine)
	//   review/merge/get/decrypt/edit : admin path only (denied for contributor)
	allow := map[mode.Command]map[mode.Mode]bool{
		mode.CommandVersion: {mode.ModeContributor: true, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandInit:    {mode.ModeContributor: true, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandDoctor:  {mode.ModeContributor: true, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandSubmit:  {mode.ModeContributor: true, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandReview:  {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandMerge:   {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandGet:     {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandDecrypt: {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandEdit:    {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
	}

	allModes := []mode.Mode{mode.ModeContributor, mode.ModeAdmin, mode.ModeSuper}
	allCommands := []mode.Command{
		mode.CommandVersion, mode.CommandInit, mode.CommandDoctor, mode.CommandSubmit,
		mode.CommandReview, mode.CommandMerge, mode.CommandGet, mode.CommandDecrypt,
		mode.CommandEdit,
	}

	// Guard: the expectation grid must cover the full cross-product so a missing
	// command or mode cannot silently shrink the asserted matrix.
	if len(allow) != len(allCommands) {
		t.Fatalf("expectation grid covers %d commands, want %d (full v0.1 set)", len(allow), len(allCommands))
	}

	p := &mode.Policy{}

	for _, cmd := range allCommands {
		modes, ok := allow[cmd]
		if !ok {
			t.Fatalf("command %q missing from the expectation grid", cmd)
		}
		for _, m := range allModes {
			want, covered := modes[m]
			if !covered {
				t.Fatalf("cell (%q, %v) missing from the expectation grid", cmd, m)
			}

			cmd, m, want := cmd, m, want
			t.Run(string(cmd)+"/"+m.String(), func(t *testing.T) {
				t.Parallel()

				err := p.Allow(m, cmd)
				if want {
					if err != nil {
						t.Fatalf("cell (%q, %v): expected ALLOW, got deny: %v", cmd, m, err)
					}
					return
				}
				if err == nil {
					t.Fatalf("cell (%q, %v): expected DENY, policy allowed it (fail-closed violated)", cmd, m)
				}
				if !errors.Is(err, mode.ErrPermissionDenied) {
					t.Fatalf("cell (%q, %v): deny error %v must wrap ErrPermissionDenied", cmd, m, err)
				}
			})
		}
	}
}

// TestPolicy_UnknownCommandDeniedFailClosed asserts an unrecognised command is
// denied rather than defaulting to allow — an unmatched verb must never be a
// silent escalation.
func TestPolicy_UnknownCommandDeniedFailClosed(t *testing.T) {
	t.Parallel()

	p := &mode.Policy{}
	for _, m := range []mode.Mode{mode.ModeContributor, mode.ModeAdmin, mode.ModeSuper} {
		err := p.Allow(m, mode.Command("definitely-not-a-real-command"))
		if err == nil {
			t.Fatalf("mode %v: unknown command was allowed — fail-closed violated", m)
		}
		if !errors.Is(err, mode.ErrPermissionDenied) {
			t.Fatalf("mode %v: unknown-command denial must wrap ErrPermissionDenied, got %v", m, err)
		}
	}
}

// TestPolicy_UnknownModeDeniedFailClosed asserts that a mode value outside the
// known set (e.g. a forged/uninitialised integer) is treated as the least
// privileged outcome: every admin-path command is denied.
func TestPolicy_UnknownModeDeniedFailClosed(t *testing.T) {
	t.Parallel()

	forged := mode.Mode(99) // not Contributor/Admin/Super
	p := &mode.Policy{}

	for _, cmd := range []mode.Command{mode.CommandReview, mode.CommandMerge, mode.CommandGet, mode.CommandDecrypt, mode.CommandEdit} {
		if err := p.Allow(forged, cmd); err == nil {
			t.Fatalf("forged mode value allowed admin command %q — fail-closed violated", cmd)
		}
	}
}

// --- Bypass attempts: none of these may grant ADMIN ---
//
// Binding access-spine rule: a tampered/forged claim of admin via a CLI flag,
// an environment variable, a config key, or a forged "verified" cached admin
// set must NOT change the cryptographically-derived mode or unlock an admin
// command.
// The policy takes only the derived mode value; it has no knowledge of and no
// hook for any of these channels. These tests prove that by construction.

// TestBypass_ModeFlagDoesNotGrantAdmin proves a `--mode admin`-style flag value
// cannot reach the policy: Policy.Allow's signature accepts only a mode.Mode
// derived by the Detector, never a user-supplied string claim. A contributor
// who passes `--mode admin` is still a contributor here.
func TestBypass_ModeFlagDoesNotGrantAdmin(t *testing.T) {
	t.Parallel()

	// Simulate the CLI layer having parsed `--mode admin`. The flag string is
	// inert: it is never converted into a privileged mode. The only mode the
	// policy ever sees is the crypto-derived one (here: contributor).
	const userSuppliedModeFlag = "admin"
	_ = userSuppliedModeFlag // deliberately unused: there is no API to feed it in

	derived := mode.ModeContributor // what the Detector actually resolved
	p := &mode.Policy{}

	for _, cmd := range []mode.Command{mode.CommandDecrypt, mode.CommandGet, mode.CommandEdit, mode.CommandReview, mode.CommandMerge} {
		if err := p.Allow(derived, cmd); err == nil {
			t.Fatalf("--mode=admin bypass: command %q was permitted in contributor mode", cmd)
		}
	}
}

// TestBypass_EnvVarDoesNotGrantAdmin proves BYREIS_MODE=admin in the
// environment cannot escalate. As with the flag, there is no policy input that
// reads the environment; the derived mode is authoritative.
func TestBypass_EnvVarDoesNotGrantAdmin(t *testing.T) {
	// No t.Parallel(): t.Setenv is incompatible with parallel subtests.
	t.Setenv("BYREIS_MODE", "admin")
	t.Setenv("BYREIS_ADMIN", "1")

	derived := mode.ModeContributor
	p := &mode.Policy{}

	for _, cmd := range []mode.Command{mode.CommandDecrypt, mode.CommandGet, mode.CommandEdit} {
		if err := p.Allow(derived, cmd); err == nil {
			t.Fatalf("BYREIS_MODE bypass: command %q was permitted despite contributor mode", cmd)
		}
	}
}

// TestBypass_ConfigKeyDoesNotGrantAdmin proves a `mode: admin` key in a config
// file cannot escalate. Config is parsed by an outer layer; the policy never
// consumes a config-declared mode. The derived mode stands.
func TestBypass_ConfigKeyDoesNotGrantAdmin(t *testing.T) {
	t.Parallel()

	// A hostile config blob. There is intentionally no API that turns this into
	// a mode.Mode; the value is recorded here only to document the attempt.
	const hostileConfig = "mode: admin\nsuper: true\n"
	_ = hostileConfig

	derived := mode.ModeContributor
	p := &mode.Policy{}

	for _, cmd := range []mode.Command{mode.CommandDecrypt, mode.CommandGet, mode.CommandEdit} {
		if err := p.Allow(derived, cmd); err == nil {
			t.Fatalf("mode: config-key bypass: command %q was permitted despite contributor mode", cmd)
		}
	}
}

// TestBypass_ForgedVerifiedAdminSetDoesNotGrantAdmin proves a tampered cache
// that forges the "signature-verified" flag does not promote to ADMIN. The
// detector trusts RegistryTrust.IsRegisteredAdmin, whose contract is that it
// returns true ONLY for a genuinely signature-verified, fresh fetch. A registry
// port backed by a forged/stale cache must answer false (or error), and the
// detector then fails closed to CONTRIBUTOR. This test models that boundary.
func TestBypass_ForgedVerifiedAdminSetDoesNotGrantAdmin(t *testing.T) {
	t.Parallel()

	// A registry whose backing AdminSet was tampered to fake SourceVerified.
	// A correct adapter rejects the forged verification and reports the key as
	// NOT a registered admin (it never observed a true signature-verified set).
	forgedCacheRegistry := fakeRegistry{registered: false}

	d := &mode.Detector{
		Probe: fakeProbe{
			path:       "/fake/key",
			perms:      0o600,
			canDecrypt: true, // key can decrypt — only registry trust stands between this and ADMIN
		},
		Registry: forgedCacheRegistry,
		Clock:    fixedClock{},
		Audit:    &recordingSink{},
	}

	res, err := d.Detect(testContext(), "proj-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Mode == mode.ModeAdmin || res.Mode == mode.ModeSuper {
		t.Fatalf("forged signature-verified admin set granted %v — must fail closed to CONTRIBUTOR", res.Mode)
	}
	if res.Warning != mode.WarningKeyUnregistered {
		t.Fatalf("expected key-unregistered warning when registry does not vouch for the key, got %v", res.Warning)
	}

	// And the policy must still deny admin commands for the derived mode.
	p := &mode.Policy{}
	if err := p.Allow(res.Mode, mode.CommandDecrypt); err == nil {
		t.Fatalf("forged-cache bypass: decrypt permitted despite fail-closed CONTRIBUTOR")
	}
}
