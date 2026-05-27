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
	//   rotate/rotation-reconcile : admin path only (denied for contributor) — V5.ROTATE.contributor-denied
	//
	// v0.2 V6 addition:
	//   request-access : contributor-only (permission inversion vs rotate);
	//     ADMIN and SUPER are DENIED (the admin path to add an admin is the
	//     out-of-band registry admin-add flow, not request-access).
	//
	// v0.2 V7 addition:
	//   request-list : admin-only read-only triage verb listing OPEN
	//     request-access PRs. The inverse of request-access: ADMIN and SUPER
	//     allowed, CONTRIBUTOR denied.
	//
	// v0.2 V8 addition:
	//   audit-show : admin-only read-only verb displaying signature-verified
	//     audit entries. Mirrors request-list: ADMIN and SUPER allowed,
	//     CONTRIBUTOR denied. Contributors read the audit log out-of-band via
	//     `git show audit/<project>.jsonl` + `git verify-commit`.
	//
	// v0.4 addition:
	//   request-reject : admin-only verb that closes a request/submission PR with
	//     a structured reason. Mirrors request-list: ADMIN and SUPER allowed,
	//     CONTRIBUTOR denied. PR-close-only; never loads a key or decrypts.
	//
	// v0.6 addition:
	//   audit-verify : all-modes read-only verb that runs the per-line audit
	//     binding walk and renders public commit metadata. Distinct from
	//     audit-show (which stays admin-only): verify carries no secret because
	//     the audit channel is public by the asymmetric design, and the capability
	//     is confined by the import graph (zero-key, zero-decrypt, read-only),
	//     NOT by a denial cell — so all three modes ALLOW.
	//
	// v0.7 addition:
	//   export : admin-only verb that emits decrypted plaintext to an external
	//     format. Byte-identical shape to decrypt/get (ADMIN and SUPER allowed,
	//     CONTRIBUTOR denied) — emitting plaintext is a privileged read, so it is
	//     gated by a denial cell, NOT the all-modes audit-verify shape.
	//
	// v0.8 addition:
	//   run : admin-only verb that decrypts the project's secrets and injects them
	//     into a spawned child process's environment. Byte-identical shape to
	//     export/decrypt/get (ADMIN and SUPER allowed, CONTRIBUTOR denied) — it
	//     decrypts and spawns with secrets, so it is a privileged read gated by a
	//     denial cell, NOT the all-modes audit-verify shape.
	allow := map[mode.Command]map[mode.Mode]bool{
		mode.CommandVersion:           {mode.ModeContributor: true, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandInit:              {mode.ModeContributor: true, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandDoctor:            {mode.ModeContributor: true, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandSubmit:            {mode.ModeContributor: true, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandReview:            {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandMerge:             {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandGet:               {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandDecrypt:           {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandEdit:              {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandRotate:            {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandRotationReconcile: {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandRequestAccess:     {mode.ModeContributor: true, mode.ModeAdmin: false, mode.ModeSuper: false},
		mode.CommandRequestList:       {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandAuditShow:         {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandRequestReject:     {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandAuditVerify:       {mode.ModeContributor: true, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandExport:            {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
		mode.CommandRun:               {mode.ModeContributor: false, mode.ModeAdmin: true, mode.ModeSuper: true},
	}

	allModes := []mode.Mode{mode.ModeContributor, mode.ModeAdmin, mode.ModeSuper}
	allCommands := []mode.Command{
		mode.CommandVersion, mode.CommandInit, mode.CommandDoctor, mode.CommandSubmit,
		mode.CommandReview, mode.CommandMerge, mode.CommandGet, mode.CommandDecrypt,
		mode.CommandEdit, mode.CommandRotate, mode.CommandRotationReconcile,
		mode.CommandRequestAccess, mode.CommandRequestList, mode.CommandAuditShow,
		mode.CommandRequestReject, mode.CommandAuditVerify, mode.CommandExport,
		mode.CommandRun,
	}

	// Guard: the expectation grid must cover the full cross-product so a missing
	// command or mode cannot silently shrink the asserted matrix.
	if len(allow) != len(allCommands) {
		t.Fatalf("expectation grid covers %d commands, want %d (full command set)", len(allow), len(allCommands))
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

	for _, cmd := range []mode.Command{
		mode.CommandReview, mode.CommandMerge, mode.CommandGet,
		mode.CommandDecrypt, mode.CommandEdit,
		mode.CommandRotate, mode.CommandRotationReconcile,
	} {
		if err := p.Allow(forged, cmd); err == nil {
			t.Fatalf("forged mode value allowed admin command %q — fail-closed violated", cmd)
		}
	}
}

// TestPolicy_AuditVerifyAllModesAllowedForgedDenied is the focused bypass set
// for the contributor audit-verify verb (T-S1-A). It asserts that every
// (CommandAuditVerify × {Contributor, Admin, Super}) cell resolves ALLOW — the
// verb is read-only and confined by the import graph, not by a denial cell — and
// that a forged/unknown mode.Command value still resolves DENY via the
// default-deny floor, so adding an all-modes verb does not open a hole for a
// typo'd or attacker-supplied command string.
func TestPolicy_AuditVerifyAllModesAllowedForgedDenied(t *testing.T) {
	t.Parallel()

	p := &mode.Policy{}

	for _, m := range []mode.Mode{mode.ModeContributor, mode.ModeAdmin, mode.ModeSuper} {
		if err := p.Allow(m, mode.CommandAuditVerify); err != nil {
			t.Fatalf("audit-verify must be ALLOW in %v mode, got deny: %v", m, err)
		}
	}

	// A forged command value that merely resembles audit-verify must not ride the
	// all-modes grant: it is unknown to the matrix and denied fail-closed.
	for _, m := range []mode.Mode{mode.ModeContributor, mode.ModeAdmin, mode.ModeSuper} {
		err := p.Allow(m, mode.Command("audit-verify-but-forged"))
		if err == nil {
			t.Fatalf("mode %v: forged audit-verify command was allowed — fail-closed violated", m)
		}
		if !errors.Is(err, mode.ErrPermissionDenied) {
			t.Fatalf("mode %v: forged-command denial must wrap ErrPermissionDenied, got %v", m, err)
		}
	}
}

// TestPolicy_AuditShowStaysAdminOnly is the regression guard (T-S1-D) proving
// the new all-modes audit-verify verb did NOT relax the admin-only audit-show
// cell. A contributor calling audit-show is still denied; admin and super still
// allowed. The contributor read path is a separate verb (audit-verify), never a
// relaxation of the plain-read show cell.
func TestPolicy_AuditShowStaysAdminOnly(t *testing.T) {
	t.Parallel()

	p := &mode.Policy{}

	if err := p.Allow(mode.ModeContributor, mode.CommandAuditShow); err == nil {
		t.Fatal("audit-show must stay DENY for contributor — the new audit-verify verb must not relax it")
	} else if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("audit-show contributor denial must wrap ErrPermissionDenied, got %v", err)
	}

	for _, m := range []mode.Mode{mode.ModeAdmin, mode.ModeSuper} {
		if err := p.Allow(m, mode.CommandAuditShow); err != nil {
			t.Fatalf("audit-show must stay ALLOW in %v mode, got deny: %v", m, err)
		}
	}
}

// TestPolicy_ExportAdminOnlyShape asserts the export verb cell directly: ALLOW
// for ADMIN and SUPER, DENY for CONTRIBUTOR. It also asserts the matrix shape is
// byte-identical to decrypt/get and explicitly DISTINCT from the all-modes
// audit-verify shape — export emits decrypted plaintext, so it must be a
// privileged read gated by a denial cell, never an all-modes verb.
func TestPolicy_ExportAdminOnlyShape(t *testing.T) {
	t.Parallel()

	p := &mode.Policy{}

	// AC-001-A: ADMIN and SUPER are allowed.
	for _, m := range []mode.Mode{mode.ModeAdmin, mode.ModeSuper} {
		if err := p.Allow(m, mode.CommandExport); err != nil {
			t.Fatalf("export must be ALLOW in %v mode, got deny: %v", m, err)
		}
	}

	// AC-001-B: CONTRIBUTOR is denied, fail-closed with the sentinel.
	if err := p.Allow(mode.ModeContributor, mode.CommandExport); err == nil {
		t.Fatal("export must be DENY for contributor — it emits decrypted plaintext")
	} else if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("export contributor denial must wrap ErrPermissionDenied, got %v", err)
	}

	// AC-001-D: export shares decrypt/get's shape (admin-only) and is DISTINCT
	// from the all-modes audit-verify shape. We prove this behaviourally: export
	// must match decrypt on every mode, and must differ from audit-verify in at
	// least the contributor cell.
	for _, m := range []mode.Mode{mode.ModeContributor, mode.ModeAdmin, mode.ModeSuper} {
		exportAllowed := p.Allow(m, mode.CommandExport) == nil
		decryptAllowed := p.Allow(m, mode.CommandDecrypt) == nil
		if exportAllowed != decryptAllowed {
			t.Fatalf("mode %v: export shape (%v) must match decrypt shape (%v)", m, exportAllowed, decryptAllowed)
		}
	}
	// Distinct from audit-verify: contributor is allowed audit-verify but denied export.
	if p.Allow(mode.ModeContributor, mode.CommandAuditVerify) != nil {
		t.Fatal("precondition: audit-verify must allow contributor")
	}
	if p.Allow(mode.ModeContributor, mode.CommandExport) == nil {
		t.Fatal("export must NOT inherit the all-modes audit-verify shape: contributor must be denied")
	}
}

// TestBypass_ExportNotPromotedByFlagEnvConfigForgedCache mirrors the existing
// bypass fixtures for the export verb (condition C3). Export emits plaintext, so
// no out-of-band channel — a `--mode admin` flag, BYREIS_MODE/BYREIS_ADMIN env,
// a `mode: admin` config key, or a forged "verified" cached admin set — may
// promote a contributor into running it. Policy.Allow accepts ONLY the
// crypto-derived mode; there is no parameter for any of these channels.
func TestBypass_ExportNotPromotedByFlagEnvConfigForgedCache(t *testing.T) {
	// No t.Parallel(): t.Setenv is incompatible with parallel subtests.
	t.Setenv("BYREIS_MODE", "admin")
	t.Setenv("BYREIS_ADMIN", "1")

	// Hostile flag/config blobs are inert: there is no API to feed them into the
	// policy. Documented here only to record the attempted channels.
	const userSuppliedModeFlag = "admin"
	const hostileConfig = "mode: admin\nsuper: true\n"
	_, _ = userSuppliedModeFlag, hostileConfig

	p := &mode.Policy{}

	// Flag/env/config channels: the only mode the policy sees is the derived one.
	derived := mode.ModeContributor
	if err := p.Allow(derived, mode.CommandExport); err == nil {
		t.Fatal("flag/env/config bypass: export permitted despite contributor mode")
	} else if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("export denial must wrap ErrPermissionDenied, got %v", err)
	}

	// Forged "signature-verified" cache: a correct registry adapter reports the
	// key as NOT registered, so the detector fails closed to CONTRIBUTOR, and the
	// policy then denies export.
	d := &mode.Detector{
		Probe: fakeProbe{
			path:       "/fake/key",
			perms:      0o600,
			canDecrypt: true,
		},
		Registry: fakeRegistry{registered: false},
		Clock:    fixedClock{},
		Audit:    &recordingSink{},
	}
	res, err := d.Detect(testContext(), "proj-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Mode == mode.ModeAdmin || res.Mode == mode.ModeSuper {
		t.Fatalf("forged-cache bypass: detector resolved %v — must fail closed to CONTRIBUTOR", res.Mode)
	}
	if err := p.Allow(res.Mode, mode.CommandExport); err == nil {
		t.Fatal("forged-cache bypass: export permitted despite fail-closed CONTRIBUTOR")
	}
}

// TestPolicy_RunAdminOnlyShape asserts the run verb cell directly: ALLOW for
// ADMIN and SUPER, DENY for CONTRIBUTOR. It also asserts the matrix shape is
// byte-identical to export/decrypt/get and explicitly DISTINCT from the
// all-modes audit-verify shape — run decrypts the project's secrets and spawns
// a child process with them in its environment, so it must be a privileged read
// gated by a denial cell, never an all-modes verb.
func TestPolicy_RunAdminOnlyShape(t *testing.T) {
	t.Parallel()

	p := &mode.Policy{}

	// AC-001-A: ADMIN and SUPER are allowed.
	for _, m := range []mode.Mode{mode.ModeAdmin, mode.ModeSuper} {
		if err := p.Allow(m, mode.CommandRun); err != nil {
			t.Fatalf("run must be ALLOW in %v mode, got deny: %v", m, err)
		}
	}

	// AC-001-B: CONTRIBUTOR is denied, fail-closed with the sentinel.
	if err := p.Allow(mode.ModeContributor, mode.CommandRun); err == nil {
		t.Fatal("run must be DENY for contributor — it decrypts secrets and spawns with them")
	} else if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("run contributor denial must wrap ErrPermissionDenied, got %v", err)
	}

	// AC-001-D: run shares export/decrypt's shape (admin-only) and is DISTINCT
	// from the all-modes audit-verify shape. We prove this behaviourally: run
	// must match export and decrypt on every mode, and must differ from
	// audit-verify in at least the contributor cell.
	for _, m := range []mode.Mode{mode.ModeContributor, mode.ModeAdmin, mode.ModeSuper} {
		runAllowed := p.Allow(m, mode.CommandRun) == nil
		exportAllowed := p.Allow(m, mode.CommandExport) == nil
		decryptAllowed := p.Allow(m, mode.CommandDecrypt) == nil
		if runAllowed != exportAllowed {
			t.Fatalf("mode %v: run shape (%v) must match export shape (%v)", m, runAllowed, exportAllowed)
		}
		if runAllowed != decryptAllowed {
			t.Fatalf("mode %v: run shape (%v) must match decrypt shape (%v)", m, runAllowed, decryptAllowed)
		}
	}
	// Distinct from audit-verify: contributor is allowed audit-verify but denied run.
	if p.Allow(mode.ModeContributor, mode.CommandAuditVerify) != nil {
		t.Fatal("precondition: audit-verify must allow contributor")
	}
	if p.Allow(mode.ModeContributor, mode.CommandRun) == nil {
		t.Fatal("run must NOT inherit the all-modes audit-verify shape: contributor must be denied")
	}
}

// TestBypass_RunNotPromotedByFlagEnvConfigForgedCache mirrors the export bypass
// fixture for the run verb. Run decrypts secrets and spawns a child with them,
// so no out-of-band channel — a `--mode admin` flag, BYREIS_MODE/BYREIS_ADMIN
// env, a `mode: admin` config key, or a forged "verified" cached admin set — may
// promote a contributor into running it. Policy.Allow accepts ONLY the
// crypto-derived mode; there is no parameter for any of these channels.
func TestBypass_RunNotPromotedByFlagEnvConfigForgedCache(t *testing.T) {
	// No t.Parallel(): t.Setenv is incompatible with parallel subtests.
	t.Setenv("BYREIS_MODE", "admin")
	t.Setenv("BYREIS_ADMIN", "1")

	// Hostile flag/config blobs are inert: there is no API to feed them into the
	// policy. Documented here only to record the attempted channels.
	const userSuppliedModeFlag = "admin"
	const hostileConfig = "mode: admin\nsuper: true\n"
	_, _ = userSuppliedModeFlag, hostileConfig

	p := &mode.Policy{}

	// Flag/env/config channels: the only mode the policy sees is the derived one.
	derived := mode.ModeContributor
	if err := p.Allow(derived, mode.CommandRun); err == nil {
		t.Fatal("flag/env/config bypass: run permitted despite contributor mode")
	} else if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("run denial must wrap ErrPermissionDenied, got %v", err)
	}

	// Forged "signature-verified" cache: a correct registry adapter reports the
	// key as NOT registered, so the detector fails closed to CONTRIBUTOR, and the
	// policy then denies run (so no decrypt and no child spawn is ever reached).
	d := &mode.Detector{
		Probe: fakeProbe{
			path:       "/fake/key",
			perms:      0o600,
			canDecrypt: true,
		},
		Registry: fakeRegistry{registered: false},
		Clock:    fixedClock{},
		Audit:    &recordingSink{},
	}
	res, err := d.Detect(testContext(), "proj-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Mode == mode.ModeAdmin || res.Mode == mode.ModeSuper {
		t.Fatalf("forged-cache bypass: detector resolved %v — must fail closed to CONTRIBUTOR", res.Mode)
	}
	if err := p.Allow(res.Mode, mode.CommandRun); err == nil {
		t.Fatal("forged-cache bypass: run permitted despite fail-closed CONTRIBUTOR")
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
