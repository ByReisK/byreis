package mode_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// fixedClock is an injected, deterministic clock. No real time is ever read in
// these unit tests so the access-spine logic is fully reproducible.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() interface{ Unix() int64 } { return c.t }

// fakeProbe is an injected KeyProbe. Every probe answer is supplied by the test
// table; no real filesystem or key material is touched.
type fakeProbe struct {
	path       string
	perms      uint32
	permsErr   error
	canDecrypt bool
	decryptErr error
}

func (p fakeProbe) KeyFilePath(context.Context) string { return p.path }

func (p fakeProbe) KeyFilePerms(context.Context) (uint32, error) {
	return p.perms, p.permsErr
}

func (p fakeProbe) CanDecryptAny(context.Context, string) (bool, error) {
	return p.canDecrypt, p.decryptErr
}

// fakeRegistry is an injected RegistryTrust. It answers whether the current
// public key is in a signature-verified, fresh registry admin set. No network.
type fakeRegistry struct {
	registered bool
	err        error
}

func (r fakeRegistry) IsRegisteredAdmin(context.Context, string) (bool, error) {
	return r.registered, r.err
}

// recordingSink captures promotion events so the test can assert that an
// ADMIN promotion is written to the audit log exactly once.
type recordingSink struct {
	events []audit.Event
	failOn bool
}

func (s *recordingSink) Append(_ context.Context, e audit.Event) error {
	if s.failOn {
		return errors.New("audit backend unavailable")
	}
	s.events = append(s.events, e)
	return nil
}

var errProbeBoom = errors.New("probe backend exploded")

// testContext returns a plain background context for unit tests; isolated in a
// helper so the intent (no real deadline/cancellation wiring needed here) is
// explicit at call sites.
func testContext() context.Context { return context.Background() }

// TestDetect_ModeResolutionOrder drives every crypto-derived-mode acceptance
// case as a table. The detector must resolve mode purely from cryptographic
// reality and must fail closed: any miss or ambiguity yields CONTRIBUTOR, the
// bad-perms case is a hard refuse-to-run error, and ADMIN is only ever reached
// when the full chain succeeds against a signature-verified, fresh registry.
func TestDetect_ModeResolutionOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		probe    fakeProbe
		registry fakeRegistry

		wantMode      mode.Mode
		wantHardError bool         // expect a non-nil error AND refuse-to-run
		wantErrIs     error        // sentinel the error must wrap, if any
		wantPromotion bool         // expect exactly one mode.promotion audit event
		wantWarning   mode.Warning // expected advisory warning, if any
		bullet        string       // the mode-resolution rule this row exercises
	}{
		{
			name:        "no key file present resolves to contributor",
			probe:       fakeProbe{path: ""},
			wantMode:    mode.ModeContributor,
			wantWarning: mode.WarningNone,
			bullet:      "no private key file -> CONTRIBUTOR, no admin command permitted",
		},
		{
			name: "key file with loose perms is a hard refuse-to-run error",
			probe: fakeProbe{
				path:  "/fake/key",
				perms: 0o644,
			},
			wantMode:      mode.ModeContributor,
			wantHardError: true,
			wantErrIs:     mode.ErrKeyPermissions,
			bullet:        "perms looser than 0600 -> non-zero exit + chmod hint, never admin",
		},
		{
			name: "key file group-readable 0640 is a hard error",
			probe: fakeProbe{
				path:  "/fake/key",
				perms: 0o640,
			},
			wantMode:      mode.ModeContributor,
			wantHardError: true,
			wantErrIs:     mode.ErrKeyPermissions,
			bullet:        "perms looser than 0600 -> hard error, never admin",
		},
		{
			name: "key file too restrictive 0400 is still rejected (must be exactly 0600)",
			probe: fakeProbe{
				path:  "/fake/key",
				perms: 0o400,
			},
			wantMode:      mode.ModeContributor,
			wantHardError: true,
			wantErrIs:     mode.ErrKeyPermissions,
			bullet:        "perms not exactly 0600 -> hard error, never admin",
		},
		{
			name: "key perms cannot be stat'd is a hard error (fail closed, never admin)",
			probe: fakeProbe{
				path:     "/fake/key",
				permsErr: errProbeBoom,
			},
			wantMode:      mode.ModeContributor,
			wantHardError: true,
			wantErrIs:     mode.ErrKeyPermissions,
			bullet:        "ambiguity in the perms check -> hard error, never admin",
		},
		{
			name: "0600 key that cannot decrypt any project file resolves to contributor",
			probe: fakeProbe{
				path:       "/fake/key",
				perms:      0o600,
				canDecrypt: false,
			},
			wantMode:    mode.ModeContributor,
			wantWarning: mode.WarningNone,
			bullet:      "0600 key but cannot decrypt -> CONTRIBUTOR",
		},
		{
			name: "decrypt probe error fails closed to contributor (never admin)",
			probe: fakeProbe{
				path:       "/fake/key",
				perms:      0o600,
				decryptErr: errProbeBoom,
			},
			wantMode:    mode.ModeContributor,
			wantWarning: mode.WarningNone,
			bullet:      "ambiguity/error in the chain -> fail closed to CONTRIBUTOR",
		},
		{
			name: "0600 key decrypts but pubkey absent from verified registry -> contributor + unregistered warning",
			probe: fakeProbe{
				path:       "/fake/key",
				perms:      0o600,
				canDecrypt: true,
			},
			registry:    fakeRegistry{registered: false},
			wantMode:    mode.ModeContributor,
			wantWarning: mode.WarningKeyUnregistered,
			bullet:      "decrypts but key not in verified registry -> CONTRIBUTOR + explicit warning",
		},
		{
			name: "registry lookup error fails closed to contributor, never admin",
			probe: fakeProbe{
				path:       "/fake/key",
				perms:      0o600,
				canDecrypt: true,
			},
			registry:    fakeRegistry{err: errProbeBoom},
			wantMode:    mode.ModeContributor,
			wantWarning: mode.WarningNone,
			bullet:      "ambiguity/error in the chain -> fail closed to CONTRIBUTOR, never ADMIN",
		},
		{
			name: "0600 key decrypts and pubkey in verified fresh registry -> admin + audited promotion",
			probe: fakeProbe{
				path:       "/fake/key",
				perms:      0o600,
				canDecrypt: true,
			},
			registry:      fakeRegistry{registered: true},
			wantMode:      mode.ModeAdmin,
			wantPromotion: true,
			wantWarning:   mode.WarningNone,
			bullet:        "0600 key decrypts + key in verified registry -> ADMIN, promotion audited",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sink := &recordingSink{}
			d := &mode.Detector{
				Probe:    tc.probe,
				Registry: tc.registry,
				Clock:    fixedClock{t: time.Unix(1_700_000_000, 0)},
				Audit:    sink,
			}

			res, err := d.Detect(context.Background(), "proj-1")

			if tc.wantHardError {
				if err == nil {
					t.Fatalf("bullet %q: expected hard refuse-to-run error, got nil", tc.bullet)
				}
				if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("bullet %q: error %v does not wrap sentinel %v", tc.bullet, err, tc.wantErrIs)
				}
				// A hard error must NEVER yield ADMIN.
				if res.Mode == mode.ModeAdmin {
					t.Fatalf("bullet %q: hard-error path resolved to ADMIN — fail-closed violated", tc.bullet)
				}
				if len(sink.events) != 0 {
					t.Fatalf("bullet %q: hard-error path wrote %d audit events, want 0", tc.bullet, len(sink.events))
				}
				return
			}

			if err != nil {
				t.Fatalf("bullet %q: unexpected error: %v", tc.bullet, err)
			}
			if res.Mode != tc.wantMode {
				t.Fatalf("bullet %q: got mode %v, want %v", tc.bullet, res.Mode, tc.wantMode)
			}
			if res.Warning != tc.wantWarning {
				t.Fatalf("bullet %q: got warning %v, want %v", tc.bullet, res.Warning, tc.wantWarning)
			}

			if tc.wantPromotion {
				if len(sink.events) != 1 {
					t.Fatalf("bullet %q: want exactly 1 promotion audit event, got %d", tc.bullet, len(sink.events))
				}
				if sink.events[0].Kind != audit.EventKindModePromotion {
					t.Fatalf("bullet %q: audit event kind = %q, want %q", tc.bullet, sink.events[0].Kind, audit.EventKindModePromotion)
				}
				if sink.events[0].ProjectID != "proj-1" {
					t.Fatalf("bullet %q: audit event project = %q, want proj-1", tc.bullet, sink.events[0].ProjectID)
				}
			} else if len(sink.events) != 0 {
				t.Fatalf("bullet %q: non-admin path wrote %d audit events, want 0", tc.bullet, len(sink.events))
			}
		})
	}
}

// TestDetect_AuditFailureBlocksPromotion asserts that if the promotion cannot be
// durably recorded, the detector fails closed: it does NOT silently grant ADMIN
// off an unrecorded promotion. An admin promotion that cannot be audited is a
// security event and must not proceed.
func TestDetect_AuditFailureBlocksPromotion(t *testing.T) {
	t.Parallel()

	d := &mode.Detector{
		Probe: fakeProbe{
			path:       "/fake/key",
			perms:      0o600,
			canDecrypt: true,
		},
		Registry: fakeRegistry{registered: true},
		Clock:    fixedClock{t: time.Unix(1_700_000_000, 0)},
		Audit:    &recordingSink{failOn: true},
	}

	res, err := d.Detect(context.Background(), "proj-1")
	if err == nil {
		t.Fatalf("expected error when promotion cannot be audited, got nil")
	}
	if res.Mode == mode.ModeAdmin {
		t.Fatalf("promotion was not audited yet mode resolved to ADMIN — fail-closed violated")
	}
}

// TestDetect_RequiresInjectedDependencies asserts the detector validates its
// injected ports up front rather than nil-panicking deep in the resolution
// chain — a security path must fail closed with a clear error, never panic.
func TestDetect_RequiresInjectedDependencies(t *testing.T) {
	t.Parallel()

	d := &mode.Detector{} // no ports injected
	res, err := d.Detect(context.Background(), "proj-1")
	if err == nil {
		t.Fatalf("expected configuration error when ports are not injected, got nil")
	}
	if res.Mode == mode.ModeAdmin {
		t.Fatalf("misconfigured detector resolved to ADMIN — fail-closed violated")
	}
}
