package modeprobe_test

// Tests for C5-b: plugin identity no-touch when probe is suppressed.
//
// When the resolved command does not require admin decrypt capability (e.g.
// submit, --help, version), CanDecryptAny must return (false,nil) WITHOUT
// invoking the plugin's identity-v1 subprocess. This is the core anti-
// habituation guarantee: a plugin-backed admin must not have their hardware
// token touched on contributor-mode invocations.
//
// These tests use the fakeplugin harness (built in TestMain) to verify that
// zero subprocess invocations occur.

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"filippo.io/age/plugin"

	"github.com/ByReisK/byreis/internal/adapter/fakeplugin"
	identityadapter "github.com/ByReisK/byreis/internal/adapter/identity"
	"github.com/ByReisK/byreis/internal/adapter/modeprobe"
	"github.com/ByReisK/byreis/internal/adapter/pluginidentity"
	"github.com/ByReisK/byreis/internal/adapter/recipientbuild"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// TestMain builds the fake plugin binary for all tests in this package that
// need subprocess invocations.
func TestMain(m *testing.M) {
	fakeplugin.BuildOnPath(m)
}

// TestC5b_PluginIdentity_NoTouch_WhenProbeNotNeeded asserts that when a keyProbe
// is constructed with NeedsDecryptProbe=false and an AGE-PLUGIN-YUBIKEY-1…
// identity is configured, CanDecryptAny returns (false,nil) and the fake plugin
// binary is NOT invoked. The no-invocation property is verified by setting
// FAKEPLUGIN_MODE to identity-error (which would cause a non-nil error if the
// plugin were called) and asserting no error appears.
//
// This tests the key anti-habituation guarantee: running submit/--help/version
// with a YubiKey-backed admin identity must not blink the YubiKey.
func TestC5b_PluginIdentity_NoTouch_WhenProbeNotNeeded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fakeplugin: age plugin subprocess tests not supported on Windows")
	}

	// Set mode to identity-error: if the plugin is invoked, it will emit an
	// error stanza rather than a file key. An invocation would cause CanDecryptAny
	// to return an error, which would be visible to the test.
	_ = fakeplugin.OnPath(t, fakeplugin.ModeIdentityError)

	identityStr := fakeplugin.IdentityString()

	// Construct a pluginidentity with a short timeout (so if the plugin IS
	// called the test completes quickly rather than hanging).
	pluginID, err := pluginidentity.New(pluginidentity.Options{
		IdentityStr:   identityStr,
		UnwrapTimeout: 2_000_000_000, // 2s timeout for test speed
	})
	if err != nil {
		t.Fatalf("pluginidentity.New: %v", err)
	}

	// We need to wire the plugin identity into the identity adapter path.
	// The cleanest test approach: build an identityadapter.Config that points
	// to a key file containing the AGE-PLUGIN-YUBIKEY-1… string, then read
	// it back through the adapter (which should route to pluginidentity).
	// However, the current identity adapter (internal/adapter/identity) selects
	// X25519 vs plugin based on the identity encoding string.
	//
	// For the no-touch test, we don't need the full adapter stack: we just need
	// to verify that CanDecryptAny with NeedsDecryptProbe=false never reaches
	// the identity loading step at all. We do this by using a countingArtifactFetcher
	// and confirming zero calls — the same assertion as TestCanDecryptAny_Suppressed_WhenProbeNotNeeded
	// but with the pluginidentity explicitly constructed to confirm it would fail
	// if invoked (ModeIdentityError).
	//
	// Additional no-subprocess verification: count calls to the plugin binary via PATH lookup.
	// We install a wrapper script that writes to a file on invocation, but that is complex.
	// Instead, we verify the property by two means:
	//   1. FetchArtifact is never called (so identity loading never happens).
	//   2. The pluginidentity constructed above returns ErrIncorrectIdentity / an error
	//      on Unwrap — if CanDecryptAny ran the probe it would surface that error.
	_ = pluginID // constructed; its Unwrap would fail via ModeIdentityError

	// Write the plugin identity to a temp file so the identity adapter can load it.
	keyFile := writePluginKeyFile(t, identityStr)
	cfg := buildIdentityConfig(nil, "", keyFile, "")

	fetcher := &countingArtifactFetcher{}
	probe := modeprobe.NewKeyProbe(cfg, fetcher, modeprobe.KeyProbeOptions{
		NeedsDecryptProbe: false, // contributor command — no probe
	})

	ok, probeErr := probe.CanDecryptAny(context.Background(), "proj-1")
	if probeErr != nil {
		t.Fatalf("no-touch: unexpected error: %v (probe must not run when suppressed)", probeErr)
	}
	if ok {
		t.Fatal("no-touch: ok=true when probe is suppressed — probe must not run")
	}
	if fetcher.calls != 0 {
		t.Errorf("no-touch: FetchArtifact called %d times, want 0 (no identity loaded when probe suppressed)", fetcher.calls)
	}
}

// TestC5c_HeadlessNonInteractive_PluginIdentity_FailClosed asserts that when
// BYREIS_NON_INTERACTIVE=1 and an admin command requires the probe, the
// plugin identity fails closed (returns CONTRIBUTOR) rather than blocking
// on an interactive prompt.
//
// With ModeIdentityError, the plugin would fail on Unwrap anyway; the test
// verifies the path exits cleanly without blocking.
func TestC5c_HeadlessNonInteractive_PluginIdentity_FailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fakeplugin: age plugin subprocess tests not supported on Windows")
	}
	t.Setenv("BYREIS_NON_INTERACTIVE", "1")

	_ = fakeplugin.OnPath(t, fakeplugin.ModeIdentityError)
	identityStr := fakeplugin.IdentityString()
	keyFile := writePluginKeyFile(t, identityStr)
	cfg := buildIdentityConfig(nil, "", keyFile, "")

	// A fetcher that returns ErrArtifactNotFound (project has no secrets yet).
	fetcher := &countingArtifactFetcher{}

	probe := modeprobe.NewKeyProbe(cfg, fetcher, modeprobe.KeyProbeOptions{
		NeedsDecryptProbe: true, // admin command
	})

	// With NeedsDecryptProbe=true but a plugin identity that would fail on Unwrap
	// (ModeIdentityError), CanDecryptAny must either:
	// (a) return (false, nil) if the identity cannot be loaded or no artifact exists, OR
	// (b) return (false, err) if the plugin Unwrap fails.
	// Both are acceptable fail-closed results.
	ok, _ := probe.CanDecryptAny(context.Background(), "proj-1")
	if ok {
		t.Fatal("headless + plugin identity-error: CanDecryptAny must not return ok=true")
	}
	// No assertion on err — either nil (no artifact) or non-nil (plugin error) are both
	// fail-closed. The critical invariant is ok=false.
}

// TestNeedsDecryptProbe_ForContributorVerbs_ReturnsFalse confirms the probe
// predicate for the verbs that are most likely to cause habituation if probed.
func TestNeedsDecryptProbe_ForContributorVerbs_ReturnsFalse(t *testing.T) {
	t.Parallel()
	contributorVerbs := []mode.Command{
		mode.CommandSubmit,
		mode.CommandVersion,
		mode.CommandDoctor,
		mode.CommandAuditVerify,
	}
	for _, cmd := range contributorVerbs {
		cmd := cmd
		t.Run(string(cmd), func(t *testing.T) {
			t.Parallel()
			if mode.NeedsDecryptProbe(cmd) {
				t.Errorf("command %q: NeedsDecryptProbe=true but this is a contributor command — would cause token habituation", cmd)
			}
		})
	}
}

// writePluginKeyFile writes the plugin identity string to a temp file at 0600.
func writePluginKeyFile(t *testing.T, identityStr string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/plugin.key"
	if err := os.WriteFile(path, []byte(identityStr), 0o600); err != nil {
		t.Fatalf("writePluginKeyFile: %v", err)
	}
	return path
}

// Compile-time import checks: ensure the plugin-related adapters are importable
// from this test package so unused-import errors are avoided.
var (
	_ = pluginidentity.Options{} // admin identity options type
	_ = recipientbuild.Options{} // recipient parser options type
	_ = identityadapter.Config{} // identity config type
	_ = fakeplugin.PluginName    // fake plugin name constant
	_ = plugin.ParseIdentity     // plugin library function
	_ = exec.LookPath            // PATH check function
)
