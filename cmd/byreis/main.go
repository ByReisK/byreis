// Command byreis is the entry point for the byreis CLI.
// It wires the cobra root, builds adapters, injects them into core, and sets
// the process exit code. No business logic lives here.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/artifactcodec"
	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/mode"
)

func main() {
	ctx := context.Background()

	deps := buildDeps(ctx)

	root := cli.NewRootCmdWithDeps(deps)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(cli.ExitCodeOf(err))
	}
}

// buildDeps constructs the real Deps for the production wiring path. It calls
// Detector.Detect before command dispatch so every command receives the
// cryptographically-derived mode. On any detector error or misconfiguration
// the deps fall back to least privilege (ModeContributor) with a non-nil Policy
// so review/merge/get/decrypt/edit hit a real denial, not a nil-skip.
//
// The read-path use-cases (Get/Decrypt/Edit) are wired via app.BuildReadPathDeps
// with the real artifactcodec.PortAdapter adapter. Adapters that require real
// tokens/config (fileofrecord.Source, identity.Loader, etc.) fall back to nil
// when not yet configured; the CLI surfaces "not wired" on those paths.
func buildDeps(ctx context.Context) *cli.Deps {
	det := realDetector()
	pol := &mode.Policy{}

	detResult, err := det.Detect(ctx, projectIDFromEnv())
	var currentMode mode.Mode
	if err != nil {
		// Fail closed: least privilege. Policy is still non-nil so all
		// admin-only commands receive a real ErrPermissionDenied denial.
		currentMode = mode.ModeContributor
	} else {
		currentMode = detResult.Mode
	}

	// Wire the real YAML artifact codec adapter. PortAdapter wraps the Codec
	// and satisfies usecase.ArtifactCodec (no-context port). It is constructed
	// once and injected behind the narrow port interface — never passed to a
	// use-case as *PortAdapter.
	codec := artifactcodec.NewPortAdapter(artifactcodec.New())

	// Build a mode gate adapter from the resolved mode. This wraps the Policy
	// so the use-cases receive the narrow ModeGate interface, not the *Policy.
	gate := &policyModeGate{pol: pol, m: currentMode}

	// Build the read-path use-cases. Each receives only its narrow port
	// interface. Source/IDLoader/Verifier/Recipients/Counter are nil when the
	// real adapters (git token, registry config) are not yet wired; the
	// resulting nil use-cases cause the CLI to surface "not configured".
	//
	// The Edit-specific ports (encryptor, signer, writer, editor) are nil here
	// because the admin signing key and repo-root adapter are not yet wired.
	// BuildReadPathDeps returns nil EditUseCase without error in this interim.
	//
	// Invariant: a non-nil error from BuildReadPathDeps here signals an
	// unexpected construction failure (not the expected nil-port interim), and
	// must fail closed rather than silently proceeding with nil use-cases.
	getter, decryptor, editor, buildErr := app.BuildReadPathDeps(
		nil,          // FileOfRecordSource: nil until git token adapter is wired
		codec,        // ArtifactCodec: real YAML codec
		nil,          // decrypt.Decryptor: nil until identity loader is wired
		nil,          // identity.Loader: nil until keychain adapter is wired
		verify.New(), // verify.VerifierOfRecord: always available (pure crypto)
		nil,          // RecipientSource: nil until registry client is wired
		nil,          // CounterStore: nil until registry client is wired
		gate,         // ModeGate: real policy gate
		nil,          // encrypt.Encryptor: nil until Edit is fully wired
		nil,          // usecase.ManifestSigner: nil until admin key adapter is wired
		nil,          // usecase.AtomicFileWriter: nil until repo-root config is wired
		nil,          // usecase.Editor: nil until TTY/$EDITOR adapter is wired
	)

	// BuildReadPathDeps returns nil use-cases when required base ports are nil.
	// That is the expected interim at this build step; the CLI will surface
	// actionable "not wired" errors when the commands are invoked.
	//
	// A non-nil error here is unexpected (it means a provided non-nil port
	// caused a construction failure inside NewGetter/NewDecryptor/NewEditor).
	// Fail closed: log and exit immediately rather than proceeding with a
	// partially-wired command tree that might silently succeed where it should
	// fail.
	if buildErr != nil {
		fmt.Fprintf(os.Stderr,
			"error: byreis: unexpected failure constructing read-path use-cases "+
				"(this is a programming error at the composition root, not a missing "+
				"adapter): %v\n", buildErr)
		os.Exit(int(cli.ExitCodeOf(buildErr)))
	}

	return &cli.Deps{
		Policy:      pol,
		CurrentMode: currentMode,
		ConfigDir:   configDirFromEnv(),
		Getter:      getter,
		Decryptor:   decryptor,
		Editor:      editor,
	}
}

// realDetector builds a mode.Detector using no-op probes. Full adapter wiring
// (keychain, registry) will be added as the adapters are completed. The
// detector is functional for the permission gate: with no-op probes it always
// resolves ModeContributor (least privilege), which is the correct safe default
// before the key/registry adapters are wired.
func realDetector() *mode.Detector {
	return &mode.Detector{
		Probe:    &noopKeyProbe{},
		Registry: &noopRegistryTrust{},
		Clock:    &wallClock{},
		Audit:    audit.Discard,
	}
}

// projectIDFromEnv reads the project ID from the environment for mode
// detection. An empty string is safe: mode detection falls back to
// ModeContributor when no project can be identified.
func projectIDFromEnv() string {
	return os.Getenv("BYREIS_PROJECT")
}

// configDirFromEnv returns the config directory path. Defaults to
// ~/.config/byreis/ following the BYREIS_CONFIG env var convention.
func configDirFromEnv() string {
	if v := os.Getenv("BYREIS_CONFIG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.config/byreis"
}

// ---- no-op mode ports for the production skeleton ---------------------------
// Full implementations will be wired when the keychain/registry adapters land.
// These no-ops produce ModeContributor (least privilege) without any I/O.

type noopKeyProbe struct{}

func (n *noopKeyProbe) KeyFilePath(_ context.Context) string                    { return "" }
func (n *noopKeyProbe) KeyFilePerms(_ context.Context) (uint32, error)          { return 0, nil }
func (n *noopKeyProbe) CanDecryptAny(_ context.Context, _ string) (bool, error) { return false, nil }

type noopRegistryTrust struct{}

func (n *noopRegistryTrust) IsRegisteredAdmin(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// wallClock wraps time.Now() for mode detection. Real wall clock is appropriate
// here: main.go is the wiring layer, not a unit test.
type wallClock struct{}

func (w *wallClock) Now() interface{ Unix() int64 } {
	return time.Now()
}

// policyModeGate wraps mode.Policy and the resolved mode, implementing
// usecase.ModeGate. This is the narrow interface injected into use-cases;
// use-cases never receive a *mode.Policy directly.
type policyModeGate struct {
	pol *mode.Policy
	m   mode.Mode
}

func (g *policyModeGate) Allow(cmd mode.Command) error {
	return g.pol.Allow(g.m, cmd)
}
