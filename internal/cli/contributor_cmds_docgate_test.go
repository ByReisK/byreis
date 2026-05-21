//go:build docgate

// V6.3 docgate row — BO-V6-CRYPTO-12 — `byreis request-access --help` carries
// the verbatim operator-honesty contract.
//
// This file discharges the V6.3 obligation: the contributor-side
// `request-access` verb's `--help` text MUST include the verbatim
// rotate.RequestAccessHonestyContract string at the verb's first contact, so
// operators understand the asymmetric-access invariant (the verb uses the
// contributor's own GitHub identity and never acquires an admin or
// registry-write credential).
//
// Assertion shape:
//   - Drive `runCobra("request-access", "--help")` through production cobra
//     composition.
//   - Capture stdout.
//   - Byte-equal substring assert that the captured help text contains the
//     verbatim constant rotate.RequestAccessHonestyContract.
//   - Byte-equal substring assert the flag list includes --key,
//     --justification, --registry (per the V6.2 verb signature).
//   - Byte-equal substring assert the verb description names the
//     contributor-side onboarding purpose.
//
// Build constraint: //go:build docgate ONLY. This tag is a sibling lane to
// shipgate; it is non-default, never compiled into a shipped binary.
//
// The test uses no real network, fs, keychain, or GitHub SDK: cobra's --help
// is a pure-stdout operation against the command tree.
package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// TestDocGate_RequestAccessHelp_VerbatimHonestyContract drives
// `byreis request-access --help` through the production cobra root and
// asserts the verbatim rotate.RequestAccessHonestyContract appears in
// stdout. A missing or modified honesty contract is release-blocking: the
// operator-facing trust surface of the contributor write path depends on
// this string being visible at the verb's first contact.
func TestDocGate_RequestAccessHelp_VerbatimHonestyContract(t *testing.T) {
	t.Parallel()

	// Mode is CONTRIBUTOR by construction; cobra's `--help` short-circuits
	// before any RunE invocation, but populating Policy + CurrentMode keeps
	// the dependency contract clean.
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	root := cli.NewRootCmdWithDeps(deps)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{"request-access", "--help"})

	if execErr := root.ExecuteContext(context.Background()); execErr != nil {
		t.Fatalf("request-access --help exited with error: %v "+
			"(stderr=%q, stdout=%q)", execErr, stderr.String(), stdout.String())
	}

	got := stdout.String()

	// (1) Verbatim honesty-contract substring — the load-bearing assertion.
	wantContract := rotate.RequestAccessHonestyContract
	if !strings.Contains(got, wantContract) {
		t.Fatalf("V6.3 BO-V6-CRYPTO-12: --help does not contain the verbatim "+
			"honesty contract.\nThis is release-blocking: operators rely on the "+
			"contributor verb naming the asymmetric-access invariant at first "+
			"contact.\n\nwant (substring):\n%q\n\ngot (full --help stdout):\n%q",
			wantContract, got)
	}

	// (2) Flag list must include --key, --justification, --registry per the
	// V6.2 verb signature. Help text mentions flags by name; cobra prints
	// "--key", "--justification", and "--registry" inclusive of the dashes.
	for _, wantFlag := range []string{"--key", "--justification", "--registry"} {
		if !strings.Contains(got, wantFlag) {
			t.Errorf("V6.3 BO-V6-CRYPTO-12: --help does not advertise required flag %q.\n"+
				"got:\n%s", wantFlag, got)
		}
	}

	// (3) Verb description must name the contributor-side onboarding
	// purpose. The Short:/Long: text says "Open a request-access PR" — that
	// is the canonical operator-facing description.
	if !strings.Contains(got, "request-access PR") {
		t.Errorf("V6.3 BO-V6-CRYPTO-12: --help does not describe the verb as "+
			"opening a request-access PR.\ngot:\n%s", got)
	}

	t.Logf("V6.3 BO-V6-CRYPTO-12: PASS — --help contains the verbatim "+
		"honesty contract (%d chars) and advertises the V6.2 flag set",
		len(wantContract))
}
