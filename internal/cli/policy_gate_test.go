package cli_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// TestPolicyGate_ContributorMode_AdminCommandsDenied exercises the production
// wiring path: a populated Deps with CurrentMode=ModeContributor and a non-nil
// Policy must deny review/admin merge/get/decrypt/edit with ErrPermissionDenied
// and ExitPermissionDenied. This verifies the denied-not-attempted property
// through the shipped entry point, not only injected fakes.
func TestPolicyGate_ContributorMode_AdminCommandsDenied(t *testing.T) {
	t.Parallel()

	// Build a Deps that mirrors the production wiring path: Policy is non-nil,
	// CurrentMode is ModeContributor (no admin key). This is the state produced
	// by buildDeps() in cmd/byreis/main.go when no admin key is present.
	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
	}

	// Commands that are ADMIN-only and must be denied.
	adminCommands := []struct {
		args    []string
		cmdName string
	}{
		{[]string{"review", "--pr", "1"}, "review"},
		{[]string{"admin", "merge", "--project", "proj", "--file", "prod", "--pr", "proj/repo#1"}, "admin merge"},
		{[]string{"get", "--key", "mykey", "--project", "proj", "--file", "prod"}, "get"},
		{[]string{"decrypt", "--project", "proj", "--file", "prod"}, "decrypt"},
		{[]string{"edit", "--project", "proj", "--file", "prod"}, "edit"},
	}

	for _, tc := range adminCommands {
		tc := tc
		t.Run(tc.cmdName, func(t *testing.T) {
			t.Parallel()

			root := cli.NewRootCmdWithDeps(deps)
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(tc.args)

			err := root.Execute()
			if err == nil {
				t.Fatalf("%s: expected ErrPermissionDenied, got nil", tc.cmdName)
			}

			// The error must wrap ErrPermissionDenied (denied-not-attempted).
			if !errors.Is(err, mode.ErrPermissionDenied) {
				t.Errorf("%s: expected error wrapping mode.ErrPermissionDenied, got: %v",
					tc.cmdName, err)
			}

			// The exit code must be ExitPermissionDenied.
			exitCode := cli.ExitCodeOf(err)
			if exitCode != int(render.ExitPermissionDenied) {
				t.Errorf("%s: expected exit code %d (ExitPermissionDenied), got %d",
					tc.cmdName, render.ExitPermissionDenied, exitCode)
			}
		})
	}
}

// TestPolicyGate_NilPolicy_AdminCommandsDenied verifies that when Policy is
// nil (the nil-skip is absent), admin-only commands (review/admin merge/get/
// decrypt/edit) still produce ErrPermissionDenied via the default-deny else
// branch. This is the belt-and-suspenders guard: even without a wired Policy,
// no admin command silently succeeds.
func TestPolicyGate_NilPolicy_AdminCommandsDenied(t *testing.T) {
	t.Parallel()

	// Nil Policy — exercises the default-deny else branch in checkPolicy and
	// the existing else branches in get/decrypt/edit.
	deps := &cli.Deps{
		Policy:      nil,
		CurrentMode: mode.ModeContributor,
	}

	adminCommands := []struct {
		args    []string
		cmdName string
	}{
		{[]string{"review", "--pr", "1"}, "review"},
		{[]string{"admin", "merge", "--project", "proj", "--file", "prod", "--pr", "proj/repo#1"}, "admin merge"},
		{[]string{"get", "--key", "mykey", "--project", "proj", "--file", "prod"}, "get"},
		{[]string{"decrypt", "--project", "proj", "--file", "prod"}, "decrypt"},
		{[]string{"edit", "--project", "proj", "--file", "prod"}, "edit"},
	}

	for _, tc := range adminCommands {
		tc := tc
		t.Run(tc.cmdName, func(t *testing.T) {
			t.Parallel()

			root := cli.NewRootCmdWithDeps(deps)
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs(tc.args)

			err := root.Execute()
			if err == nil {
				t.Fatalf("%s: expected ErrPermissionDenied with nil Policy, got nil", tc.cmdName)
			}
			if !errors.Is(err, mode.ErrPermissionDenied) {
				t.Errorf("%s: expected error wrapping mode.ErrPermissionDenied with nil Policy, got: %v",
					tc.cmdName, err)
			}
			exitCode := cli.ExitCodeOf(err)
			if exitCode != int(render.ExitPermissionDenied) {
				t.Errorf("%s: expected ExitPermissionDenied exit code with nil Policy, got %d",
					tc.cmdName, exitCode)
			}
		})
	}
}

// TestPolicyGate_Submit_AllowedInContributorMode verifies that submit is
// permitted for CONTRIBUTOR mode (it is on the open path).
func TestPolicyGate_Submit_AllowedInContributorMode(t *testing.T) {
	t.Parallel()

	deps := &cli.Deps{
		Policy:      &mode.Policy{},
		CurrentMode: mode.ModeContributor,
	}

	root := cli.NewRootCmdWithDeps(deps)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"submit", "--key", "mykey"})

	err := root.Execute()
	// submit passes the policy gate (CONTRIBUTOR is permitted) but fails with
	// "not yet implemented" because adapters are not wired. We check that the
	// error is NOT ErrPermissionDenied — the policy gate did not deny it.
	if errors.Is(err, mode.ErrPermissionDenied) {
		t.Error("submit must NOT be denied in CONTRIBUTOR mode — it is on the open path")
	}
}
