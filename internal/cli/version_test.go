package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/pkg/byreis"
)

func TestVersionCommand_PrintsVersion(t *testing.T) {
	root := cli.NewRootCmd()

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("version command returned error: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, byreis.Version) {
		t.Errorf("version output %q does not contain version string %q", got, byreis.Version)
	}
}

func TestVersionCommand_JSONFlag(t *testing.T) {
	root := cli.NewRootCmd()

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--json", "version"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("version --json returned error: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, `"version"`) {
		t.Errorf("--json output %q does not contain JSON 'version' key", got)
	}
	if !strings.Contains(got, byreis.Version) {
		t.Errorf("--json output %q does not contain version string %q", got, byreis.Version)
	}
}

func TestVersionCommand_NoArgs(t *testing.T) {
	root := cli.NewRootCmd()

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version", "extra-arg"})

	err := root.Execute()
	if err == nil {
		t.Error("expected error for extra argument, got nil")
	}
}
