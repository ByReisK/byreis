package render

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

// sortedEqual compares two "KEY=VALUE" slices as sets (env order is not
// security-relevant for a process environment).
func sortedEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string{}, a...)
	bc := append([]string{}, b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// TestBuildChildEnvBlock_InjectedWins verifies the merge rule: an injected
// secret overrides an inherited parent-env entry of the same name, while
// non-colliding inherited entries survive.
func TestBuildChildEnvBlock_InjectedWins(t *testing.T) {
	t.Parallel()

	parent := []string{"PATH=/usr/bin", "API_KEY=inherited-loser", "HOME=/home/u"}
	pairs := []EnvPair{
		{Var: "API_KEY", Value: "injected-winner"},
		{Var: "DB_HOST", Value: "db.local"},
	}

	block, err := BuildChildEnvBlock(parent, pairs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{
		"PATH=/usr/bin",
		"HOME=/home/u",
		"API_KEY=injected-winner",
		"DB_HOST=db.local",
	}
	if !sortedEqual(block, want) {
		t.Errorf("block = %v, want (as set) %v", block, want)
	}
	// The inherited API_KEY must not survive in any form.
	for _, e := range block {
		if e == "API_KEY=inherited-loser" {
			t.Error("inherited API_KEY survived; injected value must win")
		}
	}
}

// TestBuildChildEnvBlock_EmptyPairs: no injected pairs returns the inherited env
// unchanged (clean passthrough for the empty-secret-set case).
func TestBuildChildEnvBlock_EmptyPairs(t *testing.T) {
	t.Parallel()

	parent := []string{"PATH=/usr/bin", "HOME=/home/u"}
	block, err := BuildChildEnvBlock(parent, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sortedEqual(block, parent) {
		t.Errorf("block = %v, want inherited env %v", block, parent)
	}
}

// TestBuildChildEnvBlock_NulRejected: a NUL byte in any injected value is
// rejected fail-closed and the error names the variable only (never the value).
func TestBuildChildEnvBlock_NulRejected(t *testing.T) {
	t.Parallel()

	const secret = "abc\x00SENSITIVE"
	pairs := []EnvPair{{Var: "TOKEN", Value: secret}}
	block, err := BuildChildEnvBlock([]string{"PATH=/usr/bin"}, pairs)
	if err == nil {
		t.Fatal("expected ErrNulInValue, got nil")
	}
	if !errors.Is(err, ErrNulInValue) {
		t.Errorf("expected error wrapping ErrNulInValue, got: %v", err)
	}
	if block != nil {
		t.Errorf("no block must be returned on NUL error, got: %v", block)
	}
	if strings.Contains(err.Error(), "SENSITIVE") {
		t.Errorf("error leaked the secret value: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "TOKEN") {
		t.Errorf("error should name the variable %q, got: %q", "TOKEN", err.Error())
	}
}

// TestBuildChildEnvBlock_MalformedParentEntry: a parent entry without an '='
// (rare but possible) is treated as a bare name and survives unless overridden.
func TestBuildChildEnvBlock_MalformedParentEntry(t *testing.T) {
	t.Parallel()

	parent := []string{"BARE", "PATH=/usr/bin"}
	pairs := []EnvPair{{Var: "API_KEY", Value: "v"}}
	block, err := BuildChildEnvBlock(parent, pairs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"BARE", "PATH=/usr/bin", "API_KEY=v"}
	if !sortedEqual(block, want) {
		t.Errorf("block = %v, want %v", block, want)
	}
}
