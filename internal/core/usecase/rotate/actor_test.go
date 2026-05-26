package rotate_test

// Actor-identity core symbol — the consumer-defined ActorResolver port.
//
// This file covers the TESTABLE core piece of the actor-identity item
// (the registry-attested actor label): a compile-time shape assertion that the
// ActorResolver port is satisfiable without any SDK type, and that ok=false is
// the fail-closed answer for every non-resolving input. The real resolution
// logic (anchor-verified introducing commit → byreis-signer footer signerID →
// SourceVerified AdminSet.SignerKeys → human label) lives in the adapter and is
// exercised there against real signed registry fixtures — it is deliberately NOT
// mocked here.

import (
	"context"
	"testing"

	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// fakeActorResolver is an in-memory ActorResolver used only to prove the
// consumer-defined port is satisfiable without any SDK type and that an unknown
// signerID resolves to ok=false (the caller then displays "-"). It is a lookup
// over a fixed table; it deliberately implements NO part of the real
// label-source rule (anchor verification, footer parse, SignerKeys lookup) —
// that is the adapter's step.
type fakeActorResolver struct {
	labels map[string]string
}

// Compile-time assertion: the fake satisfies the consumer-defined port, proving
// ResolveActorLabel is the only method and its signature compiles.
var _ rotate.ActorResolver = (*fakeActorResolver)(nil)

func (f *fakeActorResolver) ResolveActorLabel(
	ctx context.Context, signerID string,
) (string, bool) {
	if ctx.Err() != nil {
		return "", false
	}
	label, ok := f.labels[signerID]
	return label, ok
}

// TestActorResolver_PortShape locks the contract that a resolved signerID yields
// its human label with ok=true, and that an unknown / absent signerID yields the
// fail-closed ("", false) — the caller renders "-" for that row.
func TestActorResolver_PortShape(t *testing.T) {
	t.Parallel()

	var r rotate.ActorResolver = &fakeActorResolver{
		labels: map[string]string{"abc123": "alice"},
	}

	cases := []struct {
		name      string
		signerID  string
		wantLabel string
		wantOK    bool
	}{
		{name: "known signer resolves to label", signerID: "abc123", wantLabel: "alice", wantOK: true},
		{name: "unknown signer fails closed", signerID: "deadbeef", wantLabel: "", wantOK: false},
		{name: "empty signerID fails closed", signerID: "", wantLabel: "", wantOK: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			label, ok := r.ResolveActorLabel(context.Background(), tc.signerID)
			if ok != tc.wantOK {
				t.Fatalf("ResolveActorLabel(%q) ok = %v, want %v", tc.signerID, ok, tc.wantOK)
			}
			if label != tc.wantLabel {
				t.Fatalf("ResolveActorLabel(%q) label = %q, want %q", tc.signerID, label, tc.wantLabel)
			}
		})
	}
}
