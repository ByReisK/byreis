package usecase_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// --- fakes -------------------------------------------------------------------

// fakeRejectModeGate is a ModeGate that allows or denies the reject command.
type fakeRejectModeGate struct {
	allow bool
}

func (g fakeRejectModeGate) Allow(cmd mode.Command) error {
	if cmd != mode.CommandRequestReject {
		return errors.New("unexpected command passed to mode gate: " + string(cmd))
	}
	if g.allow {
		return nil
	}
	return mode.ErrPermissionDenied
}

// fakePRCloser records its calls and returns a scripted state.
type fakePRCloser struct {
	state       usecase.RejectPRState
	fetchErr    error
	closeErr    error
	fetchCalls  int
	closeCalls  int
	closeReason string
}

func (c *fakePRCloser) FetchPRStateForReject(_ context.Context, _ git.PRRef) (usecase.RejectPRState, error) {
	c.fetchCalls++
	if c.fetchErr != nil {
		return usecase.RejectPRState{}, c.fetchErr
	}
	return c.state, nil
}

func (c *fakePRCloser) CloseWithComment(_ context.Context, _ git.PRRef, sanitizedReason string) error {
	c.closeCalls++
	c.closeReason = sanitizedReason
	return c.closeErr
}

// recordingAudit captures appended events for shape assertions.
type recordingAudit struct {
	events    []audit.Event
	appendErr error
}

func (a *recordingAudit) Append(_ context.Context, e audit.Event) error {
	a.events = append(a.events, e)
	return a.appendErr
}

func newRejecter(t *testing.T, gate usecase.ModeGate, closer usecase.PRCloser, sink audit.Logger) usecase.RequestRejecter {
	t.Helper()
	r, err := usecase.NewRequestRejecter(usecase.RejectDeps{
		Closer: closer,
		Mode:   gate,
		Audit:  sink,
	})
	if err != nil {
		t.Fatalf("NewRequestRejecter: unexpected error: %v", err)
	}
	return r
}

func registryRequestState() usecase.RejectPRState {
	return usecase.RejectPRState{
		SourceRepo: usecase.RepoKindRegistry,
		BranchName: "requests/alice.yaml",
	}
}

func projectSubmissionState() usecase.RejectPRState {
	return usecase.RejectPRState{
		SourceRepo: usecase.RepoKindProject,
		BranchName: "byreis/add-DB_PASSWORD-1700000000",
	}
}

// --- mode gate ---------------------------------------------------------------

// TestReject_ModeGateDeniedNotAttempted asserts a denied mode never reaches the
// closer: no fetch, no close, no audit. Denied-by-policy, not attempted-then-failed.
func TestReject_ModeGateDeniedNotAttempted(t *testing.T) {
	t.Parallel()

	closer := &fakePRCloser{state: projectSubmissionState()}
	sink := &recordingAudit{}
	r := newRejecter(t, fakeRejectModeGate{allow: false}, closer, sink)

	_, err := r.Reject(context.Background(), usecase.RejectInput{
		Ref:    git.PRRef{Project: "myorg/secrets", Number: 7},
		Reason: "not needed",
	})
	if err == nil {
		t.Fatal("expected denial error in CONTRIBUTOR mode, got nil")
	}
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("denial must wrap ErrPermissionDenied, got %v", err)
	}
	if closer.fetchCalls != 0 || closer.closeCalls != 0 {
		t.Fatalf("denied reject must not touch the closer: fetch=%d close=%d", closer.fetchCalls, closer.closeCalls)
	}
	if len(sink.events) != 0 {
		t.Fatalf("denied reject must not append an audit event, got %d", len(sink.events))
	}
}

// --- discriminator ------------------------------------------------------------

func TestReject_PRTypeDiscriminator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		state       usecase.RejectPRState
		wantErr     error
		wantPRType  string
		wantClose   bool
		wantKeyName string
	}{
		{
			name:        "registry request-access agreeing prefix closes",
			state:       registryRequestState(),
			wantPRType:  "access-request",
			wantClose:   true,
			wantKeyName: "", // access-request PRs carry no key name
		},
		{
			name:        "project submission agreeing prefix closes",
			state:       projectSubmissionState(),
			wantPRType:  "submission",
			wantClose:   true,
			wantKeyName: "DB_PASSWORD",
		},
		{
			name: "neither namespace fails closed",
			state: usecase.RejectPRState{
				SourceRepo: usecase.RepoKindProject,
				BranchName: "feature/random",
			},
			wantErr: usecase.ErrRejectWrongPRType,
		},
		{
			name: "repo registry but submission branch prefix disagrees",
			state: usecase.RejectPRState{
				SourceRepo: usecase.RepoKindRegistry,
				BranchName: "byreis/add-DB_PASSWORD-1700000000",
			},
			wantErr: usecase.ErrRejectWrongPRType,
		},
		{
			name: "repo project but request prefix disagrees",
			state: usecase.RejectPRState{
				SourceRepo: usecase.RepoKindProject,
				BranchName: "requests/alice.yaml",
			},
			wantErr: usecase.ErrRejectWrongPRType,
		},
		{
			name: "unknown repo kind fails closed",
			state: usecase.RejectPRState{
				SourceRepo: usecase.RepoKind(99),
				BranchName: "requests/alice.yaml",
			},
			wantErr: usecase.ErrRejectWrongPRType,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			closer := &fakePRCloser{state: tc.state}
			sink := &recordingAudit{}
			r := newRejecter(t, fakeRejectModeGate{allow: true}, closer, sink)

			res, err := r.Reject(context.Background(), usecase.RejectInput{
				Ref:    git.PRRef{Project: "myorg/secrets", Number: 7},
				Reason: "duplicate of #3",
			})

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want error %v, got %v", tc.wantErr, err)
				}
				if closer.closeCalls != 0 {
					t.Fatalf("wrong-type reject must close NOTHING, got %d close calls", closer.closeCalls)
				}
				if len(sink.events) != 0 {
					t.Fatalf("wrong-type reject must append no audit event, got %d", len(sink.events))
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantClose && closer.closeCalls != 1 {
				t.Fatalf("expected exactly one close call, got %d", closer.closeCalls)
			}
			if res.Status != "closed" {
				t.Fatalf("want Status closed, got %q", res.Status)
			}
			if len(sink.events) != 1 {
				t.Fatalf("expected one audit event, got %d", len(sink.events))
			}
			ev := sink.events[0]
			if ev.Details["pr_type"] != tc.wantPRType {
				t.Fatalf("want pr_type %q, got %q", tc.wantPRType, ev.Details["pr_type"])
			}
			if ev.KeyName != tc.wantKeyName {
				t.Fatalf("want KeyName %q, got %q", tc.wantKeyName, ev.KeyName)
			}
		})
	}
}

// --- race: merged / closed ----------------------------------------------------

// TestReject_AlreadyMergedNoComment asserts a merged PR fails closed with
// ErrRejectAlreadyMerged and NO comment is posted before the merge-state check.
func TestReject_AlreadyMergedNoComment(t *testing.T) {
	t.Parallel()

	state := projectSubmissionState()
	state.Merged = true
	closer := &fakePRCloser{state: state}
	sink := &recordingAudit{}
	r := newRejecter(t, fakeRejectModeGate{allow: true}, closer, sink)

	_, err := r.Reject(context.Background(), usecase.RejectInput{
		Ref:    git.PRRef{Project: "myorg/secrets", Number: 7},
		Reason: "too late",
	})
	if !errors.Is(err, usecase.ErrRejectAlreadyMerged) {
		t.Fatalf("want ErrRejectAlreadyMerged, got %v", err)
	}
	if closer.closeCalls != 0 {
		t.Fatalf("merged PR: no close must be attempted, got %d", closer.closeCalls)
	}
	if len(sink.events) != 0 {
		t.Fatalf("merged PR: no audit event expected, got %d", len(sink.events))
	}
}

// TestReject_AlreadyClosedIdempotent asserts an already-closed PR is idempotent:
// no error, no duplicate comment.
func TestReject_AlreadyClosedIdempotent(t *testing.T) {
	t.Parallel()

	state := projectSubmissionState()
	state.Closed = true
	closer := &fakePRCloser{state: state}
	sink := &recordingAudit{}
	r := newRejecter(t, fakeRejectModeGate{allow: true}, closer, sink)

	res, err := r.Reject(context.Background(), usecase.RejectInput{
		Ref:    git.PRRef{Project: "myorg/secrets", Number: 7},
		Reason: "noop",
	})
	if err != nil {
		t.Fatalf("already-closed reject must be idempotent (no error), got %v", err)
	}
	if closer.closeCalls != 0 {
		t.Fatalf("already-closed PR: no duplicate close/comment, got %d close calls", closer.closeCalls)
	}
	if res.Status != "already-closed" {
		t.Fatalf("want Status already-closed, got %q", res.Status)
	}
}

// --- reason core constraint ---------------------------------------------------

func TestReject_ReasonCoreConstraint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		reason  string
		wantErr bool
	}{
		{name: "plain ascii ok", reason: "duplicate of #3", wantErr: false},
		{name: "newline and tab allowed", reason: "line one\nline two\twith tab", wantErr: false},
		{name: "C0 control byte rejected", reason: "bad\x07bell", wantErr: true},
		{name: "C1 control byte rejected", reason: "bad" + string(rune(0x85)) + "nel", wantErr: true},
		{name: "DEL control byte rejected", reason: "bad" + string(rune(0x7F)) + "del", wantErr: true},
		{name: "LRO bidi override rejected", reason: "abc" + string(rune(0x202D)) + "def", wantErr: true},
		{name: "RLO bidi override rejected", reason: "abc" + string(rune(0x202E)) + "def", wantErr: true},
		{name: "PDI bidi isolate rejected", reason: "abc" + string(rune(0x2069)) + "def", wantErr: true},
		{name: "RLM bidi mark rejected", reason: "abc" + string(rune(0x200F)) + "def", wantErr: true},
		{name: "ALM arabic letter mark rejected", reason: "abc" + string(rune(0x061C)) + "def", wantErr: true},
		{name: "over 2000 bytes rejected", reason: strings.Repeat("a", 2001), wantErr: true},
		{name: "exactly 2000 bytes ok", reason: strings.Repeat("a", 2000), wantErr: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			closer := &fakePRCloser{state: projectSubmissionState()}
			sink := &recordingAudit{}
			r := newRejecter(t, fakeRejectModeGate{allow: true}, closer, sink)

			_, err := r.Reject(context.Background(), usecase.RejectInput{
				Ref:    git.PRRef{Project: "myorg/secrets", Number: 7},
				Reason: tc.reason,
			})

			if tc.wantErr {
				if !errors.Is(err, usecase.ErrRejectReasonUnsafe) {
					t.Fatalf("want ErrRejectReasonUnsafe, got %v", err)
				}
				if closer.closeCalls != 0 {
					t.Fatalf("unsafe reason must close NOTHING, got %d", closer.closeCalls)
				}
				if len(sink.events) != 0 {
					t.Fatalf("unsafe reason must append no audit event, got %d", len(sink.events))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for safe reason: %v", err)
			}
		})
	}
}

// TestReject_NonInteractiveEmptyReasonFailsClosed asserts that a non-interactive
// run with an empty reason fails closed rather than posting an empty comment.
func TestReject_NonInteractiveEmptyReasonFailsClosed(t *testing.T) {
	t.Parallel()

	closer := &fakePRCloser{state: projectSubmissionState()}
	sink := &recordingAudit{}
	r := newRejecter(t, fakeRejectModeGate{allow: true}, closer, sink)

	_, err := r.Reject(context.Background(), usecase.RejectInput{
		Ref:            git.PRRef{Project: "myorg/secrets", Number: 7},
		Reason:         "",
		NonInteractive: true,
	})
	if err == nil {
		t.Fatal("non-interactive empty reason must fail closed")
	}
	if closer.closeCalls != 0 {
		t.Fatalf("must close nothing on empty non-interactive reason, got %d", closer.closeCalls)
	}
}

// --- audit event shape: reason is structurally absent ------------------------

// TestReject_AuditEventOmitsReasonText asserts the free-text reason never lands
// in any audit field; only reason_len plus the closed metadata set.
func TestReject_AuditEventOmitsReasonText(t *testing.T) {
	t.Parallel()

	const secretishReason = "rejecting because the password Hunter2SuperSecret was wrong"
	closer := &fakePRCloser{state: projectSubmissionState()}
	sink := &recordingAudit{}
	r := newRejecter(t, fakeRejectModeGate{allow: true}, closer, sink)

	_, err := r.Reject(context.Background(), usecase.RejectInput{
		Ref:    git.PRRef{Project: "myorg/secrets", Number: 7},
		Reason: secretishReason,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected one audit event, got %d", len(sink.events))
	}
	ev := sink.events[0]

	if ev.Kind != audit.EventKindReject {
		t.Fatalf("want EventKindReject, got %q", ev.Kind)
	}

	// The reason text must not appear in ANY serialisable field of the event.
	needle := "Hunter2SuperSecret"
	if strings.Contains(ev.Outcome, needle) {
		t.Fatalf("reason text leaked into Outcome: %q", ev.Outcome)
	}
	for k, v := range ev.Details {
		if strings.Contains(v, needle) {
			t.Fatalf("reason text leaked into Details[%q]=%q", k, v)
		}
	}
	if _, ok := ev.Details["reason"]; ok {
		t.Fatal("Details must not carry a verbatim reason key")
	}

	// Only the closed metadata set is recorded.
	wantKeys := map[string]bool{"pr": true, "pr_type": true, "project": true, "reason_len": true}
	for k := range ev.Details {
		if !wantKeys[k] {
			t.Fatalf("unexpected Details key %q (closed set is pr/pr_type/project/reason_len)", k)
		}
	}
	for k := range wantKeys {
		if _, ok := ev.Details[k]; !ok {
			t.Fatalf("missing required Details key %q", k)
		}
	}

	// reason_len records the byte length, not the content.
	wantLen := len(secretishReason)
	if got := ev.Details["reason_len"]; got != itoa(wantLen) {
		t.Fatalf("reason_len = %q, want %q", got, itoa(wantLen))
	}

	// The event must pass the field validator (the use-case validates itself).
	if vErr := audit.ValidateEventFields(ev); vErr != nil {
		t.Fatalf("reject audit event failed ValidateEventFields: %v", vErr)
	}

	// The comment posted to the PR DOES carry the (sanitized) reason — the public
	// channel — but that is distinct from the audit record asserted above.
	if closer.closeReason != secretishReason {
		t.Fatalf("comment reason = %q, want the sanitized reason verbatim", closer.closeReason)
	}
}

// TestReject_AuditEventActorParityWithMerge locks the reject audit Event's Actor
// field to the same posture as every other byreis event emitter: the use-case
// layer does not yet resolve an actor identity, so Actor is left empty (the
// audit.Event.Actor doc says "empty for contributor actions"), exactly as
// merge.go, review.go, and the rotation emitter leave it. The reject path is
// confined away from any private-key/signing capability by construction, so it
// has no signing-key-label source to populate Actor with even if it wanted one.
//
// This is the GUARD against the one regression that would actually be dangerous:
// an actor field that smuggles an age recipient public key (which would be a
// pubkey leak in a world-readable-adjacent audit record). The reject event's
// Actor must NEVER be an age1... value. When a future actor-identity slice lands
// a real signing-key-label, this test is updated alongside it; until then reject
// is consistent with merge.
func TestReject_AuditEventActorParityWithMerge(t *testing.T) {
	t.Parallel()

	closer := &fakePRCloser{state: projectSubmissionState()}
	sink := &recordingAudit{}
	r := newRejecter(t, fakeRejectModeGate{allow: true}, closer, sink)

	_, err := r.Reject(context.Background(), usecase.RejectInput{
		Ref:    git.PRRef{Project: "myorg/secrets", Number: 11},
		Reason: "duplicate of an earlier request",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected one audit event, got %d", len(sink.events))
	}
	ev := sink.events[0]

	// Parity with merge: no resolved actor identity is threaded into the
	// use-case layer yet, so Actor is empty.
	if ev.Actor != "" {
		t.Fatalf("Actor = %q, want empty (parity with merge: no actor-identity slice yet)", ev.Actor)
	}

	// Hard invariant regardless of any future actor source: Actor must NEVER be
	// an age recipient public key. An age pubkey in an audit field is a key
	// leak, not an actor label.
	if strings.HasPrefix(ev.Actor, "age1") {
		t.Fatalf("Actor must never be an age public key, got %q", ev.Actor)
	}
}

// TestReject_InvalidAuditFieldSurfacedLoud asserts that if the constructed event
// fails validation the error is surfaced loudly (never silently dropped). The
// close has already happened, so it is not fatal to the close.
func TestReject_InvalidAuditFieldSurfacedLoud(t *testing.T) {
	t.Parallel()

	// A project id containing a space fails projectIDOrFileNameRE in the
	// validator, forcing the use-case's self-validation to fail loudly.
	closer := &fakePRCloser{state: usecase.RejectPRState{
		SourceRepo: usecase.RepoKindProject,
		BranchName: "byreis/add-DB_PASSWORD-1700000000",
	}}
	sink := &recordingAudit{}
	r := newRejecter(t, fakeRejectModeGate{allow: true}, closer, sink)

	_, err := r.Reject(context.Background(), usecase.RejectInput{
		Ref:    git.PRRef{Project: "bad project/secrets", Number: 7},
		Reason: "reason",
	})
	if err == nil {
		t.Fatal("expected a loud audit-validation error")
	}
	if !errors.Is(err, audit.ErrAuditEventInvalidField) {
		t.Fatalf("want ErrAuditEventInvalidField surfaced, got %v", err)
	}
	// The close still happened (the failure is post-close, non-fatal to the close).
	if closer.closeCalls != 1 {
		t.Fatalf("close should have happened before audit validation, got %d", closer.closeCalls)
	}
	// The invalid event must NOT be silently appended.
	if len(sink.events) != 0 {
		t.Fatalf("invalid event must not be appended, got %d", len(sink.events))
	}
}

// itoa is a tiny local helper to avoid importing strconv just for the test
// assertions on reason_len.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
