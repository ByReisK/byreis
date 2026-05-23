package rotate_test

// V7.1 admin-side open-request listing — read-only triage projection.
//
// This file exercises the OpenRequestSummary domain type and the
// RequestAccessReader.ListOpenRequests port method via an in-memory fake.
// No real network, fs, clock, or SDK contact: the port is the only seam, and
// the summary is asserted to carry the canonical PRRef domain type rather than
// any SDK type. The summary is NEVER fed to the request-access validation
// state machine (ValidateRequestAccess); these tests prove only the read-only
// projection contract.

import (
	"context"
	"errors"
	"testing"

	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// fakeOpenRequestLister is an in-memory RequestAccessReader used to drive the
// ListOpenRequests contract tests. The two pre-existing methods are stubbed to
// the zero/empty outcome because this fixture exercises only the list path.
type fakeOpenRequestLister struct {
	summaries []rotate.OpenRequestSummary
	err       error
}

// Compile-time assertion: the fake satisfies the full consumer-defined port,
// which proves the new ListOpenRequests method is part of the interface and the
// existing methods still compile alongside it.
var _ rotate.RequestAccessReader = (*fakeOpenRequestLister)(nil)

func (f *fakeOpenRequestLister) FetchRequestAccessYAML(
	ctx context.Context, _ coregit.PRRef,
) (rotate.RequestAccessFile, rotate.PRMetadata, error) {
	if err := ctx.Err(); err != nil {
		return rotate.RequestAccessFile{}, rotate.PRMetadata{}, err
	}
	return rotate.RequestAccessFile{}, rotate.PRMetadata{}, errors.New("not exercised")
}

func (f *fakeOpenRequestLister) FetchPRHeadSHA(
	ctx context.Context, _ coregit.PRRef,
) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	return "", "", errors.New("not exercised")
}

func (f *fakeOpenRequestLister) ListOpenRequests(
	ctx context.Context,
) ([]rotate.OpenRequestSummary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.summaries, nil
}

func (f *fakeOpenRequestLister) ListOpenRequestsBounded(
	ctx context.Context,
) ([]rotate.OpenRequestSummary, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if f.err != nil {
		return nil, false, f.err
	}
	return f.summaries, false, nil
}

// TestListOpenRequests_ReturnsSummaries asserts the port surfaces every open
// request summary verbatim, carrying the canonical PRRef domain type and the
// advisory metadata fields. The list path performs no trust decision.
func TestListOpenRequests_ReturnsSummaries(t *testing.T) {
	t.Parallel()

	want := []rotate.OpenRequestSummary{
		{
			PRRef:       coregit.PRRef{Project: "myorg/byreis-admins", Number: 42},
			AuthorLogin: "alice",
			Title:       "request-access: add alice",
			CreatedAt:   "2026-05-22T10:00:00Z",
			HeadSHA:     "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
		{
			PRRef:       coregit.PRRef{Project: "myorg/byreis-admins", Number: 43},
			AuthorLogin: "bob",
			Title:       "request-access: add bob",
			CreatedAt:   "2026-05-22T11:00:00Z",
			HeadSHA:     "cafebabecafebabecafebabecafebabecafebabe",
		},
	}

	var reader rotate.RequestAccessReader = &fakeOpenRequestLister{summaries: want}

	got, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests: unexpected error: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("ListOpenRequests: got %d summaries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("summary[%d]: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestListOpenRequests_EmptyIsNotAnError asserts a registry with no open
// request-access PRs returns an empty slice and no error — "nothing to triage"
// is a valid, non-failing outcome.
func TestListOpenRequests_EmptyIsNotAnError(t *testing.T) {
	t.Parallel()

	var reader rotate.RequestAccessReader = &fakeOpenRequestLister{summaries: nil}

	got, err := reader.ListOpenRequests(context.Background())
	if err != nil {
		t.Fatalf("ListOpenRequests: unexpected error on empty registry: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListOpenRequests: got %d summaries, want 0", len(got))
	}
}

// TestListOpenRequests_PropagatesError asserts a backend failure surfaces as a
// non-nil error rather than a silently-empty list — the read path fails closed
// so the operator never mistakes a fetch failure for "no open requests".
func TestListOpenRequests_PropagatesError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("registry fetch failed")
	var reader rotate.RequestAccessReader = &fakeOpenRequestLister{err: sentinel}

	_, err := reader.ListOpenRequests(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("ListOpenRequests: want error wrapping %v, got %v", sentinel, err)
	}
}

// TestListOpenRequests_HonoursContextCancellation asserts the port honours a
// cancelled context (binding determinism + cancellation standard for I/O ports).
func TestListOpenRequests_HonoursContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var reader rotate.RequestAccessReader = &fakeOpenRequestLister{
		summaries: []rotate.OpenRequestSummary{
			{PRRef: coregit.PRRef{Project: "myorg/byreis-admins", Number: 1}},
		},
	}

	if _, err := reader.ListOpenRequests(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListOpenRequests: want context.Canceled, got %v", err)
	}
}

// TestOpenRequestSummary_CarriesCanonicalPRRef asserts the summary's PR
// reference is the core git.PRRef domain type (owner/repo + number), not an SDK
// type, so the value can be handed straight to `rotate --add --from-request`.
func TestOpenRequestSummary_CarriesCanonicalPRRef(t *testing.T) {
	t.Parallel()

	s := rotate.OpenRequestSummary{
		PRRef: coregit.PRRef{Project: "myorg/byreis-admins", Number: 7},
	}
	if s.PRRef.Project != "myorg/byreis-admins" || s.PRRef.Number != 7 {
		t.Fatalf("OpenRequestSummary.PRRef did not round-trip: got %+v", s.PRRef)
	}
}
