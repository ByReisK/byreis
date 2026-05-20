package usecase_test

import (
	"context"

	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// Compile-time structural satisfaction pins for the IDLoader port.
//
// identity.Loader (from the inner crypto/identity package) must satisfy
// usecase.IDLoader without any producer-side change, because both interfaces
// declare Load(ctx context.Context) (identity.Identity, error). The following
// nil-assignment is sufficient; if the interface signatures diverge, the
// build fails.
var _ usecase.IDLoader = (identity.Loader)(nil)

// idLoaderStubPin is a minimal concrete type satisfying usecase.IDLoader.
// It exists only to pin that the interface is implementable from outside the
// package (i.e., the method set is correctly exported).
type idLoaderStubPin struct{}

func (idLoaderStubPin) Load(_ context.Context) (identity.Identity, error) {
	return nil, nil
}

var _ usecase.IDLoader = idLoaderStubPin{}
