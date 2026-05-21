//go:build shipgate

// V4 — single-site indirection point for the internal/app builder edge.
// Keeping the app import edge in one tiny file means the V4 row tests do
// not multiply the surface that touches the composition root. This is the
// same separation-of-concerns pattern v0.1 used for the shipgate fixture's
// app entry edge.
package usecase_test

import (
	"context"

	"github.com/ByReisK/byreis/internal/app"
	"github.com/ByReisK/byreis/internal/cli"
)

func init() {
	v4AppBuildProductionDeps = func(ctx context.Context) (*cli.Deps, error) {
		return app.BuildProductionDeps(ctx)
	}
}
