// Package registry — internal test helpers for the production transport.
//
// This file is in package registry (not registry_test) so it can access
// unexported types and methods. It exposes only the minimal exported surface
// needed by production_transport_b66_test.go (external test package) to
// exercise the SHA-mismatch invariant assertion in ReadCounter (FINAL-AC-1.5).
package registry

import (
	"sync"

	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
)

// InjectCorruptedPendingSessionForTest pushes a clone session into the pending
// queue of ft keyed by queueKey, but with the session's internal verifiedSHA
// set to corruptSHA (≠ queueKey). This creates the precondition for the
// SHA-equality assertion in ReadCounter: popPending(queueKey) succeeds, but
// sess.verifiedSHA != queueKey, triggering the FINAL-AC-1.5 fail-closed branch.
//
// ft must be the *productionFetchTransport returned by NewProductionFetchTransport.
// If ft is any other type, the function panics (internal invariant).
// cleanupFn is called when the injected session is cleaned up.
//
// This is a test-only function. It must never be referenced in production code.
func InjectCorruptedPendingSessionForTest(ft FetchTransport, queueKey, corruptSHA string, cleanupFn func()) {
	pft, ok := ft.(*productionFetchTransport)
	if !ok {
		panic("InjectCorruptedPendingSessionForTest: ft is not *productionFetchTransport")
	}
	var once sync.Once
	wrapped := func() { once.Do(cleanupFn) }
	sess := &cloneSession{
		cloneDir:    "/nonexistent/test/clone",
		verifiedSHA: corruptSHA,
		cleanupFn:   wrapped,
	}
	pft.pendingMu.Lock()
	defer pft.pendingMu.Unlock()
	if pft.pendingSessions[queueKey] == nil {
		pft.pendingSessions[queueKey] = &sessionQueue{}
	}
	pft.pendingSessions[queueKey].push(sess)
}

// NewProductionFetchTransportForTest is an alias for NewProductionFetchTransport
// used in the internal test file. Callers in the external test package use this
// to obtain a value on which InjectCorruptedPendingSessionForTest can operate.
//
// This is test-only. It must never be used in production code.
func NewProductionFetchTransportForTest(v *fetchtransport.HeadVerifier) (FetchTransport, error) {
	return NewProductionFetchTransport(v)
}
