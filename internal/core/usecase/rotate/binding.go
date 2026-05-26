package rotate

import "context"

// BindingStatus is the per-line audit-binding verification result for one
// AuditEntryView. It is a display enum: it tells the render layer whether an
// audit-log line was cryptographically bound to the signed commit that
// introduced it. It complements the monotonic-counter anti-rollback protection
// (the content/ordering layer), and is orthogonal to it.
//
// The zero value is BindingMissing — the unbindable state. This is a fail-closed
// default: an entry the verifier never labelled (including synthetic display
// rows) is never rendered as verified.
type BindingStatus int

const (
	// BindingMissing is the unbindable state and the fail-closed zero value. It
	// is carried by synthetic display rows (the truncation advisory, the
	// malformed-line warning) that are EXCLUDED from per-line hash verification,
	// and by any entry the verifier did not reach. It is distinct from
	// BindingTampered: missing means "no binding could be computed for this row",
	// not "this row's binding failed".
	BindingMissing BindingStatus = iota
	// BindingVerified means the line's content, ordering, presence, and project
	// matched the signed commit that introduced it, under the pinned trust anchor.
	BindingVerified
	// BindingUnverifiedLegacy is a DISPLAY label for a genuinely pre-binding line
	// (its introducing commit predates the binding era and carries no per-line
	// binding field). It is NEVER an error and NEVER "tamper" — a legacy line is
	// not a failed line, it is an unbindable-by-vintage line.
	BindingUnverifiedLegacy
	// BindingTampered means the line FAILED per-line binding verification: its
	// content, ordering, presence, or project no longer matches history. It is the
	// per-line counterpart of the ErrAuditLogTampered sentinel — the verifier
	// labels the offending line BindingTampered AND returns the typed error.
	BindingTampered
)

// String renders the stable display token for the BINDING column and the
// --json binding_status field. An out-of-range value degrades to "unknown"
// rather than panicking, mirroring the forward-compat tolerance of the rest of
// the audit read path.
func (s BindingStatus) String() string {
	switch s {
	case BindingMissing:
		return "missing"
	case BindingVerified:
		return "verified"
	case BindingUnverifiedLegacy:
		return "legacy"
	case BindingTampered:
		return "TAMPERED"
	default:
		return "unknown"
	}
}

// AuditVerifyResult is the result of a per-line audit-binding verification run.
// Entries carries the per-line display projection — each entry's BindingStatus
// is populated — and is returned on BOTH a clean and a tamper outcome, so the
// caller can render per-line status in either case. FullWalk is a diagnostic
// flag for the display layer; it does not affect trust.
type AuditVerifyResult struct {
	// Entries is the per-line binding projection. Each AuditEntryView carries a
	// populated BindingStatus. The slice is returned on success AND on a tamper
	// outcome alongside the typed error, so the caller renders per-line status
	// and still exits non-zero.
	Entries []AuditEntryView
	// FullWalk reports whether this run was a cold full-history walk (true) or an
	// incremental verify from a verified-HEAD checkpoint (false). Display and
	// diagnostic only — never a trust signal.
	FullWalk bool
}

// AuditVerifier is the consumer-defined port the verifying audit read path uses
// to bind every registry audit-log line to the signed commit that introduced
// it. The git-history walk and the per-commit Ed25519 re-check live in the
// adapter (internal/adapter/registry) and are mapped to this port; no
// core → adapter edge is introduced.
//
// The port is READ-ONLY. The implementation acquires NO signer and NO
// registry-write credential; it imports neither crypto/identity nor
// crypto/decrypt. It reads only public commit history and recomputes hashes —
// no private key, no plaintext. Per-commit verification pins to the SINGLE
// pinned trust anchor (the byreis-signer: footer is a label, not a trust key);
// it does NOT trust the mutable verified-registry signer set as the
// per-commit verification key.
type AuditVerifier interface {
	// VerifyAuditLog walks the registry audit/<projectID>.jsonl history and binds
	// every non-synthetic line to its introducing signed commit. It fails closed:
	//
	//   - the registry HEAD is not signature-verified against the pinned trust
	//     anchor → ErrUnsignedRegistry, returned BEFORE any per-line work (no
	//     partial walk on an unsigned HEAD);
	//   - the registry is unreachable with no integrity-checked source →
	//     ErrRegistryOffline (never a partial-verified-as-clean result);
	//   - a decode-ok content / ordering / presence / project-splice mismatch →
	//     ErrAuditLogTampered whose wrapped message names the offending line;
	//   - ctx cancellation or deadline → a typed fail-closed error, NEVER a
	//     partial result rendered as clean and NEVER a BindingVerified label on a
	//     line the walk did not reach.
	//
	// On a tamper outcome the typed error rides ALONGSIDE the projection: the
	// returned AuditVerifyResult.Entries carries the per-line binding status for
	// ALL lines (the offending line labelled BindingTampered) so the caller
	// renders the full per-line view and still exits non-zero off the error.
	// Synthetic display rows carry BindingMissing and are excluded from hash
	// verification. A genuinely pre-binding line carries BindingUnverifiedLegacy,
	// which is a display label and never an error.
	VerifyAuditLog(ctx context.Context, projectID string) (AuditVerifyResult, error)
}
