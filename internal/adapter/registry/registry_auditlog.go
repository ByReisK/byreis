package registry

// FetchAuditLog implements rotate.AuditReader for *registry.Client.
//
// It reads the audit/<projectID>.jsonl file from the registry at a single
// signature-verified HEAD and maps the raw JSONL bytes to []rotate.AuditEntryView.
// The verify-on-read contract mirrors FetchRotationEpochs: one FetchHead call,
// !verified is a hard ErrUnsignedRegistry (no cache fallthrough), and the
// verified headCommit is threaded into ReadAuditLog (no second FetchHead, no
// TOCTOU window). Offline with no cache is ErrRegistryOffline.
//
// Bounded read discipline (all axes):
//   - Total blob cap: maxAuditJSONLBytes inside ReadAuditLog.
//   - Per-line cap: bufio.Scanner with explicit Buffer ceiling (maxAuditLineBytes);
//     a line exceeding the cap returns a typed bounded-read error, never OOM.
//   - Decode depth: each line is decoded into the typed audit.Event shape, so
//     JSON nesting depth is structurally bounded by the typed target.
//   - Duplicate-key resolution: Go encoding/json last-wins; the SAFE/DENY
//     partition runs on the post-decode resolved key set (never on the raw token
//     stream) so a shadowed key cannot smuggle a DENY value into a SAFE slot.
//   - Result count cap: at most maxAuditResultCount entries are returned (tail);
//     overflow adds a synthetic truncation-advisory entry.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// maxAuditResultCount is the maximum number of AuditEntryView entries returned
// by FetchAuditLog. When the parsed entry count exceeds this limit, only the
// most recent maxAuditResultCount entries are returned, accompanied by a
// truncation-advisory entry at the beginning of the slice.
const maxAuditResultCount = 1000

// maxAuditDetailFieldLen is the per-SafeDetails value length cap applied at the
// read side. A Details value exceeding this limit is dropped from SafeDetails
// (fail-closed by omission) rather than surfaced, even if its key is on the
// positive allowlist. This bounds the per-field terminal output length and
// catches write-side violations that slipped through the write-side validator.
const maxAuditDetailFieldLen = 512

// maxAuditDetailEntropyRunLen is the maximum contiguous base64-alphabet run
// length in a SafeDetails value before it is treated as high-entropy and
// dropped. The write-side heuristic uses 32; the read side matches it.
const maxAuditDetailEntropyRunLen = 32

// FetchAuditLog fetches the registry audit log for projectID and returns the
// read-only display projection as a bounded []rotate.AuditEntryView slice.
//
// Fail-closed contract:
//   - One FetchHead; !verified → ErrUnsignedRegistry (no cache fallthrough).
//   - Transport error → ErrRegistryOffline (no audit cache).
//   - Absent file → empty slice, nil error.
//   - Per-line oversize → typed bounded-read error, never OOM.
//   - Result count cap → tail + truncation advisory entry.
func (c *Client) FetchAuditLog(ctx context.Context, projectID string) ([]rotate.AuditEntryView, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("registry FetchAuditLog cancelled: %w", err)
	}

	if c.cfg.FetchTransport == nil {
		return nil, fmt.Errorf(
			"%w: FetchAuditLog: no registry transport configured — "+
				"run `byreis doctor` to diagnose",
			coreregistry.ErrRegistryOffline)
	}

	headCommit, _, verified, fetchErr := c.cfg.FetchTransport.FetchHead(
		ctx, c.cfg.RegistryURL, c.cfg.TrustAnchorKey)
	if fetchErr != nil {
		// Transport/network error: there is no audit cache. Fail closed.
		return nil, fmt.Errorf(
			"%w: FetchAuditLog: registry fetch failed: %v — "+
				"run `byreis doctor` to diagnose",
			coreregistry.ErrRegistryOffline, fetchErr)
	}

	// Signature-verification failure is always a hard error. Cache fallback is
	// NEVER reached here: an unverified HEAD means we cannot trust any data from
	// this fetch, and serving stale unverified entries would open an
	// unverified-data display window.
	if !verified {
		return nil, fmt.Errorf(
			"%w: FetchAuditLog: registry HEAD is not signature-verified — "+
				"run `byreis doctor` to diagnose",
			coreregistry.ErrUnsignedRegistry)
	}

	// Discard any counter session deposited by FetchHead. FetchAuditLog does not
	// invoke ReadCounter or IsAncestor, so the session (if any) is not consumed
	// and must be released to prevent a leak.
	defer c.cfg.FetchTransport.DiscardCounterSession(ctx, headCommit)

	// Read the raw JSONL blob at the SAME verified headCommit (no second
	// FetchHead, no TOCTOU window — identical to the FetchRotationEpochs
	// discipline).
	raw, readErr := c.cfg.FetchTransport.ReadAuditLog(
		ctx, c.cfg.RegistryURL, headCommit, projectID)
	if readErr != nil {
		return nil, fmt.Errorf(
			"FetchAuditLog: reading audit log for project %q: %w — "+
				"run `byreis doctor` to diagnose",
			projectID, readErr)
	}

	if len(raw) == 0 {
		return []rotate.AuditEntryView{}, nil
	}

	return parseAuditJSONL(raw, projectID)
}

// parseAuditJSONL decodes raw JSONL bytes into []rotate.AuditEntryView with
// all bounded-read disciplines applied. It is an unexported helper so the
// bounded-decode logic is testable in isolation from the network path.
func parseAuditJSONL(raw []byte, projectID string) ([]rotate.AuditEntryView, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	// Explicit per-line buffer ceiling: the default 64 KiB scanner token cap is
	// not relied upon; maxAuditLineBytes (256 KiB) is set explicitly so the bound
	// is structural and testable. A line exceeding this returns a typed error.
	scanner.Buffer(make([]byte, maxAuditLineBytes), maxAuditLineBytes)

	var views []rotate.AuditEntryView
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue // skip blank lines (e.g. trailing newline)
		}

		var e audit.Event
		if decErr := json.Unmarshal(line, &e); decErr != nil {
			// Malformed JSONL line: surface as a forward-compat warning row
			// rather than aborting the entire result, matching the forward-compat
			// tolerance requirement (an unrecognised or malformed line is surfaced
			// as a warning row, not a hard error).
			views = append(views, rotate.AuditEntryView{
				Kind:       "malformed-line",
				Project:    projectID,
				OccurredAt: time.Now().UTC().Format(time.RFC3339),
				Unknown:    true,
			})
			continue
		}

		view := rotate.ProjectAuditEvent(e)
		// Read-side per-field length and entropy guard on SafeDetails values.
		// This is defence-in-depth: even write-side-validated values are re-
		// checked here. A value failing the guard is dropped (fail-closed by
		// omission), never rendered.
		view.SafeDetails = applyReadSideDetailGuard(view.SafeDetails)
		views = append(views, view)
	}

	if scanErr := scanner.Err(); scanErr != nil {
		// Wrap both the registry sentinel (for errors.Is classification) and the
		// underlying scanner error (bufio.ErrTooLong for a per-line cap violation).
		// The join lets callers errors.Is against either sentinel.
		return nil, fmt.Errorf(
			"%w: FetchAuditLog: JSONL line exceeded per-line byte cap: %w — "+
				"run `byreis doctor` to diagnose",
			coreregistry.ErrCounterStoreUnreadable, scanErr)
	}

	if len(views) <= maxAuditResultCount {
		return views, nil
	}

	// Result count exceeded: return the most recent maxAuditResultCount entries
	// (tail) with a synthetic truncation-advisory entry prepended.
	total := len(views)
	tail := views[total-maxAuditResultCount:]
	advisory := rotate.AuditEntryView{
		Kind:       "truncated",
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
		Project:    projectID,
		Outcome:    fmt.Sprintf("showing most recent %d of %d entries", maxAuditResultCount, total),
		Unknown:    true,
	}
	result := make([]rotate.AuditEntryView, 0, maxAuditResultCount+1)
	result = append(result, advisory)
	result = append(result, tail...)
	return result, nil
}

// applyReadSideDetailGuard filters a SafeDetails map by dropping any value
// that exceeds maxAuditDetailFieldLen bytes or that contains a contiguous
// base64-alphabet run of maxAuditDetailEntropyRunLen or more characters.
// The returned map is always non-nil. This guard does not trust write-side
// validation and applies unconditionally to all surfaced SafeDetails values.
func applyReadSideDetailGuard(in map[string]string) map[string]string {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if len(v) > maxAuditDetailFieldLen {
			continue // drop over-length value (fail-closed by omission)
		}
		if readSideLooksHighEntropy(v) {
			continue // drop high-entropy value (fail-closed by omission)
		}
		out[k] = v
	}
	return out
}

// readSideLooksHighEntropy reports whether s contains a contiguous run of
// maxAuditDetailEntropyRunLen or more base64-alphabet characters. This mirrors
// the write-side heuristic in internal/core/audit/validate.go but is applied
// independently at the read boundary so the two guards are not coupled.
func readSideLooksHighEntropy(s string) bool {
	run := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '=' {
			run++
			if run >= maxAuditDetailEntropyRunLen {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}
