package rotate

import (
	"context"
	"fmt"

	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
)

// NewPlanner returns the in-package planner. There are no dependencies — the
// planner is pure: every input is in PlanInput and every output is in
// RotationPlan. No fs, network, clock, randomness, or keychain access.
func NewPlanner() RotationPlanner { return planner{} }

type planner struct{}

// Plan composes R' from R + flag intents in a fixed ordering:
//
//  1. replace, 2. remove, 3. add.
//
// It rejects:
//   - --add X --remove X within a single invocation (mutual exclusion).
//   - --replace old=new where new also appears in --remove (mutual exclusion).
//   - --remove X where X is not in R.
//   - --add X where X is not a registered admin at the SourceVerified registry.
//   - an empty resulting R'.
//
// Plan never writes anywhere; the only side effect is the returned value.
// Plan is callable identically in --dry-run and real-run modes.
func (planner) Plan(ctx context.Context, in PlanInput) (RotationPlan, error) {
	if err := ctx.Err(); err != nil {
		return RotationPlan{}, fmt.Errorf("rotation plan cancelled: %w", err)
	}

	// Build lookups keyed by AgePubKey: the canonical recipient identity in
	// every flag and in R. Label is diagnostic-only and never used for
	// identity decisions here.
	preSet := pubkeySet(in.PreRotationRecipients)
	adminSet := pubkeySet(in.RegisteredAdmins)

	// Track flag intents per pubkey so mutually exclusive intents are
	// detected exactly once and the operator gets a deterministic error.
	type intent struct {
		add     bool
		remove  bool
		replace bool
	}
	intents := map[string]*intent{}
	getIntent := func(pk string) *intent {
		if i, ok := intents[pk]; ok {
			return i
		}
		i := &intent{}
		intents[pk] = i
		return i
	}

	// Stage --replace old=new first in the fixed ordering: old is treated as
	// a remove, new is treated as an add.
	for _, pair := range in.ReplacePairs {
		oldPK := pair.Old.AgePubKey
		newPK := pair.New.AgePubKey
		if oldPK == "" || newPK == "" {
			return RotationPlan{}, fmt.Errorf(
				"%w: --replace requires non-empty old and new recipient pubkeys",
				ErrRotationFlagConflict)
		}
		oi := getIntent(oldPK)
		oi.replace = true
		oi.remove = true
		ni := getIntent(newPK)
		ni.replace = true
		ni.add = true
	}

	for _, r := range in.RemovePubkeys {
		if r.AgePubKey == "" {
			return RotationPlan{}, fmt.Errorf(
				"%w: --remove requires a non-empty recipient pubkey",
				ErrRotationFlagConflict)
		}
		getIntent(r.AgePubKey).remove = true
	}

	for _, r := range in.AddPubkeys {
		if r.AgePubKey == "" {
			return RotationPlan{}, fmt.Errorf(
				"%w: --add requires a non-empty recipient pubkey",
				ErrRotationFlagConflict)
		}
		getIntent(r.AgePubKey).add = true
	}

	// Detect mutually exclusive intents per pubkey.
	for pk, i := range intents {
		if i.add && i.remove && !i.replace {
			return RotationPlan{}, fmt.Errorf(
				"%w: pubkey %q is named by both --add and --remove",
				ErrRotationFlagConflict, pk)
		}
	}

	// Validate --remove targets exist in R.
	for pk, i := range intents {
		if !i.remove {
			continue
		}
		if _, ok := preSet[pk]; !ok {
			return RotationPlan{}, fmt.Errorf(
				"%w: pubkey %q is not in the current recipient set",
				ErrRotationRemoveAbsentRecipient, pk)
		}
	}

	// Validate --add targets are registered admins.
	for pk, i := range intents {
		if !i.add {
			continue
		}
		if _, ok := adminSet[pk]; !ok {
			return RotationPlan{}, fmt.Errorf(
				"%w: pubkey %q is not a registered admin",
				ErrRotationAddNotAdmin, pk)
		}
	}

	// Compose R': start from R, apply removes, then apply adds.
	// Replaces are decomposed into one remove + one add above, so we never
	// special-case them here.
	newSet := make(map[string]rectypes.Recipient, len(in.PreRotationRecipients))
	for _, r := range in.PreRotationRecipients {
		newSet[r.AgePubKey] = r
	}
	for pk, i := range intents {
		if i.remove {
			delete(newSet, pk)
		}
	}
	// Source the added recipients from the input slices so we carry their
	// labels through. We prefer the --add slice; if a replace surfaced the
	// recipient, we use the replace.New entry.
	addedFromInput := map[string]rectypes.Recipient{}
	for _, r := range in.AddPubkeys {
		addedFromInput[r.AgePubKey] = r
	}
	for _, p := range in.ReplacePairs {
		addedFromInput[p.New.AgePubKey] = p.New
	}
	for pk, i := range intents {
		if !i.add {
			continue
		}
		newSet[pk] = addedFromInput[pk]
	}

	if len(newSet) == 0 {
		return RotationPlan{}, ErrRotationEmptyRecipientSet
	}

	// Materialise R' in a deterministic order (lex by AgePubKey) so the
	// dry-run output and the downstream Phase-1 inputs are reproducible.
	added, removed := diffSets(preSet, newSet, in.PreRotationRecipients, addedFromInput)
	final := mapToSortedRecipients(newSet)

	plan := RotationPlan{
		ProjectID:         in.ProjectID,
		NewRecipientSet:   final,
		AddedRecipients:   added,
		RemovedRecipients: removed,
		FilesToReencrypt:  append([]FileSnapshot(nil), in.PreRotationFiles...),
		NewEpoch:          in.CurrentMaxEpoch + 1,
		HasRemovals:       len(removed) > 0,
	}
	return plan, nil
}

// pubkeySet returns a set keyed by AgePubKey for fast membership tests.
func pubkeySet(rs []rectypes.Recipient) map[string]rectypes.Recipient {
	out := make(map[string]rectypes.Recipient, len(rs))
	for _, r := range rs {
		out[r.AgePubKey] = r
	}
	return out
}

// diffSets returns the recipients added (in newSet but not preSet) and
// removed (in preSet but not newSet). Order is lex by AgePubKey for
// determinism. The added entries are sourced from the addedFromInput map so
// the label travels through; the removed entries come from the pre-rotation
// slice.
func diffSets(
	preSet map[string]rectypes.Recipient,
	newSet map[string]rectypes.Recipient,
	preList []rectypes.Recipient,
	addedFromInput map[string]rectypes.Recipient,
) ([]rectypes.Recipient, []rectypes.Recipient) {
	var added, removed []rectypes.Recipient
	for pk := range newSet {
		if _, ok := preSet[pk]; !ok {
			if r, ok := addedFromInput[pk]; ok {
				added = append(added, r)
			} else {
				added = append(added, newSet[pk])
			}
		}
	}
	for _, r := range preList {
		if _, ok := newSet[r.AgePubKey]; !ok {
			removed = append(removed, r)
		}
	}
	sortByPubKey(added)
	sortByPubKey(removed)
	return added, removed
}

func mapToSortedRecipients(m map[string]rectypes.Recipient) []rectypes.Recipient {
	out := make([]rectypes.Recipient, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sortByPubKey(out)
	return out
}

// sortByPubKey sorts in place by AgePubKey. Lex order is stable across runs
// and deterministic without a clock or random source.
func sortByPubKey(rs []rectypes.Recipient) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j-1].AgePubKey > rs[j].AgePubKey; j-- {
			rs[j-1], rs[j] = rs[j], rs[j-1]
		}
	}
}
