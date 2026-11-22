package store

import (
	bolt "go.etcd.io/bbolt"
)

// Retention in days (spec/protocol.md, "Retention").
const (
	RetainBlocks        = 365
	RetainCounters      = 7
	RetainGlobal        = 400
	BindingIdleWeeks    = 13 // about 90 days without a push
	InstanceIdleWeeks   = 13 // about 90 days without contact
	ProvisionalDays     = 2  // a provisional binding older than 48 h is removed
	UndeliveredInstDays = 30 // an instance that never delivered is removed once it was also silent this long
)

// Prune applies the retention rules for blocks, opt-out pins and counters for the given day. Bindings and
// instances are pruned by the relay, which owns their in-memory copies.
func (s *Store) Prune(today int) error {
	steps := []struct {
		bucket []byte
		keep   int
		dayOf  func(k, v []byte) int
	}{
		{bBlockedPairs, RetainBlocks, pairBlockDay}, {bBlockedTokens, RetainBlocks, tokenBlockDay},
		{bOptOutPins, RetainBlocks, pinDay}, {bCounters, RetainCounters, keyDay}, {bGlobal, RetainGlobal, keyDay},
	}
	return s.update(func(tx *bolt.Tx) error {
		for _, step := range steps {
			if err := deleteWhere(tx, step.bucket, func(k, v []byte) bool { return today-step.dayOf(k, v) > step.keep }); err != nil {
				return err
			}
		}
		return nil
	})
}
