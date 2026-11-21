package store

import (
	"crypto/sha256"
	"encoding/json"
	"strconv"

	bolt "go.etcd.io/bbolt"
)

// pairKey is the stored form of a device-instance pair: SHA-256 over a label, the token MAC (itself keyed
// with the relay's token MAC key) and the instance id. It is the only form in which a pair is kept or
// exported; neither the token nor its MAC can be read back from it.
func pairKey(mac []byte, instanceID string) []byte {
	h := sha256.New()
	h.Write([]byte("hl-blocked-pair\n"))
	h.Write(mac)
	h.Write([]byte("\n" + instanceID))
	return h.Sum(nil)
}

// tokenKey is the stored form of an operator token block: SHA-256 over a label and the token MAC.
func tokenKey(mac []byte) []byte {
	h := sha256.New()
	h.Write([]byte("hl-blocked-token\n"))
	h.Write(mac)
	return h.Sum(nil)
}

// PairBlock is a stored device opt-out, kept as JSON. KeyHash and Seq describe the binding key that opted
// out and the sequence number of the binding it left: only a statement by that same key with a higher
// sequence number may lift the block. A block restored from an export carries no key and cannot be lifted.
type PairBlock struct {
	Day     int    `json:"day"`
	KeyHash []byte `json:"keyHash,omitempty"`
	Seq     int64  `json:"seq,omitempty"`
}

func decodePairBlock(v []byte) PairBlock {
	var b PairBlock
	_ = json.Unmarshal(v, &b)
	if len(b.KeyHash) != sha256.Size {
		b.KeyHash, b.Seq = nil, 0
	}
	return b
}

// pairBlockDay is the day of a stored pair block.
func pairBlockDay(_, v []byte) int { return decodePairBlock(v).Day }

// tokenBlockDay is the day of a stored token block, kept as a decimal day number.
func tokenBlockDay(_, v []byte) int { n, _ := strconv.Atoi(string(v)); return n }

// BlockPair records that the device opted out of this instance with the binding key hashed in b.KeyHash.
func (s *Store) BlockPair(mac []byte, instanceID string, b PairBlock) error {
	return s.update(func(tx *bolt.Tx) error { return put(tx, bBlockedPairs, pairKey(mac, instanceID), b) })
}

// GetPairBlock returns the stored opt-out of the pair and whether there is one.
func (s *Store) GetPairBlock(mac []byte, instanceID string) (PairBlock, bool) {
	var (
		b     PairBlock
		found bool
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bBlockedPairs).Get(pairKey(mac, instanceID)); v != nil {
			b, found = decodePairBlock(v), true
		}
		return nil
	})
	if err != nil {
		return PairBlock{}, true // fail closed: an unreadable store blocks
	}
	return b, found
}

// UnblockPair removes a device opt-out; the relay calls it only for a return the same key signed.
func (s *Store) UnblockPair(mac []byte, instanceID string) error {
	return s.update(func(tx *bolt.Tx) error { return tx.Bucket(bBlockedPairs).Delete(pairKey(mac, instanceID)) })
}

// BlockToken blocks a token MAC for every instance except its current holder.
func (s *Store) BlockToken(mac []byte, day int) error {
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bBlockedTokens).Put(tokenKey(mac), []byte(strconv.Itoa(day)))
	})
}

// UnblockToken removes a token block.
func (s *Store) UnblockToken(mac []byte) error {
	return s.update(func(tx *bolt.Tx) error { return tx.Bucket(bBlockedTokens).Delete(tokenKey(mac)) })
}

// TokenBlocked reports whether a token MAC is blocked.
func (s *Store) TokenBlocked(mac []byte) bool {
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket(bBlockedTokens).Get(tokenKey(mac)) != nil
		return nil
	})
	return found || err != nil // fail closed: an unreadable store blocks
}

// pinKey is the stored form of an opt-out key pin: SHA-256 over a label and the token MAC.
func pinKey(mac []byte) []byte {
	h := sha256.New()
	h.Write([]byte("hl-optout-pin\n"))
	h.Write(mac)
	return h.Sum(nil)
}

// OptOutPin remembers, for a token whose device opted out, which binding key did so. While the token is
// unbound, a binding with any other key has to go through the challenge the device answers; otherwise a
// second instance with a self-made key could bind the token again right after the opt-out. A pin restored
// from an export carries no key: every new binding of that token then needs the challenge.
type OptOutPin struct {
	Day     int    `json:"day"`
	KeyHash []byte `json:"keyHash,omitempty"`
}

func pinDay(_, v []byte) int {
	var p OptOutPin
	_ = json.Unmarshal(v, &p)
	return p.Day
}

// PutOptOutPin records or replaces the pin of a token.
func (s *Store) PutOptOutPin(mac []byte, p OptOutPin) error {
	return s.update(func(tx *bolt.Tx) error { return put(tx, bOptOutPins, pinKey(mac), p) })
}

// GetOptOutPin returns the pin of a token and whether there is one. A read error counts as pinned, so a
// damaged store fails closed.
func (s *Store) GetOptOutPin(mac []byte) (OptOutPin, bool) {
	var (
		p     OptOutPin
		found bool
	)
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bOptOutPins).Get(pinKey(mac)); v != nil {
			found = true
			return json.Unmarshal(v, &p)
		}
		return nil
	})
	if err != nil {
		return OptOutPin{}, true
	}
	if len(p.KeyHash) != sha256.Size {
		p.KeyHash = nil
	}
	return p, found
}
