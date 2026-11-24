package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

// RetainWalletSigns is how long the wallet signing ledger keeps an entry, in days.
const RetainWalletSigns = 400

// WalletSign is one ledger entry: which instance had a manifest signed on which day. The key is the SHA-256
// of the manifest bytes followed by the instance id; there is nothing else, no time of day, no file hash,
// no count. The ledger is not exported, logged or counted in a metric; only `admin wallet lookup` reads it.
type WalletSign struct {
	InstanceID string `json:"instanceId"`
	Day        int    `json:"day"`
}

type walletSignValue struct {
	Day int `json:"day"`
}

func walletSignKey(manifestSHA256 []byte, instanceID string) []byte {
	return append(append([]byte(nil), manifestSHA256...), instanceID...)
}

func walletSignDay(_, v []byte) int {
	var w walletSignValue
	_ = json.Unmarshal(v, &w)
	return w.Day
}

// PutWalletSign records that instanceID had the manifest with this SHA-256 signed on day.
func (s *Store) PutWalletSign(manifestSHA256 []byte, instanceID string, day int) error {
	return s.update(func(tx *bolt.Tx) error {
		return put(tx, bWalletSigns, walletSignKey(manifestSHA256, instanceID), walletSignValue{Day: day})
	})
}

// LookupWalletSign returns every entry for a manifest hash given as 64 hex characters.
func (s *Store) LookupWalletSign(hexSHA256 string) ([]WalletSign, error) {
	h, err := hex.DecodeString(hexSHA256)
	if err != nil || len(h) != 32 {
		return nil, ErrNotFound
	}
	out := []WalletSign{}
	err = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bWalletSigns).Cursor()
		for k, v := c.Seek(h); len(k) > 32 && bytes.Equal(k[:32], h); k, v = c.Next() {
			out = append(out, WalletSign{InstanceID: string(k[32:]), Day: walletSignDay(k, v)})
		}
		return nil
	})
	return out, err
}
