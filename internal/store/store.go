// Package store persists the relay state in a single bbolt file. It holds only what spec/protocol.md
// ("State") allows: instances, bindings by token MAC, blocked pairs and tokens, the denylist, day counters
// and the operator control state. Times are stored as day or week numbers only (days since the Unix epoch,
// UTC), never as a time of day. There is no column for a raw token, an address or a push class per instance.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterr "go.etcd.io/bbolt/errors"
)

// Bucket names. Adding a bucket is a reviewed change; TestStoreBucketsAreClosed pins the list.
var (
	bInstances     = []byte("instances")
	bInstanceKeys  = []byte("instance_keys")
	bBindings      = []byte("bindings")
	bBlockedPairs  = []byte("blocked_pairs")
	bBlockedTokens = []byte("blocked_tokens")
	bDenylist      = []byte("denylist")
	bCounters      = []byte("counters")
	bGlobal        = []byte("counters_global")
	bControl       = []byte("control")

	buckets = [][]byte{bInstances, bInstanceKeys, bBindings, bBlockedPairs, bBlockedTokens, bDenylist, bCounters, bGlobal, bControl}
)

// Buckets lists every bucket the store creates.
func Buckets() []string {
	out := make([]string, len(buckets))
	for i, b := range buckets {
		out[i] = string(b)
	}
	return out
}

// Tiers.
const (
	TierProbation = "probation"
	TierStandard  = "standard"
	TierSuspended = "suspended"
	TierRevoked   = "revoked"
)

// Binding states.
const (
	StateProvisional = "provisional"
	StateActive      = "active"
	StateSoftInvalid = "soft_invalid"
)

// Reasons for suspension and denylist entries: a closed set.
var Reasons = map[string]bool{
	"abuse": true, "spam": true, "invalid_tokens": true, "harassment": true, "legal": true,
	"compromised": true, "terms": true, "operator_request": true,
}

// Store wraps the bbolt database.
type Store struct {
	db     *bolt.DB
	writes atomic.Int64
}

// update runs one write transaction and counts it.
func (s *Store) update(fn func(*bolt.Tx) error) error {
	s.writes.Add(1)
	return s.db.Update(fn)
}

// Writes returns the number of write transactions since open, for tests of the write pattern.
func (s *Store) Writes() int64 { return s.writes.Load() }

// ErrNotFound is returned for missing records.
var ErrNotFound = errors.New("not found")

// Open opens or creates the database and its buckets.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range buckets {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// ErrCorrupt marks a failed consistency check.
var ErrCorrupt = errors.New("store corrupt")

// Check runs the bbolt consistency check. A finding is returned wrapped in ErrCorrupt.
func (s *Store) Check() error {
	return s.db.View(func(tx *bolt.Tx) error {
		for err := range tx.Check() {
			return fmt.Errorf("%w: %v", ErrCorrupt, err) //nolint:errorlint // the finding is detail, ErrCorrupt the class
		}
		return nil
	})
}

// IsCorrupt reports whether err proves that the database file itself is damaged, as opposed to a lock held
// by another process, wrong permissions or a full disk. Only then may the file be moved aside; any other
// failure stops the relay so that no binding is lost to a fixable cause.
func IsCorrupt(err error) bool {
	for _, e := range []error{ErrCorrupt, bolterr.ErrInvalid, bolterr.ErrVersionMismatch, bolterr.ErrChecksum, bolterr.ErrInvalidMapping} {
		if errors.Is(err, e) {
			return true
		}
	}
	// bbolt reports a truncated file with an unwrapped error.
	return err != nil && strings.HasPrefix(err.Error(), "file size too small")
}

func put(tx *bolt.Tx, bucket, k []byte, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return tx.Bucket(bucket).Put(k, b)
}

// deleteWhere removes every record of a bucket for which match reports true.
func deleteWhere(tx *bolt.Tx, bucket []byte, match func(k, v []byte) bool) error {
	bk := tx.Bucket(bucket)
	var del [][]byte
	_ = bk.ForEach(func(k, v []byte) error {
		if match(k, v) {
			del = append(del, append([]byte(nil), k...))
		}
		return nil
	})
	for _, k := range del {
		if err := bk.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// GetControl reads the operator control state into v.
func (s *Store) GetControl(v any) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bControl).Get([]byte("state"))
		if b == nil {
			return ErrNotFound
		}
		return json.Unmarshal(b, v)
	})
}

// PutControl writes the operator control state.
func (s *Store) PutControl(v any) error {
	return s.update(func(tx *bolt.Tx) error { return put(tx, bControl, []byte("state"), v) })
}
