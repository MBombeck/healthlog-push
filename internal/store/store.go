// Package store persists the relay state in a single bbolt file. It holds only what spec/protocol.md
// ("State") allows: instances, bindings by token MAC, blocked pairs and tokens, the denylist, day counters
// and the operator control state. Times are stored as day or week numbers only (days since the Unix epoch,
// UTC), never as a time of day. There is no column for a raw token, an address or a push class per instance.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterr "go.etcd.io/bbolt/errors"
)

// Bucket names. Adding a bucket is a reviewed change; TestStoreBucketsAreClosed pins the list.
var (
	bInstances    = []byte("instances")
	bInstanceKeys = []byte("instance_keys")
	bBindings     = []byte("bindings")
	bBlockedPairs = []byte("blocked_pairs")
	bBlockedToken = []byte("blocked_tokens")
	bDenylist     = []byte("denylist")
	bCounters     = []byte("counters")
	bGlobal       = []byte("counters_global")
	bControl      = []byte("control")
)

// Buckets lists every bucket the store creates.
func Buckets() []string {
	return []string{"instances", "instance_keys", "bindings", "blocked_pairs", "blocked_tokens", "denylist", "counters", "counters_global", "control"}
}

// Retention in days (spec/protocol.md, "Retention").
const (
	RetainBlocks        = 365
	RetainCounters      = 7
	RetainGlobal        = 400
	BindingIdleWeeks    = 13 // about 90 days without a push
	InstanceIdleWeeks   = 13 // about 90 days without contact
	ProvisionalDays     = 2  // a provisional binding older than 48 h is removed
	UndeliveredInstDays = 2  // an instance that never delivered is removed after 48 h
)

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

// Day returns the day number of t (UTC).
func Day(t time.Time) int { return int(t.Unix() / 86400) }

// Week returns the number of the ISO-style week (Monday to Sunday) that contains a day.
func Week(day int) int { return (day + 3) / 7 }

// WeekStart returns the day number of the Monday that starts week w.
func WeekStart(w int) int { return w*7 - 3 }

// DayString renders a day number as YYYY-MM-DD.
func DayString(day int) string { return time.Unix(int64(day)*86400, 0).UTC().Format("2006-01-02") }

// ParseDayString parses YYYY-MM-DD into a day number.
func ParseDayString(s string) (int, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return 0, err
	}
	return Day(t), nil
}

// Instance is a registered HealthLog server.
type Instance struct {
	ID               string `json:"id"`
	PublicKey        []byte `json:"publicKey"`
	Tier             string `json:"tier"`
	Reason           string `json:"reason,omitempty"`
	CreatedDay       int    `json:"createdDay"`
	LastSeenWeek     int    `json:"lastSeenWeek"`
	DeviceLimit      int    `json:"deviceLimit"`
	FirstDeliveryDay int    `json:"firstDeliveryDay,omitempty"`
	RotatedDay       int    `json:"rotatedDay,omitempty"`
	QuietSinceDay    int    `json:"quietSinceDay,omitempty"`
	LastPushDay      int    `json:"lastPushDay,omitempty"` // day of the last accepted push, for usage counts
	ReasonDay        int    `json:"reasonDay,omitempty"`   // day of the suspension or revocation
	Client           string `json:"client,omitempty"`
}

// Binding binds a device token (by MAC) to one instance with a device-held key.
type Binding struct {
	InstanceID     string `json:"instanceId"`
	KeyHash        []byte `json:"keyHash"`
	Seq            int64  `json:"seq"`
	Env            string `json:"env"`
	State          string `json:"state"`
	BoundDay       int    `json:"boundDay"`
	LastUsedWeek   int    `json:"lastUsedWeek"`
	LastSuccessDay int    `json:"lastSuccessDay,omitempty"`
	SoftInvalidDay int    `json:"softInvalidDay,omitempty"`
	ConsentVersion string `json:"consentVersion"`
	ConsentDay     string `json:"consentDay"`
	AlertsToday    int    `json:"alertsToday,omitempty"`
	AlertsDay      int    `json:"alertsDay,omitempty"`
}

// DenyEntry is a denylist entry.
type DenyEntry struct {
	InstanceID string `json:"instanceId"`
	Reason     string `json:"reason"`
	Day        int    `json:"day"`
}

// DayCounters are the per-instance day counters, kept for RetainCounters days.
type DayCounters struct {
	Sent    int64 `json:"sent"`
	Invalid int64 `json:"invalid"`
	Rebinds int64 `json:"rebinds"`
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
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second, NoFreelistSync: false})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range Buckets() {
			if _, err := tx.CreateBucketIfNotExists([]byte(b)); err != nil {
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
// by another process, wrong permissions or a full disk. Only then may the file be moved aside (M2).
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

// PutInstance writes an instance and its key index.
func (s *Store) PutInstance(in *Instance) error {
	return s.update(func(tx *bolt.Tx) error {
		if err := put(tx, bInstances, []byte(in.ID), in); err != nil {
			return err
		}
		return tx.Bucket(bInstanceKeys).Put([]byte(hex.EncodeToString(in.PublicKey)), []byte(in.ID))
	})
}

// ReplaceInstanceKey moves the key index from old to the instance's new key.
func (s *Store) ReplaceInstanceKey(in *Instance, oldKey []byte) error {
	return s.update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bInstanceKeys).Delete([]byte(hex.EncodeToString(oldKey))); err != nil {
			return err
		}
		if err := put(tx, bInstances, []byte(in.ID), in); err != nil {
			return err
		}
		return tx.Bucket(bInstanceKeys).Put([]byte(hex.EncodeToString(in.PublicKey)), []byte(in.ID))
	})
}

// DeleteInstance removes an instance, its key index and all its bindings.
func (s *Store) DeleteInstance(id string) error {
	return s.update(func(tx *bolt.Tx) error {
		v := tx.Bucket(bInstances).Get([]byte(id))
		if v != nil {
			var in Instance
			if json.Unmarshal(v, &in) == nil {
				_ = tx.Bucket(bInstanceKeys).Delete([]byte(hex.EncodeToString(in.PublicKey)))
			}
		}
		if err := tx.Bucket(bInstances).Delete([]byte(id)); err != nil {
			return err
		}
		return deleteBindingsOf(tx, id)
	})
}

func deleteBindingsOf(tx *bolt.Tx, id string) error {
	bk := tx.Bucket(bBindings)
	var del [][]byte
	_ = bk.ForEach(func(k, v []byte) error {
		var b Binding
		if json.Unmarshal(v, &b) == nil && b.InstanceID == id {
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

// DeleteBindingsOf removes all bindings of an instance.
func (s *Store) DeleteBindingsOf(id string) error {
	return s.update(func(tx *bolt.Tx) error { return deleteBindingsOf(tx, id) })
}

// Instances returns all instances.
func (s *Store) Instances() ([]*Instance, error) {
	var out []*Instance
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bInstances).ForEach(func(_, v []byte) error {
			var in Instance
			if err := json.Unmarshal(v, &in); err != nil {
				return err
			}
			out = append(out, &in)
			return nil
		})
	})
	return out, err
}

// PutBinding writes a binding under its token MAC.
func (s *Store) PutBinding(mac []byte, b *Binding) error {
	return s.update(func(tx *bolt.Tx) error { return put(tx, bBindings, mac, b) })
}

// PutBindings writes several bindings in one transaction.
func (s *Store) PutBindings(m map[string]*Binding) error {
	return s.update(func(tx *bolt.Tx) error {
		for k, b := range m {
			if err := put(tx, bBindings, []byte(k), b); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteBinding removes a binding.
func (s *Store) DeleteBinding(mac []byte) error {
	return s.update(func(tx *bolt.Tx) error { return tx.Bucket(bBindings).Delete(mac) })
}

// RenameBinding moves a binding to a new MAC key (MAC key rotation).
func (s *Store) RenameBinding(oldMac, newMac []byte, b *Binding) error {
	return s.update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bBindings).Delete(oldMac); err != nil {
			return err
		}
		return put(tx, bBindings, newMac, b)
	})
}

// Bindings returns every binding keyed by the MAC as a string of raw bytes.
func (s *Store) Bindings() (map[string]*Binding, error) {
	out := map[string]*Binding{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bBindings).ForEach(func(k, v []byte) error {
			var b Binding
			if err := json.Unmarshal(v, &b); err != nil {
				return err
			}
			out[string(k)] = &b
			return nil
		})
	})
	return out, err
}

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

// PairBlock is a stored device opt-out. KeyHash, Seq and Iat describe the binding key that opted out, the
// sequence number of the binding it left and the time of its opt-out statement: only a later statement by
// that same key may lift the block. A block restored from an export carries no key and cannot be lifted.
type PairBlock struct {
	Day     int
	KeyHash []byte
	Seq     int64
	Iat     int64
}

// encode stores a block as "day" (restored, no key) or "day|hex(keyHash)|seq|iat".
func (b PairBlock) encode() []byte {
	if len(b.KeyHash) == 0 {
		return []byte(strconv.Itoa(b.Day))
	}
	return []byte(fmt.Sprintf("%d|%x|%d|%d", b.Day, b.KeyHash, b.Seq, b.Iat))
}

func decodePairBlock(v []byte) PairBlock {
	parts := strings.Split(string(v), "|")
	var b PairBlock
	b.Day, _ = strconv.Atoi(parts[0])
	if len(parts) == 4 {
		if kh, err := hex.DecodeString(parts[1]); err == nil && len(kh) == sha256.Size {
			b.KeyHash = kh
			b.Seq, _ = strconv.ParseInt(parts[2], 10, 64)
			b.Iat, _ = strconv.ParseInt(parts[3], 10, 64)
		}
	}
	return b
}

// blockDay is the day of a stored block value in either form.
func blockDay(v []byte) int {
	d, _, _ := strings.Cut(string(v), "|")
	n, _ := strconv.Atoi(d)
	return n
}

// BlockPair records that the device opted out of this instance with the binding key hashed in b.KeyHash.
func (s *Store) BlockPair(mac []byte, instanceID string, b PairBlock) error {
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bBlockedPairs).Put(pairKey(mac, instanceID), b.encode())
	})
}

// PairBlocked reports whether the pair is blocked.
func (s *Store) PairBlocked(mac []byte, instanceID string) bool {
	_, ok := s.GetPairBlock(mac, instanceID)
	return ok
}

// GetPairBlock returns the stored opt-out of the pair.
func (s *Store) GetPairBlock(mac []byte, instanceID string) (PairBlock, bool) {
	var (
		b     PairBlock
		found bool
	)
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bBlockedPairs).Get(pairKey(mac, instanceID)); v != nil {
			b, found = decodePairBlock(v), true
		}
		return nil
	})
	return b, found
}

// UnblockPair removes a device opt-out; the relay calls it only for a return the same key signed.
func (s *Store) UnblockPair(mac []byte, instanceID string) error {
	return s.update(func(tx *bolt.Tx) error { return tx.Bucket(bBlockedPairs).Delete(pairKey(mac, instanceID)) })
}

// BlockToken blocks a token MAC for every instance except its current holder.
func (s *Store) BlockToken(mac []byte, day int) error {
	return s.update(func(tx *bolt.Tx) error { return tx.Bucket(bBlockedToken).Put(tokenKey(mac), []byte(strconv.Itoa(day))) })
}

// UnblockToken removes a token block.
func (s *Store) UnblockToken(mac []byte) error {
	return s.update(func(tx *bolt.Tx) error { return tx.Bucket(bBlockedToken).Delete(tokenKey(mac)) })
}

// TokenBlocked reports whether a token MAC is blocked.
func (s *Store) TokenBlocked(mac []byte) bool {
	found := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket(bBlockedToken).Get(tokenKey(mac)) != nil
		return nil
	})
	return found
}

// PutDeny writes a denylist entry.
func (s *Store) PutDeny(e *DenyEntry) error {
	return s.update(func(tx *bolt.Tx) error { return put(tx, bDenylist, []byte(e.InstanceID), e) })
}

// DeleteDeny removes a denylist entry.
func (s *Store) DeleteDeny(id string) error {
	return s.update(func(tx *bolt.Tx) error { return tx.Bucket(bDenylist).Delete([]byte(id)) })
}

// Denylist returns all entries.
func (s *Store) Denylist() ([]*DenyEntry, error) {
	var out []*DenyEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bDenylist).ForEach(func(_, v []byte) error {
			var e DenyEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, &e)
			return nil
		})
	})
	return out, err
}

func counterKey(day int, instanceID string) []byte {
	return fmt.Appendf(nil, "%06d|%s", day, instanceID)
}

// AddCounters adds to the per-instance counters of a day.
func (s *Store) AddCounters(day int, instanceID string, d DayCounters) error {
	return s.update(func(tx *bolt.Tx) error {
		k := counterKey(day, instanceID)
		var c DayCounters
		if v := tx.Bucket(bCounters).Get(k); v != nil {
			_ = json.Unmarshal(v, &c)
		}
		c.Sent += d.Sent
		c.Invalid += d.Invalid
		c.Rebinds += d.Rebinds
		return put(tx, bCounters, k, &c)
	})
}

// Counters returns the counters of an instance for a day.
func (s *Store) Counters(day int, instanceID string) DayCounters {
	var c DayCounters
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bCounters).Get(counterKey(day, instanceID)); v != nil {
			_ = json.Unmarshal(v, &c)
		}
		return nil
	})
	return c
}

// AddGlobal adds n to a global day counter. class and result come from closed sets.
func (s *Store) AddGlobal(day int, class, result string, n int64) error {
	return s.update(func(tx *bolt.Tx) error {
		k := fmt.Appendf(nil, "%06d|%s|%s", day, class, result)
		var cur int64
		if v := tx.Bucket(bGlobal).Get(k); v != nil {
			cur, _ = strconv.ParseInt(string(v), 10, 64)
		}
		if result == "peak_minute" {
			cur = max(cur, n)
		} else {
			cur += n
		}
		return tx.Bucket(bGlobal).Put(k, []byte(strconv.FormatInt(cur, 10)))
	})
}

// Global returns a global day counter.
func (s *Store) Global(day int, class, result string) int64 {
	var n int64
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bGlobal).Get(fmt.Appendf(nil, "%06d|%s|%s", day, class, result)); v != nil {
			n, _ = strconv.ParseInt(string(v), 10, 64)
		}
		return nil
	})
	return n
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

// Prune applies the retention rules for blocks, denylist and counters for the given day. Bindings and
// instances are pruned by the relay, which owns their in-memory copies.
func (s *Store) Prune(today int) error {
	return s.update(func(tx *bolt.Tx) error {
		pruneDay := func(bucket []byte, keep int, dayOf func(k, v []byte) int) error {
			bk := tx.Bucket(bucket)
			var del [][]byte
			_ = bk.ForEach(func(k, v []byte) error {
				if today-dayOf(k, v) > keep {
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
		valDay := func(_, v []byte) int { return blockDay(v) }
		keyDay := func(k, _ []byte) int { d, _, _ := strings.Cut(string(k), "|"); n, _ := strconv.Atoi(d); return n }
		denyDay := func(_, v []byte) int { var e DenyEntry; _ = json.Unmarshal(v, &e); return e.Day }
		for _, step := range []struct {
			b    []byte
			keep int
			f    func(k, v []byte) int
		}{
			{bBlockedPairs, RetainBlocks, valDay}, {bBlockedToken, RetainBlocks, valDay}, {bDenylist, RetainBlocks, denyDay},
			{bCounters, RetainCounters, keyDay}, {bGlobal, RetainGlobal, keyDay},
		} {
			if err := pruneDay(step.b, step.keep, step.f); err != nil {
				return err
			}
		}
		return nil
	})
}

// Flush is one batch of periodic writes.
type Flush struct {
	Bindings  map[string]*Binding    // by MAC
	Instances []*Instance            // changed records only
	Counters  map[string]DayCounters // per instance, added to the day's counters
	Global    map[[3]string]int64    // (day, class, result) added to the global counters
	Day       int
	Peak      int64 // busiest minute of the day so far
}

// ApplyFlush writes a flush in a single transaction (one fsync, however many instances there are).
func (s *Store) ApplyFlush(f *Flush) error {
	return s.update(func(tx *bolt.Tx) error {
		for k, b := range f.Bindings {
			if err := put(tx, bBindings, []byte(k), b); err != nil {
				return err
			}
		}
		for _, in := range f.Instances {
			if err := put(tx, bInstances, []byte(in.ID), in); err != nil {
				return err
			}
		}
		for id, d := range f.Counters {
			k := counterKey(f.Day, id)
			var c DayCounters
			if v := tx.Bucket(bCounters).Get(k); v != nil {
				_ = json.Unmarshal(v, &c)
			}
			c.Sent += d.Sent
			c.Invalid += d.Invalid
			c.Rebinds += d.Rebinds
			if err := put(tx, bCounters, k, &c); err != nil {
				return err
			}
		}
		add := func(key []byte, n int64, peak bool) error {
			var cur int64
			if v := tx.Bucket(bGlobal).Get(key); v != nil {
				cur, _ = strconv.ParseInt(string(v), 10, 64)
			}
			if peak {
				cur = max(cur, n)
			} else {
				cur += n
			}
			return tx.Bucket(bGlobal).Put(key, []byte(strconv.FormatInt(cur, 10)))
		}
		for k, n := range f.Global {
			d, _ := strconv.Atoi(k[0])
			if err := add(fmt.Appendf(nil, "%06d|%s|%s", d, k[1], k[2]), n, false); err != nil {
				return err
			}
		}
		return add(fmt.Appendf(nil, "%06d|all|peak_minute", f.Day), f.Peak, true)
	})
}
