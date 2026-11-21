package store

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// DayCounters are the per-instance day counters, kept for RetainCounters days.
type DayCounters struct {
	Sent    int64 `json:"sent"`
	Invalid int64 `json:"invalid"`
	Rebinds int64 `json:"rebinds"`
}

// GlobalKey names one global day counter. Class and Result come from closed sets.
type GlobalKey struct {
	Day           int
	Class, Result string
}

func counterKey(day int, instanceID string) []byte {
	return fmt.Appendf(nil, "%06d|%s", day, instanceID)
}

func globalKey(day int, class, result string) []byte {
	return fmt.Appendf(nil, "%06d|%s|%s", day, class, result)
}

// keyDay is the day of a counter key in either form.
func keyDay(k, _ []byte) int {
	d, _, _ := strings.Cut(string(k), "|")
	n, _ := strconv.Atoi(d)
	return n
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

// Global returns a global day counter.
func (s *Store) Global(day int, class, result string) int64 {
	var n int64
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bGlobal).Get(globalKey(day, class, result)); v != nil {
			n, _ = strconv.ParseInt(string(v), 10, 64)
		}
		return nil
	})
	return n
}

// Flush is one batch of periodic writes.
type Flush struct {
	Bindings  map[string]*Binding    // by MAC
	Instances []*Instance            // changed records only
	Counters  map[string]DayCounters // per instance, added to the day's counters
	Global    map[GlobalKey]int64    // added to the global counters
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
			if err := addCounters(tx, counterKey(f.Day, id), d); err != nil {
				return err
			}
		}
		for k, n := range f.Global {
			if err := addGlobal(tx, globalKey(k.Day, k.Class, k.Result), n, false); err != nil {
				return err
			}
		}
		return addGlobal(tx, globalKey(f.Day, "all", "peak_minute"), f.Peak, true)
	})
}

func addCounters(tx *bolt.Tx, k []byte, d DayCounters) error {
	var c DayCounters
	if v := tx.Bucket(bCounters).Get(k); v != nil {
		_ = json.Unmarshal(v, &c)
	}
	c.Sent += d.Sent
	c.Invalid += d.Invalid
	c.Rebinds += d.Rebinds
	return put(tx, bCounters, k, &c)
}

// addGlobal adds n to a global counter, or raises it to n for a peak.
func addGlobal(tx *bolt.Tx, k []byte, n int64, peak bool) error {
	var cur int64
	if v := tx.Bucket(bGlobal).Get(k); v != nil {
		cur, _ = strconv.ParseInt(string(v), 10, 64)
	}
	if peak {
		cur = max(cur, n)
	} else {
		cur += n
	}
	return tx.Bucket(bGlobal).Put(k, []byte(strconv.FormatInt(cur, 10)))
}
