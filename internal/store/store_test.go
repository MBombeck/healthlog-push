package store

import (
	"path/filepath"
	"slices"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func open(t *testing.T) *Store {
	s, err := Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestStoreBucketsAreClosed pins the bucket list: a new bucket is a privacy decision (spec/protocol.md).
func TestStoreBucketsAreClosed(t *testing.T) {
	s := open(t)
	var got []string
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error { got = append(got, string(name)); return nil })
	})
	slices.Sort(got)
	want := []string{"bindings", "blocked_pairs", "blocked_tokens", "control", "counters", "counters_global", "denylist", "instance_keys", "instances"}
	if !slices.Equal(got, want) {
		t.Fatalf("buckets %v", got)
	}
}

func TestRetention(t *testing.T) {
	s := open(t)
	today := 20000
	_ = s.BlockPair([]byte("m1"), "i", today-366)
	_ = s.BlockPair([]byte("m2"), "i", today-10)
	_ = s.AddCounters(today-8, "i", DayCounters{Sent: 1})
	_ = s.AddCounters(today-6, "i", DayCounters{Sent: 1})
	_ = s.AddGlobal(today-401, "alert", "accepted", 1)
	_ = s.AddGlobal(today-399, "alert", "accepted", 1)
	_ = s.PutDeny(&DenyEntry{InstanceID: "old", Reason: "abuse", Day: today - 400})
	if err := s.Prune(today); err != nil {
		t.Fatal(err)
	}
	if s.PairBlocked([]byte("m1"), "i") || !s.PairBlocked([]byte("m2"), "i") {
		t.Error("blocked pairs: 12 months")
	}
	if s.Counters(today-8, "i").Sent != 0 || s.Counters(today-6, "i").Sent != 1 {
		t.Error("per-instance counters: 7 days")
	}
	if s.Global(today-401, "alert", "accepted") != 0 || s.Global(today-399, "alert", "accepted") != 1 {
		t.Error("global counters: 400 days")
	}
	if d, _ := s.Denylist(); len(d) != 0 {
		t.Error("denylist: 12 months")
	}
}

func TestExportRoundTrip(t *testing.T) {
	s := open(t)
	_ = s.PutInstance(&Instance{ID: "a", PublicKey: make([]byte, 32), Tier: TierStandard, CreatedDay: 1, DeviceLimit: 50})
	_ = s.PutBinding([]byte("mac"), &Binding{InstanceID: "a"})
	_ = s.PutDeny(&DenyEntry{InstanceID: "b", Reason: "spam", Day: 5})
	dir := t.TempDir()
	ex, _ := s.BuildExport(10)
	if err := WriteExport(dir, ex); err != nil {
		t.Fatal(err)
	}
	back, err := ReadExport(filepath.Join(dir, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	s2 := open(t)
	if n, err := s2.Import(back, 10); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if n, _ := s2.Import(back, 10); n != 0 {
		t.Fatal("import not idempotent")
	}
	if b, _ := s2.Bindings(); len(b) != 0 {
		t.Fatal("bindings traveled with the export")
	}
	if d, _ := s2.Denylist(); len(d) != 1 {
		t.Fatal("denylist missing")
	}
}

func TestWeeksStartOnMonday(t *testing.T) {
	d, _ := ParseDayString("2026-11-23") // a Monday
	if DayString(WeekStart(Week(d))) != "2026-11-23" || Week(d+6) != Week(d) || Week(d+7) != Week(d)+1 {
		t.Fatal("week boundaries")
	}
}

// TestExportBlocksRetention: only unexpired pair blocks are exported, and an import drops expired ones too.
func TestExportBlocksRetention(t *testing.T) {
	s := open(t)
	today := 20000
	_ = s.BlockPair([]byte("old-mac"), "i", today-366)
	_ = s.BlockPair([]byte("new-mac"), "i", today-10)
	ex, err := s.BuildExport(today)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.BlockedPairs) != 1 || ex.BlockedPairs[0].ExpiresDay != DayString(today-10+RetainBlocks) {
		t.Fatalf("export: %+v", ex.BlockedPairs)
	}
	ex.BlockedPairs = append(ex.BlockedPairs, ExportedBlock{Pair: ex.BlockedPairs[0].Pair[:62] + "00", Reason: ReasonDeviceOptOut, ExpiresDay: DayString(today - 1)})
	s2 := open(t)
	if _, err := s2.Import(ex, today); err != nil {
		t.Fatal(err)
	}
	if !s2.PairBlocked([]byte("new-mac"), "i") {
		t.Fatal("block lost on import")
	}
	ex2, _ := s2.BuildExport(today)
	if len(ex2.BlockedPairs) != 1 {
		t.Fatalf("expired block imported: %d", len(ex2.BlockedPairs))
	}
}
