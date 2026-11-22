package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
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
	want := []string{"bindings", "blocked_pairs", "blocked_tokens", "control", "counters", "counters_global", "instance_keys", "instances", "optout_pins"}
	if !slices.Equal(got, want) {
		t.Fatalf("buckets %v", got)
	}
}

func TestRetention(t *testing.T) {
	s := open(t)
	today := 20000
	_ = s.BlockPair([]byte("m1"), "i", PairBlock{Day: today - 366})
	_ = s.BlockPair([]byte("m2"), "i", PairBlock{Day: today - 10})
	kh := sha256.Sum256([]byte("key"))
	_ = s.BlockPair([]byte("m3"), "i", PairBlock{Day: today - 366, KeyHash: kh[:], Seq: 4})
	_ = s.BlockPair([]byte("m4"), "i", PairBlock{Day: today - 10, KeyHash: kh[:], Seq: 4})
	// Counters are seeded the way the relay writes them: through a flush.
	for _, f := range []*Flush{
		{Day: today - 8, Counters: map[string]DayCounters{"i": {Sent: 1}}, Global: map[GlobalKey]int64{{today - 401, "alert", "accepted"}: 1}},
		{Day: today - 6, Counters: map[string]DayCounters{"i": {Sent: 1}}, Global: map[GlobalKey]int64{{today - 399, "alert", "accepted"}: 1}},
	} {
		if err := s.ApplyFlush(f); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.PutOptOutPin([]byte("p1"), OptOutPin{Day: today - 366, KeyHash: kh[:]})
	_ = s.PutOptOutPin([]byte("p2"), OptOutPin{Day: today - 10, KeyHash: kh[:]})
	if err := s.Prune(today); err != nil {
		t.Fatal(err)
	}
	if pairBlocked(s, "m1") || !pairBlocked(s, "m2") {
		t.Error("blocked pairs: 12 months")
	}
	if pairBlocked(s, "m3") || !pairBlocked(s, "m4") {
		t.Error("blocked pairs with a key: 12 months")
	}
	if b, _ := s.GetPairBlock([]byte("m4"), "i"); !bytes.Equal(b.KeyHash, kh[:]) || b.Seq != 4 || b.Day != today-10 {
		t.Errorf("stored opt-out: %+v", b)
	}
	if s.Counters(today-8, "i").Sent != 0 || s.Counters(today-6, "i").Sent != 1 {
		t.Error("per-instance counters: 7 days")
	}
	if s.Global(today-401, "alert", "accepted") != 0 || s.Global(today-399, "alert", "accepted") != 1 {
		t.Error("global counters: 400 days")
	}
	if _, ok := s.GetOptOutPin([]byte("p1")); ok {
		t.Error("opt-out pins: 12 months")
	}
	if p, ok := s.GetOptOutPin([]byte("p2")); !ok || !bytes.Equal(p.KeyHash, kh[:]) {
		t.Error("recent opt-out pin lost")
	}
}

func pairBlocked(s *Store, mac string) bool {
	_, ok := s.GetPairBlock([]byte(mac), "i")
	return ok
}

func TestExportRoundTrip(t *testing.T) {
	s := open(t)
	_ = s.PutInstance(&Instance{ID: testID, PublicKey: make([]byte, 32), Tier: TierStandard, CreatedDay: 1, DeviceLimit: 50})
	_ = s.PutInstance(&Instance{ID: testID2, PublicKey: bytes.Repeat([]byte{3}, 32), Tier: TierRevoked, Reason: "spam", ReasonDay: 5, DeviceLimit: 50})
	_ = s.PutBinding([]byte("mac"), &Binding{InstanceID: testID})
	dir := t.TempDir()
	ex, _ := s.BuildExport("push.example.org", 10)
	if err := WriteExport(dir, ex); err == nil {
		t.Fatal("unsigned export written")
	}
	ex.Signature = "sig"
	if err := WriteExport(dir, ex); err != nil {
		t.Fatal(err)
	}
	back, err := ReadExport(dir, "registry.json")
	if err != nil {
		t.Fatal(err)
	}
	s2 := open(t)
	if n, err := s2.Import(back, 10, 150); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if n, _ := s2.Import(back, 10, 150); n != 0 {
		t.Fatal("import not idempotent")
	}
	if b, _ := s2.Bindings(); len(b) != 0 {
		t.Fatal("bindings traveled with the export")
	}
	ins, _ := s2.Instances()
	for _, in := range ins {
		if in.ID == testID2 && (in.Tier != TierRevoked || in.Reason != "spam") {
			t.Fatal("revocation lost on import")
		}
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
	_ = s.BlockPair([]byte("old-mac"), "i", PairBlock{Day: today - 366})
	_ = s.BlockPair([]byte("new-mac"), "i", PairBlock{Day: today - 10})
	_ = s.BlockToken([]byte("old-token-mac"), today-366)
	_ = s.BlockToken([]byte("new-token-mac"), today-10)
	_ = s.PutInstance(&Instance{ID: testID, PublicKey: make([]byte, 32), Tier: TierRevoked, ReasonDay: today - 366, DeviceLimit: 50})
	_ = s.PutInstance(&Instance{ID: testID2, PublicKey: bytes.Repeat([]byte{1}, 32), Tier: TierSuspended, Reason: "spam", ReasonDay: today - 10, DeviceLimit: 50})
	_ = s.PutOptOutPin([]byte("pin-old"), OptOutPin{Day: today - 366})
	_ = s.PutOptOutPin([]byte("pin-new"), OptOutPin{Day: today - 10})
	ex, err := s.BuildExport("push.example.org", today)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.BlockedPairs) != 1 || ex.BlockedPairs[0].ExpiresDay != DayString(today-10+RetainBlocks) {
		t.Fatalf("export: %+v", ex.BlockedPairs)
	}
	if len(ex.BlockedTokens) != 1 || len(ex.OptOutPins) != 1 || len(ex.Instances) != 1 || ex.Instances[0].ID != testID2 {
		t.Fatalf("12-month retention not applied on export: %+v %+v %+v", ex.BlockedTokens, ex.OptOutPins, ex.Instances)
	}
	ex.BlockedPairs = append(ex.BlockedPairs, ExportedBlock{Pair: ex.BlockedPairs[0].Pair[:62] + "00", Reason: ReasonDeviceOptOut, ExpiresDay: DayString(today - 1)})
	s2 := open(t)
	if _, err := s2.Import(ex, today, 150); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.GetPairBlock([]byte("new-mac"), "i"); !ok || !s2.TokenBlocked([]byte("new-token-mac")) || s2.TokenBlocked([]byte("old-token-mac")) {
		t.Fatal("blocks not restored exactly")
	}
	if _, ok := s2.GetOptOutPin([]byte("pin-new")); !ok {
		t.Fatal("opt-out pin not restored")
	}
	ex2, _ := s2.BuildExport("push.example.org", today)
	if len(ex2.BlockedPairs) != 1 {
		t.Fatalf("expired block imported: %d", len(ex2.BlockedPairs))
	}
}

const (
	testID  = "6f1c2a4e-1b9d-4c3e-8a7f-0d2b5e9c1a37"
	testID2 = "7a2d3b5f-2c0e-4d4f-9b8a-1e3c6f0d2b48"
)

// TestImportRefusesFieldsOutsideTheClosedSets: an export edited to invent tiers, ids or limits is refused
// as a whole.
func TestImportRefusesFieldsOutsideTheClosedSets(t *testing.T) {
	good := ExportedInst{ID: testID, PublicKey: make([]byte, 32), Tier: TierProbation, DeviceLimit: 20}
	for name, mut := range map[string]func(e *ExportedInst){
		"tier":   func(e *ExportedInst) { e.Tier = "admin" },
		"id":     func(e *ExportedInst) { e.ID = "x" },
		"limit":  func(e *ExportedInst) { e.DeviceLimit = 10000 },
		"reason": func(e *ExportedInst) { e.Reason = "because" },
		"key":    func(e *ExportedInst) { e.PublicKey = []byte{1} },
	} {
		e := good
		mut(&e)
		if _, err := open(t).Import(&Export{Format: ExportFormat, Instances: []ExportedInst{e}}, 10, 150); err == nil {
			t.Errorf("%s: invalid instance imported", name)
		}
	}
	if _, err := open(t).Import(&Export{Format: ExportFormat, Instances: []ExportedInst{good}}, 10, 150); err != nil {
		t.Fatal(err)
	}
}

func TestImportRefusesMalformedBlocks(t *testing.T) {
	ex := &Export{Format: ExportFormat, BlockedPairs: []ExportedBlock{{Pair: "zz", Reason: ReasonDeviceOptOut, ExpiresDay: "2099-01-01"}}}
	if _, err := open(t).Import(ex, 10, 150); err == nil {
		t.Fatal("malformed block imported")
	}
}

// TestReadExportStaysInTheExportDir: the export is read only from inside the export directory. A relative
// or absolute path that climbs out, a symbolic link pointing out, and an empty name are refused before a
// byte is read; a plain name and an absolute path inside the directory are read.
func TestReadExportStaysInTheExportDir(t *testing.T) {
	s := open(t)
	_ = s.PutInstance(&Instance{ID: testID, PublicKey: make([]byte, 32), Tier: TierStandard, CreatedDay: 1, DeviceLimit: 50})
	parent := t.TempDir()
	dir := filepath.Join(parent, "export")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	ex, _ := s.BuildExport("push.example.org", 10)
	ex.Signature = "sig"
	if err := WriteExport(dir, ex); err != nil {
		t.Fatal(err)
	}
	// A valid export next to the directory: reading it would succeed if the confinement failed.
	if err := WriteExport(parent, ex); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(parent, "registry.json"), filepath.Join(dir, "link.json")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"registry.json", filepath.Join(dir, "registry.json"), filepath.Join(dir, "sub", "..", "registry.json")} {
		if _, err := ReadExport(dir, name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, name := range []string{
		"../registry.json", filepath.Join(dir, "..", "registry.json"), filepath.Join(parent, "registry.json"),
		"/etc/passwd", "", ".", dir, "sub/../../registry.json",
	} {
		if _, err := ReadExport(dir, name); !errors.Is(err, ErrExportOutsideDir) {
			t.Errorf("%q: %v, want ErrExportOutsideDir", name, err)
		}
	}
	if _, err := ReadExport(dir, "link.json"); err == nil {
		t.Error("a symbolic link out of the export directory was followed")
	}
	if _, err := ReadExport("", "registry.json"); !errors.Is(err, ErrExportOutsideDir) {
		t.Errorf("no export directory: %v", err)
	}
}
