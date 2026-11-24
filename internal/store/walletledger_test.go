package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// TestWalletLedgerIsMinimal: an entry is the manifest hash and the instance id as key and the day as the
// only value; lookups find every instance for a hash; entries older than 400 days are pruned; the ledger is
// not part of the registry export.
func TestWalletLedgerIsMinimal(t *testing.T) {
	s := open(t)
	today := 20000
	h := sha256.Sum256([]byte("manifest"))
	other := sha256.Sum256([]byte("other"))
	for _, e := range []struct {
		h    []byte
		inst string
		day  int
	}{{h[:], "inst-a", today}, {h[:], "inst-b", today - 401}, {other[:], "inst-a", today - 399}} {
		if err := s.PutWalletSign(e.h, e.inst, e.day); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bWalletSigns).ForEach(func(k, v []byte) error {
			if len(k) != 32+len("inst-a") || string(v) != `{"day":`+strconv.Itoa(walletSignDay(k, v))+`}` {
				t.Errorf("entry %x = %s", k, v)
			}
			return nil
		})
	})
	got, err := s.LookupWalletSign(hex.EncodeToString(h[:]))
	if err != nil || len(got) != 2 || got[0].InstanceID != "inst-a" || got[0].Day != today || got[1].InstanceID != "inst-b" {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if _, err := s.LookupWalletSign("zz"); err == nil {
		t.Fatal("a malformed hash was looked up")
	}
	if err := s.Prune(today); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LookupWalletSign(hex.EncodeToString(h[:])); len(got) != 1 || got[0].InstanceID != "inst-a" {
		t.Fatalf("after prune: %+v", got)
	}
	if got, _ := s.LookupWalletSign(hex.EncodeToString(other[:])); len(got) != 1 {
		t.Fatalf("a 399-day entry was pruned: %+v", got)
	}
	ex, err := s.BuildExport("push.example.org", today)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(ex); bytes.Contains(b, []byte(hex.EncodeToString(h[:]))) {
		t.Fatal("the export carries the ledger")
	}
}
