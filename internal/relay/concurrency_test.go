package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"sync"
	"testing"
)

// TestRotateRacingDeleteLeavesNoZombie: a rotation and a deletion of the same instance run at the same
// time. Whichever wins, a deleted instance must stay deleted in memory and in the store, and registering
// with the rotated key must work (no nil dereference on a stale key index).
func TestRotateRacingDeleteLeavesNoZombie(t *testing.T) {
	h := newHarness(t)
	for range 60 {
		i := h.register()
		_, nk, _ := ed25519.GenerateKey(rand.Reader)
		var wg sync.WaitGroup
		var del response
		wg.Add(2)
		go func() { defer wg.Done(); i.rotate(nk) }()
		go func() { defer wg.Done(); del = i.do(http.MethodDelete, "/v1/instances/self", nil) }()
		wg.Wait()
		if del.Status != http.StatusNoContent {
			continue // the rotation won and the old key no longer signs: nothing to check
		}
		ins, err := h.st.Instances()
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range ins {
			if in.ID == i.id {
				t.Fatal("deleted instance written back to the store")
			}
		}
		h.r.mu.Lock()
		_, zombie := h.r.byKey[string(nk[32:])]
		h.r.mu.Unlock()
		if zombie {
			t.Fatal("key index points at a deleted instance")
		}
		if rp := (&instance{h: h, key: nk}).registerRaw(""); rp.Status != http.StatusCreated {
			t.Fatalf("registering with the rotated key: %d %s", rp.Status, rp.Raw)
		}
	}
}
