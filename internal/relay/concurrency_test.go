package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/MBombeck/healthlog-push/internal/wire"
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

// TestAppAnswersCostTheSameWork: an opt-out or self-read for a token without a binding runs the same
// signature check as one for a bound token, so a former instance cannot time whether the device is still
// bound with a key it knows.
func TestAppAnswersCostTheSameWork(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	bound, stranger := newDevice(0x51), newDevice(0x52)
	i.activate(bound)
	for name, call := range map[string]func() response{
		"self-read unknown": func() response { return h.selfRead(stranger) },
		"opt-out unknown":   func() response { return h.unbindSelf(stranger, stranger.key, i.id) },
		"opt-out wrong key": func() response { return h.unbindSelf(bound, stranger.key, i.id) },
	} {
		before := wire.Verifications()
		if rp := call(); rp.Status != http.StatusNotFound {
			t.Fatalf("%s: %d", name, rp.Status)
		}
		if wire.Verifications()-before != 1 {
			t.Errorf("%s: %d signature checks, want exactly 1", name, wire.Verifications()-before)
		}
	}
}
