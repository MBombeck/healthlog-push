package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestSlot(t *testing.T) {
	var k map[string]string
	if err := json.Unmarshal(hosted, &k); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{SlotCurrent, SlotNext, SlotEmergency} {
		pub, err := base64.RawURLEncoding.DecodeString(k[s])
		if err != nil || len(pub) != ed25519.PublicKeySize {
			t.Fatalf("%s: %v", s, err)
		}
		if got := Slot(k["host"], pub); got != s {
			t.Errorf("slot of %s: %s", s, got)
		}
		if got := Slot("relay.example.org", pub); got != SlotUnpinned {
			t.Errorf("another host: %s", got)
		}
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if got := Slot(k["host"], other); got != SlotUnpinned {
		t.Errorf("unknown key: %s", got)
	}
}
