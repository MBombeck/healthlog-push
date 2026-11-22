// Package keys holds the published identity keys of the hosted relay, the same file docs/hosted-relay.md and the
// release notes publish, so the relay can tell which pinned slot its own key occupies.
package keys

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/json"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

//go:embed push.healthlog.dev.json
var hosted []byte

// The slots of a pinned identity key. Unpinned is a key that is not one of the published keys of the host,
// as on a self-hosted relay.
const (
	SlotCurrent   = "current"
	SlotNext      = "next"
	SlotEmergency = "emergency"
	SlotUnpinned  = "unpinned"
)

// Slots is the closed set of slot labels.
var Slots = []string{SlotCurrent, SlotNext, SlotEmergency, SlotUnpinned}

// Slot returns the slot that pub occupies among the published keys of host.
func Slot(host string, pub ed25519.PublicKey) string {
	var k map[string]string
	if json.Unmarshal(hosted, &k) != nil || k["host"] != host {
		return SlotUnpinned
	}
	enc := wire.EncodeB64(pub)
	for _, s := range []string{SlotCurrent, SlotNext, SlotEmergency} {
		if k[s] != "" && k[s] == enc {
			return s
		}
	}
	return SlotUnpinned
}
