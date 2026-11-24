package apns

import (
	"encoding/json"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// AttributesType is the ActivityKit attributes type a relay start names. The app defines it with the fields
// of startAttributes only, so nothing about the dose, in particular no medication name, ever travels.
const AttributesType = "HealthLogDoseAttributes"

// startAttributes is the attributes object of a relay start: the fixed version, and the start id S, which is
// the item's ref. The instance chooses the ref as an opaque random id per start; the app reads it back to tell
// which start an activity belongs to and never shows it. The relay copies it and reads nothing into it.
type startAttributes struct {
	V int    `json:"v"`
	S string `json:"s,omitempty"`
}

// maxStartID bounds the start id; the ref check of the wire format is stricter still.
const maxStartID = 64

// startID returns ref as the start id when it is 1 to 64 printable ASCII characters without a quote or a
// backslash, and "" otherwise, so that the attributes then carry the version alone.
func startID(ref string) string {
	if ref == "" || len(ref) > maxStartID {
		return ""
	}
	for i := 0; i < len(ref); i++ {
		if c := ref[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return ""
		}
	}
	return ref
}

// laState is the content state as Apple receives it: exactly the six fields of the closed template.
type laState struct {
	Status          string `json:"status"`
	CountdownTarget int64  `json:"countdownTarget"`
	Confirmed       bool   `json:"confirmed"`
	PendingConfirm  bool   `json:"pendingConfirm"`
	IsOverdue       bool   `json:"isOverdue"`
	TimeFormatRaw   string `json:"timeFormatRaw"`
}

func stateOf(c *wire.ContentState) laState {
	return laState{Status: *c.Status, CountdownTarget: *c.CountdownTarget, Confirmed: *c.Confirmed,
		PendingConfirm: *c.PendingConfirm, IsOverdue: *c.IsOverdue, TimeFormatRaw: *c.TimeFormatRaw}
}

type locKey struct {
	LocKey string `json:"loc-key"`
}

type laAlert struct {
	Title locKey `json:"title"`
	Body  locKey `json:"body"`
}

type laAPS struct {
	Timestamp      int64            `json:"timestamp"`
	Event          string           `json:"event"`
	ContentState   laState          `json:"content-state"`
	DismissalDate  int64            `json:"dismissal-date,omitempty"`
	AttributesType string           `json:"attributes-type,omitempty"`
	Attributes     *startAttributes `json:"attributes,omitempty"`
	Alert          *laAlert         `json:"alert,omitempty"`
}

func laPayload(a laAPS) []byte {
	b, _ := json.Marshal(struct {
		APS laAPS `json:"aps"`
	}{a})
	return b
}

// LiveActivityEndPayload is the fixed Live Activity end with a constant content state; only the
// timestamps come from the relay clock.
func LiveActivityEndPayload(now time.Time) []byte {
	return laPayload(laAPS{Timestamp: now.Unix(), Event: "end", DismissalDate: now.Unix(),
		ContentState: laState{Status: "taken", TimeFormatRaw: "AUTO"}})
}

// LiveActivityStartPayload starts an activity through a push-to-start token: the checked content state,
// the attributes (the version and ref as the start id) and a fixed localized alert.
func LiveActivityStartPayload(now time.Time, ref string, c *wire.ContentState) []byte {
	return laPayload(laAPS{Timestamp: now.Unix(), Event: "start", ContentState: stateOf(c),
		AttributesType: AttributesType, Attributes: &startAttributes{V: 1, S: startID(ref)},
		Alert: &laAlert{Title: locKey{"HL_LA_START_TITLE"}, Body: locKey{"HL_LA_START_BODY"}}})
}

// LiveActivityUpdatePayload updates a running activity with the checked content state.
func LiveActivityUpdatePayload(now time.Time, c *wire.ContentState) []byte {
	return laPayload(laAPS{Timestamp: now.Unix(), Event: "update", ContentState: stateOf(c)})
}

// LiveActivityUrgent reports whether a Live Activity push goes with priority 10. iOS grants each device an
// hourly budget of priority 10 Live Activity pushes and may throttle beyond it; priority 5 does not count
// against it (Apple, "Starting and updating Live Activities with ActivityKit push notifications",
// "Determine the update frequency"). Only what needs the person's attention now is urgent: a start or update
// whose state turns `due` or `overdue`, and the end, so a dose recorded elsewhere leaves the lock screen at
// once. Everything else (`pending`, `snoozed`, `taken`, `skipped`) goes with 5.
func LiveActivityUrgent(event string, c *wire.ContentState) bool {
	if event == wire.EventEnd {
		return true
	}
	if c == nil || c.Status == nil {
		return false
	}
	return *c.Status == "due" || *c.Status == "overdue"
}
