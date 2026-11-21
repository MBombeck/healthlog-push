package apns

import (
	"encoding/json"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// AttributesType is the ActivityKit attributes type a relay start names. The app defines it with the single
// field of StartAttributes, so nothing about the dose, in particular no medication name, ever travels.
const AttributesType = "HealthLogDoseAttributes"

// startAttributes is the fixed attributes object of a relay start.
type startAttributes struct {
	V int `json:"v"`
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
// the fixed attributes and a fixed localized alert.
func LiveActivityStartPayload(now time.Time, c *wire.ContentState) []byte {
	return laPayload(laAPS{Timestamp: now.Unix(), Event: "start", ContentState: stateOf(c),
		AttributesType: AttributesType, Attributes: &startAttributes{V: 1},
		Alert: &laAlert{Title: locKey{"HL_LA_START_TITLE"}, Body: locKey{"HL_LA_START_BODY"}}})
}

// LiveActivityUpdatePayload updates a running activity with the checked content state.
func LiveActivityUpdatePayload(now time.Time, c *wire.ContentState) []byte {
	return laPayload(laAPS{Timestamp: now.Unix(), Event: "update", ContentState: stateOf(c)})
}
