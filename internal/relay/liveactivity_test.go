package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

func ptr[T any](v T) *T { return &v }

func dueState(now time.Time) *wire.ContentState {
	return &wire.ContentState{Status: ptr("due"), CountdownTarget: ptr(now.Unix() + 600), IsOverdue: ptr(false),
		Confirmed: ptr(false), PendingConfirm: ptr(false), TimeFormatRaw: ptr("AUTO")}
}

// laItem builds a start or update item. A start is signed over the push-to-start token as hl-la-start-v1,
// an update over the activity's update token as hl-activity-v1.
func (d *device) laItem(ref, event, instID string, la []byte, iat int64, st *wire.ContentState) wire.PushItem {
	it := d.activity(ref, instID, la, iat)
	it.Activity.Event, it.Activity.State = event, st
	if event == wire.EventStart {
		tag, laTag := wire.TokenTag(d.token), wire.TokenTag(la)
		it.Activity.Signature = wire.EncodeB64(ed25519.Sign(d.key, []byte(wire.LAStartText(host, instID, tag, laTag, iat))))
	}
	return it
}

// laConsent passes the device's signed Live Activity consent on to the relay.
func (i *instance) laConsent(d *device, signer ed25519.PrivateKey) response {
	iat := i.h.clk.Now().Unix()
	b := wire.LAConsentBody{Token: d.hex(), BindingKey: wire.EncodeB64(ed25519.PublicKey(signer[32:]))}
	b.Consent.TextVersion, b.Consent.Day, b.Consent.Iat = "2026-11-21", "2026-11-21", iat
	b.Signature = wire.EncodeB64(ed25519.Sign(signer, []byte(wire.LAConsentText(host, i.id, wire.TokenTag(d.token), "2026-11-21", iat))))
	return i.do(http.MethodPost, "/v1/bindings/liveactivity", b)
}

// TestLiveActivityStartNeedsItsOwnConsent: start and update need the device's separate Live Activity
// consent; the relay consent alone is not enough, and only the device key can give it.
func TestLiveActivityStartNeedsItsOwnConsent(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xa1)
	i.activate(d)
	start := bytes.Repeat([]byte{0x3a}, 32)
	now := h.clk.Now()
	if res := i.push1(d.laItem("s1", wire.EventStart, i.id, start, now.Unix(), dueState(now))); res.Error != "liveactivity_consent_required" {
		t.Fatalf("start without consent: %+v", res)
	}
	_, forged, _ := ed25519.GenerateKey(nil)
	if rp := i.laConsent(d, forged); rp.Status != http.StatusNotFound && rp.Status != http.StatusForbidden {
		t.Fatalf("consent by another key: %d", rp.Status)
	}
	if rp := i.laConsent(d, d.key); rp.Status != 200 {
		t.Fatalf("consent: %d %s", rp.Status, rp.Raw)
	}
	if sr := h.selfRead(d); sr.str("liveActivityConsentVersion") != "2026-11-21" {
		t.Fatalf("self read lacks the consent: %s", sr.Raw)
	}
	if res := i.push1(d.laItem("s2", wire.EventStart, i.id, start, now.Unix(), dueState(now))); res.Result != "accepted" {
		t.Fatalf("start with consent: %+v", res)
	}
	r := h.apns.requests()[len(h.apns.requests())-1]
	var p struct {
		APS map[string]json.RawMessage `json:"aps"`
	}
	_ = json.Unmarshal([]byte(r.Body), &p)
	var cs map[string]any
	_ = json.Unmarshal(p.APS["content-state"], &cs)
	if r.Token != hex.EncodeToString(start) || string(p.APS["event"]) != `"start"` || string(p.APS["attributes-type"]) != `"HealthLogDoseAttributes"` ||
		string(p.APS["attributes"]) != `{"v":1,"s":"s2"}` || len(cs) != 6 || cs["status"] != "due" || r.Header.Get("apns-push-type") != "liveactivity" {
		t.Fatalf("start payload: %s %v", r.Body, r.Header)
	}
	// The device withdraws directly; start is refused again.
	iat := h.clk.Now().Unix()
	tag := wire.TokenTag(d.token)
	wb := map[string]any{"token": d.hex(), "bindingKey": wire.EncodeB64(ed25519.PublicKey(d.key[32:])),
		"statement": map[string]any{"instanceId": i.id, "tokenTag": hex.EncodeToString(tag), "iat": iat},
		"signature": wire.EncodeB64(ed25519.Sign(d.key, []byte(wire.LAWithdrawText(host, i.id, tag, iat))))}
	raw, _ := json.Marshal(wb)
	req, _ := http.NewRequest(http.MethodDelete, h.srv.URL+"/v1/bindings/self/liveactivity", bytes.NewReader(raw))
	if rp := h.send(req, ""); rp.Status != http.StatusNoContent {
		t.Fatalf("withdraw: %d %s", rp.Status, rp.Raw)
	}
	if res := i.push1(d.laItem("s3", wire.EventStart, i.id, start, now.Unix(), dueState(now))); res.Error != "liveactivity_consent_required" {
		t.Fatalf("start after withdrawal: %+v", res)
	}
	// The end needs no extra consent, as before.
	if res := i.push1(d.activity("e1", i.id, bytes.Repeat([]byte{0x3b}, 32), now.Unix())); res.Result != "accepted" {
		t.Fatalf("end: %+v", res)
	}
}

// TestContentStateTemplateIsClosed: only the six fields, fixed types, closed enumerations and a bounded
// time; anything else is refused before Apple sees it.
func TestContentStateTemplateIsClosed(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xa2)
	i.activate(d)
	i.laConsent(d, d.key)
	now := h.clk.Now()
	la := bytes.Repeat([]byte{0x3c}, 32)
	bad := map[string]func(*wire.ContentState){
		"status free text":  func(c *wire.ContentState) { c.Status = ptr("Take 2 Metformin") },
		"unknown format":    func(c *wire.ContentState) { c.TimeFormatRaw = ptr("H25") },
		"countdown too far": func(c *wire.ContentState) { c.CountdownTarget = ptr(now.Unix() + 72*3600) },
		"countdown too old": func(c *wire.ContentState) { c.CountdownTarget = ptr(now.Unix() - 25*3600) },
		"missing field":     func(c *wire.ContentState) { c.Confirmed = nil },
	}
	n := 0
	for name, mut := range bad {
		st := dueState(now)
		mut(st)
		n++
		if res := i.push1(d.laItem("u"+strconv.Itoa(n), wire.EventUpdate, i.id, la, now.Unix(), st)); res.Status != http.StatusUnprocessableEntity {
			t.Errorf("%s: %+v", name, res)
		}
	}
	// A key outside the template refuses the whole request (strict JSON).
	body := []byte(`{"items":[{"ref":"x","token":"` + d.hex() + `","env":"production","class":"liveactivity","ttlSeconds":60,` +
		`"activity":{"event":"update","token":"` + hex.EncodeToString(la) + `","bindingKey":"","statement":{},"signature":"",` +
		`"state":{"status":"due","countdownTarget":0,"isOverdue":false,"confirmed":false,"pendingConfirm":false,"timeFormatRaw":"AUTO","medicationName":"x"}}}]}`)
	if rp := i.do(http.MethodPost, "/v1/push", body); rp.Status != http.StatusUnprocessableEntity {
		t.Fatalf("extra state key: %d", rp.Status)
	}
	if res := i.push1(d.laItem("ok", wire.EventUpdate, i.id, la, now.Unix(), dueState(now))); res.Result != "accepted" {
		t.Fatalf("valid update: %+v", res)
	}
	r := h.apns.requests()[len(h.apns.requests())-1]
	if !bytes.Contains([]byte(r.Body), []byte(`"event":"update"`)) || bytes.Contains([]byte(r.Body), []byte("attributes")) {
		t.Fatalf("update payload: %s", r.Body)
	}
}

// TestActivityStatementsAreNotInterchangeable: a start needs hl-la-start-v1 over the push-to-start token,
// which may be up to 30 days old; an update statement (hl-activity-v1) cannot start an activity.
func TestActivityStatementsAreNotInterchangeable(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xa3)
	i.activate(d)
	i.laConsent(d, d.key)
	now := h.clk.Now()
	start := bytes.Repeat([]byte{0x3d}, 32)
	asUpdate := d.activity("x1", i.id, start, now.Unix())
	asUpdate.Activity.Event, asUpdate.Activity.State = wire.EventStart, dueState(now)
	if res := i.push1(asUpdate); res.Error != "activity_refused" {
		t.Fatalf("start with an update statement: %+v", res)
	}
	if res := i.push1(d.laItem("x2", wire.EventStart, i.id, start, now.Unix()-29*24*3600, dueState(now))); res.Result != "accepted" {
		t.Fatalf("29-day-old start statement: %+v", res)
	}
	if res := i.push1(d.laItem("x3", wire.EventStart, i.id, start, now.Unix()-31*24*3600, dueState(now))); res.Error != "activity_refused" {
		t.Fatalf("31-day-old start statement: %+v", res)
	}
}

// TestActivityUpdatesLimitedPerActivity: 12 updates per activity and hour; another activity is not affected.
func TestActivityUpdatesLimitedPerActivity(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xa4)
	i.activate(d)
	i.laConsent(d, d.key)
	now := h.clk.Now()
	la, other := bytes.Repeat([]byte{0x3e}, 32), bytes.Repeat([]byte{0x3f}, 32)
	n := 0
	for ; n < 20; n++ {
		res := i.push1(d.laItem("q"+strconv.Itoa(n), wire.EventUpdate, i.id, la, now.Unix(), dueState(now)))
		if res.Status == http.StatusTooManyRequests {
			if res.Scope != "activity" {
				t.Fatalf("scope %s", res.Scope)
			}
			break
		}
	}
	if n != 12 {
		t.Fatalf("updates per activity and hour: %d, want 12", n)
	}
	if res := i.push1(d.laItem("o1", wire.EventUpdate, i.id, other, now.Unix(), dueState(now))); res.Result != "accepted" {
		t.Fatalf("another activity limited: %+v", res)
	}
}
