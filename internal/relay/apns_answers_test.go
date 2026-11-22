package relay

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// TestLiveActivityPriorityFollowsTheState: a Live Activity push goes with priority 10 only when its state
// turns due or overdue, and for the end; every other state goes with 5, outside the device's budget.
func TestLiveActivityPriorityFollowsTheState(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xb1)
	i.activate(d)
	if rp := i.laConsent(d, d.key); rp.Status != 200 {
		t.Fatalf("consent: %d %s", rp.Status, rp.Raw)
	}
	now := h.clk.Now()
	start, la := bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x52}, 32)
	state := func(status string) *wire.ContentState {
		st := dueState(now)
		st.Status = ptr(status)
		st.IsOverdue = ptr(status == "overdue")
		return st
	}
	cases := []struct {
		ref, event, status, want string
	}{
		{"start-due", wire.EventStart, "due", "10"},
		{"start-pending", wire.EventStart, "pending", "5"},
		{"up-pending", wire.EventUpdate, "pending", "5"},
		{"up-due", wire.EventUpdate, "due", "10"},
		{"up-overdue", wire.EventUpdate, "overdue", "10"},
		{"up-snoozed", wire.EventUpdate, "snoozed", "5"},
		{"up-taken", wire.EventUpdate, "taken", "5"},
		{"up-skipped", wire.EventUpdate, "skipped", "5"},
		{"end", wire.EventEnd, "", "10"},
	}
	for _, c := range cases {
		var it wire.PushItem
		switch c.event {
		case wire.EventStart:
			it = d.laItem(c.ref, c.event, i.id, start, now.Unix(), state(c.status))
		case wire.EventUpdate:
			it = d.laItem(c.ref, c.event, i.id, la, now.Unix(), state(c.status))
		default:
			it = d.activity(c.ref, i.id, la, now.Unix())
		}
		if res := i.push1(it); res.Result != "accepted" {
			t.Fatalf("%s: %+v", c.ref, res)
		}
		r := h.apns.requests()[len(h.apns.requests())-1]
		if got := r.Header.Get("apns-priority"); got != c.want || r.Header.Get("apns-push-type") != "liveactivity" {
			t.Errorf("%s: priority %q, want %s", c.ref, got, c.want)
		}
	}
	// Device pushes keep their priorities.
	if res := i.push1(silentItem("s", d)); res.Result != "accepted" {
		t.Fatal(res)
	}
	if got := h.apns.requests()[len(h.apns.requests())-1].Header.Get("apns-priority"); got != "5" {
		t.Errorf("silent priority %s", got)
	}
}

// TestStale410KeepsAReboundBinding: Apple's 410 timestamp says when the token stopped being valid. A binding
// made or renewed on a day that began after that time is not deleted; the answer is handled like a soft
// failure, so a token that keeps answering 410 is still deleted on a later day. A 410 at or after the
// binding day, or one without a timestamp, deletes at once as before.
func TestStale410KeepsAReboundBinding(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	stale, fresh, bare, sameDay := newDevice(0xc1), newDevice(0xc2), newDevice(0xc3), newDevice(0xc4)
	for _, d := range []*device{stale, fresh, bare, sameDay} {
		i.activate(d)
	}
	now := h.clk.Now() // 10:00 UTC on the binding day
	ts := map[string]int64{
		stale.hex():   now.Add(-36 * time.Hour).UnixMilli(),                           // the day before the binding
		fresh.hex():   now.Add(-time.Minute).UnixMilli(),                              // after the binding was made
		sameDay.hex(): now.Truncate(24 * time.Hour).Add(-5 * time.Minute).UnixMilli(), // within the tolerance
	}
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 410, "Unregistered" })
	h.apns.setExtra(func(tok string, _ apnsReq) (map[string]string, int64) { return nil, ts[tok] })

	res := i.push1(alertItem("st1", stale))
	if res.Status != 200 || res.Result != "soft_invalid" || res.Reason != "Unregistered" {
		t.Fatalf("stale 410: %+v", res)
	}
	if h.state(stale) != store.StateSoftInvalid {
		t.Fatalf("stale 410 state %q", h.state(stale))
	}
	for name, d := range map[string]*device{"fresh": fresh, "no timestamp": bare, "within tolerance": sameDay} {
		if res := i.push1(alertItem("g-"+d.hex()[:4], d)); res.Status != 410 || res.Error != "unregistered" {
			t.Fatalf("%s: %+v", name, res)
		}
		if h.state(d) != "" {
			t.Fatalf("%s: binding not deleted", name)
		}
	}
	// The same stale 410 on a later day deletes the binding: a dead token cannot linger.
	h.clk.Add(24 * time.Hour)
	if res := i.push1(alertItem("st2", stale)); res.Result != "soft_invalid" {
		t.Fatalf("second stale 410: %+v", res)
	}
	if h.state(stale) != "" {
		t.Fatal("a second stale 410 on another day did not delete")
	}
}

// TestReboundAfterIsLoose: the comparison is by binding day, with ten minutes of tolerance.
func TestReboundAfterIsLoose(t *testing.T) {
	day := 20500
	start := time.Unix(int64(day)*86400, 0)
	cases := []struct {
		since time.Time
		want  bool
	}{
		{time.Time{}, false},
		{start.Add(-48 * time.Hour), true},
		{start.Add(-11 * time.Minute), true},
		{start.Add(-9 * time.Minute), false},
		{start.Add(time.Hour), false},
		{start.Add(72 * time.Hour), false},
	}
	for _, c := range cases {
		if got := reboundAfter(day, c.since); got != c.want {
			t.Errorf("since %v: %v, want %v", c.since, got, c.want)
		}
	}
}

// TestDeliveryTraceIsBrief: Apple's apns-unique-id is kept per instance and ref for 72 hours in memory and
// shown only on the admin socket; it is gone afterwards and with the instance, and never reaches the store.
func TestDeliveryTraceIsBrief(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xd1)
	i.activate(d)
	const uid = "3f0c1d2e-4b5a-4c6d-8e7f-90a1b2c3d4e5"
	h.apns.setExtra(func(string, apnsReq) (map[string]string, int64) {
		return map[string]string{"apns-unique-id": "3F0C1D2E-4B5A-4C6D-8E7F-90A1B2C3D4E5"}, 0
	})
	if res := i.push1(alertItem("trace-1", d)); res.Result != "accepted" {
		t.Fatal(res)
	}
	got, err := h.r.admin(&AdminRequest{Cmd: "delivery", Args: []string{i.id, "trace-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := got.(map[string]string); !ok || m["apnsUniqueId"] != uid || m["result"] != "accepted" {
		t.Fatalf("trace: %v", m)
	}
	if _, err := h.r.admin(&AdminRequest{Cmd: "delivery", Args: []string{i.id, "other"}}); err == nil {
		t.Fatal("trace for an unknown ref")
	}
	// A malformed header is not kept.
	h.apns.setExtra(func(string, apnsReq) (map[string]string, int64) {
		return map[string]string{"apns-unique-id": "not-a-uuid"}, 0
	})
	if res := i.push1(alertItem("trace-2", d)); res.Result != "accepted" {
		t.Fatal(res)
	}
	if _, err := h.r.DeliveryTrace(i.id, "trace-2"); err == nil {
		t.Fatal("malformed apns-unique-id kept")
	}
	// Nothing of it reaches the database file.
	h.r.Tick()
	h.r.mu.Lock()
	h.r.flushLocked()
	h.r.mu.Unlock()
	raw, err := os.ReadFile(filepath.Join(h.dir, "relay.db"))
	if err != nil || len(raw) == 0 {
		t.Fatalf("store file: %v", err)
	}
	for name, blob := range map[string][]byte{"store": raw, "logs": h.logs.Bytes()} {
		if bytes.Contains(bytes.ToLower(blob), []byte(uid)) {
			t.Fatalf("apns-unique-id in the %s", name)
		}
	}
	h.clk.Add(traceTTL + time.Minute)
	h.r.Tick()
	if _, err := h.r.DeliveryTrace(i.id, "trace-1"); err == nil {
		t.Fatal("trace kept past 72 hours")
	}
	h.r.mu.Lock()
	n := len(h.r.traces.byKey) + len(h.r.traces.order)
	h.r.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d trace entries left after expiry", n)
	}
}

// TestTracesAreBounded: beyond traceMax the oldest traces go first, and a dropped instance takes its own.
func TestTracesAreBounded(t *testing.T) {
	var tr traces
	now := time.Unix(1795000000, 0)
	for n := range traceMax + 10 {
		tr.put("inst\x00r"+strconv.Itoa(n), "u", "accepted", now)
	}
	if len(tr.byKey) != traceMax || len(tr.order) != traceMax {
		t.Fatalf("%d/%d entries", len(tr.byKey), len(tr.order))
	}
	if _, ok := tr.get("inst\x00r0", now); ok {
		t.Fatal("oldest trace kept beyond the bound")
	}
	if _, ok := tr.get("inst\x00r"+strconv.Itoa(traceMax+9), now); !ok {
		t.Fatal("newest trace missing")
	}
	// A retry of the same ref replaces the trace; the older slot does not delete the newer value.
	tr.put("other\x00x", "first", "apns_unavailable", now)
	tr.put("other\x00x", "second", "accepted", now.Add(time.Hour))
	tr.prune(now.Add(traceTTL))
	if got, ok := tr.get("other\x00x", now.Add(traceTTL)); !ok || got.uniqueID != "second" {
		t.Fatalf("retry trace: %+v %v", got, ok)
	}
	tr.dropInstance("other")
	if _, ok := tr.get("other\x00x", now.Add(traceTTL)); ok {
		t.Fatal("trace of a dropped instance kept")
	}
}
