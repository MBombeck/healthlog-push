package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
)

func withPublicStats(c *Config) { c.PublicStats = true }

// getStats fetches /stats, checks the signature and decodes the body.
func (h *harness) getStats() (response, PublicStats) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/stats", http.NoBody)
	rp := h.send(req, "")
	var ps PublicStats
	if rp.Status == http.StatusOK {
		if err := json.Unmarshal(rp.Raw, &ps); err != nil {
			h.t.Fatalf("stats: %v %s", err, rp.Raw)
		}
	}
	return rp, ps
}

// pushedToday registers an instance, binds a device and has one alert accepted, then flushes the counters
// as the minute tick does.
func (h *harness) pushedToday(n byte) *instance {
	i := h.register()
	i.activate(newDevice(n))
	h.r.Tick()
	return i
}

// TestStatsOffByDefault: without the setting there is no /stats at all, only the signed 404 of any unknown
// path.
func TestStatsOffByDefault(t *testing.T) {
	h := newHarness(t)
	for n := range 4 {
		h.pushedToday(byte(0x50 + n))
	}
	h.clk.Add(24 * time.Hour)
	if rp, _ := h.getStats(); rp.Status != http.StatusNotFound || rp.str("error") != "not_found" {
		t.Fatalf("/stats without the setting: %d %s", rp.Status, rp.Raw)
	}
}

// TestStatsFloor: no figure while fewer than three servers are registered, and no window while fewer than
// three servers had a push accepted on a completed day in it. A server that pushed only today does not
// count, and the answer never carries an instance id.
func TestStatsFloor(t *testing.T) {
	h := newHarness(t, withPublicStats)
	a, b := h.pushedToday(0x61), h.pushedToday(0x62)
	h.clk.Add(24 * time.Hour)

	_, ps := h.getStats()
	if ps.Shown || ps.Windows != nil || ps.MinInstances != 3 {
		t.Fatalf("two servers: %+v", ps)
	}

	// A third server, registered but silent: the relay has three servers, but no window has three that
	// pushed, so every window is empty.
	h.clk.Add(statsRefresh)
	c := h.register()
	rp, ps := h.getStats()
	if !ps.Shown || len(ps.Windows) != 2 || ps.Windows["7d"] != nil || ps.Windows["30d"] != nil {
		t.Fatalf("three servers, two pushed: %s", rp.Raw)
	}

	// The third pushes today. Today is not a completed day, so it still does not count.
	c.activate(newDevice(0x63))
	h.r.Tick()
	h.clk.Add(statsRefresh)
	if _, ps := h.getStats(); ps.Windows["7d"] != nil {
		t.Fatalf("a push today counted for the floor: %+v", ps.Windows["7d"])
	}

	// Once that day is complete, three servers pushed in the window and the figures appear.
	h.clk.Add(24 * time.Hour)
	rp, ps = h.getStats()
	w := ps.Windows["7d"]
	if w == nil || ps.Windows["30d"] == nil {
		t.Fatalf("three servers pushed: %s", rp.Raw)
	}
	if w.Items != 3 || w.Delivered != 3 || w.DeliveredShare != 1 || w.FailedShare != 0 || w.Latency == nil || w.Latency.DaysCovered != 2 {
		t.Fatalf("7d window: %+v latency %+v", w, w.Latency)
	}
	for _, id := range []string{a.id, b.id, c.id} {
		if strings.Contains(string(rp.Raw), id) {
			t.Fatalf("/stats names an instance: %s", rp.Raw)
		}
	}
}

// TestStatsShares: items are what went to Apple, and each outcome lands in its share.
func TestStatsShares(t *testing.T) {
	h := newHarness(t, withPublicStats)
	insts := []*instance{h.pushedToday(0x71), h.pushedToday(0x72), h.pushedToday(0x73)}
	d := newDevice(0x74)
	insts[0].activate(d)
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 500, "InternalServerError" })
	insts[0].push1(alertItem("f1", d))
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 400, "BadDeviceToken" })
	insts[0].push1(alertItem("g1", d))
	h.r.Tick()
	h.clk.Add(24 * time.Hour)
	_, ps := h.getStats()
	w := ps.Windows["30d"]
	if w == nil {
		t.Fatalf("no 30d window: %+v", ps)
	}
	// Four accepted (three servers' activations and d), one failed, one with a bad token.
	if w.Items != 6 || w.Delivered != 4 || w.FailedShare != share(1, 6) || w.TokenGoneShare != share(1, 6) || w.ThrottledShare != 0 {
		t.Fatalf("shares: %+v", w)
	}
}

// TestStatsCached: the answer is computed at most every statsRefresh; inside that time new completed-day
// figures do not show.
func TestStatsCached(t *testing.T) {
	h := newHarness(t, withPublicStats)
	for n := range 3 {
		h.pushedToday(byte(0x81 + n))
	}
	h.clk.Add(24 * time.Hour)
	first, ps := h.getStats()
	if !ps.Shown {
		t.Fatalf("three servers: %s", first.Raw)
	}
	// One server leaves the active tiers: a fresh computation would fall below the floor.
	h.r.mu.Lock()
	for _, s := range h.r.instances {
		s.rec.Tier = store.TierRevoked
		break
	}
	h.r.mu.Unlock()
	h.clk.Add(statsRefresh - time.Second)
	if again, _ := h.getStats(); !bytes.Equal(again.Raw, first.Raw) {
		t.Fatalf("recomputed inside the refresh period:\n%s\n%s", first.Raw, again.Raw)
	}
	h.clk.Add(2 * time.Second)
	if rp, ps := h.getStats(); ps.Shown || ps.Windows != nil {
		t.Fatalf("not recomputed after the refresh period: %s", rp.Raw)
	}
}

func TestBucketQuantile(t *testing.T) {
	var l latencyDays
	for range 50 {
		l.observe(10, 0.12) // the 0.15 bucket
	}
	for range 45 {
		l.observe(10, 0.2) // 0.25
	}
	for range 5 {
		l.observe(11, 3) // 5
	}
	b, covered := l.sum(10, 11)
	if covered != 2 {
		t.Fatalf("covered %d", covered)
	}
	if p := bucketQuantile(b, 0.5); p != 0.15 {
		t.Errorf("p50 %g", p)
	}
	if p := bucketQuantile(b, 0.9); p != 0.25 {
		t.Errorf("p90 %g", p)
	}
	if p := bucketQuantile(b, 0.99); p != 5 {
		t.Errorf("p99 %g", p)
	}
	// Beyond the last bound reports the last bound.
	l.observe(12, 60)
	b, _ = l.sum(12, 12)
	if p := bucketQuantile(b, 0.5); p != latencyBounds[len(latencyBounds)-1] {
		t.Errorf("overflow p50 %g", p)
	}
	// Old days leave memory.
	l.observe(12+latencyDaysKept, 0.1)
	if _, covered := l.sum(0, 12); covered != 0 {
		t.Errorf("days older than %d kept: %d covered", latencyDaysKept, covered)
	}
	if _, covered := l.sum(12+latencyDaysKept, 12+latencyDaysKept); covered != 1 {
		t.Errorf("the new day is missing")
	}
}
