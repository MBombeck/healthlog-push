package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
)

// TestNothingIdentifyingReachesLogsMetricsOrStats runs real traffic and then checks the log stream, the
// metrics, the operator stats and the export for instance ids, tokens, token MACs and addresses.
func TestNothingIdentifyingReachesLogsMetricsOrStats(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0x31)
	i.activate(d)
	i.push1(silentItem("s", d))
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 410, "Unregistered" })
	i.push1(alertItem("u", d))
	_ = h.r.SetPause("silent", "all", time.Minute)
	h.clk.Add(2 * time.Hour)
	h.r.Tick()
	h.r.Daily()

	rec := httptest.NewRecorder()
	h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	stats, _ := json.Marshal(h.r.UsageReport(28))
	svc, _ := json.Marshal(h.r.Stats())
	export, err := os.ReadFile(filepath.Join(h.dir, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := mac(h.r.cfg.MACKeys[0], d.token)
	forbidden := []string{i.id, d.hex(), hex.EncodeToString([]byte(m)), "127.0.0.1", "::1"}
	for name, blob := range map[string]string{"logs": h.logs.String(), "metrics": rec.Body.String(), "usage": string(stats), "stats": string(svc)} {
		if blob == "" {
			t.Fatalf("%s empty: the check would prove nothing", name)
		}
		for _, f := range forbidden {
			if strings.Contains(blob, f) {
				t.Errorf("%s contains %q", name, f)
			}
		}
	}
	// The export holds instances and the denylist only: the instance id is expected there, tokens are not.
	for _, f := range []string{d.hex(), hex.EncodeToString([]byte(m)), "bindings", "keyHash", "consent"} {
		if bytes.Contains(export, []byte(f)) {
			t.Errorf("export contains %q", f)
		}
	}
	if !bytes.Contains(export, []byte(i.id)) {
		t.Error("export lacks the instance")
	}
}

// TestUsageAggregates covers the usage statistics: counts per day and week, no instance granularity.
func TestUsageAggregates(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d1, d2 := newDevice(0x41), newDevice(0x42)
	a.activate(d1)
	b.activate(d2)
	a.push1(silentItem("s1", d1))
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 400, "BadDeviceToken" })
	b.push1(alertItem("x", d2))
	_ = h.unbindSelf(d1, d1.key, a.id)
	h.clk.Add(24 * time.Hour)
	u := h.r.UsageReport(14)
	if u.ActiveInstances != 2 || u.PushedLast7Days != 2 || u.PushedLast30Days != 2 || u.ActiveBindings != 1 {
		t.Fatalf("usage: %+v", u)
	}
	y := u.PushesPerDay[len(u.PushesPerDay)-1]
	if y.Total != 4 || y.ByClass["alert"] != 3 || y.ByClass["silent"] != 1 || y.Accepted != 3 || y.SoftFailed != 1 {
		t.Fatalf("yesterday: %+v", y)
	}
	// Weeks are reported once completed.
	h.clk.Add(7 * 24 * time.Hour)
	u = h.r.UsageReport(14)
	var reg, opt int64
	for _, w := range u.RegistrationsPerWeek {
		reg += w.N
	}
	for _, w := range u.OptOutsPerWeek {
		opt += w.N
	}
	if reg != 2 || opt != 1 {
		t.Fatalf("weekly: registrations %d opt-outs %d", reg, opt)
	}
	// The current day is never reported: a partial day of a small population would be too fine.
	for _, dp := range u.PushesPerDay {
		if dp.Day == store.DayString(store.Day(h.clk.Now())) {
			t.Fatal("report includes the current day")
		}
	}
}

// TestMetricsCoarseBelowThreshold: with fewer than 20 active instances the scrape is a snapshot refreshed
// hourly, so one instance's push cannot be timed from it.
func TestMetricsCoarseBelowThreshold(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0x51)
	scrape := func() string {
		rec := httptest.NewRecorder()
		h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
		return rec.Body.String()
	}
	first := scrape()
	i.activate(d)
	if scrape() != first {
		t.Fatal("metrics changed within the hour with fewer than 20 instances")
	}
	h.clk.Add(time.Hour)
	if scrape() == first {
		t.Fatal("metrics never refresh")
	}
}
