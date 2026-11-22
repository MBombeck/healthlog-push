package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

// TestHeldMetricsRefreshEveryFiveMinutes: every metric outside the live set, the figures about who is
// registered and every count by class or kind among them, shows from a copy taken every five minutes, at
// every number of instances. The moment one instance registers, one device binds, or a push of one kind
// passes cannot be read off the scrape.
func TestHeldMetricsRefreshEveryFiveMinutes(t *testing.T) {
	h := newHarness(t)
	held := func() string {
		rec := httptest.NewRecorder()
		h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
		var out []string
		for _, line := range strings.Split(rec.Body.String(), "\n") {
			name, _, _ := strings.Cut(line, "{")
			name, _, _ = strings.Cut(name, " ")
			name = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")
			if strings.HasPrefix(name, "hlp_") && !slices.Contains(liveMetrics, name) {
				out = append(out, line)
			}
		}
		if len(out) < 40 {
			t.Fatalf("only %d held series in the scrape: the check would prove little", len(out))
		}
		return strings.Join(out, "\n")
	}
	first := held()
	i := h.register()
	d := newDevice(0x51)
	i.activate(d)
	i.push1(alertItem("a", d))
	h.clk.Add(heldRefresh - time.Second)
	// Even with the current values already in the registry, the scrape keeps showing the copy it holds.
	h.r.usageGauges()
	if held() != first {
		t.Fatal("a held metric changed before its refresh")
	}
	h.clk.Add(time.Second)
	after := held()
	for _, want := range []string{`hlp_bindings{state="active"} 1`, "hlp_usage_active_instances 1",
		`hlp_apns_sends_total{kind="alert"} 2`, `hlp_push_total{class="alert",result="accepted"} 2`,
		`hlp_registrations_total{result="created"} 1`} {
		if !strings.Contains(after, want+"\n") {
			t.Errorf("missing %q after the refresh:\n%s", want, after)
		}
	}
}

// TestLiveMetricsAreTheNarrowSet: exactly these metrics are current at every scrape. Widening the set is a
// change to a published promise (privacy notice section 6, docs/transparency.md), so it has to change this
// list as well. The gauges among them exist from the first scrape, before anything went wrong, so a rule on
// one of them never looks at no data.
func TestLiveMetricsAreTheNarrowSet(t *testing.T) {
	want := []string{"hlp_apns_misconfigured", "hlp_apns_rejections_total", "hlp_apns_requests_total", "hlp_breaker_open",
		"hlp_db_writable", "hlp_delivery_latency_seconds", "hlp_requests_total"}
	h := newHarness(t)
	if got := h.r.Metrics.LiveNames(); !slices.Equal(got, want) {
		t.Fatalf("live metrics %v, want %v", got, want)
	}
	rec := httptest.NewRecorder()
	h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	for _, line := range []string{"hlp_apns_misconfigured 0", "hlp_breaker_open 0", "hlp_db_writable 1", "hlp_apns_requests_total 0"} {
		if !strings.Contains(rec.Body.String(), "\n"+line+"\n") {
			t.Errorf("missing %q on a healthy relay:\n%s", line, rec.Body.String())
		}
	}
}

// TestStateGaugesAreSums checks that the binding-state gauges carry the same sums as `admin stats`, and the
// tier gauges too for every tier that holds at least three instances, with every label of the closed sets
// present, zero included.
func TestStateGaugesAreSums(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	h.register()
	a.activate(newDevice(0x61))
	b.bind(newDevice(0x62))
	rec := httptest.NewRecorder()
	h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	body := rec.Body.String()
	st := h.r.Stats()
	want := map[string]int{`hlp_instances{tier="` + tierOther + `"}`: 0}
	for _, tier := range stateTiers {
		want[`hlp_instances{tier="`+tier+`"}`] = st.Instances[tier]
	}
	for _, s := range stateBindings {
		want[`hlp_bindings{state="`+s+`"}`] = st.Bindings[s]
	}
	if st.Instances["probation"] != 3 || st.Bindings["active"] != 1 || st.Bindings["provisional"] != 1 {
		t.Fatalf("fixture: %+v %+v", st.Instances, st.Bindings)
	}
	for series, n := range want {
		if line := series + " " + strconv.Itoa(n) + "\n"; !strings.Contains(body, line) {
			t.Errorf("missing %q in\n%s", line, body)
		}
	}
}

// TestSmallTiersAreMergedIntoOther: a tier with one or two instances is not shown on its own, because that
// would say which tier a single instance is in. Its instances count under `other`, and the tier shows zero.
func TestSmallTiersAreMergedIntoOther(t *testing.T) {
	h := newHarness(t)
	scrape := func() string {
		h.clk.Add(heldRefresh)
		rec := httptest.NewRecorder()
		h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
		return rec.Body.String()
	}
	has := func(body, series string, n int) {
		t.Helper()
		if line := series + " " + strconv.Itoa(n) + "\n"; !strings.Contains(body, line) {
			t.Errorf("missing %q in\n%s", line, body)
		}
	}
	h.register()
	suspended := h.register()
	body := scrape()
	has(body, `hlp_instances{tier="probation"}`, 0)
	has(body, `hlp_instances{tier="other"}`, 2)
	h.register()
	h.register()
	if err := h.r.Suspend(suspended.id, "spam"); err != nil {
		t.Fatal(err)
	}
	body = scrape()
	// Three on probation show as their tier; the one suspended instance stays merged.
	has(body, `hlp_instances{tier="probation"}`, 3)
	has(body, `hlp_instances{tier="suspended"}`, 0)
	has(body, `hlp_instances{tier="other"}`, 1)
	if st := h.r.Stats(); st.Instances["suspended"] != 1 || st.Instances["probation"] != 3 {
		t.Fatalf("admin stats must keep the exact sums: %+v", st.Instances)
	}
}
