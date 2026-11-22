package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// live renders the registry as it is now, without the coarse snapshot, so a test sees each increment.
func live(t *testing.T, h *harness) map[string]float64 {
	t.Helper()
	var b bytes.Buffer
	if err := h.r.Metrics.WriteSnapshot(&b, h.clk.Now().Add(1000*time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, line := range strings.Split(b.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		out[line[:i]] = v
	}
	return out
}

// grew fails unless series rose by at least n between before and after.
func grew(t *testing.T, before, after map[string]float64, series string, n float64) {
	t.Helper()
	if _, ok := after[series]; !ok {
		t.Fatalf("series %s missing", series)
	}
	if d := after[series] - before[series]; d < n {
		t.Errorf("%s rose by %g, want at least %g", series, d, n)
	}
}

// TestOperationalPushMetrics: kinds, latency, key slot, Apple's reasons, retries and silent sync refusals
// each count what they describe.
func TestOperationalPushMetrics(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.IdentitySlot = "current" })
	i := h.register()
	d := newDevice(0xc1)
	m0 := live(t, h)
	i.activate(d)
	if res := i.push1(silentItem("s0", d)); res.Result != "accepted" {
		t.Fatalf("silent: %+v", res)
	}
	m1 := live(t, h)
	grew(t, m0, m1, `hlp_apns_sends_total{kind="alert"}`, 1)
	grew(t, m0, m1, `hlp_apns_sends_total{kind="silent_sync"}`, 1)
	grew(t, m0, m1, `hlp_deliveries_by_key_slot_total{slot="current"}`, 2)
	grew(t, m0, m1, `hlp_delivery_latency_seconds_count`, 2)
	grew(t, m0, m1, `hlp_delivery_latency_seconds_bucket{le="+Inf"}`, 2)
	if m1[`hlp_deliveries_by_key_slot_total{slot="unpinned"}`] != 0 {
		t.Error("a pinned key counted as unpinned")
	}

	// The same ref again is an instance retry, answered from memory.
	if res := i.push1(silentItem("s0", d)); !res.Duplicate {
		t.Fatalf("replay: %+v", res)
	}
	grew(t, m1, live(t, h), `hlp_push_retries_total{answer="replayed"}`, 1)

	// The silent budget of the device (6 per hour) refuses the rest as a sync refusal and a push rate hit.
	m2 := live(t, h)
	for n := range 8 {
		i.push1(silentItem("sb"+strconv.Itoa(n), d))
	}
	m3 := live(t, h)
	grew(t, m2, m3, `hlp_silent_budget_refused_total{kind="sync"}`, 1)
	grew(t, m2, m3, `hlp_rate_limited_total{surface="push"}`, 1)
	if m3[`hlp_silent_budget_refused_total{kind="wake"}`] != 0 {
		t.Error("a sync refusal counted as wake")
	}

	// Apple's reason codes, with an unknown one mapped to other.
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 400, "BadTopic" })
	i.push1(alertItem("r1", d))
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 400, "SomethingApple<added>" })
	i.push1(alertItem("r2", d))
	m4 := live(t, h)
	grew(t, m3, m4, `hlp_apns_rejections_total{reason="BadTopic"}`, 1)
	grew(t, m3, m4, `hlp_apns_rejections_total{reason="other"}`, 1)
	for k := range m4 {
		if strings.Contains(k, "SomethingApple") {
			t.Fatalf("an unknown reason became a label: %s", k)
		}
	}
}

// TestLiveActivityKindsAndPriority: start, update and end are told apart, and so are priorities 10 and 5.
func TestLiveActivityKindsAndPriority(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xc2)
	i.activate(d)
	if rp := i.laConsent(d, d.key); rp.Status != 200 {
		t.Fatalf("consent: %d %s", rp.Status, rp.Raw)
	}
	now := h.clk.Now()
	start, la := bytes.Repeat([]byte{0x61}, 32), bytes.Repeat([]byte{0x62}, 32)
	pending := dueState(now)
	pending.Status = ptr("pending")
	m0 := live(t, h)
	for _, it := range []wire.PushItem{
		d.laItem("st", wire.EventStart, i.id, start, now.Unix(), dueState(now)),
		d.laItem("up", wire.EventUpdate, i.id, la, now.Unix(), pending),
		d.activity("end", i.id, la, now.Unix()),
	} {
		if res := i.push1(it); res.Result != "accepted" {
			t.Fatalf("%s: %+v", it.Ref, res)
		}
	}
	m1 := live(t, h)
	for _, k := range []string{kindLAStart, kindLAUpdate, kindLAEnd} {
		grew(t, m0, m1, `hlp_apns_sends_total{kind="`+k+`"}`, 1)
	}
	grew(t, m0, m1, `hlp_liveactivity_priority_total{priority="10"}`, 2)
	grew(t, m0, m1, `hlp_liveactivity_priority_total{priority="5"}`, 1)
}

// TestChallengeIsASilentWake: the relay's challenge push counts as silent_wake, and the second challenge
// of the day for the same token is a wake refusal.
func TestChallengeIsASilentWake(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(0xc3)
	a.activate(d)
	m0 := live(t, h)
	if rp := b.bind(newDevice(0xc3)); rp.str("reason") != "challenge_sent" {
		t.Fatalf("conflict: %d %s", rp.Status, rp.Raw)
	}
	deadline := time.Now().Add(5 * time.Second)
	for live(t, h)[`hlp_apns_sends_total{kind="silent_wake"}`] < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	grew(t, m0, live(t, h), `hlp_apns_sends_total{kind="silent_wake"}`, 1)
	if rp := b.bind(newDevice(0xc3)); rp.str("reason") != "challenge_quota" {
		t.Fatalf("second challenge: %d %s", rp.Status, rp.Raw)
	}
	grew(t, m0, live(t, h), `hlp_silent_budget_refused_total{kind="wake"}`, 1)
}

// TestRegistrationRejectionsAndRateLimits: every refusal reason of a new registration and the rate limit
// surfaces count.
func TestRegistrationRejectionsAndRateLimits(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Registrations = limits.DefaultRegistrationLimits
		c.Limits = DefaultLimits
	})
	mk := func() *instance { _, k, _ := ed25519.GenerateKey(rand.Reader); return &instance{h: h, key: k} }
	m0 := live(t, h)
	// A proof signed by another key.
	bad := mk()
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	pub := ed25519.PublicKey(bad.key[32:])
	ts := h.clk.Now().Unix()
	body := wire.RegisterBody{PublicKey: wire.EncodeB64(pub), Client: "healthlog/1.49.0", Time: ts,
		Proof: wire.EncodeB64(ed25519.Sign(other, []byte(wire.RegisterText(host, pub, ts))))}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/instances", bytes.NewReader(raw))
	if rp := h.send(req, ""); rp.str("error") != "bad_signature" {
		t.Fatalf("bad proof: %d %s", rp.Status, rp.Raw)
	}
	// The address cap of the default limits allows three.
	i := h.register()
	h.register()
	h.register()
	if rp := mk().registerRaw(""); rp.str("error") != "registration_paused" {
		t.Fatalf("over the cap: %d %s", rp.Status, rp.Raw)
	}
	_ = h.r.SetRegistration(RegInvite)
	if rp := mk().registerRaw(""); rp.str("error") != "invite_required" {
		t.Fatalf("no invite: %d %s", rp.Status, rp.Raw)
	}
	// The request rate of a probation instance.
	for range DefaultLimits.Probation.RequestsMinute + 1 {
		i.do(http.MethodGet, "/v1/status", nil)
	}
	m1 := live(t, h)
	for _, reason := range registrationRejections {
		grew(t, m0, m1, `hlp_registrations_rejected_total{reason="`+reason+`"}`, 1)
	}
	grew(t, m0, m1, `hlp_rate_limited_total{surface="registration"}`, 1)
	grew(t, m0, m1, `hlp_rate_limited_total{surface="instance_requests"}`, 1)
}

// TestQueueDepthGauge: the queue depth is set on every scrape.
func TestQueueDepthGauge(t *testing.T) {
	h := newHarness(t)
	rec := httptest.NewRecorder()
	h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	if !strings.Contains(rec.Body.String(), "\nhlp_queue_depth 0\n") {
		t.Fatalf("no queue depth in\n%s", rec.Body.String())
	}
}

// labelValues is the closed set of values every label may take. A label outside this map, or a value
// outside its set, fails TestMetricLabelsAreAllowlisted.
func labelValues() map[string][]string {
	statusClasses := []string{"1xx", "2xx", "3xx", "4xx", "5xx"}
	outcomes := []string{string(apns.Accepted), string(apns.Unregistered), string(apns.SoftInvalid), string(apns.DeviceThrottled),
		string(apns.ProviderExpired), string(apns.ProviderInvalid), string(apns.ProviderTooMany), string(apns.Rejected),
		string(apns.Unavailable), string(apns.NoProviderToken)}
	results := append([]string{"accepted", "activity_gone", "soft_invalid", "unregistered", "device_throttled", "apns_unavailable",
		"relay_misconfigured", "apns_rejected", "invalid_item", "queue_full", "binding_unknown", "maintenance", "global",
		"device_quota", "binding_quota", "instance_quota", "instance_rate", "activity_refused", "liveactivity_consent_required",
		"created", "limited", "bound", "opt_out_lifted", "unbound_instance", "unbound_self", "conflict", "challenge_resolved",
		"liveactivity_consent", "liveactivity_consent_withdrawn"}, outcomes...)
	return map[string][]string{
		"class":    {"alert", "silent", "liveactivity", "unknown"},
		"result":   results,
		"status":   statusClasses,
		"reason":   append(append([]string{"bad_signature"}, apns.ReasonLabels()...), registrationRejections...),
		"tier":     stateTiers,
		"state":    stateBindings,
		"window":   {"7d", "30d"},
		"outcome":  {"accepted", "soft_failed", "unregistered"},
		"kind":     append(slices.Clone(pushKinds), "sync", "wake"),
		"answer":   {"replayed", "joined"},
		"priority": {"5", "10"},
		"slot":     identitySlots,
		"surface":  rateSurfaces,
		"le":       {"0.1", "0.25", "0.5", "1", "2.5", "5", "+Inf"},
	}
}

var labelPair = regexp.MustCompile(`([a-z_]+)="([^"]*)"`)

// TestMetricLabelsAreAllowlisted runs traffic through every path that counts something and then checks
// every series in the registry: each label name is on the allowlist and each value in its closed set. A
// label that could carry an instance, a device, a token or anything per person cannot be added without
// failing here.
func TestMetricLabelsAreAllowlisted(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(0xc4)
	a.activate(d)
	a.push1(silentItem("s", d))
	_ = b.bind(newDevice(0xc4))
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 400, "BadTopic" })
	a.push1(alertItem("x", d))
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 410, "Unregistered" })
	a.push1(alertItem("y", d))
	rec := httptest.NewRecorder()
	h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	series := live(t, h)
	if len(series) < 50 {
		t.Fatalf("only %d series: the check would prove little", len(series))
	}
	allowed := labelValues()
	for s := range series {
		_, labels, ok := strings.Cut(s, "{")
		if !ok {
			continue
		}
		pairs := labelPair.FindAllStringSubmatch(labels, -1)
		if len(pairs) == 0 {
			t.Fatalf("unparsed labels in %s", s)
		}
		for _, p := range pairs {
			vals, known := allowed[p[1]]
			if !known {
				t.Errorf("%s: label %q is not on the allowlist", s, p[1])
				continue
			}
			if !slices.Contains(vals, p[2]) {
				t.Errorf("%s: value %q of %q is outside its closed set", s, p[2], p[1])
			}
		}
	}
}

// TestOperationalMetricsKeepTheCoarseSnapshot: below 20 instances a push moves none of the new series
// within the hour either.
func TestOperationalMetricsKeepTheCoarseSnapshot(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xc5)
	scrape := func() string {
		rec := httptest.NewRecorder()
		h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
		return rec.Body.String()
	}
	first := scrape()
	if !strings.Contains(first, "hlp_delivery_latency_seconds_count 0") {
		t.Fatalf("histogram missing from the snapshot:\n%s", first)
	}
	i.activate(d)
	i.push1(silentItem("s", d))
	if scrape() != first {
		t.Fatal("operational metrics changed within the hour with fewer than 20 instances")
	}
	h.clk.Add(time.Hour)
	if after := scrape(); after == first || !strings.Contains(after, `hlp_apns_sends_total{kind="silent_sync"} 1`) {
		t.Fatal("the snapshot never shows the push")
	}
}
