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

// live renders the registry as it is now, the population gauges included, so a test sees each change.
func live(t *testing.T, h *harness) map[string]float64 {
	t.Helper()
	var b bytes.Buffer
	if err := h.r.Metrics.Write(&b, h.clk.Now().Add(1000*time.Hour), 0); err != nil {
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

// TestEveryItemRefusalIsCounted: an item refused before it is queued counts in hlp_push_total like every
// other outcome. A push to a binding the relay does not hold for the instance, or for the other APNs
// environment, used to leave no trace in the metrics at all, so a send that never reached Apple looked
// like no send.
func TestEveryItemRefusalIsCounted(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xc6)
	m0 := live(t, h)
	if res := i.push1(alertItem("u", newDevice(0xc7))); res.Error != "binding_unknown" {
		t.Fatalf("unknown binding: %+v", res)
	}
	i.activate(d)
	m1 := live(t, h)
	grew(t, m0, m1, `hlp_push_total{class="alert",result="binding_unknown"}`, 1)
	wrongEnv := silentItem("e", d)
	wrongEnv.Env = "sandbox"
	if res := i.push1(wrongEnv); res.Error != "invalid_item" {
		t.Fatalf("other environment: %+v", res)
	}
	grew(t, m1, live(t, h), `hlp_push_total{class="silent",result="invalid_item"}`, 1)
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
		"class":      {"alert", "silent", "liveactivity", "unknown"},
		"result":     results,
		"status":     statusClasses,
		"reason":     append(append([]string{"bad_signature"}, apns.ReasonLabels()...), registrationRejections...),
		"tier":       append(slices.Clone(stateTiers), tierOther),
		"state":      stateBindings,
		"window":     {"7d", "30d"},
		"outcome":    {"accepted", "soft_failed", "unregistered"},
		"kind":       append(slices.Clone(pushKinds), "sync", "wake"),
		"answer":     {"replayed", "joined"},
		"priority":   {"5", "10"},
		"slot":       identitySlots,
		"surface":    rateSurfaces,
		"connection": {connNew, connReused},
		"le":         {"0.05", "0.1", "0.15", "0.25", "0.5", "1", "2.5", "5", "10", "+Inf"},
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

// TestOnlyTheNarrowSetIsLive: a push shows in the very next scrape only as the request, one request to
// Apple without its kind, and its latency. Its class, its kind, its outcome and the key slot, like the
// binding it made active, wait for the next refresh of the held copy, at any number of instances.
func TestOnlyTheNarrowSetIsLive(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xc5)
	scrape := func() string {
		rec := httptest.NewRecorder()
		h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
		return rec.Body.String()
	}
	has := func(body, line, when string) {
		t.Helper()
		if !strings.Contains(body, line+"\n") {
			t.Errorf("%s: missing %q in\n%s", when, line, body)
		}
	}
	first := scrape()
	for _, line := range []string{"hlp_delivery_latency_seconds_count 0", "hlp_apns_requests_total 0",
		`hlp_apns_sends_total{kind="silent_sync"} 0`, `hlp_bindings{state="active"} 0`, `hlp_deliveries_by_key_slot_total{slot="unpinned"} 0`} {
		has(first, line, "first scrape")
	}
	i.activate(d)
	i.push1(silentItem("s", d))
	next := scrape()
	// The alert that activates the binding and the silent push: two requests to Apple.
	for _, line := range []string{"hlp_apns_requests_total 2", "hlp_delivery_latency_seconds_count 2"} {
		has(next, line, "right after the push")
	}
	for _, line := range []string{`hlp_apns_sends_total{kind="silent_sync"} 0`, `hlp_apns_sends_total{kind="alert"} 0`,
		`hlp_deliveries_by_key_slot_total{slot="unpinned"} 0`, `hlp_bindings{state="active"} 0`} {
		has(next, line, "held until the refresh")
	}
	if strings.Contains(next, `hlp_push_total{class="silent"`) {
		t.Errorf("the class of the push shows before the refresh:\n%s", next)
	}
	h.clk.Add(heldRefresh)
	after := scrape()
	for _, line := range []string{`hlp_apns_sends_total{kind="silent_sync"} 1`, `hlp_apns_sends_total{kind="alert"} 1`,
		`hlp_push_total{class="silent",result="accepted"} 1`, `hlp_deliveries_by_key_slot_total{slot="unpinned"} 2`,
		`hlp_bindings{state="active"} 1`} {
		has(after, line, "after the refresh")
	}
}

// TestLatencyBucketsResolveTheUsefulRange: answers in 60, 120 and 200 ms fall into three buckets, and one
// that took seven seconds is told from one beyond ten, so a slow 95th percentile is a number and not the last
// bound.
func TestLatencyBucketsResolveTheUsefulRange(t *testing.T) {
	h := newHarness(t)
	for _, v := range []float64{0.04, 0.06, 0.12, 0.2, 7, 12} {
		h.r.Metrics.Observe("hlp_delivery_latency_seconds", v)
	}
	m := live(t, h)
	for series, want := range map[string]float64{
		`hlp_delivery_latency_seconds_bucket{le="0.05"}`: 1,
		`hlp_delivery_latency_seconds_bucket{le="0.1"}`:  2,
		`hlp_delivery_latency_seconds_bucket{le="0.15"}`: 3,
		`hlp_delivery_latency_seconds_bucket{le="0.25"}`: 4,
		`hlp_delivery_latency_seconds_bucket{le="5"}`:    4,
		`hlp_delivery_latency_seconds_bucket{le="10"}`:   5,
		`hlp_delivery_latency_seconds_bucket{le="+Inf"}`: 6,
	} {
		if m[series] != want {
			t.Errorf("%s = %v, want %v", series, m[series], want)
		}
	}
}

// sendsByKind is the sum of hlp_apns_sends_total over every kind.
func sendsByKind(m map[string]float64) float64 {
	var n float64
	for _, k := range pushKinds {
		n += m[`hlp_apns_sends_total{kind="`+k+`"}`]
	}
	return n
}

// TestEverySendCountsOneKind: every request to Apple, on every send path and whatever Apple answers,
// raises hlp_apns_requests_total and exactly one kind of hlp_apns_sends_total by one, so the kinds always
// add up to the total. A send path that skipped the split would let the two drift apart.
func TestEverySendCountsOneKind(t *testing.T) {
	answers := []struct {
		name   string
		status int
		reason string
	}{{"accepted", 200, ""}, {"refused", 400, "BadTopic"}, {"unavailable", 503, "ServiceUnavailable"}}
	cases := []struct {
		kind string
		item func(h *harness, i *instance, d *device, ref string) wire.PushItem
	}{
		{kindAlert, func(_ *harness, _ *instance, d *device, ref string) wire.PushItem { return alertItem(ref, d) }},
		{kindSilentSync, func(_ *harness, _ *instance, d *device, ref string) wire.PushItem { return silentItem(ref, d) }},
		{kindLAStart, func(h *harness, i *instance, d *device, ref string) wire.PushItem {
			now := h.clk.Now()
			return d.laItem(ref, wire.EventStart, i.id, bytes.Repeat([]byte{0x71}, 32), now.Unix(), dueState(now))
		}},
		{kindLAUpdate, func(h *harness, i *instance, d *device, ref string) wire.PushItem {
			now := h.clk.Now()
			return d.laItem(ref, wire.EventUpdate, i.id, bytes.Repeat([]byte{0x72}, 32), now.Unix(), dueState(now))
		}},
		{kindLAEnd, func(h *harness, i *instance, d *device, ref string) wire.PushItem {
			return d.activity(ref, i.id, bytes.Repeat([]byte{0x73}, 32), h.clk.Now().Unix())
		}},
	}
	for _, a := range answers {
		for _, c := range cases {
			t.Run(c.kind+"/"+a.name, func(t *testing.T) {
				h := newHarness(t)
				i := h.register()
				d := newDevice(0xd1)
				i.activate(d)
				if rp := i.laConsent(d, d.key); rp.Status != 200 {
					t.Fatalf("consent: %d %s", rp.Status, rp.Raw)
				}
				m0 := live(t, h)
				h.apns.setAnswer(func(string, apnsReq) (int, string) { return a.status, a.reason })
				if res := i.push1(c.item(h, i, d, "k")); res.Status == http.StatusTooManyRequests || res.Error == "invalid_item" {
					t.Fatalf("not sent: %+v", res)
				}
				m1 := live(t, h)
				if d := m1["hlp_apns_requests_total"] - m0["hlp_apns_requests_total"]; d != 1 {
					t.Fatalf("requests rose by %g, want 1", d)
				}
				for _, k := range pushKinds {
					want := 0.0
					if k == c.kind {
						want = 1
					}
					s := `hlp_apns_sends_total{kind="` + k + `"}`
					if d := m1[s] - m0[s]; d != want {
						t.Errorf("%s rose by %g, want %g", s, d, want)
					}
				}
				if sendsByKind(m1) != m1["hlp_apns_requests_total"] {
					t.Errorf("kinds add up to %g, requests %g", sendsByKind(m1), m1["hlp_apns_requests_total"])
				}
			})
		}
	}
	// The relay's own wake push for a challenge is the remaining send path.
	t.Run(kindSilentWake, func(t *testing.T) {
		h := newHarness(t)
		a, b := h.register(), h.register()
		a.activate(newDevice(0xd2))
		m0 := live(t, h)
		if rp := b.bind(newDevice(0xd2)); rp.str("reason") != "challenge_sent" {
			t.Fatalf("conflict: %d %s", rp.Status, rp.Raw)
		}
		deadline := time.Now().Add(5 * time.Second)
		for live(t, h)["hlp_apns_requests_total"] == m0["hlp_apns_requests_total"] && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		m1 := live(t, h)
		grew(t, m0, m1, `hlp_apns_sends_total{kind="silent_wake"}`, 1)
		if sendsByKind(m1) != m1["hlp_apns_requests_total"] || sendsByKind(m1) != sendsByKind(m0)+1 {
			t.Errorf("kinds %g, requests %g", sendsByKind(m1), m1["hlp_apns_requests_total"])
		}
	})
}

// TestKindSplitIsHeldNotLost: the split by kind is served from the copy taken every heldRefresh while the
// total is live, so between two copies the kinds can trail the total. They are equal again at the next
// copy; nothing is lost.
func TestKindSplitIsHeldNotLost(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xd3)
	scrape := func() map[string]float64 {
		t.Helper()
		var b bytes.Buffer
		if err := h.r.Metrics.Write(&b, h.clk.Now(), heldRefresh); err != nil {
			t.Fatal(err)
		}
		out := map[string]float64{}
		for _, line := range strings.Split(b.String(), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k := strings.LastIndexByte(line, ' ')
			v, _ := strconv.ParseFloat(line[k+1:], 64)
			out[line[:k]] = v
		}
		return out
	}
	scrape()
	i.activate(d)
	i.push1(silentItem("h1", d))
	i.push1(d.activity("h2", i.id, bytes.Repeat([]byte{0x74}, 32), h.clk.Now().Unix()))
	m := scrape()
	if m["hlp_apns_requests_total"] != 3 || sendsByKind(m) != 0 {
		t.Fatalf("before the next copy: requests %g, kinds %g", m["hlp_apns_requests_total"], sendsByKind(m))
	}
	h.clk.Add(heldRefresh)
	if m = scrape(); sendsByKind(m) != m["hlp_apns_requests_total"] {
		t.Fatalf("after the next copy: requests %g, kinds %g", m["hlp_apns_requests_total"], sendsByKind(m))
	}
}

// TestAPNsConnectionReuseIsCounted: every request to Apple counts once as new or reused, the first one on a
// fresh client as new and the following ones over the same HTTP/2 connection as reused, so the share of
// reused requests can be read off the two series.
func TestAPNsConnectionReuseIsCounted(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0xc7)
	m0 := live(t, h)
	if m0[`hlp_apns_connections_total{connection="new"}`] != 0 || m0[`hlp_apns_connections_total{connection="reused"}`] != 0 {
		t.Fatalf("connections counted before any send: %v", m0)
	}
	i.activate(d)
	for n := range 3 {
		if res := i.push1(alertItem("cr"+strconv.Itoa(n), d)); res.Result != "accepted" {
			t.Fatalf("push: %+v", res)
		}
	}
	m1 := live(t, h)
	fresh, reused := m1[`hlp_apns_connections_total{connection="new"}`], m1[`hlp_apns_connections_total{connection="reused"}`]
	if fresh != 1 || reused != 3 {
		t.Fatalf("new %g reused %g, want 1 and 3", fresh, reused)
	}
	if sent := m1[`hlp_apns_requests_total`] - m0[`hlp_apns_requests_total`]; fresh+reused != sent {
		t.Fatalf("%g connection counts for %g requests to Apple", fresh+reused, sent)
	}
}
