package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// TestEndToEndAlert covers the main path: register, device-signed binding, alert through the fake APNs
// HTTP/2 server with the fixed template, activation of the binding, signed responses throughout.
func TestEndToEndAlert(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0x0f)
	if rp := i.bind(d); rp.Status != http.StatusCreated || rp.str("state") != store.StateProvisional {
		t.Fatalf("bind: %d %s", rp.Status, rp.Raw)
	}
	it := alertItem("ref-1", d)
	it.TTLSeconds = 99999 // clamped to 6 h
	res := i.push1(it)
	if res.Status != 200 || res.Result != "accepted" {
		t.Fatalf("push: %+v", res)
	}
	reqs := h.apns.requests()
	if len(reqs) != 1 {
		t.Fatalf("apns requests: %d", len(reqs))
	}
	got := reqs[0]
	if got.Proto != "HTTP/2.0" {
		t.Errorf("APNs protocol %s, want HTTP/2.0", got.Proto)
	}
	if got.Token != d.hex() {
		t.Errorf("token path %s", got.Token)
	}
	want := `{"aps":{"alert":{"loc-key":"HL_RELAY_ALERT"},"mutable-content":1,"sound":"default"},"e":"` + it.Envelope + `"}`
	if got.Body != want {
		t.Errorf("payload is not the fixed template:\n%s", got.Body)
	}
	hd := got.Header
	if hd.Get("apns-push-type") != "alert" || hd.Get("apns-priority") != "10" || hd.Get("apns-topic") != "dev.example.app" || hd.Get("apns-collapse-id") != collapse {
		t.Errorf("headers: %v", hd)
	}
	if exp, _ := strconv.ParseInt(hd.Get("apns-expiration"), 10, 64); exp != h.clk.Now().Unix()+6*3600 {
		t.Errorf("expiration %d not clamped to 6 h", exp)
	}
	if h.state(d) != store.StateActive {
		t.Errorf("binding not active after accepted push: %s", h.state(d))
	}
	sr := h.selfRead(d)
	if sr.Status != 200 || sr.str("state") != "active" || sr.str("instanceId") != i.id || sr.str("consentVersion") != "2026-11-21" {
		t.Errorf("self read: %d %s", sr.Status, sr.Raw)
	}
}

func TestSilentTemplateAndPriority(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(1)
	i.activate(d)
	it := silentItem("s1", d)
	if res := i.push1(it); res.Result != "accepted" {
		t.Fatal(res)
	}
	r := h.apns.requests()[1]
	if r.Body != `{"aps":{"content-available":1},"e":"`+it.Envelope+`"}` || r.Header.Get("apns-push-type") != "background" || r.Header.Get("apns-priority") != "5" {
		t.Errorf("silent: %s %v", r.Body, r.Header)
	}
}

// TestUnregisteredIsTheOnlyFinalDeletion: Unregistered deletes a binding at once, a soft failure only on a
// second day, and a transient Apple error never changes a binding.
func TestUnregisteredIsTheOnlyFinalDeletion(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	gone, soft, flaky := newDevice(10), newDevice(11), newDevice(12)
	for _, d := range []*device{gone, soft, flaky} {
		i.activate(d)
	}
	h.apns.setAnswer(func(tok string, _ apnsReq) (int, string) {
		switch tok {
		case gone.hex():
			return 410, "Unregistered"
		case soft.hex():
			return 400, "BadDeviceToken"
		}
		return 500, "InternalServerError"
	})
	if res := i.push1(alertItem("g", gone)); res.Status != 410 || res.Error != "unregistered" {
		t.Fatalf("unregistered: %+v", res)
	}
	if h.state(gone) != "" {
		t.Fatal("410 did not delete")
	}
	if res := i.push1(alertItem("s1", soft)); res.Status != 200 || res.Result != "soft_invalid" {
		t.Fatalf("soft: %+v", res)
	}
	// A soft-invalid binding gets no further push on the day it failed, and nothing is deleted.
	if res := i.push1(alertItem("s2", soft)); res.Status != 429 || res.Error != "binding_quota" || h.state(soft) != store.StateSoftInvalid {
		t.Fatalf("second push on the same day: %+v %s", res, h.state(soft))
	}
	if res := i.push1(alertItem("f", flaky)); res.Status != 503 || res.Error != "apns_unavailable" {
		t.Fatalf("5xx: %+v", res)
	}
	if h.state(flaky) != store.StateActive {
		t.Fatal("a transient Apple error changed the binding")
	}
	h.clk.Add(24 * time.Hour)
	if res := i.push1(alertItem("s3", soft)); res.Result != "soft_invalid" {
		t.Fatal(res)
	}
	if h.state(soft) != "" {
		t.Fatal("second soft hit on another day did not delete")
	}
}

func TestDeviceAlertBucketAndSilentLimit(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(13)
	i.activate(d) // one alert used
	var refused ItemResult
	for n := range 25 {
		res := i.push1(alertItem("a"+strconv.Itoa(n), d))
		if res.Status == 429 {
			refused = res
			if n != 19 {
				t.Fatalf("alert bucket refused after %d alerts, want 20 in total", n+1)
			}
			break
		}
	}
	if refused.Error != "device_quota" || refused.Scope != "device" || refused.RetryAfter <= 0 {
		t.Fatalf("alert bucket: %+v", refused)
	}
	// Silent: 6 per hour, halved to 3 until midnight after a (re)start.
	e := newDevice(14)
	i.activate(e)
	var n int
	for n = 0; n < 10; n++ {
		if res := i.push1(silentItem("s"+strconv.Itoa(n), e)); res.Status == 429 {
			break
		}
	}
	if n != 3 {
		t.Fatalf("silent after restart: %d allowed, want 3", n)
	}
}

func TestInstanceRateLimits(t *testing.T) {
	h := newHarness(t, withDefaultLimits)
	i := h.register()
	var got int
	for got = 0; got < 30; got++ {
		if rp := i.do(http.MethodGet, "/v1/status", nil); rp.Status == 429 {
			if rp.str("scope") != "instance" || rp.Header.Get("Retry-After") == "" {
				t.Fatalf("429 without scope or Retry-After: %s", rp.Raw)
			}
			break
		}
	}
	if got != 20 { // registration does not count; 20 per minute in probation
		t.Fatalf("probation request limit: %d accepted, want 20", got+1)
	}
}

func TestPushesPerMinuteProbation(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits = DefaultLimits; c.Limits.Probation.RequestsMinute = 1000 })
	i := h.register()
	var devs []*device
	for n := range 10 {
		d := newDevice(byte(100 + n))
		devs = append(devs, d)
		if rp := i.bind(d); rp.Status != 201 {
			t.Fatal(rp.Status)
		}
	}
	h.clk.Add(time.Minute)
	var items []wire.PushItem
	for k := range 40 {
		items = append(items, alertItem("p"+strconv.Itoa(k), devs[k%10]))
	}
	_, res := i.push(items...)
	accepted, limited := 0, 0
	for _, r := range res {
		switch {
		case r.Result == "accepted":
			accepted++
		case r.Error == "instance_rate" && r.Scope == "instance":
			limited++
		}
	}
	if accepted != 30 || limited != 10 {
		t.Fatalf("probation pushes per minute: %d accepted, %d limited; want 30 and 10", accepted, limited)
	}
}

// TestIdempotency: a retry with the same ref returns the first result without a second send,
// while a transient failure is not cached.
func TestIdempotency(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(15)
	i.activate(d)
	before := len(h.apns.requests())
	it := alertItem("idem-1", d)
	r1 := i.push1(it)
	r2 := i.push1(it)
	if r1.Result != "accepted" || r2.Result != "accepted" || !r2.Duplicate || len(h.apns.requests()) != before+1 {
		t.Fatalf("idempotency: %+v %+v sends=%d", r1, r2, len(h.apns.requests())-before)
	}
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 503, "ServiceUnavailable" })
	it2 := alertItem("idem-2", d)
	_ = i.push1(it2)
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 200, "" })
	if res := i.push1(it2); res.Result != "accepted" || res.Duplicate {
		t.Fatalf("transient failure was cached: %+v", res)
	}
	// Duplicate refs inside one batch are refused.
	_, res := i.push(alertItem("dup", d), alertItem("dup", d))
	if res[1].Error != "invalid_item" {
		t.Fatalf("duplicate ref in batch: %+v", res)
	}
}

// TestLiveActivityEnd: the activity token reaches the relay only with the end, needs the
// device's activity statement, and its failure never touches the device binding.
func TestLiveActivityEnd(t *testing.T) {
	h := newHarness(t)
	i, other := h.register(), h.register()
	d := newDevice(16)
	i.activate(d)
	la := bytes.Repeat([]byte{0x2e}, 32)
	now := h.clk.Now().Unix()
	if res := i.push1(d.activity("la1", i.id, la, now-3600)); res.Result != "accepted" {
		t.Fatalf("end: %+v", res)
	}
	r := h.apns.requests()[len(h.apns.requests())-1]
	if r.Token != hex.EncodeToString(la) || r.Header.Get("apns-push-type") != "liveactivity" || r.Header.Get("apns-topic") != "dev.example.app.push-type.liveactivity" {
		t.Errorf("LA request: %s %v", r.Token, r.Header)
	}
	var p map[string]map[string]any
	_ = json.Unmarshal([]byte(r.Body), &p)
	cs, _ := p["aps"]["content-state"].(map[string]any)
	if p["aps"]["event"] != "end" || len(cs) != 6 || cs["status"] != "taken" {
		t.Errorf("LA payload: %s", r.Body)
	}
	_, forged, _ := ed25519.GenerateKey(rand.Reader)
	forger := &device{key: forged, token: d.token}
	if res := i.push1(forger.activity("la2", i.id, la, now)); res.Error != "activity_refused" {
		t.Fatalf("forged statement: %+v", res)
	}
	if res := other.push1(d.activity("la3", other.id, la, now)); res.Error != "binding_unknown" {
		t.Fatalf("other instance: %+v", res)
	}
	if res := i.push1(d.activity("la4", i.id, la, now-13*3600)); res.Error != "activity_refused" {
		t.Fatalf("statement older than 12 h: %+v", res)
	}
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 410, "Unregistered" })
	if res := i.push1(d.activity("la5", i.id, la, now)); res.Result != "activity_gone" {
		t.Fatalf("LA unregistered: %+v", res)
	}
	if h.state(d) != store.StateActive {
		t.Fatal("an ended activity token removed the device binding")
	}
}

func TestEnvelopeFrameChecked(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(17)
	i.activate(d)
	it := alertItem("bad", d)
	e, _ := wire.DecodeB64(it.Envelope, 0)
	e[2] = 2 // silent class byte in an alert item
	it.Envelope = wire.EncodeB64(e)
	if res := i.push1(it); res.Status != 422 {
		t.Fatalf("class byte mismatch: %+v", res)
	}
	// Unknown fields refuse the whole request; there is no way to pass text to Apple.
	rp := i.do(http.MethodPost, "/v1/push", []byte(`{"items":[{"ref":"x","token":"`+d.hex()+`","env":"production","class":"alert","ttlSeconds":60,"alert":"Dose changed"}]}`))
	if rp.Status != 422 {
		t.Fatalf("unknown field: %d", rp.Status)
	}
}

func TestInvalidTokenBudget(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.Probation.NewBindingsDay = 1000 })
	h.r.breaker.minSends = 1 << 30 // isolate the budget from the breaker
	i := h.register()
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 410, "Unregistered" })
	// 21 invalid tokens over three days of the probation budget (20 per day, 10 provisional at once).
	n := 0
	for round := 0; n <= 20 && round < 5; round++ {
		for k := 0; k < 10 && n <= 20; k++ {
			d := newDevice(byte(150 + n))
			n++
			if rp := i.bind(d); rp.Status != 201 {
				t.Fatalf("bind %d: %d %s", n, rp.Status, rp.Raw)
			}
			i.push1(alertItem("inv"+strconv.Itoa(n), d))
		}
	}
	rp := i.bind(newDevice(240))
	if rp.Status != 429 || rp.str("error") != "binding_quota" {
		t.Fatalf("budget exceeded but binding accepted: %d %s", rp.Status, rp.Raw)
	}
}

func TestProviderTokenErrors(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(24)
	i.activate(d)
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 403, "ExpiredProviderToken" })
	if res := i.push1(alertItem("e1", d)); res.Error != "apns_unavailable" || h.tokens.refresh != 1 {
		t.Fatalf("expired provider token: %+v refresh=%d", res, h.tokens.refresh)
	}
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 403, "InvalidProviderToken" })
	i.push1(alertItem("e2", d))
	h.clk.Add(21 * time.Minute)
	h.tokens.renew(t, h.clk.Now())
	i.push1(alertItem("e3", d)) // rejected again with a newer token: stop sending
	if rp, _ := i.push(alertItem("e4", d)); rp.Status != 503 || rp.str("error") != "relay_misconfigured" {
		t.Fatalf("after second rejection: %d %s", rp.Status, rp.Raw)
	}
	if hz, _ := h.r.Health(); hz.Status != "down" {
		t.Fatalf("health: %+v", hz)
	}
	_ = h.r.BreakerCommand("reset-apns")
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 429, "TooManyProviderTokenUpdates" })
	i.push1(alertItem("e5", d))
	if rp, _ := i.push(alertItem("e6", d)); rp.Status != 503 || rp.str("error") != "apns_unavailable" {
		t.Fatalf("too many token updates: %d", rp.Status)
	}
}

func TestAppleDeviceThrottle(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(25)
	i.activate(d)
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 429, "TooManyRequests" })
	i.push1(alertItem("t1", d))
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 200, "" })
	if res := i.push1(alertItem("t2", d)); res.Error != "device_quota" || res.Scope != "device" {
		t.Fatalf("throttled device not paused: %+v", res)
	}
	if res := i.push1(silentItem("t3", d)); res.Result != "accepted" {
		t.Fatalf("other class paused too: %+v", res)
	}
}

// TestReceiptsDriveDeliveryHealth: receipts feed the delivery signal, but only from standard instances, never
// above what the relay itself accepted for them, and never into the health status.
func TestReceiptsDriveDeliveryHealth(t *testing.T) {
	h := newHarness(t)
	fresh := h.register() // probation: ignored
	if rp := fresh.do(http.MethodPost, "/v1/receipts", wire.ReceiptsBody{Accepted: 100000, Confirmed: 0}); rp.Status != 204 {
		t.Fatal(rp.Status)
	}
	if hz, _ := h.r.Health(); hz.Delivery != "unknown" {
		t.Fatalf("a probation instance moved the delivery signal: %+v", hz)
	}
	var std []*instance
	for n := range 3 {
		in := h.registerStandard()
		for k := range 8 {
			in.activate(newDevice(byte(0x40 + n*8 + k)))
		}
		std = append(std, in)
	}
	for _, in := range std {
		if rp := in.do(http.MethodPost, "/v1/receipts", wire.ReceiptsBody{Accepted: 100000, Confirmed: 4}); rp.Status != 204 {
			t.Fatal(rp.Status)
		}
	}
	hz, ok := h.r.Health()
	if hz.Delivery != "degraded" || hz.Status != "ok" || !ok {
		t.Fatalf("health: %+v", hz)
	}
	h.r.mu.Lock()
	var acc int64
	for _, s := range h.r.receipts {
		acc += s.accepted
	}
	h.r.mu.Unlock()
	if acc != 24 {
		t.Fatalf("reported accepted not capped by the relay's own count: %d", acc)
	}
	if rp := std[0].do(http.MethodPost, "/v1/receipts", wire.ReceiptsBody{Accepted: 1, Confirmed: 1}); rp.Status != 429 {
		t.Fatal("receipts more often than every 45 minutes")
	}
	h.clk.Add(46 * time.Minute)
	if rp := std[0].do(http.MethodPost, "/v1/receipts", wire.ReceiptsBody{Accepted: 1, Confirmed: 1}); rp.Status != 204 {
		t.Fatal("receipts after 46 minutes refused")
	}
}

func TestStorageFailureKeepsSending(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(26)
	i.activate(d)
	_ = h.st.Close()
	if res := i.push1(alertItem("ro", d)); res.Result != "accepted" {
		t.Fatalf("send with a dead store: %+v", res)
	}
	h.r.Tick()
	if rp := i.bind(newDevice(27)); rp.Status != 503 || rp.str("error") != "storage_unavailable" {
		t.Fatalf("bind with a dead store: %d %s", rp.Status, rp.Raw)
	}
	if hz, _ := h.r.Health(); hz.DBWritable {
		t.Fatal("health still reports a writable store")
	}
}

// TestFlushIsOneTransaction: the minute tick writes once, however many instances exist.
func TestFlushIsOneTransaction(t *testing.T) {
	h := newHarness(t)
	for range 100 {
		h.register()
	}
	h.r.Tick()
	before := h.st.Writes()
	h.r.Tick()
	if w := h.st.Writes() - before; w > 1 {
		t.Fatalf("tick with 100 idle instances wrote %d transactions", w)
	}
	i := h.register()
	d := newDevice(9)
	i.activate(d)
	before = h.st.Writes()
	h.r.Tick()
	if w := h.st.Writes() - before; w != 1 {
		t.Fatalf("tick after traffic wrote %d transactions, want 1", w)
	}
}

// TestOldProviderRejectionForgotten: one InvalidProviderToken, then days of accepted pushes with renewed
// tokens, then another single rejection: that is not "the renewed token was rejected too" and must not stop
// the relay.
func TestOldProviderRejectionForgotten(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0x24)
	i.activate(d)
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 403, "InvalidProviderToken" })
	i.push1(alertItem("r1", d))
	h.clk.Add(30 * time.Minute)
	h.tokens.renew(t, h.clk.Now())
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 200, "" })
	if res := i.push1(alertItem("ok", d)); res.Result != "accepted" {
		t.Fatal(res)
	}
	h.clk.Add(5 * 24 * time.Hour)
	h.tokens.renew(t, h.clk.Now())
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 403, "InvalidProviderToken" })
	i.push1(alertItem("r2", d))
	if hz, _ := h.r.Health(); hz.Status != "ok" {
		t.Fatalf("an old rejection plus a new one stopped the relay: %+v", hz)
	}
}
