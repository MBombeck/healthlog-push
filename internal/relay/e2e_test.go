package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
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
	if sr.Status != 200 || sr.str("state") != "active" || sr.str("instanceId") != i.id || sr.str("consentVersion") != "2026-12-01" {
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

func TestResponseSignatureBindsNonce(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	nonce := randNonce()
	rp := i.doRaw(http.MethodGet, "/v1/status", nil, h.clk.Now().Unix(), nonce, nil)
	sig, _ := wire.ParseSignature(rp.Header.Get("HL-Relay-Signature"))
	if wire.Verify(h.relayP, wire.ResponseText(host, randNonce(), rp.Status, rp.Raw), sig) {
		t.Fatal("signature verifies for a different nonce")
	}
	if wire.Verify(h.relayP, wire.ResponseText(host, nonce, 410, rp.Raw), sig) {
		t.Fatal("signature verifies for a different status")
	}
	if wire.Verify(h.relayP, wire.ResponseText("other.example.org", nonce, rp.Status, rp.Raw), sig) {
		t.Fatal("signature verifies for a different host")
	}
}

func TestRequestSignatureScope(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	now := h.clk.Now().Unix()
	cases := map[string]func(string) string{
		"host":   func(s string) string { return strings.Replace(s, host, "relay.example.net", 1) },
		"method": func(s string) string { return strings.Replace(s, "\nGET\n", "\nPOST\n", 1) },
		"query":  func(s string) string { return strings.Replace(s, "/v1/status", "/v1/status?x=1", 1) },
		"body":   func(s string) string { return s[:len(s)-64] + wire.HexSHA256([]byte("{}")) },
		"time": func(s string) string {
			return strings.Replace(s, strconv.FormatInt(now, 10), strconv.FormatInt(now+1, 10), 1)
		},
	}
	for name, mut := range cases {
		if rp := i.doRaw(http.MethodGet, "/v1/status", nil, now, randNonce(), mut); rp.Status != 401 || rp.str("error") != "bad_signature" {
			t.Errorf("%s: %d %s", name, rp.Status, rp.Raw)
		}
	}
	if rp := i.doRaw(http.MethodGet, "/v1/status", nil, now, randNonce(), nil); rp.Status != 200 {
		t.Fatalf("valid: %d", rp.Status)
	}
}

func TestNonceReplayAndTimeWindow(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	now := h.clk.Now().Unix()
	n := randNonce()
	if rp := i.doRaw(http.MethodGet, "/v1/status", nil, now, n, nil); rp.Status != 200 {
		t.Fatal(rp.Status)
	}
	if rp := i.doRaw(http.MethodGet, "/v1/status", nil, now, n, nil); rp.Status != 401 || rp.str("error") != "replayed" {
		t.Fatalf("replay: %d %s", rp.Status, rp.Raw)
	}
	rp := i.doRaw(http.MethodGet, "/v1/status", nil, now+301, randNonce(), nil)
	if rp.Status != 401 || rp.str("error") != "stale_timestamp" || rp.Body["relayTime"] != float64(now) {
		t.Fatalf("future: %d %s", rp.Status, rp.Raw)
	}
	// Timestamps before the relay start are refused (the nonce cache does not survive a restart).
	if rp := i.doRaw(http.MethodGet, "/v1/status", nil, now-10, randNonce(), nil); rp.Status != 401 {
		t.Fatalf("before start: %d", rp.Status)
	}
}

func TestUnknownInstanceAndBadSignatureBudget(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	ghost := &instance{h: h, key: i.key, id: "00000000-0000-4000-8000-000000000000"}
	if rp := ghost.do(http.MethodGet, "/v1/status", nil); rp.Status != 401 || rp.str("error") != "unknown_instance" {
		t.Fatalf("unknown: %d %s", rp.Status, rp.Raw)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forger := &instance{h: h, key: other, id: i.id}
	var last response
	for range 40 {
		last = forger.do(http.MethodGet, "/v1/status", nil)
		if last.Status == 429 {
			break
		}
	}
	if last.Status != 429 || last.str("error") != "instance_rate" {
		t.Fatalf("bad signature budget not enforced: %d", last.Status)
	}
}

func TestRegistration(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Registrations = store0Limits() })
	a := h.register()
	// The same key again returns the same id (idempotent).
	if rp := a.registerRaw(""); rp.Status != 200 || rp.str("instanceId") != a.id {
		t.Fatalf("re-register: %d %s", rp.Status, rp.Raw)
	}
	h.register()
	h.register()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if rp := (&instance{h: h, key: key}).registerRaw(""); rp.Status != 503 || rp.str("error") != "registration_paused" {
		t.Fatalf("4th registration from one address: %d %s", rp.Status, rp.Raw)
	}
}

func store0Limits() (l limitsT) {
	return limitsT{PerNarrowDay: 3, PerWideDay: 10, GlobalHour: 30, GlobalDay: 200}
}

func TestRegistrationModes(t *testing.T) {
	h := newHarness(t)
	mk := func() *instance { _, k, _ := ed25519.GenerateKey(rand.Reader); return &instance{h: h, key: k} }
	if err := h.r.SetRegistration(RegClosed); err != nil {
		t.Fatal(err)
	}
	if rp := mk().registerRaw(""); rp.Status != 503 {
		t.Fatalf("closed: %d", rp.Status)
	}
	_ = h.r.SetRegistration(RegInvite)
	if rp := mk().registerRaw(""); rp.Status != 403 || rp.str("error") != "invite_required" {
		t.Fatalf("invite missing: %d", rp.Status)
	}
	code, _ := h.r.NewInvite()
	if rp := mk().registerRaw(code); rp.Status != 201 {
		t.Fatalf("invite: %d %s", rp.Status, rp.Raw)
	}
	if rp := mk().registerRaw(code); rp.Status != 403 {
		t.Fatalf("invite reused: %d", rp.Status)
	}
}

// TestBindingProofOfPossession covers H1, A1, B4: a binding needs the device key; an instance that only
// knows the token cannot take it over; an old statement cannot be replayed; the device can move.
func TestBindingProofOfPossession(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(2)
	a.activate(d)

	// B signs with its own key for the same token: a conflict, never a takeover.
	thief := newDevice(2)
	rp := b.bind(thief)
	if rp.Status != 409 || rp.str("error") != "binding_conflict" || rp.str("reason") != "challenge_sent" {
		t.Fatalf("conflict: %d %s", rp.Status, rp.Raw)
	}
	if h.bindingOwner(d) != a.id {
		t.Fatal("binding moved without proof")
	}
	// B replays A's statement: the instance id is signed, so it fails.
	stmt := d.bindBody(a.id, h.clk.Now().Unix())
	if rp := b.do(http.MethodPost, "/v1/bindings", stmt); rp.Status != 403 {
		t.Fatalf("replayed statement: %d %s", rp.Status, rp.Raw)
	}
	// Unsigned or wrongly signed statement.
	bad := d.bindBody(b.id, h.clk.Now().Unix())
	bad.Signature = wire.EncodeB64(make([]byte, 64))
	if rp := b.do(http.MethodPost, "/v1/bindings", bad); rp.Status != 403 {
		t.Fatalf("bad signature: %d", rp.Status)
	}
	// The device moves to B with a higher seq; A now gets binding_unknown.
	if rp := b.bind(d); rp.Status != 201 {
		t.Fatalf("move: %d %s", rp.Status, rp.Raw)
	}
	if res := a.push1(alertItem("after-move", d)); res.Status != 404 || res.Error != "binding_unknown" {
		t.Fatalf("old instance after move: %+v", res)
	}
	// An older statement (lower seq) is refused.
	d.seq -= 5
	if rp := a.bind(d); rp.Status != 403 {
		t.Fatalf("lower seq: %d", rp.Status)
	}
}

// TestUniformAnswers covers A7: an unknown token and a token bound elsewhere look the same.
func TestUniformAnswers(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(3)
	a.activate(d)
	r1 := b.push1(alertItem("x", d))
	r2 := b.push1(alertItem("y", newDevice(4)))
	if r1.Status != 404 || r2.Status != 404 || r1.Error != r2.Error || r1.Error != "binding_unknown" {
		t.Fatalf("not uniform: %+v %+v", r1, r2)
	}
	// Deleting a binding the instance does not hold answers the same as deleting one it does.
	if rp := b.do(http.MethodDelete, "/v1/bindings", map[string]string{"token": d.hex()}); rp.Status != 204 {
		t.Fatal(rp.Status)
	}
	if h.bindingOwner(d) != a.id {
		t.Fatal("foreign delete removed the binding")
	}
}

// TestChallengeFlow covers 1.5.3: the conflicting key wins only by answering the challenge push.
func TestChallengeFlow(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(5)
	a.activate(d)
	restored := newDevice(5) // same token, new key (restored app) registering with B
	if rp := b.bind(restored); rp.Status != 409 {
		t.Fatalf("conflict: %d", rp.Status)
	}
	time.Sleep(200 * time.Millisecond)
	var ch string
	for _, r := range h.apns.requests() {
		if strings.Contains(r.Body, `"c":"`) {
			if r.Header.Get("apns-push-type") != "background" {
				t.Errorf("challenge push type %s", r.Header.Get("apns-push-type"))
			}
			var p struct {
				C string `json:"c"`
			}
			_ = json.Unmarshal([]byte(r.Body), &p)
			ch = p.C
		}
	}
	if ch == "" {
		t.Fatal("no challenge push sent")
	}
	answer := func(key ed25519.PrivateKey) response {
		tag := wire.TokenTag(d.token)
		b, _ := json.Marshal(wire.ChallengeBody{BindingKey: wire.EncodeB64(ed25519.PublicKey(key[32:])), Challenge: ch,
			TokenTag: hex.EncodeToString(tag), Signature: wire.EncodeB64(ed25519.Sign(key, []byte(wire.ChallengeText(host, ch, tag))))})
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/bindings/challenge", bytes.NewReader(b))
		return h.send(req, "")
	}
	if rp := answer(d.key); rp.Status != 403 {
		t.Fatalf("answer with the old key: %d", rp.Status)
	}
	if rp := answer(restored.key); rp.Status != 200 {
		t.Fatalf("answer: %d %s", rp.Status, rp.Raw)
	}
	if h.bindingOwner(d) != b.id {
		t.Fatal("binding did not move after a valid answer")
	}
	if rp := answer(restored.key); rp.Status != 403 {
		t.Fatal("challenge usable twice")
	}
	// One challenge per token per day.
	other := newDevice(5)
	if rp := a.bind(other); rp.Status != 409 || rp.str("reason") != "challenge_quota" {
		t.Fatalf("second challenge same day: %d %s", rp.Status, rp.Raw)
	}
}

func TestConflictFallbackAfterSevenQuietDays(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(6)
	a.activate(d)
	h.clk.Add(8 * 24 * time.Hour)
	if rp := b.bind(newDevice(6)); rp.Status != 201 {
		t.Fatalf("after 8 quiet days: %d %s", rp.Status, rp.Raw)
	}
	if h.bindingOwner(d) != b.id {
		t.Fatal("fallback did not move the binding")
	}
}

// TestDirectOptOut covers A2 and the ex-partner case: only the device key can opt out, it works without
// the instance, and the pair stays blocked.
func TestDirectOptOut(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(7)
	a.activate(d)
	if rp := h.unbindSelf(d, a.key, a.id); rp.Status != 404 {
		t.Fatalf("opt-out with the instance key: %d", rp.Status)
	}
	if rp := h.unbindSelf(d, d.key, b.id); rp.Status != 404 {
		t.Fatalf("opt-out naming another instance: %d", rp.Status)
	}
	if rp := h.unbindSelf(d, d.key, a.id); rp.Status != 204 {
		t.Fatalf("opt-out: %d %s", rp.Status, rp.Raw)
	}
	if h.state(d) != "" {
		t.Fatal("binding still present")
	}
	if rp := a.bind(d); rp.Status != 403 || rp.str("error") != "binding_refused" {
		t.Fatalf("blocked pair rebind: %d %s", rp.Status, rp.Raw)
	}
	if rp := b.bind(d); rp.Status != 201 {
		t.Fatalf("another instance after opt-out: %d", rp.Status)
	}
	if sr := h.selfRead(newDevice(99)); sr.Status != 404 {
		t.Fatalf("self read of an unknown token: %d", sr.Status)
	}
}

// TestUnregisteredIsTheOnlyFinalDeletion covers F1 (abuse) and 4.4.
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
	if res := i.push1(alertItem("s2", soft)); res.Result != "soft_invalid" || h.state(soft) != store.StateSoftInvalid {
		t.Fatalf("second soft hit on the same day deleted or changed: %+v %s", res, h.state(soft))
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

// TestBreakerProtectsBindings covers F1 (abuse): a wrong topic answered with DeviceTokenNotForTopic for
// everyone must not wipe the bindings, and the breaker closes again only on Apple's acceptance.
func TestBreakerProtectsBindings(t *testing.T) {
	h := newHarness(t)
	insts := []*instance{h.register(), h.register(), h.register()}
	var devs []*device
	for n := range 30 {
		d := newDevice(byte(40 + n))
		insts[n%3].activate(d)
		devs = append(devs, d)
	}
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 400, "DeviceTokenNotForTopic" })
	var opened bool
	for n, d := range devs {
		_, res := insts[n%3].push(alertItem("b"+strconv.Itoa(n), d))
		if len(res) == 1 && res[0].Error == "relay_misconfigured" {
			opened = true
		}
		rp, _ := insts[n%3].push(alertItem("c"+strconv.Itoa(n), d))
		if rp.Status == 503 {
			opened = true
		}
	}
	if !opened || h.r.Stats().Breaker != BreakerOpen {
		t.Fatalf("breaker did not open: %s", h.r.Stats().Breaker)
	}
	h.r.mu.Lock()
	n := len(h.r.bindings)
	h.r.mu.Unlock()
	if n != 30 {
		t.Fatalf("bindings deleted while the topic was wrong: %d left", n)
	}
	if rp, _ := insts[0].push(alertItem("while-open", devs[0])); rp.Status != 503 || rp.str("error") != "relay_misconfigured" {
		t.Fatalf("open breaker answer: %d %s", rp.Status, rp.Raw)
	}
	if hz, _ := h.r.Health(); hz.Status != "degraded" || hz.Breaker != BreakerOpen {
		t.Fatalf("health: %+v", hz)
	}
	// Cool-down, then Apple accepts again: half-open, then closed.
	h.clk.Add(11 * time.Minute)
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 200, "" })
	for k, d := range devs[:25] {
		insts[k%3].push1(alertItem("h"+strconv.Itoa(k), d))
	}
	if s := h.r.Stats().Breaker; s != BreakerClosed {
		t.Fatalf("breaker did not close after acceptance: %s", s)
	}
}

func TestBreakerHalfOpenDoesNotDelete(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(9)
	i.activate(d)
	_ = h.r.BreakerCommand("open")
	h.clk.Add(11 * time.Minute)
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 410, "Unregistered" })
	res := i.push1(alertItem("ho", d))
	if res.Error != "relay_misconfigured" || h.state(d) == "" {
		t.Fatalf("half-open deleted a binding: %+v", res)
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

// TestIdempotency covers F3: a retry with the same ref returns the first result without a second send,
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

func activityItem(ref string, d *device, instID string, la []byte, signer ed25519.PrivateKey, iat int64) wire.PushItem {
	tag, laTag := wire.TokenTag(d.token), wire.TokenTag(la)
	a := &wire.Activity{Token: hex.EncodeToString(la), BindingKey: wire.EncodeB64(ed25519.PublicKey(signer[32:])),
		Signature: wire.EncodeB64(ed25519.Sign(signer, []byte(wire.ActivityText(host, instID, tag, laTag, iat))))}
	a.Statement.InstanceID, a.Statement.TokenTag, a.Statement.LATokenTag, a.Statement.Iat = instID, hex.EncodeToString(tag), hex.EncodeToString(laTag), iat
	return wire.PushItem{Ref: ref, Token: d.hex(), Env: "production", Class: wire.ClassLiveActivity, TTLSeconds: 3600, Activity: a}
}

// TestLiveActivityEnd covers 3.3, B2, L1: the activity token reaches the relay only with the end, needs the
// device's activity statement, and its failure never touches the device binding.
func TestLiveActivityEnd(t *testing.T) {
	h := newHarness(t)
	i, other := h.register(), h.register()
	d := newDevice(16)
	i.activate(d)
	la := bytes.Repeat([]byte{0x2e}, 32)
	now := h.clk.Now().Unix()
	if res := i.push1(activityItem("la1", d, i.id, la, d.key, now-3600)); res.Result != "accepted" {
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
	if res := i.push1(activityItem("la2", d, i.id, la, forged, now)); res.Error != "activity_refused" {
		t.Fatalf("forged statement: %+v", res)
	}
	if res := other.push1(activityItem("la3", d, other.id, la, d.key, now)); res.Error != "binding_unknown" {
		t.Fatalf("other instance: %+v", res)
	}
	if res := i.push1(activityItem("la4", d, i.id, la, d.key, now-13*3600)); res.Error != "activity_refused" {
		t.Fatalf("statement older than 12 h: %+v", res)
	}
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 410, "Unregistered" })
	if res := i.push1(activityItem("la5", d, i.id, la, d.key, now)); res.Result != "activity_gone" {
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

func TestProvisionalAndInstanceRetention(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	quiet := h.register() // never delivers
	d := newDevice(18)
	if rp := i.bind(d); rp.Status != 201 {
		t.Fatal(rp.Status)
	}
	h.clk.Add(3*24*time.Hour + time.Hour)
	h.r.Daily()
	if h.state(d) != "" {
		t.Fatal("provisional binding older than 48 h kept")
	}
	if _, err := h.r.Instance(quiet.id); err == nil {
		t.Fatal("instance without a delivery kept after 48 h")
	}
}

func TestPromotionAfterSevenDays(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(19)
	i.activate(d)
	h.clk.Add(6 * 24 * time.Hour)
	h.r.Daily()
	if info, _ := h.r.Instance(i.id); info.Tier != store.TierProbation {
		t.Fatal("promoted before 7 days")
	}
	h.clk.Add(24 * time.Hour)
	i.push1(alertItem("keepalive", d))
	h.r.Daily()
	if info, _ := h.r.Instance(i.id); info.Tier != store.TierStandard || info.DeviceLimit != 50 {
		t.Fatalf("not promoted: %+v", info)
	}
}

func TestInvalidTokenBudget(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.Probation.NewBindingsDay = 1000 })
	h.r.breaker.MinSends = 1 << 30 // isolate the budget from the breaker
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

func TestPauseNoticeSuspendRevoke(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(20)
	i.activate(d)
	_ = h.r.SetPause("silent", "all", 30*time.Minute)
	if res := i.push1(silentItem("ps", d)); res.Error != "maintenance" {
		t.Fatalf("paused silent: %+v", res)
	}
	if res := i.push1(alertItem("pa", d)); res.Result != "accepted" {
		t.Fatalf("alert during silent pause: %+v", res)
	}
	h.clk.Add(31 * time.Minute)
	if res := i.push1(silentItem("ps2", d)); res.Result != "accepted" {
		t.Fatalf("pause did not expire: %+v", res)
	}
	_ = h.r.SetNotice("planned_maintenance", "planned", time.Hour)
	if st := i.do(http.MethodGet, "/v1/status", nil); !strings.Contains(string(st.Raw), `"planned_maintenance"`) {
		t.Fatalf("notice missing: %s", st.Raw)
	}
	_ = h.r.Suspend(i.id, "abuse")
	if rp := i.do(http.MethodGet, "/v1/status", nil); rp.Status != 403 || rp.str("reason") != "abuse" {
		t.Fatalf("suspended: %d %s", rp.Status, rp.Raw)
	}
	if h.state(d) == "" {
		t.Fatal("suspension removed bindings")
	}
	_ = h.r.Revoke(i.id, "abuse")
	if h.state(d) != "" {
		t.Fatal("revoke kept bindings")
	}
	if rp := i.registerRaw(""); rp.Status != 403 || rp.str("error") != "instance_revoked" {
		t.Fatalf("revoked key re-registered: %d", rp.Status)
	}
}

func TestBlockToken(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(21)
	a.activate(d)
	if err := h.r.BlockToken(d.hex(), "", false); err != nil {
		t.Fatal(err)
	}
	if res := a.push1(alertItem("holder", d)); res.Result != "accepted" {
		t.Fatalf("current holder blocked: %+v", res)
	}
	_ = h.unbindSelf(d, d.key, a.id)
	if rp := b.bind(d); rp.Status != 403 {
		t.Fatalf("blocked token bound by another instance: %d", rp.Status)
	}
}

func TestRotateAndDelete(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	_, nk, _ := ed25519.GenerateKey(rand.Reader)
	pub := ed25519.PublicKey(nk[32:])
	ts := h.clk.Now().Unix()
	body := wire.RegisterBody{PublicKey: wire.EncodeB64(pub), Time: ts, Proof: wire.EncodeB64(ed25519.Sign(nk, []byte(wire.RegisterText(host, pub, ts))))}
	if rp := i.do(http.MethodPost, "/v1/instances/self/rotate", body); rp.Status != 200 {
		t.Fatalf("rotate: %d %s", rp.Status, rp.Raw)
	}
	if rp := i.do(http.MethodGet, "/v1/status", nil); rp.Status != 401 {
		t.Fatal("old key still accepted")
	}
	i.key = nk
	if rp := i.do(http.MethodGet, "/v1/status", nil); rp.Status != 200 || rp.str("keyRotatedDay") == "" {
		t.Fatalf("new key: %d %s", rp.Status, rp.Raw)
	}
	_, k3, _ := ed25519.GenerateKey(rand.Reader)
	p3 := ed25519.PublicKey(k3[32:])
	b3 := wire.RegisterBody{PublicKey: wire.EncodeB64(p3), Time: ts, Proof: wire.EncodeB64(ed25519.Sign(k3, []byte(wire.RegisterText(host, p3, ts))))}
	if rp := i.do(http.MethodPost, "/v1/instances/self/rotate", b3); rp.Status != 429 {
		t.Fatalf("second rotation same day: %d", rp.Status)
	}
	d := newDevice(22)
	i.bind(d)
	if rp := i.do(http.MethodDelete, "/v1/instances/self", nil); rp.Status != 204 {
		t.Fatal(rp.Status)
	}
	if h.state(d) != "" {
		t.Fatal("instance delete kept bindings")
	}
}

func TestSandboxRefusedWhenNotServed(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(23)
	bb := d.bindBody(i.id, h.clk.Now().Unix())
	bb.Env = "sandbox"
	if rp := i.do(http.MethodPost, "/v1/bindings", bb); rp.Status != 422 || rp.str("error") != "env_unsupported" {
		t.Fatalf("sandbox: %d %s", rp.Status, rp.Raw)
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

func TestReceiptsDriveDeliveryHealth(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	if rp := i.do(http.MethodPost, "/v1/receipts", wire.ReceiptsBody{Accepted: 100, Confirmed: 40}); rp.Status != 204 {
		t.Fatal(rp.Status)
	}
	if hz, _ := h.r.Health(); hz.Delivery != "unknown" || hz.Status != "ok" {
		t.Fatalf("a single instance turned the health red: %+v", hz)
	}
	for range 2 {
		h.register().do(http.MethodPost, "/v1/receipts", wire.ReceiptsBody{Accepted: 10, Confirmed: 4})
	}
	if hz, _ := h.r.Health(); hz.Delivery != "degraded" || hz.Status != "degraded" {
		t.Fatalf("health: %+v", hz)
	}
	if rp := i.do(http.MethodPost, "/v1/receipts", wire.ReceiptsBody{Accepted: 1, Confirmed: 1}); rp.Status != 429 {
		t.Fatal("receipts more than once per hour")
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

type limitsT = regLimits
