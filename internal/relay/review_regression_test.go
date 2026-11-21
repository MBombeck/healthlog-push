package relay

// Regression tests for the pre-launch security review. Each one fails on the code before its fix.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// TestInventedTokensCannotOpenTheBreaker (K1, ported from the review): free instances pushing to tokens
// they invented must neither open the breaker for everybody nor keep pushing to their soft-invalid bindings.
// Three attacking instances are used, so the three-instance rule alone does not carry the test.
func TestInventedTokensCannotOpenTheBreaker(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits = DefaultLimits; c.Limits.Probation.InvalidTokensDay = 5 })
	victim := h.register()
	vd := newDevice(1)
	victim.activate(vd)
	attacker := h.register()
	helpers := []*instance{h.register(), h.register()}
	h.apns.setAnswer(func(tok string, _ apnsReq) (int, string) {
		if strings.HasPrefix(tok, "01") {
			return 200, ""
		}
		return 400, "BadDeviceToken"
	})
	var devs []*device
	for n := range 10 {
		d := newDevice(byte(100 + n))
		if rp := attacker.bind(d); rp.Status != 201 {
			t.Fatalf("bind %d: %d", n, rp.Status)
		}
		devs = append(devs, d)
	}
	helperDevs := map[*instance][]*device{}
	for k, hi := range helpers {
		for n := range 10 {
			d := newDevice(byte(150 + k*10 + n))
			hi.bind(d)
			helperDevs[hi] = append(helperDevs[hi], d)
		}
	}
	for c := range 8 {
		h.clk.Add(61 * time.Second)
		var items []wire.PushItem
		for n, d := range devs {
			items = append(items, alertItem("a"+strconv.Itoa(c)+"-"+strconv.Itoa(n), d))
		}
		attacker.push(items...)
		for hi, ds := range helperDevs {
			var hitems []wire.PushItem
			for n, d := range ds {
				hitems = append(hitems, alertItem("h"+strconv.Itoa(c)+"-"+strconv.Itoa(n), d))
			}
			hi.push(hitems...)
		}
		if s := h.r.Stats().Breaker; s != BreakerClosed {
			t.Fatalf("round %d: invented tokens moved the breaker to %s", c, s)
		}
		if res := victim.push1(alertItem("v"+strconv.Itoa(c), vd)); res.Result != "accepted" {
			t.Fatalf("round %d: victim push %+v", c, res)
		}
	}
	// The flood shows up in the operator's overview, worst first.
	sus := h.r.Suspects(10)
	listed := map[string]bool{}
	for _, s := range sus {
		if s.InvalidToday == 0 {
			t.Fatalf("suspect without invalid tokens: %+v", s)
		}
		listed[s.ID] = true
	}
	if len(sus) != 3 || !listed[attacker.id] || !listed[helpers[0].id] || !listed[helpers[1].id] {
		t.Fatalf("suspects: %+v", sus)
	}
	for _, s := range sus {
		if s.ID == victim.id {
			t.Fatal("victim listed as suspect")
		}
	}
	// Over the invalid-token budget no binding of the attacker that is not active receives pushes, even on
	// the next day when a soft-invalid binding would otherwise get its daily probe.
	h.clk.Add(14 * time.Hour)
	_, res := attacker.push(alertItem("late", devs[0]))
	if res[0].Error != "binding_quota" || res[0].Scope != "instance" {
		t.Fatalf("push to a soft-invalid binding after the flood: %+v", res[0])
	}
}

// TestBreakerStillOpensOnRealMisconfiguration (K1): established bindings of three instances failing
// together still open the breaker, which is what it is for.
func TestBreakerStillOpensOnRealMisconfiguration(t *testing.T) {
	h := newHarness(t)
	insts := []*instance{h.register(), h.register(), h.register()}
	var devs []*device
	for n := range 24 {
		d := newDevice(byte(0x60 + n))
		insts[n%3].activate(d)
		devs = append(devs, d)
	}
	h.apns.setAnswer(func(string, apnsReq) (int, string) { return 400, "DeviceTokenNotForTopic" })
	for n, d := range devs {
		insts[n%3].push(alertItem("m"+strconv.Itoa(n), d))
	}
	if s := h.r.Stats().Breaker; s != BreakerOpen {
		t.Fatalf("a wrong topic for everybody did not open the breaker: %s", s)
	}
}

// TestHeadersCheckedBeforeBody (H2): an unknown instance is refused from the headers alone, while the body
// is still being sent; a missing or oversized declared length is refused without reading.
func TestHeadersCheckedBeforeBody(t *testing.T) {
	h := newHarness(t)
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.srv.URL+"/v1/push", pr)
	req.ContentLength = maxPushBody - 1
	req.Header.Set("HL-Instance", "00000000-0000-4000-8000-000000000000")
	req.Header.Set("HL-Nonce", randNonce())
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("no answer while the body is pending: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown instance with a pending body: %d", resp.StatusCode)
	}
	i := h.register()
	for name, c := range map[string]struct {
		n    int64
		want int
	}{"undeclared": {-1, http.StatusLengthRequired}, "too large": {maxPushBody + 1, http.StatusRequestEntityTooLarge}} {
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/push", io.NopCloser(strings.NewReader("{}")))
		req.ContentLength = c.n
		req.Header.Set("HL-Instance", i.id)
		if rp := h.send(req, ""); rp.Status != c.want {
			t.Errorf("%s: %d, want %d", name, rp.Status, c.want)
		}
	}
}

// TestBufferedBodyBudget (H2): once the bytes reserved for bodies in flight reach the cap, further bodies are
// refused with 503 instead of being buffered.
func TestBufferedBodyBudget(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	h.r.bodyBytes.Store(maxBufferedBodies - 10)
	rp := i.do(http.MethodPost, "/v1/receipts", wire.ReceiptsBody{Accepted: 1, Confirmed: 1})
	if rp.Status != http.StatusServiceUnavailable || rp.str("error") != "overloaded" {
		t.Fatalf("over the body budget: %d %s", rp.Status, rp.Raw)
	}
	h.r.bodyBytes.Store(0)
	if rp := i.do(http.MethodPost, "/v1/receipts", wire.ReceiptsBody{Accepted: 1, Confirmed: 1}); rp.Status != http.StatusNoContent {
		t.Fatalf("after release: %d", rp.Status)
	}
	if n := h.r.bodyBytes.Load(); n != 0 {
		t.Fatalf("reservation leaked: %d", n)
	}
}

// TestJunkCannotStarveOptOut (H5, ported from the review): unauthenticated junk on the app endpoints does
// not stop a correctly signed opt-out.
func TestJunkCannotStarveOptOut(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(5)
	i.activate(d)
	var last response
	for range 300 {
		req, _ := http.NewRequest(http.MethodDelete, h.srv.URL+"/v1/bindings/self", http.NoBody)
		last = h.send(req, "")
	}
	if last.Status != http.StatusTooManyRequests || last.str("scope") != "global" {
		t.Fatalf("failed app calls are not limited: %d %s", last.Status, last.Raw)
	}
	if rp := h.selfRead(d); rp.Status != 200 {
		t.Fatalf("self read after junk: %d %s", rp.Status, rp.Raw)
	}
	if rp := h.unbindSelf(d, d.key, i.id); rp.Status != 204 {
		t.Fatalf("opt-out after junk: %d %s", rp.Status, rp.Raw)
	}
}

// TestAppEndpointsLimitedPerDevice (H5): verified app calls are limited per token, not globally.
func TestAppEndpointsLimitedPerDevice(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	a, b := newDevice(6), newDevice(7)
	i.activate(a)
	i.activate(b)
	var n int
	for n = 0; n < 20; n++ {
		if rp := h.selfRead(a); rp.Status == 429 {
			if rp.str("scope") != "device" {
				t.Fatalf("scope %s", rp.str("scope"))
			}
			break
		}
	}
	if n != 10 {
		t.Fatalf("self reads per device: %d, want 10", n)
	}
	if rp := h.selfRead(b); rp.Status != 200 {
		t.Fatal("another device limited by the first one")
	}
}

// TestFlushIsOneTransaction (M3): the minute tick writes once, however many instances exist.
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

// TestResponseSizeBounded (M5): the largest answer the relay gives, a full batch of errors, stays far below
// the 256 KiB a server is told to accept.
func TestResponseSizeBounded(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	var items []wire.PushItem
	for n := range wire.MaxPushItems {
		it := alertItem(strings.Repeat("r", 38)+strconv.Itoa(n%10)+strconv.Itoa(n/10), newDevice(byte(n)))
		items = append(items, it)
	}
	rp, res := i.push(items...)
	if rp.Status != 200 || len(res) != wire.MaxPushItems {
		t.Fatal(rp.Status)
	}
	if len(rp.Raw) > maxResponseBytes {
		t.Fatalf("response %d bytes, documented maximum %d", len(rp.Raw), maxResponseBytes)
	}
	var probe map[string]any
	if json.Unmarshal(rp.Raw, &probe) != nil || bytes.Contains(rp.Raw, []byte(items[0].Token)) {
		t.Fatal("response echoes tokens")
	}
}

// TestBindAfterInstanceDeletion (N2): a binding request that authenticated just before its instance was
// deleted leaves no orphan binding.
func TestBindAfterInstanceDeletion(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0x33)
	h.r.mu.Lock()
	s := h.r.instances[i.id]
	h.r.dropInstanceLocked(i.id)
	b, err := wire.ParseBind(mustJSON(d.bindBody(i.id, h.clk.Now().Unix())), host, i.id, h.clk.Now().Unix())
	if err != nil {
		h.r.mu.Unlock()
		t.Fatal(err)
	}
	status, _, e := h.r.bindLocked(s, b, h.clk.Now())
	h.r.mu.Unlock()
	if e == nil || status != http.StatusUnauthorized || h.state(d) != "" {
		t.Fatalf("orphan binding: %d %+v %q", status, e, h.state(d))
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// TestInviteKeptWhenLimitRefuses (N4): an invite is spent only by a registration that went through.
func TestInviteKeptWhenLimitRefuses(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Registrations = regLimits{PerNarrowDay: 1, PerWideDay: 10, GlobalHour: 30, GlobalDay: 200}
	})
	h.register() // uses the one registration this address has today
	_ = h.r.SetRegistration(RegInvite)
	code, _ := h.r.NewInvite()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	if rp := (&instance{h: h, key: k}).registerRaw(code); rp.Status != http.StatusServiceUnavailable {
		t.Fatalf("over the address limit: %d", rp.Status)
	}
	h.r.mu.Lock()
	ok := h.r.inviteValid(code, 0)
	h.r.mu.Unlock()
	if !ok {
		t.Fatal("invite spent by a refused registration")
	}
}

// TestNotFoundUnderV1NeedsNonce: an unknown /v1 path is also bound to a nonce, so even a 404 cannot be
// replayed onto another request.
func TestNotFoundUnderV1NeedsNonce(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/v1/nope", http.NoBody)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown /v1 path without nonce: %d", resp.StatusCode)
	}
	if out, _ := json.Marshal(h.r.Suspects(10)); string(out) != "[]" {
		t.Fatalf("suspects without rows: %s", out)
	}
}
