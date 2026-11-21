package relay

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// TestBreakerProtectsBindings: a wrong topic answered with DeviceTokenNotForTopic for
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
	// The breaker is shown, but it never turns the health status or the deploy gate.
	if hz, ok := h.r.Health(); hz.Status != "ok" || !ok || hz.Breaker != BreakerOpen {
		t.Fatalf("health: %+v", hz)
	}
	// Cool-down (a day, so the bindings marked before it opened may take their daily probe), then Apple
	// accepts again: half-open, then closed.
	h.clk.Add(24 * time.Hour)
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

// TestInventedTokensCannotOpenTheBreaker: free instances pushing to tokens
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

// TestBreakerStillOpensOnRealMisconfiguration: established bindings of three instances failing
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
