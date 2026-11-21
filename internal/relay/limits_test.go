package relay

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

func TestDeviceDayCapAllClasses(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.Device.AllDay = 5 })
	i := h.register()
	d := newDevice(0x81)
	i.activate(d)
	n := 1
	for ; n < 10; n++ {
		if res := i.push1(alertItem("d"+strconv.Itoa(n), d)); res.Status == 429 {
			if res.Error != "device_quota" || res.Scope != "device" {
				t.Fatal(res)
			}
			break
		}
	}
	if n != 5 {
		t.Fatalf("device day cap allowed %d, want 5", n)
	}
}

func TestAlertDayCapSurvivesRestart(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.Device.AlertDay = 3 })
	i := h.register()
	d := newDevice(0x82)
	i.activate(d)
	i.push1(alertItem("a1", d))
	i.push1(alertItem("a2", d))
	if res := i.push1(alertItem("a3", d)); res.Error != "device_quota" {
		t.Fatalf("alert day cap: %+v", res)
	}
	// alerts_today is written to the binding, so a restart does not hand out fresh alerts.
	h.r.Tick()
	b, _ := h.st.Bindings()
	for _, bd := range b {
		if bd.AlertsToday != 3 {
			t.Fatalf("persisted alerts_today %d", bd.AlertsToday)
		}
	}
}

func TestLiveActivityEndsPerDay(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0x83)
	i.activate(d)
	la := bytes.Repeat([]byte{0x2f}, 32)
	n := 0
	for ; n < 10; n++ {
		if res := i.push1(d.activity("la"+strconv.Itoa(n), i.id, la, h.clk.Now().Unix())); res.Status == 429 {
			break
		}
	}
	if n != 6 { // 12 per day, halved until midnight after a start
		t.Fatalf("LA ends allowed %d, want 6", n)
	}
}

func TestBindingQuotas(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Limits.Probation.Provisional = 2
		c.Limits.Probation.Devices = 3
		c.Limits.Probation.NewBindingsDay = 5
	})
	i := h.register()
	if i.bind(newDevice(0x90)).Status != 201 || i.bind(newDevice(0x91)).Status != 201 {
		t.Fatal("first two")
	}
	if rp := i.bind(newDevice(0x92)); rp.Status != 429 || rp.str("error") != "binding_quota" {
		t.Fatalf("provisional cap: %d %s", rp.Status, rp.Raw)
	}
	// Activate both, then the active device limit applies.
	i.push1(alertItem("q1", newDevice(0x90)))
	i.push1(alertItem("q2", newDevice(0x91)))
	if i.bind(newDevice(0x93)).Status != 201 {
		t.Fatal("third")
	}
	i.push1(alertItem("q3", newDevice(0x93)))
	if rp := i.bind(newDevice(0x94)); rp.Status != 429 {
		t.Fatalf("active device limit: %d", rp.Status)
	}
	h2 := newHarness(t, func(c *Config) { c.Limits.Probation.NewBindingsDay = 2 })
	j := h2.register()
	j.bind(newDevice(1))
	j.bind(newDevice(2))
	if rp := j.bind(newDevice(3)); rp.Status != 429 {
		t.Fatalf("new bindings per day: %d", rp.Status)
	}
}

func TestProvisionalNeedsRoomBelowDeviceLimit(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.Probation.Devices = 1; c.Limits.Probation.Provisional = 5 })
	i := h.register()
	a, b := newDevice(0xa1), newDevice(0xa2)
	i.bind(a)
	i.bind(b)
	i.push1(alertItem("p1", a))
	if res := i.push1(alertItem("p2", b)); res.Error != "binding_quota" {
		t.Fatalf("provisional pushed beyond the device limit: %+v", res)
	}
}

func TestProbationPoolIsSeparate(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.ProbationPoolMin = 3 })
	i := h.register()
	var refused ItemResult
	for n := range 6 {
		d := newDevice(byte(0xb0 + n))
		i.bind(d)
		if res := i.push1(alertItem("pp"+strconv.Itoa(n), d)); res.Status == 429 {
			refused = res
			break
		}
	}
	if refused.Error != "global" || refused.Scope != "tier" {
		t.Fatalf("probation pool: %+v", refused)
	}
}

func TestSilentPausedOnAppleThrottling(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	var devs []*device
	for n := range 60 {
		d := newDevice(byte(n + 1))
		devs = append(devs, d)
	}
	h.r.mu.Lock()
	for _, d := range devs[:50] {
		h.r.countApple429Locked(h.clk.Now(), false)
		_ = d
	}
	for range 2 {
		h.r.countApple429Locked(h.clk.Now(), true)
	}
	h.r.mu.Unlock()
	d := newDevice(0xee)
	i.activate(d)
	if res := i.push1(silentItem("sp", d)); res.Error != "global" || res.Scope != "global" {
		t.Fatalf("silent not paused after >2%% Apple 429: %+v", res)
	}
	if res := i.push1(alertItem("ap", d)); res.Result != "accepted" {
		t.Fatalf("alerts must continue: %+v", res)
	}
}

func TestRequestLevelRefusals(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MinClient = [3]int{1, 49, 0} })
	i := h.register()
	if rp := i.do(http.MethodGet, "/v1/status", nil); rp.Status != 426 || rp.str("error") != "min_server_version" {
		t.Fatalf("no client header: %d", rp.Status)
	}
	h2 := newHarness(t)
	j := h2.register()
	d := newDevice(0xc1)
	var items []wire.PushItem
	for n := range 51 {
		items = append(items, alertItem("m"+strconv.Itoa(n), d))
	}
	if rp, _ := j.push(items...); rp.Status != 413 || rp.str("error") != "too_many_items" {
		t.Fatalf("51 items: %d", rp.Status)
	}
	big := []byte(`{"token":"` + strings.Repeat("a", 5000) + `"}`)
	if rp := j.do(http.MethodPost, "/v1/bindings", big); rp.Status != 413 {
		t.Fatalf("body over 4 KB: %d", rp.Status)
	}
	if rp := j.do(http.MethodGet, "/v1/status", nil); rp.Status != 200 {
		t.Fatal("instance unusable after refusals")
	}
	_ = time.Second
}

// TestDeviceLimitRaisedAfterQuietMonth: 50 becomes 80 by itself after 30 quiet days above 80 %.
func TestDeviceLimitRaisedAfterQuietMonth(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits.Standard.Devices = 5; c.Limits.StandardDevicesUp = 8 })
	i := h.registerStandard()
	for n := range 5 {
		i.activate(newDevice(byte(0xd0 + n)))
	}
	h.clk.Add(29 * 24 * time.Hour)
	h.r.Daily()
	if info, _ := h.r.Instance(i.id); info.DeviceLimit != 5 {
		t.Fatalf("raised before 30 days: %d", info.DeviceLimit)
	}
	h.clk.Add(2 * 24 * time.Hour)
	h.r.Daily()
	if info, _ := h.r.Instance(i.id); info.DeviceLimit != 8 {
		t.Fatalf("not raised after 30 quiet days: %d", info.DeviceLimit)
	}
}

// TestFlagSurvivesMidnightAndRestart: an instance flagged late on day 7 is not promoted by the daily run
// shortly after midnight, even after a restart in between.
func TestFlagSurvivesMidnightAndRestart(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(0x91)
	a.activate(d)
	b.activate(newDevice(0x92))
	h.clk.Add(7*24*time.Hour - 10*time.Hour - time.Minute) // day 7, 23:59
	if rp := b.bind(newDevice(0x91)); rp.Status != 409 {   // conflict: flags b
		t.Fatalf("conflict: %d", rp.Status)
	}
	h.r.Tick()
	h.clk.Add(2 * time.Minute)
	b.do(http.MethodGet, "/v1/status", nil) // first request of the new day
	h.r.Daily()
	if info, _ := h.r.Instance(b.id); info.Tier != store.TierProbation {
		t.Fatal("flagged instance promoted after midnight")
	}
	if info, _ := h.r.Instance(a.id); info.Tier != store.TierStandard {
		t.Fatal("unflagged instance not promoted")
	}
}
