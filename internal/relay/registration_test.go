package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/store"
)

func TestRegistration(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Registrations = limits.DefaultRegistrationLimits })
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

func TestRotateAndDelete(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	_, nk, _ := ed25519.GenerateKey(rand.Reader)
	if rp := i.rotate(nk); rp.Status != 200 {
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
	if rp := i.rotate(k3); rp.Status != 429 {
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

// TestInviteKeptWhenLimitRefuses: an invite is spent only by a registration that went through.
func TestInviteKeptWhenLimitRefuses(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Registrations = limits.RegistrationLimits{PerNarrowDay: 1, PerWideDay: 10, GlobalHour: 30, GlobalDay: 200}
	})
	h.register() // uses the one registration this address has today
	_ = h.r.SetRegistration(RegInvite)
	code, _ := h.r.NewInvite()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	if rp := (&instance{h: h, key: k}).registerRaw(code); rp.Status != http.StatusServiceUnavailable {
		t.Fatalf("over the address limit: %d", rp.Status)
	}
	h.r.mu.Lock()
	ok := h.r.inviteIndex(code, 0) >= 0
	h.r.mu.Unlock()
	if !ok {
		t.Fatal("invite spent by a refused registration")
	}
}
