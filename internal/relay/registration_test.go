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

// A new store refuses registration before any admin command: without a configured mode it starts in
// invite, and the mode is stored before the first request can arrive.
func TestFreshStoreRefusesRegistration(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Registration = "" })
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	if rp := (&instance{h: h, key: k}).registerRaw(""); rp.Status != 403 || rp.str("error") != "invite_required" {
		t.Fatalf("fresh store, no admin command: %d %s", rp.Status, rp.Raw)
	}
	var c Control
	if err := h.st.GetControl(&c); err != nil || c.Registration != RegInvite {
		t.Fatalf("stored mode %q, %v", c.Registration, err)
	}
	if st := h.r.Stats(); st.Registration != RegInvite {
		t.Fatalf("stats: %q", st.Registration)
	}

	h2 := newHarness(t, func(c *Config) { c.Registration = RegClosed })
	_, k2, _ := ed25519.GenerateKey(rand.Reader)
	if rp := (&instance{h: h2, key: k2}).registerRaw(""); rp.Status != 503 || rp.str("error") != "registration_paused" {
		t.Fatalf("configured closed: %d %s", rp.Status, rp.Raw)
	}
}

// The configured mode only seeds a store that has none; a mode set by the operator survives a restart.
func TestStoredRegistrationModeWins(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Registration = RegInvite })
	if err := h.r.SetRegistration(RegClosed); err != nil {
		t.Fatal(err)
	}
	cfg := h.r.cfg
	cfg.Registration = RegOpen
	r2, err := New(cfg, h.st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if r2.control.Registration != RegClosed {
		t.Fatalf("restart reopened registration: %q", r2.control.Registration)
	}
	cfg.Registration = "ajar"
	if _, err := New(cfg, h.st, nil); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestProvisionalAndInstanceRetention(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(18)
	if rp := i.bind(d); rp.Status != 201 {
		t.Fatal(rp.Status)
	}
	h.clk.Add(3*24*time.Hour + time.Hour)
	h.r.Daily()
	if h.state(d) != "" {
		t.Fatal("provisional binding older than 48 h kept")
	}
}

// TestUndeliveredInstanceStaysWhileItChecksIn: an instance that never had an accepted push is kept while it
// stays in contact, by status calls or by registering its key again, however long it waits for its first
// device. One that never delivered and then went silent is removed once it has been silent for more than
// 30 days.
func TestUndeliveredInstanceStaysWhileItChecksIn(t *testing.T) {
	h := newHarness(t)
	silent := h.register()
	polling := h.register()
	reregistering := h.register()
	gone := func(i *instance) bool { _, err := h.r.Instance(i.id); return err != nil }
	day := 24 * time.Hour
	for n := 1; n <= 70; n++ {
		h.clk.Add(day)
		if n%7 == 0 {
			if rp := polling.do(http.MethodGet, "/v1/status", nil); rp.Status != http.StatusOK {
				t.Fatalf("status on day %d: %d %s", n, rp.Status, rp.Raw)
			}
			if rp := reregistering.registerRaw(""); rp.Status != http.StatusOK || rp.str("instanceId") != reregistering.id {
				t.Fatalf("registration on day %d: %d %s", n, rp.Status, rp.Raw)
			}
		}
		h.r.Daily()
		if n == 30 && gone(silent) {
			t.Fatal("an undelivered instance was removed within 30 days")
		}
	}
	if !gone(silent) {
		t.Fatal("an undelivered instance silent for 70 days was kept")
	}
	if gone(polling) {
		t.Fatal("an undelivered instance that calls status every week was removed")
	}
	if gone(reregistering) {
		t.Fatal("an undelivered instance that registers its key every week was removed")
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

// TestSmallContractChecks: DELETE /v1/instances/self takes no body; a revoked instance cannot be suspended
// (and later unsuspended into probation); an invite survives a registration the store could not record.
func TestSmallContractChecks(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	if rp := i.do(http.MethodDelete, "/v1/instances/self", []byte(`{"x":1}`)); rp.Status != http.StatusUnprocessableEntity {
		t.Fatalf("delete with a body: %d", rp.Status)
	}
	j := h.register()
	_ = h.r.Revoke(j.id, "abuse")
	if err := h.r.Suspend(j.id, "spam"); err == nil {
		t.Fatal("revoked instance suspended")
	}
	_ = h.r.SetRegistration(RegInvite)
	code, _ := h.r.NewInvite()
	_ = h.st.Close()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	if rp := (&instance{h: h, key: k}).registerRaw(code); rp.Status != http.StatusServiceUnavailable {
		t.Fatalf("registration with a dead store: %d", rp.Status)
	}
	h.r.mu.Lock()
	still := h.r.inviteIndex(code, 0) >= 0
	h.r.mu.Unlock()
	if !still {
		t.Fatal("invite spent although nothing was stored")
	}
}
