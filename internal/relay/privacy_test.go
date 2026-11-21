package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// TestNothingIdentifyingReachesLogsMetricsOrStats runs real traffic and then checks the log stream, the
// metrics, the operator stats and the export for instance ids, tokens, token MACs and addresses (5.2, B10).
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
	for _, w := range u.RegistrationsWk {
		reg += w.N
	}
	for _, w := range u.OptOutsWk {
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

// TestMetricsCoarseBelowThreshold: with fewer than 20 active instances the scrape is a snapshot refreshed
// hourly, so one instance's push cannot be timed from it.
func TestMetricsCoarseBelowThreshold(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0x51)
	scrape := func() string {
		rec := httptest.NewRecorder()
		h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
		return rec.Body.String()
	}
	first := scrape()
	i.activate(d)
	if scrape() != first {
		t.Fatal("metrics changed within the hour with fewer than 20 instances")
	}
	h.clk.Add(time.Hour)
	if scrape() == first {
		t.Fatal("metrics never refresh")
	}
}

// TestMigrationExportRestore covers the host move (docs/migration.md): only the export travels; on the new
// host the instances keep their ids and keys, bindings come back through the rebind path, and the token MAC
// key from the secret store keeps token MACs stable.
func TestMigrationExportRestore(t *testing.T) {
	old := newHarness(t)
	i := old.register()
	d := newDevice(0x61)
	i.activate(d)
	if err := old.r.ExportNow(); err != nil {
		t.Fatal(err)
	}
	ex, err := store.ReadExport(filepath.Join(old.dir, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	nh := newHarness(t, func(c *Config) { c.MACKeys = old.r.cfg.MACKeys })
	n, err := nh.r.SetRecovery(store.Day(nh.clk.Now())+14, ex)
	if err != nil || n != 1 {
		t.Fatalf("import: %d %v", n, err)
	}
	moved := &instance{h: nh, key: i.key, id: i.id}
	if rp := moved.do(http.MethodGet, "/v1/status", nil); rp.Status != 200 || rp.str("tier") != store.TierProbation {
		t.Fatalf("instance after migration: %d %s", rp.Status, rp.Raw)
	}
	if res := moved.push1(alertItem("m1", d)); res.Error != "binding_unknown" {
		t.Fatalf("bindings must not migrate: %+v", res)
	}
	if rp := moved.bind(d); rp.Status != 201 {
		t.Fatalf("rebind: %d %s", rp.Status, rp.Raw)
	}
	if res := moved.push1(alertItem("m2", d)); res.Result != "accepted" {
		t.Fatalf("push after rebind: %+v", res)
	}
	// During the recovery window an unknown instance starts as standard.
	if fresh := nh.register(); fresh != nil {
		if info, _ := nh.r.Instance(fresh.id); info.Tier != store.TierStandard {
			t.Fatalf("recovery window tier: %s", info.Tier)
		}
	}
}

// TestMACKeyRotation: bindings stored under the previous MAC key are found and moved to the current key.
func TestMACKeyRotation(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0x71)
	i.activate(d)
	h.r.mu.Lock()
	oldKey := h.r.cfg.MACKeys[0]
	h.r.cfg.MACKeys = [][]byte{bytes.Repeat([]byte{9}, 32), oldKey}
	h.r.mu.Unlock()
	if res := i.push1(alertItem("rot", d)); res.Result != "accepted" {
		t.Fatalf("after MAC rotation: %+v", res)
	}
	if h.state(d) == "" {
		t.Fatal("binding not moved to the current MAC key")
	}
}

func TestPublicEndpoints(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/healthz", "/version", "/privacy", "/terms", "/", "/nope"} {
		req, _ := http.NewRequest(http.MethodGet, h.srv.URL+p, http.NoBody)
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.Header.Get("Strict-Transport-Security") == "" || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: security headers missing", p)
		}
		if strings.HasPrefix(p, "/nope") != (resp.StatusCode == http.StatusNotFound) {
			t.Errorf("%s: status %d", p, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/healthz", http.NoBody)
	rp := h.send(req, "")
	for _, k := range []string{"status", "db_writable", "apns_recent", "breaker", "delivery"} {
		if _, ok := rp.Body[k]; !ok {
			t.Errorf("healthz lacks %s", k)
		}
	}
	if len(rp.Body) != 5 {
		t.Errorf("healthz has extra fields: %s", rp.Raw)
	}
}

func TestStatusFileSigned(t *testing.T) {
	h := newHarness(t)
	_ = h.r.SetNotice("relay_shutdown", "action_required", 0)
	sf := h.r.StatusFile()
	sig, _ := wire.ParseSignature(sf.Signature)
	if !wire.Verify(h.relayP, wire.StatusFileText(host, sf.Body), sig) || !bytes.Contains(sf.Body, []byte("relay_shutdown")) {
		t.Fatal("status file not signed or notice missing")
	}
}

func TestAdminCommands(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	run := func(cmd string, args []string, p map[string]string) error {
		_, err := h.r.admin(&AdminRequest{Cmd: cmd, Args: args, Params: p})
		return err
	}
	for _, c := range []struct {
		cmd  string
		args []string
		p    map[string]string
	}{
		{"stats", nil, nil}, {"instance", []string{i.id}, nil}, {"pause", nil, map[string]string{"class": "silent", "for": "10m"}},
		{"resume", nil, nil}, {"registration", []string{"invite"}, nil}, {"invite", nil, nil},
		{"notice", []string{"set", "planned_maintenance"}, map[string]string{"level": "planned", "for": "1h"}}, {"notice", []string{"clear"}, nil},
		{"limits", []string{i.id}, map[string]string{"devices": "80"}}, {"export", nil, nil}, {"breaker", []string{"close"}, nil},
		{"status-file", nil, nil}, {"suspend", []string{i.id, "spam"}, nil}, {"unsuspend", []string{i.id}, nil},
		{"recovery", nil, map[string]string{"until": "2026-12-15"}},
	} {
		if err := run(c.cmd, c.args, c.p); err != nil {
			t.Errorf("%s: %v", c.cmd, err)
		}
	}
	for _, bad := range []AdminRequest{{Cmd: "pause", Params: map[string]string{"class": "everything"}}, {Cmd: "suspend", Args: []string{i.id, "because"}},
		{Cmd: "limits", Args: []string{i.id}, Params: map[string]string{"devices": "151"}}, {Cmd: "notice", Args: []string{"set", "Free Text!"}}, {Cmd: "nope"}} {
		if _, err := h.r.admin(&bad); err == nil {
			t.Errorf("%s %v accepted", bad.Cmd, bad.Args)
		}
	}
}

// TestBlocksSurviveMACRotation: a device opt-out stays in force after the token MAC key rotates.
func TestBlocksSurviveMACRotation(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0x72)
	i.activate(d)
	if rp := h.unbindSelf(d, d.key, i.id); rp.Status != 204 {
		t.Fatal(rp.Status)
	}
	h.r.mu.Lock()
	h.r.cfg.MACKeys = [][]byte{bytes.Repeat([]byte{9}, 32), h.r.cfg.MACKeys[0]}
	h.r.mu.Unlock()
	if rp := i.bind(d); rp.Status != 403 {
		t.Fatalf("opt-out lost after MAC rotation: %d", rp.Status)
	}
}

func TestRevokedRecordsExpireWithTheDenylist(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	_ = h.r.Revoke(i.id, "abuse")
	h.clk.Add(300 * 24 * time.Hour)
	h.r.Daily()
	if _, err := h.r.Instance(i.id); err != nil {
		t.Fatal("revoked record removed before 12 months")
	}
	h.clk.Add(70 * 24 * time.Hour)
	h.r.Daily()
	if _, err := h.r.Instance(i.id); err == nil {
		t.Fatal("revoked record kept beyond 12 months")
	}
}

// TestOptOutSurvivesRestore: a device opt-out ("stop pushes from this server") travels in the export and is
// still in force on a relay rebuilt from it. Losing it would silently reopen the channel for a hostile
// instance operator.
func TestOptOutSurvivesRestore(t *testing.T) {
	old := newHarness(t)
	hostile, other := old.register(), old.register()
	d := newDevice(0x62)
	hostile.activate(d)
	if rp := old.unbindSelf(d, d.key, hostile.id); rp.Status != 204 {
		t.Fatal(rp.Status)
	}
	if err := old.r.ExportNow(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(old.dir, "registry.json"))
	var ex store.Export
	_ = json.Unmarshal(raw, &ex)
	if len(ex.BlockedPairs) != 1 || ex.BlockedPairs[0].Reason != store.ReasonDeviceOptOut || len(ex.BlockedPairs[0].Pair) != 64 {
		t.Fatalf("export blocks: %+v", ex.BlockedPairs)
	}
	for _, f := range []string{d.hex(), hex.EncodeToString([]byte(mac(old.r.cfg.MACKeys[0], d.token)))} {
		if bytes.Contains(raw, []byte(f)) {
			t.Fatal("export leaks the token or its MAC")
		}
	}
	restored := newHarness(t, func(c *Config) { c.MACKeys = old.r.cfg.MACKeys })
	if _, err := restored.r.SetRecovery(store.Day(restored.clk.Now())+14, &ex); err != nil {
		t.Fatal(err)
	}
	h2 := &instance{h: restored, key: hostile.key, id: hostile.id}
	// The export carries no binding key, so even a later statement by the device cannot lift a restored
	// block: after a restore only a new token returns the device to that instance.
	restored.clk.Add(time.Hour)
	if rp := h2.bind(d); rp.Status != 403 || rp.str("error") != "binding_refused" {
		t.Fatalf("opt-out lost on restore: %d %s", rp.Status, rp.Raw)
	}
	o2 := &instance{h: restored, key: other.key, id: other.id}
	if rp := o2.bind(d); rp.Status != 201 {
		t.Fatalf("another instance after restore: %d %s", rp.Status, rp.Raw)
	}
}

// TestAbuseBlocksSurviveRestore: operator token blocks and suspended or revoked instances are still in force
// on a relay rebuilt from the export; an abuse block that vanished on restore would reopen the abuse.
func TestAbuseBlocksSurviveRestore(t *testing.T) {
	old := newHarness(t)
	holder, abuser, revoked, suspended := old.register(), old.register(), old.register(), old.register()
	d := newDevice(0x63)
	holder.activate(d)
	if err := old.r.BlockToken(d.hex(), "", false); err != nil {
		t.Fatal(err)
	}
	_ = old.r.Revoke(revoked.id, "abuse")
	_ = old.r.Suspend(suspended.id, "spam")
	if err := old.r.ExportNow(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(old.dir, "registry.json"))
	var ex store.Export
	_ = json.Unmarshal(raw, &ex)
	if len(ex.BlockedTokens) != 1 || ex.BlockedTokens[0].Reason != store.ReasonOperatorBlock || len(ex.Denylist) != 2 {
		t.Fatalf("export: tokens %+v denylist %+v", ex.BlockedTokens, ex.Denylist)
	}
	if bytes.Contains(raw, []byte(d.hex())) || bytes.Contains(raw, []byte(hex.EncodeToString([]byte(mac(old.r.cfg.MACKeys[0], d.token))))) {
		t.Fatal("export leaks the token or its MAC")
	}
	restored := newHarness(t, func(c *Config) { c.MACKeys = old.r.cfg.MACKeys })
	if _, err := restored.r.SetRecovery(store.Day(restored.clk.Now())+14, &ex); err != nil {
		t.Fatal(err)
	}
	// Bindings are gone after a restore; the blocked token must not be bindable by another instance.
	a := &instance{h: restored, key: abuser.key, id: abuser.id}
	if rp := a.bind(d); rp.Status != 403 || rp.str("error") != "binding_refused" {
		t.Fatalf("token block lost on restore: %d %s", rp.Status, rp.Raw)
	}
	if rp := (&instance{h: restored, key: revoked.key, id: revoked.id}).do(http.MethodGet, "/v1/status", nil); rp.Status != 403 || rp.str("error") != "instance_revoked" {
		t.Fatalf("revocation lost on restore: %d %s", rp.Status, rp.Raw)
	}
	if rp := (&instance{h: restored, key: revoked.key}).registerRaw(""); rp.Status != 403 {
		t.Fatalf("revoked key registered again after restore: %d", rp.Status)
	}
	if rp := (&instance{h: restored, key: suspended.key, id: suspended.id}).do(http.MethodGet, "/v1/status", nil); rp.Status != 403 || rp.str("reason") != "spam" {
		t.Fatalf("suspension lost on restore: %d %s", rp.Status, rp.Raw)
	}
}
