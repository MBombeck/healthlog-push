package relay

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

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
