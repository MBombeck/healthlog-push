package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
)

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
	nh := newHarness(t, func(c *Config) { c.MACKeys, c.Identity = old.r.cfg.MACKeys, old.r.cfg.Identity })
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
	// During the recovery window an unknown key starts in probation like any other; only keys that come
	// back from the export keep their tier.
	if fresh := nh.register(); fresh != nil {
		if info, _ := nh.r.Instance(fresh.id); info.Tier != store.TierProbation {
			t.Fatalf("recovery window tier of a stranger: %s", info.Tier)
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
	if rp := i.do(http.MethodPost, "/v1/bindings", d.heldBody(i.id, h.clk.Now().Unix())); rp.Status != 403 {
		t.Fatalf("opt-out lost after MAC rotation: %d", rp.Status)
	}
}

func TestRevokedRecordsExpireAfterTwelveMonths(t *testing.T) {
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
	restored := newHarness(t, func(c *Config) { c.MACKeys, c.Identity = old.r.cfg.MACKeys, old.r.cfg.Identity })
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
	// The restored pin carries no key either: another instance may bind the token only through the
	// challenge the device answers.
	o2 := &instance{h: restored, key: other.key, id: other.id}
	if rp := o2.bind(d); rp.Status != 409 || rp.str("reason") != "challenge_sent" {
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
	if len(ex.BlockedTokens) != 1 || ex.BlockedTokens[0].Reason != store.ReasonOperatorBlock {
		t.Fatalf("export: tokens %+v", ex.BlockedTokens)
	}
	if bytes.Contains(raw, []byte(d.hex())) || bytes.Contains(raw, []byte(hex.EncodeToString([]byte(mac(old.r.cfg.MACKeys[0], d.token))))) {
		t.Fatal("export leaks the token or its MAC")
	}
	restored := newHarness(t, func(c *Config) { c.MACKeys, c.Identity = old.r.cfg.MACKeys, old.r.cfg.Identity })
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

// TestEditedExportRefused: the export is signed with the relay identity key; an edited file, one signed by
// another key or one for another host is refused, so a change in the backup path cannot lift a block.
func TestEditedExportRefused(t *testing.T) {
	old := newHarness(t)
	i := old.register()
	_ = old.r.Suspend(i.id, "spam")
	if err := old.r.ExportNow(); err != nil {
		t.Fatal(err)
	}
	ex, err := store.ReadExport(filepath.Join(old.dir, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	same := newHarness(t, func(c *Config) { c.MACKeys, c.Identity = old.r.cfg.MACKeys, old.r.cfg.Identity })
	edited := *ex
	edited.Instances = append([]store.ExportedInst(nil), ex.Instances...)
	edited.Instances[0].Tier = store.TierStandard
	if _, err := same.r.SetRecovery(99999, &edited); err == nil {
		t.Fatal("edited export imported")
	}
	other := newHarness(t)
	if _, err := other.r.SetRecovery(99999, ex); err == nil {
		t.Fatal("export of another relay imported")
	}
	if _, err := same.r.SetRecovery(99999, ex); err != nil {
		t.Fatalf("genuine export refused: %v", err)
	}
}
