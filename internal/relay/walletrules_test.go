package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// TestWalletSignRefusals: a foreign brand image or an unknown file is refused by the relay before the
// wallet process is asked; a manifest the relay lets through but the wallet process refuses still never
// reaches the key; malformed bodies are shape errors.
func TestWalletSignRefusals(t *testing.T) {
	pins := walletTestPins()
	pins["logo@2x.png"] = append(pins["logo@2x.png"], walletSHA1("only the relay knows this logo"))
	h := newWalletHarness(t, func(c *Config) { c.WalletPins = pins })
	i := h.register()
	icon := walletSHA1("brand icon.png")
	cases := map[string]string{
		`{"pass.json":"` + walletSHA1("p") + `","icon.png":"` + walletSHA1("foreign") + `"}`:                                 "foreign_asset",
		`{"pass.json":"` + walletSHA1("p") + `","icon.png":"` + icon + `","thumbnail.png":"` + walletSHA1("t") + `"}`:        "unknown_file",
		`{"pass.json":"` + walletSHA1("p") + `","icon.png":"` + icon + `","de.lproj/logo@2x.png":"` + walletSHA1("l") + `"}`: "unknown_file",
		`{"pass.json":"` + walletSHA1("p") + `"}`: "missing_file",
		`{"pass.json":"` + walletSHA1("p") + `","icon.png":"` + icon + `","logo@2x.png":"` + pins["logo@2x.png"][1] + `"}`: "foreign_asset",
		`not json`: "shape",
	}
	for m, want := range cases {
		rp := i.sign([]byte(m))
		if rp.Status != http.StatusUnprocessableEntity || rp.str("error") != "wallet_manifest_invalid" || rp.str("reason") != want {
			t.Errorf("%s: %d %s", m, rp.Status, rp.Raw)
		}
	}
	for _, body := range []string{`{"v":2,"manifest":"e30"}`, `{"v":1,"manifest":"e30="}`, `{"v":1}`, `{"v":1,"manifest":"e30","x":1}`} {
		if rp := i.do(http.MethodPost, "/v1/wallet/apple/sign", []byte(body)); rp.Status != http.StatusUnprocessableEntity || rp.str("reason") != "shape" {
			t.Errorf("%s: %d %s", body, rp.Status, rp.Raw)
		}
	}
	if h.w.svc.KeyUses() != 0 {
		t.Fatalf("the key was used %d times", h.w.svc.KeyUses())
	}
}

// TestWalletOffAndDown: without a wallet process both endpoints answer 503 and the status says sign false;
// a wallet process that stops answering is taken as gone once its last answer is three minutes old.
func TestWalletOffAndDown(t *testing.T) {
	off := newHarness(t)
	i := off.register()
	if rp := i.sign(minimalManifest()); rp.Status != http.StatusServiceUnavailable || rp.str("error") != "wallet_unavailable" || rp.Header.Get("Retry-After") == "" {
		t.Fatalf("off: %d %s", rp.Status, rp.Raw)
	}
	if rp, _ := i.notify(wire.WalletNotifyItem{Ref: "r", Token: passToken(1)}); rp.Status != http.StatusServiceUnavailable {
		t.Fatalf("off notify: %d %s", rp.Status, rp.Raw)
	}
	st := i.do(http.MethodGet, "/v1/status", nil)
	if !strings.Contains(string(st.Raw), `"wallet":{"sign":false,"notify":false}`) {
		t.Fatalf("status %s", st.Raw)
	}
	off.r.PollWallet(context.Background()) // nothing configured: nothing to ask

	h := newWalletHarness(t)
	j := h.register()
	h.w.down.Store(true)
	h.r.PollWallet(context.Background())
	if rp := j.sign(minimalManifest()); rp.Status != http.StatusServiceUnavailable {
		t.Fatalf("down: a sign request must reach the dead process and fail: %d %s", rp.Status, rp.Raw)
	}
	h.clk.Add(4 * time.Minute)
	if rp := j.sign(minimalManifest()); rp.Status != http.StatusServiceUnavailable || rp.str("error") != "wallet_unavailable" {
		t.Fatalf("stale: %d %s", rp.Status, rp.Raw)
	}
	h.w.down.Store(false)
	h.r.PollWallet(context.Background())
	if rp := j.sign(minimalManifest()); rp.Status != http.StatusOK {
		t.Fatalf("back: %d %s", rp.Status, rp.Raw)
	}
}

// TestWalletBlockAndSuspension: an operator's Wallet block refuses signing and pass pushes with 403 and
// leaves pushes to the app alone; a suspended instance is refused like on every endpoint.
func TestWalletBlockAndSuspension(t *testing.T) {
	h := newWalletHarness(t)
	i := h.register()
	if _, err := h.r.admin(&AdminRequest{Cmd: "wallet", Args: []string{"block", i.id}}); err != nil {
		t.Fatal(err)
	}
	if rp := i.sign(minimalManifest()); rp.Status != http.StatusForbidden || rp.str("error") != "wallet_blocked" {
		t.Fatalf("blocked: %d %s", rp.Status, rp.Raw)
	}
	if rp, _ := i.notify(wire.WalletNotifyItem{Ref: "r", Token: passToken(1)}); rp.Status != http.StatusForbidden {
		t.Fatalf("blocked notify: %d", rp.Status)
	}
	if st := i.do(http.MethodGet, "/v1/status", nil); !strings.Contains(string(st.Raw), `"sign":false`) {
		t.Fatalf("status %s", st.Raw)
	}
	d := newDevice(0x61)
	i.activate(d) // pushes to the app still work
	if _, err := h.r.admin(&AdminRequest{Cmd: "wallet", Args: []string{"unblock", i.id}}); err != nil {
		t.Fatal(err)
	}
	if rp := i.sign(minimalManifest()); rp.Status != http.StatusOK {
		t.Fatalf("unblocked: %d %s", rp.Status, rp.Raw)
	}
	if err := h.r.Suspend(i.id, "abuse"); err != nil {
		t.Fatal(err)
	}
	if rp := i.sign(minimalManifest()); rp.Status != http.StatusForbidden || rp.str("error") != "instance_suspended" {
		t.Fatalf("suspended: %d %s", rp.Status, rp.Raw)
	}
	if _, err := h.r.admin(&AdminRequest{Cmd: "wallet", Args: []string{"block", "nobody"}}); err == nil {
		t.Fatal("blocked an unknown instance")
	}
	if _, err := h.r.admin(&AdminRequest{Cmd: "wallet", Args: []string{"nonsense"}}); err == nil {
		t.Fatal("unknown wallet command accepted")
	}
}

// TestWalletLimits: signatures per instance and minute, per day and relay-wide per minute; pass pushes per
// instance and minute and per token and hour.
func TestWalletLimits(t *testing.T) {
	h := newWalletHarness(t, withDefaultLimits, func(c *Config) { c.Limits.Wallet.GlobalSignsMinute = 15; c.Limits.Probation.RequestsMinute = 1000 })
	a, b := h.register(), h.register()
	for n := range 10 {
		if rp := a.sign(minimalManifest()); rp.Status != http.StatusOK {
			t.Fatalf("sign %d: %d %s", n, rp.Status, rp.Raw)
		}
	}
	if rp := a.sign(minimalManifest()); rp.Status != http.StatusTooManyRequests || rp.str("error") != "wallet_rate" {
		t.Fatalf("11th: %d %s", rp.Status, rp.Raw)
	}
	for range 5 {
		_ = b.sign(minimalManifest())
	}
	if rp := b.sign(minimalManifest()); rp.Status != http.StatusTooManyRequests || rp.str("error") != "global" {
		t.Fatalf("global: %d %s", rp.Status, rp.Raw)
	}
	// The day: 200 for probation, counted across minutes.
	for n := 10; n < 200; n++ {
		if n%10 == 0 {
			h.later(time.Minute)
		}
		if rp := a.sign(minimalManifest()); rp.Status != http.StatusOK {
			t.Fatalf("sign %d: %d %s", n, rp.Status, rp.Raw)
		}
	}
	h.later(time.Minute)
	if rp := a.sign(minimalManifest()); rp.Status != http.StatusTooManyRequests || rp.str("error") != "wallet_quota" {
		t.Fatalf("201st: %d %s", rp.Status, rp.Raw)
	}
	// Pass pushes: 12 per token and hour, 60 per instance and minute.
	c := h.register()
	for n := range 12 {
		if _, res := c.notify(wire.WalletNotifyItem{Ref: "t" + strconv.Itoa(n), Token: passToken(7)}); len(res) != 1 || res[0].Result != wire.PassAccepted {
			t.Fatalf("push %d: %+v", n, res)
		}
	}
	if _, res := c.notify(wire.WalletNotifyItem{Ref: "t12", Token: passToken(7)}); res[0].Result != wire.PassTokenQuota {
		t.Fatalf("13th push to one token: %+v", res)
	}
	items := make([]wire.WalletNotifyItem, 47) // 13 so far, 60 a minute
	for n := range items {
		items[n] = wire.WalletNotifyItem{Ref: "m" + strconv.Itoa(n), Token: passToken(byte(0x80 + n))}
	}
	if rp, _ := c.notify(items...); rp.Status != http.StatusOK {
		t.Fatalf("47 more: %d %s", rp.Status, rp.Raw)
	}
	if rp, _ := c.notify(wire.WalletNotifyItem{Ref: "over", Token: passToken(9)}); rp.Status != http.StatusTooManyRequests || rp.str("error") != "wallet_rate" {
		t.Fatalf("61st push in a minute: %d %s", rp.Status, rp.Raw)
	}
	h.later(time.Hour)
	h.r.Tick()
	if _, res := c.notify(wire.WalletNotifyItem{Ref: "later", Token: passToken(7)}); res[0].Result != wire.PassAccepted {
		t.Fatalf("an hour later: %+v", res)
	}
}

// TestWalletNotifyResultsAndIdempotency: results come back per item; a repeated reference within ten
// minutes gets its first result without a second push; an unavailable result is sent again on retry; bad
// bodies are refused.
func TestWalletNotifyResultsAndIdempotency(t *testing.T) {
	h := newWalletHarness(t)
	h.pusher.answer = func(tok string) string {
		switch tok[:2] {
		case "02":
			return wire.PassUnregistered
		case "03":
			return wire.PassUnavailable
		case "04":
			return "something else"
		}
		return wire.PassAccepted
	}
	i := h.register()
	items := []wire.WalletNotifyItem{{Ref: "a", Token: passToken(1)}, {Ref: "b", Token: passToken(2)}, {Ref: "c", Token: passToken(3)}, {Ref: "d", Token: passToken(4)}}
	_, res := i.notify(items...)
	want := []string{wire.PassAccepted, wire.PassUnregistered, wire.PassUnavailable, wire.PassRejected}
	for n, r := range res {
		if r.Ref != items[n].Ref || r.Result != want[n] {
			t.Fatalf("results %+v", res)
		}
	}
	_, res = i.notify(items...)
	if h.pusher.count() != 5 || res[0].Result != wire.PassAccepted || res[1].Result != wire.PassUnregistered || res[2].Result != wire.PassUnavailable {
		t.Fatalf("repeat: %d pushes, %+v", h.pusher.count(), res)
	}
	h.later(11 * time.Minute)
	h.r.Tick()
	_, _ = i.notify(items[0])
	if h.pusher.count() != 6 {
		t.Fatalf("after ten minutes the reference is new: %d pushes", h.pusher.count())
	}
	for _, body := range []string{`{"items":[]}`, `{"items":[{"ref":"a","token":"0"}]}`, `{"items":[{"ref":"a","token":"` + passToken(1) + `"},{"ref":"a","token":"` + passToken(2) + `"}]}`,
		`{"items":[{"ref":"a b","token":"` + passToken(1) + `"}]}`} {
		if rp := i.do(http.MethodPost, "/v1/wallet/apple/notify", []byte(body)); rp.Status != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d", body, rp.Status)
		}
	}
	h.w.down.Store(true)
	if _, res := i.notify(wire.WalletNotifyItem{Ref: "z", Token: passToken(5)}); res[0].Result != wire.PassUnavailable {
		t.Fatalf("process down: %+v", res)
	}
}

// TestWalletLedgerStaysOutOfLogsMetricsAndExport: after signing, neither the manifest hash nor the
// instance id appears in the logs, the metrics, the stats or the export; only the admin lookup finds it.
func TestWalletLedgerStaysOutOfLogsMetricsAndExport(t *testing.T) {
	h := newWalletHarness(t)
	i := h.register()
	m := minimalManifest()
	if rp := i.sign(m); rp.Status != http.StatusOK {
		t.Fatal(rp.Status)
	}
	_, _ = i.notify(wire.WalletNotifyItem{Ref: "r", Token: passToken(0x42)})
	h.later(2 * time.Hour)
	h.r.Tick()
	h.r.Daily()
	sum := sha256.Sum256(m)
	hash := hex.EncodeToString(sum[:])
	rec := httptest.NewRecorder()
	h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	if !strings.Contains(rec.Body.String(), `hlp_wallet_requests_total{op="sign",result="ok"} 1`) || !strings.Contains(rec.Body.String(), "hlp_wallet_cert_days_left ") {
		t.Fatalf("wallet metrics missing:\n%s", rec.Body.String())
	}
	stats, _ := json.Marshal(h.r.Stats())
	export, err := os.ReadFile(filepath.Join(h.dir, "registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, blob := range map[string]string{"logs": h.logs.String(), "metrics": rec.Body.String(), "stats": string(stats), "export": string(export)} {
		for _, f := range []string{hash, passToken(0x42), string(m)} {
			if strings.Contains(blob, f) {
				t.Errorf("%s contains %q", name, f)
			}
		}
		if name != "export" && strings.Contains(blob, i.id) {
			t.Errorf("%s contains the instance id", name)
		}
	}
	out, err := h.r.admin(&AdminRequest{Cmd: "wallet", Args: []string{"lookup", hash}})
	if b, _ := json.Marshal(out); err != nil || !strings.Contains(string(b), i.id) {
		t.Fatalf("lookup: %s %v", b, err)
	}
	if _, err := h.r.admin(&AdminRequest{Cmd: "wallet", Args: []string{"lookup", "xyz"}}); err == nil {
		t.Fatal("malformed lookup accepted")
	}
	st, _ := h.r.admin(&AdminRequest{Cmd: "wallet", Args: []string{"status"}})
	if wi, ok := st.(WalletInfo); !ok || !wi.Up || wi.PassTypeIdentifier == "" {
		t.Fatalf("status %+v", st)
	}
}
