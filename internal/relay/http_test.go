package relay

// Request handling: signed responses bound to the nonce, request signing, header checks before any body
// byte, the buffered body budget, response size and the app-direct refusal rules.

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

func TestResponseSignatureBindsNonce(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	nonce := randNonce()
	rp := i.doRaw(http.MethodGet, "/v1/status", nil, h.clk.Now().Unix(), nonce, nil)
	sig, _ := wire.ParseSignature(rp.Header.Get("HL-Relay-Signature"))
	ok := func(method, path, n string, status int, hst string) bool {
		return wire.Verify(h.relayP, wire.ResponseText(hst, method, path, n, status, rp.Raw), sig)
	}
	if !ok("GET", "/v1/status", nonce, rp.Status, host) {
		t.Fatal("genuine response does not verify")
	}
	for name, bad := range map[string]bool{
		"other nonce":  ok("GET", "/v1/status", randNonce(), rp.Status, host),
		"no nonce":     ok("GET", "/v1/status", "-", rp.Status, host),
		"other status": ok("GET", "/v1/status", nonce, 410, host),
		"other host":   ok("GET", "/v1/status", nonce, rp.Status, "other.example.org"),
		"other method": ok("POST", "/v1/status", nonce, rp.Status, host),
		"other path":   ok("GET", "/v1/push", nonce, rp.Status, host),
	} {
		if bad {
			t.Errorf("signature verifies for %s", name)
		}
	}
}

// TestNonceMandatoryOnV1: every /v1 request needs a nonce, including registration and the app-direct
// endpoints; the refusal itself is bound to "-" and is never a valid answer to anything.
func TestNonceMandatoryOnV1(t *testing.T) {
	h := newHarness(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/v1/instances"}, {http.MethodDelete, "/v1/bindings/self"}, {http.MethodGet, "/v1/bindings/self"},
		{http.MethodPost, "/v1/bindings/challenge"}, {http.MethodGet, "/v1/status"},
	} {
		req, _ := http.NewRequest(c.method, h.srv.URL+c.path, strings.NewReader("{}"))
		req.Header.Set("HL-Nonce", "not-a-nonce")
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s %s without a valid nonce: %d", c.method, c.path, resp.StatusCode)
		}
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
		"body":   func(s string) string { return s[:len(s)-64] + hexSHA256([]byte("{}")) },
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

func TestUnknownInstance(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	ghost := &instance{h: h, key: i.key, id: "00000000-0000-4000-8000-000000000000"}
	if rp := ghost.do(http.MethodGet, "/v1/status", nil); rp.Status != 401 || rp.str("error") != "unknown_instance" {
		t.Fatalf("unknown: %d %s", rp.Status, rp.Raw)
	}
}

// TestForgedSignaturesCannotLockOutAnInstance: the instance id is
// not secret, so failed signatures by a third party must never refuse a correctly signed request.
func TestForgedSignaturesCannotLockOutAnInstance(t *testing.T) {
	h := newHarness(t, withDefaultLimits)
	victim := h.register()
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forger := &instance{h: h, key: other, id: victim.id}
	for range 100 {
		if rp := forger.do(http.MethodGet, "/v1/status", nil); rp.Status != 401 {
			t.Fatalf("forged request: %d %s", rp.Status, rp.Raw)
		}
	}
	if rp := victim.do(http.MethodGet, "/v1/status", nil); rp.Status != 200 {
		t.Fatalf("valid request after 100 forged ones: %d %s", rp.Status, rp.Raw)
	}
	for range 15 {
		h.clk.Add(2 * time.Second)
		forger.do(http.MethodGet, "/v1/status", nil)
		if rp := victim.do(http.MethodGet, "/v1/status", nil); rp.Status != 200 {
			t.Fatalf("victim refused while the forger keeps going: %d", rp.Status)
		}
	}
}

func TestPublicEndpoints(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/healthz", "/version", "/privacy", "/terms", "/.well-known/security.txt", "/", "/nope"} {
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

// TestHeadersCheckedBeforeBody: an unknown instance is refused from the headers alone, while the body
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

// TestBufferedBodyBudget: once the bytes reserved for bodies in flight reach the cap, further bodies are
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

// TestJunkCannotStarveOptOut: unauthenticated junk on the app endpoints does
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

// TestAppEndpointsLimitedPerDevice: verified app calls are limited per token, not globally.
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

// TestResponseSizeBounded: the largest answer the relay gives, a full batch of errors, stays far below
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

// TestNonCanonicalPathsAreSigned404: a path with a doubled or trailing slash, or /v1 itself, gets a signed
// 404 or nonce refusal, never an unsigned redirect.
func TestNonCanonicalPathsAreSigned404(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/v1//push", "/v1/push/", "/v1/./status", "/healthz/"} {
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+p, strings.NewReader("{}"))
		req.Header.Set("HL-Nonce", randNonce())
		h.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		rp := h.send(req, req.Header.Get("HL-Nonce"))
		if rp.Status != http.StatusNotFound {
			t.Errorf("%s: %d", p, rp.Status)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/v1", http.NoBody)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("/v1 without nonce: %d", resp.StatusCode)
	}
}
