package wallet

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/wallet/wallettest"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// shortDir is a temporary directory with a short path: unix socket paths are limited to about 100 bytes.
func shortDir(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp("", "hlw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// fakePassAPNs is Apple's push endpoint for passes: TLS with a required client certificate, HTTP/2.
type fakePassAPNs struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
	body []string
	cert []byte // the client certificate of the last request
}

func newFakePassAPNs(t *testing.T, p *wallettest.PKI, answer func(token string) (int, string)) *fakePassAPNs {
	f := &fakePassAPNs{}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, r)
		f.body = append(f.body, string(b))
		f.cert = append([]byte(nil), r.TLS.PeerCertificates[0].Raw...)
		f.mu.Unlock()
		status, reason := answer(strings.TrimPrefix(r.URL.Path, "/3/device/"))
		w.WriteHeader(status)
		if reason != "" {
			_, _ = io.WriteString(w, `{"reason":"`+reason+`"}`)
		}
	}))
	f.srv.EnableHTTP2 = true
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{p.ServerTLS(t, "api.push.apple.com")}, ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS12}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// testTunnel stands in for the relay's byte tunnel: a unix socket whose connections are copied to addr.
func testTunnel(t *testing.T, path, addr string) {
	ln, err := Listen(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				up, err := net.Dial("tcp", addr)
				if err != nil {
					_ = c.Close()
					return
				}
				go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
				_, _ = io.Copy(c, up)
				_ = c.Close()
			}()
		}
	}()
}

// startWallet runs a service with a notifier through a test tunnel to f, and returns a client.
func startWallet(t *testing.T, p *wallettest.PKI, f *fakePassAPNs) (*Service, *Client) {
	logx.SetOutput(io.Discard)
	dir := shortDir(t)
	id := loadTestIdentity(t, p)
	testTunnel(t, filepath.Join(dir, TunnelName), f.srv.Listener.Addr().String())
	svc, err := NewService(id, testPins(), NewNotifier(id, filepath.Join(dir, TunnelName), p.Roots()))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(context.Background(), filepath.Join(dir, SocketName))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return svc, NewClient(filepath.Join(dir, SocketName))
}

func call(t *testing.T, c *Client, req *wire.WalletRequest) *wire.WalletReply {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rep, err := c.Do(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// TestWalletSocketRoundTrip: sign, a refused manifest, info and a malformed request over the real socket.
func TestWalletSocketRoundTrip(t *testing.T) {
	p := wallettest.Default(t)
	f := newFakePassAPNs(t, p, func(string) (int, string) { return 200, "" })
	svc, c := startWallet(t, p, f)
	rep := call(t, c, &wire.WalletRequest{Op: wire.WalletOpSign, Manifest: manifestJSON(minimal(svc.Pins))})
	if rep.Error != "" || len(rep.Signature) < 1000 || rep.Info.PassTypeIdentifier != wallettest.PassTypeID || !rep.Info.Usable {
		t.Fatalf("%+v", rep)
	}
	rep = call(t, c, &wire.WalletRequest{Op: wire.WalletOpSign, Manifest: []byte(`{"pass.json":"` + sha1hex("p") + `","icon.png":"` + sha1hex("x") + `"}`)})
	if rep.Error != wire.WalletErrManifest || rep.Reason != ReasonForeignAsset || rep.Signature != nil {
		t.Fatalf("%+v", rep)
	}
	if rep = call(t, c, &wire.WalletRequest{Op: wire.WalletOpInfo}); rep.Error != "" || rep.Info.TeamIdentifier != wallettest.TeamID {
		t.Fatalf("%+v", rep)
	}
	for _, bad := range []*wire.WalletRequest{{Op: "delete"}, {Op: wire.WalletOpSign}, {Op: wire.WalletOpInfo, Manifest: []byte("x")},
		{Op: wire.WalletOpNotify}, {Op: wire.WalletOpNotify, Tokens: make([][]byte, wire.WalletNotifyMax+1)}} {
		if rep = call(t, c, bad); rep.Error != wire.WalletErrBadRequest {
			t.Errorf("%+v: %+v", bad, rep)
		}
	}
	// Garbage on the socket gets a bad_request answer, a frame over the limit none at all.
	conn, err := net.Dial("unix", c.Path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte{0, 0, 0, 3, '{', '}', 'x'})
	b, err := ReadFrame(conn, wire.WalletReplyFrameMax)
	_ = conn.Close()
	var r wire.WalletReply
	if err != nil || json.Unmarshal(b, &r) != nil || r.Error != wire.WalletErrBadRequest {
		t.Fatalf("garbage: %v %s", err, b)
	}
	conn, _ = net.Dial("unix", c.Path)
	_, _ = conn.Write([]byte{0, 1, 0, 0})
	b, err = ReadFrame(conn, wire.WalletReplyFrameMax)
	_ = conn.Close()
	if err != nil || json.Unmarshal(b, &r) != nil || r.Error != wire.WalletErrBadRequest {
		t.Fatalf("oversized frame: %v %s", err, b)
	}
}

// TestWalletNotifyThroughTunnel: pass pushes go through the tunnel with TLS to Apple's name, the pass
// certificate as client certificate, topic = Pass Type ID, body {} and no push type; results map 1:1.
func TestWalletNotifyThroughTunnel(t *testing.T) {
	p := wallettest.Default(t)
	type answer struct {
		status int
		reason string
	}
	answers := map[string]answer{"aa": {200, ""}, "bb": {410, "Unregistered"}, "cc": {400, "BadDeviceToken"}, "dd": {400, "BadTopic"}, "ee": {503, "ServiceUnavailable"}}
	f := newFakePassAPNs(t, p, func(tok string) (int, string) {
		a := answers[tok[:2]]
		return a.status, a.reason
	})
	_, c := startWallet(t, p, f)
	var toks [][]byte
	for _, pre := range []string{"aa", "bb", "cc", "dd", "ee"} {
		b, _ := hex.DecodeString(strings.Repeat(pre, 32))
		toks = append(toks, b)
	}
	rep := call(t, c, &wire.WalletRequest{Op: wire.WalletOpNotify, Tokens: toks})
	want := []string{wire.PassAccepted, wire.PassUnregistered, wire.PassUnregistered, wire.PassRejected, wire.PassUnavailable}
	if rep.Error != "" || strings.Join(rep.Results, ",") != strings.Join(want, ",") {
		t.Fatalf("%+v", rep)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) != 5 || !bytes.Equal(f.cert, p.PassCert.Raw) {
		t.Fatalf("%d requests, client certificate is the pass certificate: %v", len(f.reqs), bytes.Equal(f.cert, p.PassCert.Raw))
	}
	for i, r := range f.reqs {
		if r.ProtoMajor != 2 || r.Host != "api.push.apple.com" || r.Header.Get("apns-topic") != wallettest.PassTypeID ||
			r.Header.Get("apns-push-type") != "" || r.Header.Get("apns-priority") != "" || f.body[i] != "{}" {
			t.Fatalf("request %d: %s %s %v %q", i, r.Proto, r.Host, r.Header, f.body[i])
		}
	}
}

// TestWalletNotifyWithoutPusher: a service without a push path answers unavailable.
func TestWalletNotifyWithoutPusher(t *testing.T) {
	svc := testService(t, testPins())
	rep := svc.Handle(context.Background(), &wire.WalletRequest{Op: wire.WalletOpNotify, Tokens: [][]byte{make([]byte, 32)}})
	if rep.Error != wire.WalletErrUnavailable {
		t.Fatalf("%+v", rep)
	}
	if _, err := NewService(nil, testPins(), nil); err == nil {
		t.Fatal("a service without identity")
	}
	if _, err := NewService(svc.ID, Pins{}, nil); err == nil {
		t.Fatal("a service with an empty pin set")
	}
}

// TestDurationBuckets: the request log keeps only a coarse duration.
func TestDurationBuckets(t *testing.T) {
	for d, want := range map[time.Duration]string{time.Millisecond: "lt_100ms", 500 * time.Millisecond: "lt_1s", 2 * time.Second: "ge_1s"} {
		if got := durationBucket(d); got != want {
			t.Errorf("%s: %s", d, got)
		}
	}
}

// TestClientWaitsForASlot: a client with every slot taken gives up when its context ends.
func TestClientWaitsForASlot(t *testing.T) {
	c := NewClient(filepath.Join(shortDir(t), "none.sock"))
	for range MaxConcurrent {
		c.sem <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Do(ctx, &wire.WalletRequest{Op: wire.WalletOpInfo}); err == nil {
		t.Fatal("no error without a slot")
	}
	<-c.sem
	if _, err := c.Do(context.Background(), &wire.WalletRequest{Op: wire.WalletOpInfo}); err == nil {
		t.Fatal("no error without a socket")
	}
}
