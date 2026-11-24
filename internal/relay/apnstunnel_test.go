package relay

import (
	"bytes"
	"context"
	"crypto/tls"
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

	"github.com/MBombeck/healthlog-push/internal/wallet"
	"github.com/MBombeck/healthlog-push/internal/wallet/wallettest"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

func shortSocketDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "hlr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// startTunnel serves a tunnel on dir/apns.sock whose dialer records the address it was asked for and
// connects to target instead.
func startTunnel(t *testing.T, dir, target string) func() []string {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	tun := &Tunnel{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		asked = append(asked, network+" "+addr)
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target)
	}}
	ln, err := wallet.Listen(context.Background(), filepath.Join(dir, wallet.TunnelName))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tun.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

// TestTunnelDialsOnlyApple: every connection is joined to APNsHostPort and nothing else, bytes pass both
// ways unchanged, and a third connection at the same time is closed.
func TestTunnelDialsOnlyApple(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	dir := shortSocketDir(t)
	asked := startTunnel(t, dir, echo.Addr().String())
	var conns []net.Conn
	for range 2 {
		c, err := net.Dial("unix", filepath.Join(dir, wallet.TunnelName))
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		_, _ = c.Write([]byte("ping"))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("echo through the tunnel: %q %v", buf, err)
		}
	}
	third, err := net.Dial("unix", filepath.Join(dir, wallet.TunnelName))
	if err != nil {
		t.Fatal(err)
	}
	_ = third.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := third.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("a third tunnel was opened")
	}
	for _, c := range conns {
		_ = c.Close()
	}
	if got := asked(); len(got) != 2 || got[0] != "tcp "+APNsHostPort || got[1] != "tcp "+APNsHostPort || APNsHostPort != "api.push.apple.com:443" {
		t.Fatalf("dialed %v", got)
	}
}

// TestWalletThroughSocketsAndTunnel runs the whole Wallet path as in production, over the real unix
// sockets: the relay asks the wallet process, which signs, and pushes through the relay's tunnel with TLS
// to Apple's name and the pass certificate as client certificate.
func TestWalletThroughSocketsAndTunnel(t *testing.T) {
	pki := wallettest.Default(t)
	var mu sync.Mutex
	var seen []*http.Request
	apple := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r)
		mu.Unlock()
		if len(r.TLS.PeerCertificates) == 0 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, pki.PassCert.Raw) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	apple.EnableHTTP2 = true
	apple.Config.ErrorLog = log.New(io.Discard, "", 0)
	apple.TLS = &tls.Config{Certificates: []tls.Certificate{pki.ServerTLS(t, "api.push.apple.com")}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	apple.StartTLS()
	defer apple.Close()
	dir := shortSocketDir(t)
	startTunnel(t, dir, apple.Listener.Addr().String())
	id, err := wallet.LoadIdentity(pki.KeyPEM(t), wallettest.CertPEM(pki.PassCert), pki.InterCert, wallettest.PassTypeID, wallettest.TeamID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := wallet.NewService(id, walletTestPins(), wallet.NewNotifier(id, filepath.Join(dir, wallet.TunnelName), pki.Roots()))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := wallet.Listen(context.Background(), filepath.Join(dir, wallet.SocketName))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = svc.Serve(ctx, ln) }()
	h := newHarness(t, func(c *Config) {
		c.Wallet, c.WalletPins = wallet.NewClient(filepath.Join(dir, wallet.SocketName)), walletTestPins()
	})
	h.r.PollWallet(context.Background())
	i := h.register()
	if rp := i.sign(minimalManifest()); rp.Status != http.StatusOK {
		t.Fatalf("sign: %d %s", rp.Status, rp.Raw)
	}
	_, res := i.notify(wire.WalletNotifyItem{Ref: "a", Token: passToken(0xab)})
	if len(res) != 1 || res[0].Result != wire.PassAccepted {
		t.Fatalf("notify: %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0].Host != "api.push.apple.com" || seen[0].Header.Get("apns-topic") != wallettest.PassTypeID ||
		!strings.HasSuffix(seen[0].URL.Path, passToken(0xab)) {
		t.Fatalf("Apple saw %d requests: %+v", len(seen), seen)
	}
}
