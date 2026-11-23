package apns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// stallProxy forwards TCP between the client and a server. While frozen it drops everything the server
// sends, so the connection stays open but HTTP/2 goes silent, including PING acknowledgements.
type stallProxy struct {
	ln             net.Listener
	frozen         atomic.Bool
	opened, closed atomic.Int32
}

func newStallProxy(t *testing.T, target string) *stallProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &stallProxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.opened.Add(1)
			s, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			go func() { // server to client, dropped while frozen
				buf := make([]byte, 32<<10)
				for {
					n, err := s.Read(buf)
					if n > 0 && !p.frozen.Load() {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
			go func() { // client to server; ends when the client closes the connection
				_, _ = io.Copy(s, c)
				p.closed.Add(1)
				_ = s.Close()
				_ = c.Close()
			}()
		}
	}()
	return p
}

func pingTestClient(t *testing.T) (*http.Client, *stallProxy) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	p := newStallProxy(t, srv.Listener.Addr().String())
	c := newHTTPClient(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, 100*time.Millisecond, 100*time.Millisecond)
	t.Cleanup(c.CloseIdleConnections)
	return c, p
}

func get(t *testing.T, c *http.Client, addr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", http.NoBody)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK {
		t.Fatalf("got %s %d", resp.Proto, resp.StatusCode)
	}
}

// TestUnansweredPingDropsConnection: an idle connection whose PING goes unanswered is closed by the client,
// and the next request opens a new one instead of waiting on the dead one.
func TestUnansweredPingDropsConnection(t *testing.T) {
	c, p := pingTestClient(t)
	addr := p.ln.Addr().String()
	get(t, c, addr)
	p.frozen.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	for p.closed.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the client kept a connection whose PING was not answered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	p.frozen.Store(false)
	get(t, c, addr)
	if n := p.opened.Load(); n != 2 {
		t.Fatalf("%d connections opened, want 2", n)
	}
}

// TestAnsweredPingKeepsConnection: a healthy idle connection answers its PINGs and is reused.
func TestAnsweredPingKeepsConnection(t *testing.T) {
	c, p := pingTestClient(t)
	addr := p.ln.Addr().String()
	get(t, c, addr)
	time.Sleep(600 * time.Millisecond) // several ping intervals
	get(t, c, addr)
	if o, cl := p.opened.Load(), p.closed.Load(); o != 1 || cl != 0 {
		t.Fatalf("opened %d, closed %d; want the one connection kept", o, cl)
	}
}

func TestSharedClientPingSettings(t *testing.T) {
	tr, ok := NewHTTPClient(nil).Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	h2 := tr.HTTP2
	if h2.SendPingTimeout != PingAfterIdle || h2.PingTimeout != PingTimeout {
		t.Fatalf("ping after %v, timeout %v", h2.SendPingTimeout, h2.PingTimeout)
	}
	if PingAfterIdle < time.Minute || PingAfterIdle > 5*time.Minute {
		t.Fatalf("PingAfterIdle %v outside 1 to 5 minutes", PingAfterIdle)
	}
}
