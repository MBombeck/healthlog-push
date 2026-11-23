package apns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

// TestOnConnTellsNewFromReused: the first request opens a connection, the next ones reuse it, and the
// first request of a fresh client opens a new one again. OnConn sees exactly that, once per request.
func TestOnConnTellsNewFromReused(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hc := NewHTTPClient(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	var mu sync.Mutex
	var seen []bool
	c := &Client{HTTP: hc, BaseURL: srv.URL, Topic: "t", Tokens: fixedTokens{},
		OnConn: func(reused bool) { mu.Lock(); seen = append(seen, reused); mu.Unlock() }}
	send := func() {
		if r := c.Send(context.Background(), &Push{Token: []byte{1}, Payload: []byte("{}"), Expiration: time.Now()}); r.Outcome != Accepted {
			t.Fatalf("send: %+v", r)
		}
	}
	send()
	send()
	send()
	// A fresh client has no connection yet, so its first request opens one again.
	hc.CloseIdleConnections()
	c.HTTP = NewHTTPClient(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	defer c.HTTP.CloseIdleConnections()
	send()
	mu.Lock()
	defer mu.Unlock()
	if want := []bool{false, true, true, false}; !slices.Equal(seen, want) {
		t.Fatalf("OnConn saw %v, want %v", seen, want)
	}
}

// TestSendWithoutOnConn: a client without the hook sends as before.
func TestSendWithoutOnConn(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c := &Client{HTTP: NewHTTPClient(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}), BaseURL: srv.URL, Topic: "t", Tokens: fixedTokens{}}
	if r := c.Send(context.Background(), &Push{Token: []byte{1}, Payload: []byte("{}"), Expiration: time.Now()}); r.Outcome != Accepted {
		t.Fatalf("send: %+v", r)
	}
}
