package apns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// BenchmarkSend is one request to a fake Apple over TLS and HTTP/2 on loopback, with the production client
// settings: headers, the fixed payload, the answer read and classified. The fake answers at once, so the
// figure is the client's own cost and a loopback round trip, not Apple's.
func BenchmarkSend(b *testing.B) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	hc := NewHTTPClient(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	defer hc.CloseIdleConnections()
	c := &Client{HTTP: hc, BaseURL: srv.URL, Topic: "dev.example.app", Tokens: fixedTokens{}, OnConn: func(bool) {}}
	env := make([]byte, 1100)
	push := &Push{Token: make([]byte, 32), Payload: AlertPayload(env), Expiration: time.Now().Add(time.Hour), Collapse: "CCCCCCCCCCCCCCCCCCCCCC"}
	b.Run("serial", func(b *testing.B) {
		for b.Loop() {
			if r := c.Send(context.Background(), push); r.Outcome != Accepted {
				b.Fatalf("send: %+v", r)
			}
		}
	})
	b.Run("parallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if r := c.Send(context.Background(), push); r.Outcome != Accepted {
					b.Errorf("send: %+v", r)
					return
				}
			}
		})
	})
}
