package apns

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// TestPassPushTemplate: a pass update push is POST /3/device/<token> with the body {} and exactly the
// headers apns-topic (the Pass Type ID) and content-type: no push type, no priority, no expiration, no
// collapse id, nothing an instance chose. The answer maps to a closed set of results.
func TestPassPushTemplate(t *testing.T) {
	if PassUpdateBody != "{}" {
		t.Fatalf("body %q", PassUpdateBody)
	}
	h := http.Header{}
	SetPassUpdateHeaders(h, "pass.org.example.test")
	if len(h) != 2 || h.Get("apns-topic") != "pass.org.example.test" || h.Get("content-type") != "application/json" {
		t.Fatalf("headers %v", h)
	}
	var got []*http.Request
	var bodies []string
	type answer struct {
		status int
		reason string
	}
	answers := map[string]answer{"01": {200, ""}, "02": {410, "Unregistered"}, "03": {400, "DeviceTokenNotForTopic"},
		"04": {403, "BadCertificate"}, "05": {429, "TooManyRequests"}, "06": {500, "InternalServerError"}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, bodies = append(got, r), append(bodies, string(b))
		a := answers[strings.TrimPrefix(r.URL.Path, "/3/device/")[:2]]
		w.WriteHeader(a.status)
		_, _ = io.WriteString(w, `{"reason":"`+a.reason+`"}`)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	tr, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("test client transport")
	}
	roots := tr.TLSClientConfig.RootCAs
	hc := NewTunnelHTTPClient(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, ServerName: "example.com"},
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		})
	want := map[string]string{"01": wire.PassAccepted, "02": wire.PassUnregistered, "03": wire.PassUnregistered, "04": wire.PassRejected,
		"05": wire.PassUnavailable, "06": wire.PassUnavailable}
	for pre, w := range want {
		tok := make([]byte, 32)
		tok[0] = pre[1] - '0' // hex of the token starts with pre
		if r := SendPassUpdate(context.Background(), hc, "https://example.com", "pass.org.example.test", tok); r != w {
			t.Errorf("%s: %s, want %s", pre, r, w)
		}
	}
	for i, r := range got {
		if r.Method != http.MethodPost || r.ProtoMajor != 2 || bodies[i] != "{}" || r.Header.Get("apns-push-type") != "" || r.Header.Get("apns-priority") != "" ||
			r.Header.Get("apns-expiration") != "" || r.Header.Get("authorization") != "" || r.Header.Get("apns-topic") != "pass.org.example.test" {
			t.Fatalf("request %d: %s %s %v %q", i, r.Method, r.Proto, r.Header, bodies[i])
		}
	}
	if r := SendPassUpdate(context.Background(), &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, io.ErrUnexpectedEOF
	}}}, "https://example.com", "pass.x", []byte{1}); r != wire.PassUnavailable {
		t.Fatalf("transport error: %s", r)
	}
	if r := SendPassUpdate(context.Background(), hc, "://bad", "pass.x", []byte{1}); r != wire.PassRejected {
		t.Fatalf("bad url: %s", r)
	}
}
