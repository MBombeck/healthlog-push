package wallet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// pushParallel bounds the pass pushes of one request in flight at once; they share one HTTP/2 connection.
const pushParallel = 16

// Notifier sends pass update pushes over HTTP/2 to Apple. Its connections go through the relay's byte
// tunnel (a unix socket); TLS is negotiated here, with the pass certificate as the client certificate, so
// the relay carries bytes it cannot read.
type Notifier struct {
	HTTP  *http.Client
	Base  string // apns.ProductionURL; a test server in tests
	Topic string // the Pass Type ID
}

// NewNotifier returns a notifier that dials the tunnel socket for every connection. roots nil means the
// system roots (the image's CA bundle).
func NewNotifier(id *Identity, tunnel string, roots *x509.CertPool) *Notifier {
	cert := tls.Certificate{Certificate: [][]byte{id.Cert.Raw, id.Intermediate.Raw}, PrivateKey: id.Key, Leaf: id.Cert}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, RootCAs: roots}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", tunnel)
	}
	return &Notifier{HTTP: apns.NewTunnelHTTPClient(cfg, dial), Base: apns.ProductionURL, Topic: id.PassTypeID}
}

// Push sends one empty pass update push per token and returns one result per token, in order.
func (n *Notifier) Push(ctx context.Context, tokens [][]byte) []string {
	out := make([]string, len(tokens))
	sem := make(chan struct{}, pushParallel)
	var wg sync.WaitGroup
	for i, t := range tokens {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			out[i] = apns.SendPassUpdate(ctx, n.HTTP, n.Base, n.Topic, t)
		}()
	}
	wg.Wait()
	return out
}

// logRequest writes one line per request: the operation, a result from a closed set and a coarse duration.
// No instance, no hash, no token: the wallet process is never told who asked.
func logRequest(op string, rep *wire.WalletReply, d time.Duration) {
	result := "ok"
	switch {
	case rep.Error == wire.WalletErrManifest:
		result = rep.Reason
	case rep.Error != "":
		result = rep.Error
	}
	if op != wire.WalletOpSign && op != wire.WalletOpNotify && op != wire.WalletOpInfo {
		op = "other"
	}
	if op == wire.WalletOpInfo && result == "ok" {
		return // the relay asks every minute; that is no event
	}
	logx.Event("wallet.request", logx.Str(logx.KOp, op), logx.Str(logx.KResult, result), logx.Str(logx.KDuration, durationBucket(d)))
}

func durationBucket(d time.Duration) string {
	switch {
	case d < 100*time.Millisecond:
		return "lt_100ms"
	case d < time.Second:
		return "lt_1s"
	}
	return "ge_1s"
}
