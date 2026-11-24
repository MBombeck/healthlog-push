package apns

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// PassUpdateBody is the only body of a Wallet pass update push: an empty dictionary, as Apple's PassKit web
// service documentation requires. Wallet then asks the instance for the changed pass; nothing else travels.
const PassUpdateBody = "{}"

// NewTunnelHTTPClient is the HTTP/2 client of the wallet process: the APNs client above, with every
// connection dialed by dial (the relay's byte tunnel) and at most two connections.
func NewTunnelHTTPClient(tlsCfg *tls.Config, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	c := newHTTPClient(tlsCfg, PingAfterIdle, PingTimeout)
	if tr, ok := c.Transport.(*http.Transport); ok {
		tr.DialContext = dial
		tr.MaxConnsPerHost, tr.MaxIdleConnsPerHost = 2, 2
	}
	return c
}

// SetPassUpdateHeaders sets the headers of a pass update push: the Pass Type ID as topic and the content
// type. No apns-push-type, no priority, no expiration: Apple's documented pass push carries none of them.
func SetPassUpdateHeaders(h http.Header, passTypeID string) {
	h.Set("apns-topic", passTypeID)
	h.Set("content-type", "application/json")
}

// SendPassUpdate sends one pass update push to base (ProductionURL in service) and returns accepted,
// unregistered, rejected or unavailable. A 410, or a token Apple calls bad or not for this topic, is
// unregistered: the instance drops the registration, and Wallet registers again with a fresh token.
func SendPassUpdate(ctx context.Context, hc *http.Client, base, passTypeID string, token []byte) string {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+hex.EncodeToString(token), strings.NewReader(PassUpdateBody))
	if err != nil {
		return wire.PassRejected
	}
	SetPassUpdateHeaders(req.Header, passTypeID)
	resp, err := hc.Do(req)
	if err != nil {
		return wire.PassUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Reason string `json:"reason"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = json.Unmarshal(b, &body)
	switch out := Classify(resp.StatusCode, body.Reason); out {
	case Accepted:
		return wire.PassAccepted
	case Unregistered, SoftInvalid:
		return wire.PassUnregistered
	case Unavailable, DeviceThrottled, ProviderTooMany:
		return wire.PassUnavailable
	default:
		return wire.PassRejected
	}
}
