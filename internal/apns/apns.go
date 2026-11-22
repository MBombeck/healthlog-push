// Package apns sends fixed-template notifications to Apple Push Notification service over one shared
// HTTP/2 client. The payloads are constants in this file: an instance can only choose the class, the
// opaque envelope, the lifetime and the collapse id, never any visible text, category or key in userInfo.
package apns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// RequestTimeout bounds a single request to Apple.
const RequestTimeout = 3 * time.Second

// Apple's endpoints. They are constants on purpose: no configuration can send the provider token and the
// device tokens to another host.
const (
	ProductionURL = "https://api.push.apple.com"
	SandboxURL    = "https://api.sandbox.push.apple.com"
)

// Outcome is the classified result of one send.
type Outcome string

// Outcomes. Only Unregistered is final.
const (
	Accepted        Outcome = "accepted"
	Unregistered    Outcome = "unregistered"      // 410: the token is gone; the only final deletion
	SoftInvalid     Outcome = "soft_invalid"      // BadDeviceToken, DeviceTokenNotForTopic
	DeviceThrottled Outcome = "device_throttled"  // 429 TooManyRequests for this token
	ProviderExpired Outcome = "provider_expired"  // 403 ExpiredProviderToken
	ProviderInvalid Outcome = "provider_invalid"  // 403 InvalidProviderToken
	ProviderTooMany Outcome = "provider_too_many" // 429 TooManyProviderTokenUpdates
	Rejected        Outcome = "rejected"          // other 4xx: a relay or request defect, nothing is deleted
	Unavailable     Outcome = "unavailable"       // 5xx, timeout, connection error
	NoProviderToken Outcome = "no_provider_token" // no JWT available from the signer
)

// Result is what a send returns: an outcome and Apple's reason from a closed set.
type Result struct {
	Outcome  Outcome
	Reason   string
	Latency  time.Duration
	TokenIat int64 // iat of the provider token used, to tell a rejected new token from a rejected old one
	// InvalidSince is Apple's `timestamp` on a 410: when APNs confirmed the token was no longer valid for
	// the topic. Zero when Apple sent none or an implausible one.
	InvalidSince time.Time
	// UniqueID is Apple's `apns-unique-id` response header, which Apple sends only in the development
	// environment, for a lookup in the delivery log of the Push Notifications Console. Empty otherwise.
	UniqueID string
}

// knownReasons is the closed set of Apple reasons the relay reports or logs; anything else becomes "other".
var knownReasons = map[string]bool{
	"BadCollapseId": true, "BadDeviceToken": true, "BadExpirationDate": true, "BadMessageId": true,
	"BadPriority": true, "BadTopic": true, "DeviceTokenNotForTopic": true, "DuplicateHeaders": true,
	"IdleTimeout": true, "InvalidPushType": true, "MissingDeviceToken": true, "MissingTopic": true,
	"PayloadEmpty": true, "TopicDisallowed": true, "BadCertificate": true, "BadCertificateEnvironment": true,
	"ExpiredProviderToken": true, "Forbidden": true, "InvalidProviderToken": true, "MissingProviderToken": true,
	"UnrelatedKeyIdInToken": true, "BadEnvironmentKeyInToken": true, "BadPath": true, "MethodNotAllowed": true,
	"ExpiredToken": true, "Unregistered": true, "PayloadTooLarge": true, "TooManyProviderTokenUpdates": true,
	"TooManyRequests": true, "InternalServerError": true, "ServiceUnavailable": true, "Shutdown": true,
}

// Classify maps an APNs status and reason to an outcome.
func Classify(status int, reason string) Outcome {
	switch {
	case status == http.StatusOK:
		return Accepted
	case status == http.StatusGone:
		return Unregistered
	case status == http.StatusBadRequest && (reason == "BadDeviceToken" || reason == "DeviceTokenNotForTopic"):
		return SoftInvalid
	case status == http.StatusForbidden && reason == "ExpiredProviderToken":
		return ProviderExpired
	case status == http.StatusForbidden && reason == "InvalidProviderToken":
		return ProviderInvalid
	case status == http.StatusTooManyRequests && reason == "TooManyProviderTokenUpdates":
		return ProviderTooMany
	case status == http.StatusTooManyRequests:
		return DeviceThrottled
	case status >= 500:
		return Unavailable
	default:
		return Rejected
	}
}

// Fixed payload templates (spec/protocol.md, "What the relay sends to Apple").
const (
	alertPrefix  = `{"aps":{"alert":{"loc-key":"HL_RELAY_ALERT"},"mutable-content":1,"sound":"default"},"e":"`
	silentPrefix = `{"aps":{"content-available":1},"e":"`
	suffix       = `"}`
)

// AlertPayload is the only alert payload the relay can produce.
func AlertPayload(envelope []byte) []byte {
	return []byte(alertPrefix + wire.EncodeB64(envelope) + suffix)
}

// SilentPayload is the only background payload the relay can produce.
func SilentPayload(envelope []byte) []byte {
	return []byte(silentPrefix + wire.EncodeB64(envelope) + suffix)
}

// ChallengePayload is the background push that carries a binding conflict challenge. The challenge is a
// random value generated by the relay, not content.
func ChallengePayload(challenge string) []byte {
	return []byte(`{"aps":{"content-available":1},"c":"` + challenge + `"}`)
}

// Push is one request to Apple.
type Push struct {
	Token      []byte
	Class      wire.Class
	Challenge  bool
	Payload    []byte
	Expiration time.Time
	Collapse   string
	Sandbox    bool
	// Urgent selects priority 10 for a Live Activity push; without it the push goes with priority 5, which
	// does not count against the device's Live Activity budget. See LiveActivityUrgent.
	Urgent bool
}

// TokenSource returns the current provider JWT.
type TokenSource interface {
	Token() (jwt string, iat int64, ok bool)
	RequestRefresh()
}

// Client sends to APNs.
type Client struct {
	HTTP *http.Client
	// BaseURL and SandboxURL are the production and sandbox endpoints: ProductionURL and SandboxURL in the
	// service, a fake server in tests.
	BaseURL    string
	SandboxURL string
	Topic      string // the app's bundle id
	Tokens     TokenSource

	// Until Apple has answered once, requests go out one at a time (warmMu), so the first connection is
	// set up once instead of by every concurrent sender. warm is set after the first attempt.
	warmMu sync.Mutex
	warm   atomic.Bool
}

// NewHTTPClient returns the shared HTTP/2 client: TLS 1.2+ (Apple's minimum), at most four connections,
// a new connection when the server's stream limit is reached, and a PING after an hour without traffic.
// No proxy is taken from the environment and idle connections are kept open. tlsCfg replaces the default
// TLS configuration when not nil (tests pass their own roots).
func NewHTTPClient(tlsCfg *tls.Config) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     4,
		MaxIdleConnsPerHost: 4,
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: time.Hour,
			PingTimeout:     15 * time.Second,
		},
		Protocols: protocolsHTTP2(),
	}
	if tlsCfg != nil {
		tr.TLSClientConfig = tlsCfg
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func protocolsHTTP2() *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP2(true)
	return p
}

// Send performs one request. It never retries; the instance owns retries and deadlines.
func (c *Client) Send(ctx context.Context, p *Push) Result {
	jwt, iat, ok := c.Tokens.Token()
	if !ok {
		return Result{Outcome: NoProviderToken}
	}
	if !c.warm.Load() {
		c.warmMu.Lock()
		defer c.warmMu.Unlock()
	}
	base := c.BaseURL
	if p.Sandbox {
		base = c.SandboxURL
	}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+hex.EncodeToString(p.Token), bytes.NewReader(p.Payload))
	if err != nil {
		return Result{Outcome: Rejected, Reason: "other"}
	}
	c.setHeaders(req.Header, p, jwt)
	start := time.Now()
	resp, err := c.HTTP.Do(req)
	lat := time.Since(start)
	// The first attempt ends the warm-up whatever its outcome, so an unreachable Apple at start cannot
	// serialize every sender behind one lock.
	c.warm.Store(true)
	if err != nil {
		return Result{Outcome: Unavailable, Reason: "transport", Latency: lat, TokenIat: iat}
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Reason    string `json:"reason"`
		Timestamp int64  `json:"timestamp"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = json.Unmarshal(b, &body)
	reason := body.Reason
	if reason != "" && !knownReasons[reason] {
		reason = "other"
	}
	out := Classify(resp.StatusCode, reason)
	if out == ProviderExpired {
		c.Tokens.RequestRefresh()
	}
	res := Result{Outcome: out, Reason: reason, Latency: lat, TokenIat: iat, UniqueID: uniqueID(resp.Header.Get("apns-unique-id"))}
	if out == Unregistered {
		res.InvalidSince = invalidSince(body.Timestamp)
	}
	return res
}

// uniqueID returns Apple's apns-unique-id when it is a canonical UUID, otherwise nothing: the value is only
// ever kept and shown, so anything outside that shape is dropped rather than stored.
func uniqueID(v string) string {
	if len(v) != 36 {
		return ""
	}
	for i, ch := range v {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if ch != '-' {
				return ""
			}
		case ch >= '0' && ch <= '9', ch >= 'a' && ch <= 'f', ch >= 'A' && ch <= 'F':
		default:
			return ""
		}
	}
	return strings.ToLower(v)
}

// invalidSince converts Apple's 410 timestamp (milliseconds since the epoch) to a time. A value that is
// missing or before 2015 (when the HTTP/2 provider API started, so also a value sent in seconds) is treated
// as absent. A broken value can therefore only make the relay fall back to deleting: a time in the future
// never lies before a binding day.
func invalidSince(ms int64) time.Time {
	t := time.UnixMilli(ms)
	if ms <= 0 || t.Year() < 2015 {
		return time.Time{}
	}
	return t
}

// setHeaders sets the APNs request headers of p: provider token, expiration, push type, priority, topic
// and collapse id. No apns-id is sent.
func (c *Client) setHeaders(h http.Header, p *Push, jwt string) {
	h.Set("authorization", "bearer "+jwt)
	h.Set("content-type", "application/json")
	h.Set("apns-expiration", strconv.FormatInt(p.Expiration.Unix(), 10))
	switch {
	case p.Challenge || p.Class == wire.ClassSilent:
		h.Set("apns-push-type", "background")
		h.Set("apns-priority", "5")
		h.Set("apns-topic", c.Topic)
	case p.Class == wire.ClassAlert:
		h.Set("apns-push-type", "alert")
		h.Set("apns-priority", "10")
		h.Set("apns-topic", c.Topic)
	case p.Class == wire.ClassLiveActivity:
		h.Set("apns-push-type", "liveactivity")
		if p.Urgent {
			h.Set("apns-priority", "10")
		} else {
			h.Set("apns-priority", "5")
		}
		h.Set("apns-topic", c.Topic+".push-type.liveactivity")
	}
	if p.Collapse != "" {
		h.Set("apns-collapse-id", p.Collapse)
	}
}

// FileTokens reads the JWT the signer writes to a shared tmpfs and asks for a refresh by creating an empty
// marker file in a second directory. It never sees the signing key.
type FileTokens struct {
	Dir        string
	RefreshDir string
	mu         sync.Mutex
	cached     string
	iat        int64
	readAt     time.Time
}

// Token returns the current JWT if it is younger than 55 minutes.
func (f *FileTokens) Token() (string, int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.readAt) > 10*time.Second || f.cached == "" {
		if b, err := os.ReadFile(filepath.Join(f.Dir, "token")); err == nil {
			s := strings.TrimSpace(string(b))
			if iat, err := wire.JWTIssuedAt(s); err == nil {
				f.cached, f.iat = s, iat
			}
		}
		f.readAt = time.Now()
	}
	if f.cached == "" || time.Now().Unix()-f.iat > 55*60 {
		return "", 0, false
	}
	return f.cached, f.iat, true
}

// RequestRefresh creates the refresh marker. The signer honors it at most every 20 minutes.
func (f *FileTokens) RequestRefresh() {
	if f.RefreshDir == "" {
		return
	}
	name := filepath.Join(f.RefreshDir, "refresh")
	fh, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o640) //nolint:gosec // fixed name
	if err == nil {
		_ = fh.Close()
		now := time.Now()
		_ = os.Chtimes(name, now, now)
	}
	f.mu.Lock()
	f.readAt = time.Time{}
	f.mu.Unlock()
}
