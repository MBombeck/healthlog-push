package relay

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/MBombeck/healthlog-push/internal/notice"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// Body limits.
const (
	maxPushBody  = 128 << 10
	maxOtherBody = 4 << 10
)

// Handler returns the public HTTP handler.
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/instances", r.handleRegister)
	mux.HandleFunc("POST /v1/instances/self/rotate", r.handleRotate)
	mux.HandleFunc("DELETE /v1/instances/self", r.handleDeleteInstance)
	mux.HandleFunc("POST /v1/bindings", r.handleBind)
	mux.HandleFunc("DELETE /v1/bindings", r.handleUnbindByInstance)
	mux.HandleFunc("POST /v1/bindings/challenge", r.handleChallenge)
	mux.HandleFunc("DELETE /v1/bindings/self", r.handleUnbindSelf)
	mux.HandleFunc("GET /v1/bindings/self", r.handleSelfRead)
	mux.HandleFunc("POST /v1/push", r.handlePush)
	mux.HandleFunc("POST /v1/receipts", r.handleReceipts)
	mux.HandleFunc("GET /v1/status", r.handleStatus)
	mux.HandleFunc("GET /healthz", r.handleHealthz)
	mux.HandleFunc("GET /version", r.handleVersion)
	mux.HandleFunc("GET /privacy", textPage(notice.Privacy))
	mux.HandleFunc("GET /terms", textPage(notice.Terms))
	mux.HandleFunc("GET /{$}", textPage(notice.Index))
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Content-Security-Policy", "default-src 'none'")
		if _, pattern := mux.Handler(req); pattern == "" {
			r.fail(w, req, http.StatusNotFound, errBody{Error: "not_found"})
			return
		}
		mux.ServeHTTP(w, req)
	})
}

func textPage(s string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, s)
	}
}

// errBody is the error envelope of every refused request or item.
type errBody struct {
	Error      string      `json:"error"`
	Scope      string      `json:"scope,omitempty"`
	RetryAfter int         `json:"retryAfter,omitempty"`
	RelayTime  int64       `json:"relayTime,omitempty"`
	Reason     string      `json:"reason,omitempty"`
	Limits     *TierLimits `json:"limits,omitempty"`
}

// requestNonce is the nonce the response signature binds to: the HL-Nonce header when well formed, else "-".
func requestNonce(req *http.Request) string {
	if n, err := wire.ParseNonce(req.Header.Get("HL-Nonce")); err == nil {
		return n
	}
	return "-"
}

// reply writes a JSON body signed with the relay identity key over host, request nonce, status and body.
func (r *Relay) reply(w http.ResponseWriter, req *http.Request, status int, v any) {
	var body []byte
	if v != nil {
		var err error
		if body, err = json.Marshal(v); err != nil {
			status, body = http.StatusInternalServerError, []byte(`{"error":"internal"}`)
		}
	}
	h := w.Header()
	if len(body) > 0 {
		h.Set("Content-Type", "application/json")
	}
	h.Set("HL-Relay-Signature", wire.EncodeB64(ed25519.Sign(r.cfg.Identity, []byte(wire.ResponseText(r.cfg.Host, requestNonce(req), status, body)))))
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
	r.M.Inc("hlp_requests_total", "status", strconv.Itoa(status/100)+"xx")
}

func (r *Relay) fail(w http.ResponseWriter, req *http.Request, status int, e errBody) {
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.RetryAfter))
	}
	r.reply(w, req, status, e)
}

// jitter spreads a retry hint by plus or minus 30 % so that refused clients do not return in step.
func jitter(d time.Duration) int {
	s := d.Seconds()
	if s < 1 {
		s = 1
	}
	return max(1, int(s*(0.7+0.6*rand.Float64()))) //nolint:gosec // jitter, not security
}

func readBody(w http.ResponseWriter, req *http.Request, limit int64) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, req.Body, limit))
	if err != nil {
		return nil, false
	}
	return b, true
}

// remoteAddr is the only place that reads the client address; it is used for the registration limiter and
// never stored or logged.
func remoteAddr(req *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr()
}

// auth verifies an instance request (spec/protocol.md, "Request signing"). Order: body size, known instance,
// time window, signature budget, signature, tier, request rate, nonce. It writes the error response itself.
func (r *Relay) auth(w http.ResponseWriter, req *http.Request, limit int64) (*instState, []byte, bool) {
	body, ok := readBody(w, req, limit)
	if !ok {
		r.fail(w, req, http.StatusRequestEntityTooLarge, errBody{Error: "too_large"})
		return nil, nil, false
	}
	now := r.cfg.Now()
	id := req.Header.Get("HL-Instance")
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.instances[id]
	if !wire.ValidInstanceID(id) || s == nil {
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "unknown_instance"})
		return nil, nil, false
	}
	ts, err := wire.ParseUnix(req.Header.Get("HL-Timestamp"))
	if err != nil || !wire.WithinSkew(ts, now.Unix()) || ts < r.started.Unix() {
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "stale_timestamp", RelayTime: now.Unix()})
		return nil, nil, false
	}
	if !s.badSig.Peek(now) {
		r.fail(w, req, http.StatusTooManyRequests, errBody{Error: "instance_rate", Scope: "instance", RetryAfter: jitter(s.badSig.RetryAfter(now))})
		return nil, nil, false
	}
	nonce, nerr := wire.ParseNonce(req.Header.Get("HL-Nonce"))
	sig, serr := wire.ParseSignature(req.Header.Get("HL-Signature"))
	if nerr != nil || serr != nil || !wire.Verify(s.rec.PublicKey, wire.RequestText(r.cfg.Host, id, req.Method, req.RequestURI, ts, nonce, body), sig) {
		s.badSig.Allow(now)
		r.M.Inc("hlp_auth_failures_total", "reason", "bad_signature")
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "bad_signature"})
		return nil, nil, false
	}
	switch s.rec.Tier {
	case store.TierRevoked:
		r.fail(w, req, http.StatusForbidden, errBody{Error: "instance_revoked"})
		return nil, nil, false
	case store.TierSuspended:
		r.fail(w, req, http.StatusForbidden, errBody{Error: "instance_suspended", Reason: s.rec.Reason})
		return nil, nil, false
	}
	tl := r.tierLimits(s.rec)
	if !s.reqMin.Allow(now, tl.RequestsMinute) {
		r.fail(w, req, http.StatusTooManyRequests, errBody{Error: "instance_rate", Scope: "instance", RetryAfter: jitter(s.reqMin.RetryAfter(now)), Limits: &tl})
		return nil, nil, false
	}
	if _, seen := s.nonces[nonce]; seen {
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "replayed"})
		return nil, nil, false
	}
	r.pruneNonces(s, now)
	if len(s.nonces) >= noncePerInst || r.nonceTotal >= nonceTotalMax {
		r.fail(w, req, http.StatusServiceUnavailable, errBody{Error: "overloaded", RetryAfter: jitter(5 * time.Second)})
		return nil, nil, false
	}
	s.nonces[nonce] = now.Unix() + 2*wire.ClockSkew
	r.nonceTotal++
	if minVer := r.cfg.MinClient; minVer != [3]int{} {
		_, ver, err := wire.ParseClient(req.Header.Get("HL-Client"))
		if err != nil || less(ver, minVer) {
			r.fail(w, req, http.StatusUpgradeRequired, errBody{Error: "min_server_version"})
			return nil, nil, false
		}
	}
	s.rec.LastSeenWeek = store.Week(store.Day(now))
	r.rollInstanceDay(s, now)
	return s, body, true
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func (r *Relay) pruneNonces(s *instState, now time.Time) {
	if len(s.nonces) < noncePerInst/2 {
		return
	}
	for n, exp := range s.nonces {
		if exp < now.Unix() {
			delete(s.nonces, n)
			r.nonceTotal--
		}
	}
}

func (r *Relay) rollInstanceDay(s *instState, now time.Time) {
	if d := store.Day(now); d != s.day {
		s.day, s.newBindings, s.invalid, s.challenges, s.flaggedToday = d, 0, 0, 0, false
	}
}

// appDirect limits the unauthenticated app endpoints globally; per-device checks follow in the handler.
func (r *Relay) appDirectAllowed(w http.ResponseWriter, req *http.Request) bool {
	r.mu.Lock()
	ok := r.appDirect.Allow(r.cfg.Now())
	r.mu.Unlock()
	if !ok {
		r.fail(w, req, http.StatusTooManyRequests, errBody{Error: "global", Scope: "global", RetryAfter: jitter(2 * time.Second)})
	}
	return ok
}
