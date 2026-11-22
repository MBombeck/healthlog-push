package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"slices"
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
	// maxBufferedBodies caps the request bodies held in memory at the same time across all connections,
	// well below the container's memory limit.
	maxBufferedBodies = 32 << 20
	// maxResponseBytes is the documented upper bound of any relay response body (spec/protocol.md); a
	// client may refuse anything longer.
	maxResponseBytes = 64 << 10
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
	mux.HandleFunc("POST /v1/bindings/liveactivity", r.handleLAConsent)
	mux.HandleFunc("DELETE /v1/bindings/liveactivity", r.handleLAConsentRemove)
	mux.HandleFunc("DELETE /v1/bindings/self/liveactivity", r.handleLAWithdrawSelf)
	mux.HandleFunc("POST /v1/push", r.handlePush)
	mux.HandleFunc("POST /v1/receipts", r.handleReceipts)
	mux.HandleFunc("GET /v1/status", r.handleStatus)
	mux.HandleFunc("GET /healthz", r.handleHealthz)
	mux.HandleFunc("GET /version", r.handleVersion)
	mux.HandleFunc("GET /privacy", textPage(notice.Privacy))
	mux.HandleFunc("GET /terms", textPage(notice.Terms))
	mux.HandleFunc("GET /.well-known/security.txt", textPage(notice.SecurityTxt))
	mux.HandleFunc("GET /{$}", textPage(notice.Index))
	return r.edge(mux)
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

// requestNonce is the nonce the response signature binds to: the HL-Nonce header when well formed, else "-"
// (only possible on /healthz, /version and the nonce_required refusal).
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
		if body, err = json.Marshal(v); err != nil || len(body) > maxResponseBytes {
			// The documented maximum is a promise to clients; nothing larger ever leaves the relay.
			status, body = http.StatusInternalServerError, []byte(`{"error":"internal"}`)
		}
	}
	h := w.Header()
	if len(body) > 0 {
		h.Set("Content-Type", "application/json")
	}
	text := wire.ResponseText(r.cfg.Host, req.Method, req.RequestURI, requestNonce(req), status, body)
	h.Set("HL-Relay-Signature", wire.EncodeB64(ed25519.Sign(r.cfg.Identity, []byte(text))))
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
	r.Metrics.Inc("hlp_requests_total", "status", strconv.Itoa(status/100)+"xx")
}

// errStorage is the refusal while the store does not accept writes; a positive retry adds a retry hint.
func errStorage(retry time.Duration) errBody {
	e := errBody{Error: "storage_unavailable"}
	if retry > 0 {
		e.RetryAfter = jitter(retry)
	}
	return e
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

func (r *Relay) reserveBody(n int64) bool {
	if r.bodyBytes.Add(n) > maxBufferedBodies {
		r.bodyBytes.Add(-n)
		return false
	}
	return true
}

func (r *Relay) releaseBody(n int64) { r.bodyBytes.Add(-n) }

// readBody reads a body whose declared length the handler wrapper has already checked and reserved.
func readBody(w http.ResponseWriter, req *http.Request, limit int64) ([]byte, bool) {
	if req.ContentLength > limit {
		return nil, false
	}
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

// auth verifies an instance request (spec/protocol.md, "Request signing"). Order: known instance and time
// window from the headers, declared length, body, signature, tier, request rate, nonce. The signature is
// always verified: a valid request is never refused because of someone else's failed attempts. It writes
// the error response itself.
func (r *Relay) auth(w http.ResponseWriter, req *http.Request, limit int64) (*instState, []byte, bool) {
	now := r.cfg.Now()
	id := req.Header.Get("HL-Instance")
	r.mu.Lock()
	var key []byte
	if s := r.instances[id]; s != nil {
		key = s.rec.PublicKey
	}
	r.mu.Unlock()
	if !wire.ValidInstanceID(id) || key == nil {
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "unknown_instance"})
		return nil, nil, false
	}
	ts, err := wire.ParseUnix(req.Header.Get("HL-Timestamp"))
	if err != nil || !wire.WithinSkew(ts, now.Unix()) || ts < r.started.Unix() {
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "stale_timestamp", RelayTime: now.Unix()})
		return nil, nil, false
	}
	body, ok := readBody(w, req, limit)
	if !ok {
		r.fail(w, req, http.StatusRequestEntityTooLarge, errBody{Error: "too_large"})
		return nil, nil, false
	}
	nonce, nerr := wire.ParseNonce(req.Header.Get("HL-Nonce"))
	sig, serr := wire.ParseSignature(req.Header.Get("HL-Signature"))
	// Verified outside the lock: a flood of bad signatures must not serialize the relay.
	valid := nerr == nil && serr == nil && wire.Verify(key, wire.RequestText(r.cfg.Host, id, req.Method, req.RequestURI, ts, nonce, body), sig)
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.instances[id]
	if s == nil {
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "unknown_instance"})
		return nil, nil, false
	}
	if !valid || !bytes.Equal(s.rec.PublicKey, key) { // a rotation in between invalidates the old key
		// The bucket only limits how often failures are counted; it never refuses anyone.
		if s.badSig.Allow(now) {
			r.Metrics.Inc("hlp_auth_failures_total", "reason", "bad_signature")
		}
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "bad_signature"})
		return nil, nil, false
	}
	if status, e := r.admitRequestLocked(s, nonce, now); e != nil {
		r.fail(w, req, status, *e)
		return nil, nil, false
	}
	if r.clientTooOld(req) {
		r.fail(w, req, http.StatusUpgradeRequired, errBody{Error: "min_server_version"})
		return nil, nil, false
	}
	if wk := store.Week(store.Day(now)); s.rec.LastSeenWeek != wk {
		s.rec.LastSeenWeek = wk
		r.dirtyInst[s.rec.ID] = true
	}
	r.rollInstanceDay(s, now)
	return s, body, true
}

// stillThere reports whether s is still the live record of its instance. Handlers that release the lock
// after auth and take it again check this first: a concurrent deletion must not be undone by a later write.
// Caller holds r.mu.
func (r *Relay) stillThere(s *instState) bool { return r.instances[s.rec.ID] == s }

// admitRequestLocked applies, to a verified request of instance s, the tier, the request rate and the
// nonce rules, and records the nonce.
func (r *Relay) admitRequestLocked(s *instState, nonce string, now time.Time) (int, *errBody) {
	switch s.rec.Tier {
	case store.TierRevoked:
		return http.StatusForbidden, &errBody{Error: "instance_revoked"}
	case store.TierSuspended:
		return http.StatusForbidden, &errBody{Error: "instance_suspended", Reason: s.rec.Reason}
	}
	tl := r.tierLimits(s.rec)
	if !s.reqMin.Allow(now, tl.RequestsMinute) {
		r.rateLimited(surfaceInstanceRequests)
		return http.StatusTooManyRequests, &errBody{Error: "instance_rate", Scope: "instance", RetryAfter: jitter(s.reqMin.RetryAfter(now)), Limits: &tl}
	}
	if _, seen := s.nonces[nonce]; seen {
		return http.StatusUnauthorized, &errBody{Error: "replayed"}
	}
	r.pruneNonces(s, now)
	if len(s.nonces) >= noncePerInst || r.nonceTotal >= nonceTotalMax {
		return http.StatusServiceUnavailable, &errBody{Error: "overloaded", RetryAfter: jitter(5 * time.Second)}
	}
	s.nonces[nonce] = now.Unix() + 2*wire.ClockSkew
	r.nonceTotal++
	return 0, nil
}

// clientTooOld reports whether a minimum server version is configured and the HL-Client header does not
// meet it.
func (r *Relay) clientTooOld(req *http.Request) bool {
	minVer := r.cfg.MinClient
	if minVer == [3]int{} {
		return false
	}
	_, ver, err := wire.ParseClient(req.Header.Get("HL-Client"))
	return err != nil || slices.Compare(ver[:], minVer[:]) < 0
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
		s.day, s.newBindings, s.invalid, s.challenges = d, 0, 0, 0
	}
}
