package relay

import (
	"net/http"
	"time"
)

// appFailLocked answers a failed app-direct request. Failures are charged to one global bucket; when it is
// empty the answer becomes 429 global. A request that verifies is never charged here, so junk traffic cannot
// block a device's opt-out, self-read or challenge answer. Caller holds r.mu.
func (r *Relay) appFailLocked(w http.ResponseWriter, req *http.Request, status int, e errBody) {
	if !r.appDirect.Allow(r.cfg.Now()) {
		r.fail(w, req, http.StatusTooManyRequests, errBody{Error: "global", Scope: "global", RetryAfter: jitter(2 * time.Second)})
		return
	}
	r.fail(w, req, status, e)
}

// appFail is appFailLocked for callers that do not hold r.mu.
func (r *Relay) appFail(w http.ResponseWriter, req *http.Request, status int, e errBody) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.appFailLocked(w, req, status, e)
}

// appAllowedLocked applies the per-device bucket to a verified app-direct request. Caller holds r.mu.
func (r *Relay) appAllowedLocked(w http.ResponseWriter, req *http.Request, m string) bool {
	now := r.cfg.Now()
	d := r.dev(m)
	if !d.app.Allow(now) {
		r.fail(w, req, http.StatusTooManyRequests, errBody{Error: "device_quota", Scope: "device", RetryAfter: jitter(d.app.RetryAfter(now))})
		return false
	}
	return true
}
