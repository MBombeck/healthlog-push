package relay

import (
	"net/http"
	"time"
)

// heldRefresh is how often the scrape takes its copy of every metric that is not in liveMetrics.
const heldRefresh = 5 * time.Minute

// HeldRefresh is the refresh period of the held metrics, for the test that holds docs/transparency.md to
// the code.
func HeldRefresh() time.Duration { return heldRefresh }

// MetricsHandler serves /metrics (127.0.0.1 only) and a local /healthz for the container health check.
func (r *Relay) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		now := r.cfg.Now()
		// The held gauges are computed only when the scrape is going to show them anew.
		if r.Metrics.HeldDue(now, heldRefresh) {
			r.usageGauges()
			r.Metrics.Set("hlp_queue_depth", float64(r.q.Len()))
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_ = r.Metrics.Write(w, now, heldRefresh)
	})
	mux.HandleFunc("GET /healthz", r.handleHealthz)
	return mux
}

// HealthStatus is the public /healthz body.
type HealthStatus struct {
	Status     string `json:"status"`
	DBWritable bool   `json:"db_writable"`
	APNsRecent bool   `json:"apns_recent"`
	Breaker    string `json:"breaker"`
	Delivery   string `json:"delivery"`
}

// Health returns the coarse public health. There is no time stamp in it.
func (r *Relay) Health() (HealthStatus, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	h := HealthStatus{DBWritable: r.dbWritable, APNsRecent: !r.apnsLastOK.IsZero() && now.Sub(r.apnsLastOK) < 15*time.Minute,
		Breaker: r.breaker.State(now), Delivery: r.deliveryLocked(now)}
	// The status, its HTTP code and the deploy gate depend only on the relay's own facts: a provider token
	// that Apple accepts and a writable store. The breaker and the delivery signal can be influenced by
	// third parties (instances sending traffic or reporting receipts), so they are shown but never turn the
	// status.
	switch {
	case r.misconfigured || (r.cfg.ProviderTokenOK != nil && !r.cfg.ProviderTokenOK()):
		h.Status = "down"
	case !h.DBWritable:
		h.Status = "degraded"
	default:
		h.Status = "ok"
	}
	return h, h.Status == "ok"
}

func (r *Relay) handleHealthz(w http.ResponseWriter, req *http.Request) {
	h, ok := r.Health()
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	r.reply(w, req, status, h)
}

func (r *Relay) handleVersion(w http.ResponseWriter, req *http.Request) {
	r.reply(w, req, http.StatusOK, map[string]string{"version": r.cfg.Version, "commit": r.cfg.Commit, "imageDigest": r.cfg.ImageDigest})
}
