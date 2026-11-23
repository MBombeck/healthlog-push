package relay

import (
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/buildinfo"
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

// VersionInfo is the public /version body: enough to match the running relay to a signed release
// (docs/verify.md), and nothing about its configuration, its host or anyone using it.
type VersionInfo struct {
	Version     string `json:"version"`
	Commit      string `json:"commit"`
	ImageDigest string `json:"imageDigest"`
	// BinarySHA256 is the SHA-256 of the running executable, hashed by the process at start; the release
	// lists the same value in SHA256SUMS. Absent when the file could not be read.
	BinarySHA256 string `json:"binarySha256,omitempty"`
	Platform     string `json:"platform"`
	GoVersion    string `json:"goVersion"`
}

func (r *Relay) handleVersion(w http.ResponseWriter, req *http.Request) {
	r.reply(w, req, http.StatusOK, VersionInfo{Version: r.cfg.Version, Commit: r.cfg.Commit, ImageDigest: r.cfg.ImageDigest,
		BinarySHA256: r.cfg.BinarySHA256, Platform: buildinfo.Platform(), GoVersion: buildinfo.GoVersion()})
}
