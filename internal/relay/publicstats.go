package relay

import (
	"encoding/json"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
)

// Public statistics at GET /stats (docs/api.md, "GET /stats"): day aggregates of the relay's work, for
// anyone, off unless the operator turns them on. They never name an instance, a device or a time of day,
// and they are shown only while enough HealthLog servers use the relay that no figure is one server's.

// statsMinInstances is the floor: below it /stats shows no figure at all, and a window in which fewer
// servers sent a push shows none for that window. With one or two servers, every total would be that
// household's.
const statsMinInstances = 3

// statsRefresh is how long a computed answer is served before it is computed again. The figures cover
// completed days only, so a fresh computation changes them at most once a day.
const statsRefresh = 15 * time.Minute

// latencyDaysKept is how many days of the per-day latency histogram stay in memory.
const latencyDaysKept = 31

// StatsWindows are the windows /stats reports, in completed days.
var statsWindows = []struct {
	name string
	days int
}{{"7d", 7}, {"30d", 30}}

// appleResults are the day-counter results of items that went to Apple, the denominator of every share.
var (
	resultsFailed    = []string{"apns_unavailable", "apns_rejected", "relay_misconfigured"}
	resultsTokenGone = []string{"unregistered", "soft_invalid", "activity_gone"}
)

// latencyDays keeps, per UTC day, the delivery latency in the buckets of hlp_delivery_latency_seconds plus
// one beyond the last bound. It is memory only: after a restart the days before it are gone, and /stats
// says how many days its percentiles cover.
type latencyDays struct {
	mu   sync.Mutex
	days map[int][]uint64
}

func (l *latencyDays) observe(day int, seconds float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.days == nil {
		l.days = map[int][]uint64{}
	}
	c := l.days[day]
	if c == nil {
		c = make([]uint64, len(latencyBounds)+1)
		l.days[day] = c
		for d := range l.days {
			if d <= day-latencyDaysKept {
				delete(l.days, d)
			}
		}
	}
	i := 0
	for i < len(latencyBounds) && seconds > latencyBounds[i] {
		i++
	}
	c[i]++
}

// sum adds the buckets of the days from first to last and returns them with the number of days that had
// any sample.
func (l *latencyDays) sum(first, last int) ([]uint64, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]uint64, len(latencyBounds)+1)
	covered := 0
	for d := first; d <= last; d++ {
		c := l.days[d]
		if c == nil {
			continue
		}
		covered++
		for i, n := range c {
			out[i] += n
		}
	}
	return out, covered
}

// bucketQuantile is the upper bound of the bucket that holds the q-quantile, so "at most this long". A
// quantile beyond the last bound reports the last bound; by design no item takes that long.
func bucketQuantile(buckets []uint64, q float64) float64 {
	var total uint64
	for _, n := range buckets {
		total += n
	}
	rank := uint64(math.Ceil(q * float64(total)))
	var cum uint64
	for i, n := range buckets {
		cum += n
		if cum >= rank && i < len(latencyBounds) {
			return latencyBounds[i]
		}
	}
	return latencyBounds[len(latencyBounds)-1]
}

// PublicStats is the /stats body.
type PublicStats struct {
	MinInstances int                    `json:"minInstances"`
	Shown        bool                   `json:"shown"`
	Granularity  string                 `json:"granularity"` // always "day": completed UTC days only
	UptimeHours  int64                  `json:"uptimeHours"`
	Windows      map[string]*StatWindow `json:"windows,omitempty"`
}

// StatWindow is one window of completed days. Shares are of the items that went to Apple.
type StatWindow struct {
	From           string        `json:"from"`
	To             string        `json:"to"`
	Items          int64         `json:"items"`
	Delivered      int64         `json:"delivered"`
	DeliveredShare float64       `json:"deliveredShare"`
	FailedShare    float64       `json:"failedShare"`
	TokenGoneShare float64       `json:"tokenGoneShare"`
	ThrottledShare float64       `json:"throttledShare"`
	Latency        *StatsLatency `json:"latency"`
}

// StatsLatency are percentiles of the time from the relay accepting an item to Apple's answer, each the
// upper bound of its bucket, over the days of the window the relay has been running for.
type StatsLatency struct {
	P50         float64 `json:"p50Seconds"`
	P90         float64 `json:"p90Seconds"`
	P99         float64 `json:"p99Seconds"`
	DaysCovered int     `json:"daysCovered"`
}

func share(n, of int64) float64 {
	if of == 0 {
		return 0
	}
	return math.Round(float64(n)/float64(of)*1e4) / 1e4
}

// PublicStatsReport computes the /stats body now. Below the floor it carries no figure.
func (r *Relay) PublicStatsReport() PublicStats {
	now := r.cfg.Now()
	out := PublicStats{MinInstances: statsMinInstances, Granularity: "day", UptimeHours: int64(now.Sub(r.started) / time.Hour)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activeInstancesLocked() < statsMinInstances {
		return out
	}
	out.Shown = true
	out.Windows = map[string]*StatWindow{}
	today := store.Day(now)
	for _, win := range statsWindows {
		first, last := today-win.days, today-1
		if !r.enoughPushedLocked(first, last) {
			out.Windows[win.name] = nil
			continue
		}
		w := &StatWindow{From: store.DayString(first), To: store.DayString(last)}
		var failed, gone, throttled int64
		for d := first; d <= last; d++ {
			for _, c := range usageClasses {
				w.Delivered += r.globalLocked(d, c, "accepted")
				throttled += r.globalLocked(d, c, "device_throttled")
				for _, res := range resultsFailed {
					failed += r.globalLocked(d, c, res)
				}
				for _, res := range resultsTokenGone {
					gone += r.globalLocked(d, c, res)
				}
			}
		}
		w.Items = w.Delivered + failed + gone + throttled
		w.DeliveredShare, w.FailedShare = share(w.Delivered, w.Items), share(failed, w.Items)
		w.TokenGoneShare, w.ThrottledShare = share(gone, w.Items), share(throttled, w.Items)
		if b, covered := r.latDays.sum(first, last); covered > 0 {
			w.Latency = &StatsLatency{P50: bucketQuantile(b, 0.5), P90: bucketQuantile(b, 0.9), P99: bucketQuantile(b, 0.99), DaysCovered: covered}
		}
		out.Windows[win.name] = w
	}
	return out
}

// enoughPushedLocked reports whether at least statsMinInstances servers had an accepted push on a day from
// first to last. It reads the stored per-server day counters, so a server that only pushed today does not
// count, and it stops at the floor.
func (r *Relay) enoughPushedLocked(first, last int) bool {
	n := 0
	for id, s := range r.instances {
		if s.rec.LastPushDay < first {
			continue
		}
		for d := first; d <= last; d++ {
			if r.st.Counters(d, id).Sent > 0 {
				n++
				break
			}
		}
		if n >= statsMinInstances {
			return true
		}
	}
	return false
}

// statsCache holds the last computed /stats body for statsRefresh.
type statsCache struct {
	mu   sync.Mutex
	at   time.Time
	body json.RawMessage
}

func (r *Relay) handleStats(w http.ResponseWriter, req *http.Request) {
	now := r.cfg.Now()
	c := &r.statsCache
	c.mu.Lock()
	if c.body == nil || now.Sub(c.at) >= statsRefresh || now.Before(c.at) {
		b, err := json.Marshal(r.PublicStatsReport())
		if err != nil {
			c.mu.Unlock()
			r.fail(w, req, http.StatusInternalServerError, errBody{Error: "internal"})
			return
		}
		c.body, c.at = b, now
	}
	body := c.body
	c.mu.Unlock()
	r.reply(w, req, http.StatusOK, body)
}
