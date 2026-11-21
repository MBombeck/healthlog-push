package relay

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/store"
)

// fewInstances is the threshold below which logs and metrics are only refreshed hourly, so that the
// traffic of a single instance cannot be read off them.
const fewInstances = 20

func (r *Relay) countGlobalLocked(today int, class, result string) {
	r.global[[3]string{strconv.Itoa(today), class, result}]++
}

// flushLocked writes dirty bindings, per-instance counters and pending global counters.
func (r *Relay) flushLocked() {
	if len(r.dirty) > 0 {
		m := make(map[string]*store.Binding, len(r.dirty))
		for k := range r.dirty {
			if b := r.bindings[k]; b != nil {
				m[k] = b
			}
		}
		if r.persist(r.st.PutBindings(m)) {
			r.dirty = map[string]bool{}
		}
	}
	today := store.Day(r.cfg.Now())
	for id, s := range r.instances {
		if s.pending != (store.DayCounters{}) {
			if r.persist(r.st.AddCounters(today, id, s.pending)) {
				s.pending = store.DayCounters{}
			}
		}
		if r.dbWritable {
			_ = r.st.PutInstance(s.rec)
		}
	}
	for k, n := range r.global {
		d, _ := strconv.Atoi(k[0])
		if r.persist(r.st.AddGlobal(d, k[1], k[2], n)) {
			delete(r.global, k)
		}
	}
	// A successful write after a failure makes the store writable again (disk freed, file system remounted).
	if err := r.st.AddGlobal(today, "all", "peak_minute", r.peakToday); err == nil {
		if !r.dbWritable {
			logx.Event("store.writable_again")
		}
		r.dbWritable = true
		r.M.Set("hlp_db_writable", 1)
	} else {
		r.setDBError(err)
	}
}

// Run drives the periodic work until ctx ends: every minute a flush and the summary log line, at every
// day change the retention, promotion and export tasks.
func (r *Relay) Run(ctx context.Context) {
	r.Daily()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Tick()
		}
	}
}

// Tick is one minute of maintenance.
func (r *Relay) Tick() {
	r.mu.Lock()
	r.flushLocked()
	now := r.cfg.Now()
	for ch, pc := range r.conflicts {
		if now.After(pc.expires) {
			delete(r.conflicts, ch)
		}
	}
	for k, e := range r.idem {
		if e.res != nil && now.After(e.exp) {
			delete(r.idem, k)
		}
	}
	if len(r.idemOrder) > 2*len(r.idem)+1024 {
		keep := r.idemOrder[:0]
		for _, k := range r.idemOrder {
			if r.idem[k] != nil {
				keep = append(keep, k)
			}
		}
		r.idemOrder = keep
	}
	r.M.Set("hlp_breaker_open", boolf(r.breaker.State(now) != BreakerClosed))
	r.M.Set("hlp_http_errors_total", float64(r.ErrLog.Count()))
	r.logSummaryLocked(now)
	newDay := store.Day(now) != r.lastDay
	r.mu.Unlock()
	if newDay {
		r.Daily()
	}
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (r *Relay) activeInstancesLocked() int {
	n := 0
	for _, s := range r.instances {
		if s.rec.Tier == store.TierProbation || s.rec.Tier == store.TierStandard {
			n++
		}
	}
	return n
}

// logSummaryLocked writes sums without any instance: every minute with at least 20 active instances,
// otherwise every hour.
func (r *Relay) logSummaryLocked(now time.Time) {
	period := time.Hour
	name := "hour"
	if r.activeInstancesLocked() >= fewInstances {
		period, name = time.Minute, "minute"
	}
	if now.Sub(r.summary.start) < period {
		return
	}
	var p95 int64
	if l := r.summary.latencies; len(l) > 0 {
		slices.Sort(l)
		p95 = l[(len(l)*95)/100]
	}
	logx.Event("relay.summary", logx.Str(logx.KPeriod, name), logx.Int(logx.KPushes, r.summary.pushes),
		logx.Counts(logx.KErrors, r.summary.errors), logx.Int(logx.KP95, p95))
	r.summary = summary{errors: map[string]int64{}, start: now}
}

// Daily runs retention, tier promotion, the automatic device-limit raise, the consistency check and the
// registry export. It is safe to call more than once a day.
func (r *Relay) Daily() {
	r.mu.Lock()
	now := r.cfg.Now()
	today := store.Day(now)
	if today != r.lastDay {
		r.peaks7 = append(r.peaks7, r.peakToday)
		if len(r.peaks7) > 7 {
			r.peaks7 = r.peaks7[len(r.peaks7)-7:]
		}
		r.peakToday = 0
		r.lastDay = today
	}
	r.flushLocked()
	thisWeek := store.Week(today)
	removed := 0
	for m, b := range r.bindings {
		stale := b.LastUsedWeek < thisWeek-store.BindingIdleWeeks
		if b.State == store.StateProvisional && today-b.BoundDay > store.ProvisionalDays {
			stale = true
		}
		if stale && r.persist(r.st.DeleteBinding([]byte(m))) {
			delete(r.bindings, m)
			delete(r.dirty, m)
			removed++
		}
	}
	for id, s := range r.instances {
		in := s.rec
		if in.Tier == store.TierRevoked || in.Tier == store.TierSuspended {
			// Kept as long as the denylist entry (12 months), then removed with its bindings.
			if today-in.ReasonDay > store.RetainBlocks && r.persist(r.st.DeleteInstance(id)) {
				r.dropInstanceLocked(id)
			}
			continue
		}
		idle := in.LastSeenWeek < thisWeek-store.InstanceIdleWeeks
		never := in.FirstDeliveryDay == 0 && today-in.CreatedDay > store.UndeliveredInstDays
		if idle || never {
			if r.persist(r.st.DeleteInstance(id)) {
				r.dropInstanceLocked(id)
			}
			continue
		}
		r.promoteLocked(s, today)
	}
	if err := r.st.Prune(today); err != nil {
		r.setDBError(err)
	}
	if err := r.st.Check(); err != nil {
		r.setDBError(err)
		logx.Event("store.check_failed")
	}
	for m, d := range r.challengeDay {
		if d != today {
			delete(r.challengeDay, m)
		}
	}
	r.mu.Unlock()
	if r.cfg.ExportDir != "" {
		if err := r.ExportNow(); err != nil {
			logx.Event("export.failed")
		} else {
			logx.Event("export.written")
		}
	}
	logx.Event("relay.daily", logx.Int(logx.KCount, int64(removed)))
}

// promoteLocked moves a probation instance to standard after seven days with at least one delivered push
// and no anomaly, and raises a standard instance's device limit to 80 after 30 quiet days above 80 % use.
func (r *Relay) promoteLocked(s *instState, today int) {
	in := s.rec
	if s.flaggedToday || r.suspiciousLocked(in.ID, today) {
		in.QuietSinceDay = today
	}
	switch in.Tier {
	case store.TierProbation:
		if today-in.CreatedDay >= 7 && in.FirstDeliveryDay != 0 && !r.suspiciousLocked(in.ID, today) && !s.flaggedToday {
			in.Tier, in.QuietSinceDay = store.TierStandard, today
			logx.Event("instance.promoted", logx.Str(logx.KState, store.TierStandard))
		}
	case store.TierStandard:
		base := r.cfg.Limits.Standard.Devices
		if in.DeviceLimit == base && in.QuietSinceDay != 0 && today-in.QuietSinceDay >= 30 {
			if a, _ := r.counts(in.ID); float64(a) > 0.8*float64(base) {
				in.DeviceLimit = r.cfg.Limits.StandardDevicesUp
				logx.Event("instance.limit_raised", logx.Int(logx.KValue, int64(in.DeviceLimit)))
			}
		}
	}
	r.persist(r.st.PutInstance(in))
}

// suspiciousLocked: over the last seven days more than 20 % invalid tokens (at least 10 sends), or more
// than 20 rebinds.
func (r *Relay) suspiciousLocked(id string, today int) bool {
	var sum store.DayCounters
	for d := today - 7; d <= today; d++ {
		c := r.st.Counters(d, id)
		sum.Sent += c.Sent
		sum.Invalid += c.Invalid
		sum.Rebinds += c.Rebinds
	}
	if sum.Rebinds > 20 {
		return true
	}
	return sum.Sent+sum.Invalid >= 10 && float64(sum.Invalid)/float64(sum.Sent+sum.Invalid) > 0.2
}

// Usage is the aggregate usage report: counts only, no instance ids, no per-instance values.
type Usage struct {
	Granularity      string      `json:"granularity"` // "day" below 20 active instances, else "day" plus live gauges
	ActiveInstances  int         `json:"activeInstances"`
	PushedLast7Days  int         `json:"instancesPushedLast7Days"`
	PushedLast30Days int         `json:"instancesPushedLast30Days"`
	ActiveBindings   int         `json:"activeBindings"`
	RegistrationsWk  []WeekCount `json:"registrationsPerWeek"`
	OptOutsWk        []WeekCount `json:"optOutsPerWeek"`
	PushesPerDay     []DayPushes `json:"pushesPerDay"`
}

// WeekCount is a count for the week starting on the given day.
type WeekCount struct {
	WeekOf string `json:"weekOf"`
	N      int64  `json:"n"`
}

// DayPushes are the pushes of one completed day by class and outcome.
type DayPushes struct {
	Day          string           `json:"day"`
	Total        int64            `json:"total"`
	ByClass      map[string]int64 `json:"byClass"`
	Accepted     int64            `json:"accepted"`
	SoftFailed   int64            `json:"softFailed"`
	Unregistered int64            `json:"unregistered"`
}

var usageClasses = []string{"alert", "silent", "liveactivity"}

// UsageReport builds the usage report for the last weeks. Days are completed days only (yesterday back),
// so no partial day of a small population is ever shown.
func (r *Relay) UsageReport(days int) Usage {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushLocked()
	now := r.cfg.Now()
	today := store.Day(now)
	u := Usage{Granularity: "day", ActiveInstances: r.activeInstancesLocked()}
	for _, s := range r.instances {
		if s.rec.LastPushDay != 0 && today-s.rec.LastPushDay < 7 {
			u.PushedLast7Days++
		}
		if s.rec.LastPushDay != 0 && today-s.rec.LastPushDay < 30 {
			u.PushedLast30Days++
		}
	}
	for _, b := range r.bindings {
		if b.State == store.StateActive || b.State == store.StateSoftInvalid {
			u.ActiveBindings++
		}
	}
	for d := today - days; d < today; d++ {
		dp := DayPushes{Day: store.DayString(d), ByClass: map[string]int64{}}
		for _, c := range usageClasses {
			acc := r.st.Global(d, c, "accepted")
			soft := r.st.Global(d, c, "soft_invalid")
			unreg := r.st.Global(d, c, "unregistered")
			gone := r.st.Global(d, c, "activity_gone")
			n := acc + soft + unreg + gone
			dp.ByClass[c] = n
			dp.Total += n
			dp.Accepted += acc
			dp.SoftFailed += soft + gone
			dp.Unregistered += unreg
		}
		u.PushesPerDay = append(u.PushesPerDay, dp)
	}
	for w := store.Week(today - days); w < store.Week(today); w++ {
		var reg, opt int64
		for d := store.WeekStart(w); d < store.WeekStart(w)+7; d++ {
			reg += r.st.Global(d, "instance", "registered")
			opt += r.st.Global(d, "binding", "opt_out")
		}
		u.RegistrationsWk = append(u.RegistrationsWk, WeekCount{WeekOf: store.DayString(store.WeekStart(w)), N: reg})
		u.OptOutsWk = append(u.OptOutsWk, WeekCount{WeekOf: store.DayString(store.WeekStart(w)), N: opt})
	}
	return u
}

// usageGauges publishes the usage counts as metrics. Gauges for completed days only; the snapshot itself
// refreshes hourly below 20 active instances.
func (r *Relay) usageGauges() {
	u := r.UsageReport(7)
	r.M.Set("hlp_usage_active_instances", float64(u.ActiveInstances))
	r.M.Set("hlp_usage_instances_pushed", float64(u.PushedLast7Days), "window", "7d")
	r.M.Set("hlp_usage_instances_pushed", float64(u.PushedLast30Days), "window", "30d")
	r.M.Set("hlp_usage_active_bindings", float64(u.ActiveBindings))
	if n := len(u.PushesPerDay); n > 0 {
		y := u.PushesPerDay[n-1]
		for c, v := range y.ByClass {
			r.M.Set("hlp_usage_pushes_yesterday", float64(v), "class", c)
		}
		r.M.Set("hlp_usage_outcomes_yesterday", float64(y.Accepted), "outcome", "accepted")
		r.M.Set("hlp_usage_outcomes_yesterday", float64(y.SoftFailed), "outcome", "soft_failed")
		r.M.Set("hlp_usage_outcomes_yesterday", float64(y.Unregistered), "outcome", "unregistered")
	}
	if n := len(u.RegistrationsWk); n > 0 {
		r.M.Set("hlp_usage_registrations_last_week", float64(u.RegistrationsWk[n-1].N))
		r.M.Set("hlp_usage_opt_outs_last_week", float64(u.OptOutsWk[n-1].N))
	}
}

// MetricsHandler serves /metrics (127.0.0.1 only) and a local /healthz for the container health check.
func (r *Relay) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		interval := time.Hour
		if r.activeInstancesLocked() >= fewInstances {
			interval = time.Minute
		}
		r.mu.Unlock()
		r.usageGauges()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_ = r.M.WriteSnapshot(w, r.cfg.Now(), interval)
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
	switch {
	case r.misconfigured || (r.cfg.ProviderTokenOK != nil && !r.cfg.ProviderTokenOK()):
		h.Status = "down"
	case h.Breaker != BreakerClosed || !h.DBWritable || h.Delivery == "degraded":
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
