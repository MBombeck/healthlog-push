package relay

import (
	"context"
	"slices"
	"time"

	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// fewInstances is the threshold below which the summary log line is written hourly instead of every minute,
// so that the traffic of a single instance cannot be read off the log.
const fewInstances = 20

func (r *Relay) countGlobalLocked(today int, class, result string) {
	r.global[store.GlobalKey{Day: today, Class: class, Result: result}]++
}

// flushLocked writes dirty bindings, changed instance records, per-instance counters and pending global
// counters in one write transaction. Instances that did not change are not written, so the cost of a flush
// follows the traffic, not the number of instances.
func (r *Relay) flushLocked() {
	today := store.Day(r.cfg.Now())
	f := store.Flush{Bindings: map[string]*store.Binding{}, Counters: map[string]store.DayCounters{}, Global: map[store.GlobalKey]int64{},
		Day: today, Peak: r.peakToday}
	for k := range r.dirty {
		if b := r.bindings[k]; b != nil {
			f.Bindings[k] = b
		}
	}
	for id := range r.dirtyInst {
		if s := r.instances[id]; s != nil {
			f.Instances = append(f.Instances, s.rec)
		}
	}
	for id, s := range r.instances {
		if s.pending != (store.DayCounters{}) {
			f.Counters[id] = s.pending
		}
	}
	for k, n := range r.global {
		f.Global[k] = n
	}
	if err := r.st.ApplyFlush(&f); err != nil {
		r.setDBError(err)
		return
	}
	r.dirty, r.dirtyInst, r.global = map[string]bool{}, map[string]bool{}, map[store.GlobalKey]int64{}
	for id := range f.Counters {
		r.instances[id].pending = store.DayCounters{}
	}
	// A successful write after a failure makes the store writable again (disk freed, file system remounted).
	if !r.dbWritable {
		logx.Event("store.writable_again")
	}
	r.dbWritable = true
	r.Metrics.Set("hlp_db_writable", 1)
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
	if newDay := store.Day(now); newDay != store.Day(r.lastTick) {
		r.activities = map[string]*activityQuota{} // per-activity update windows never span more than a day
	}
	r.lastTick = now
	for k, t := range r.recentOptOuts {
		if now.Unix()-t > 2*wire.ClockSkew {
			delete(r.recentOptOuts, k)
		}
	}
	r.traces.prune(now)
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
	r.Metrics.Set("hlp_breaker_open", boolf(r.breaker.State(now) != BreakerClosed))
	r.Metrics.Set("hlp_http_errors_total", float64(r.ErrLog.Count()))
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
		logx.Counts(logx.KErrors, r.summary.errors), logx.Counts(logx.KEvents, r.summary.events), logx.Int(logx.KP95, p95))
	r.summary = newSummary(now)
}

// Daily runs retention, tier promotion, the automatic device-limit raise, the consistency check and the
// registry export. It is safe to call more than once a day.
func (r *Relay) Daily() {
	r.mu.Lock()
	today := store.Day(r.cfg.Now())
	if today != r.lastDay {
		r.peaks7 = append(r.peaks7, r.peakToday)
		if len(r.peaks7) > 7 {
			r.peaks7 = r.peaks7[len(r.peaks7)-7:]
		}
		r.peakToday = 0
		r.lastDay = today
	}
	r.flushLocked()
	removed := r.pruneBindingsLocked(today)
	r.pruneInstancesLocked(today)
	if err := r.st.Prune(today); err != nil {
		r.setDBError(err)
	}
	if err := r.st.Check(); err != nil {
		r.setDBError(err)
		logx.Event("store.check_failed")
	}
	r.pruneMemoryLocked(today)
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

// pruneBindingsLocked removes bindings without a push for BindingIdleWeeks and provisional bindings older
// than ProvisionalDays, and returns how many it removed.
func (r *Relay) pruneBindingsLocked(today int) int {
	thisWeek := store.Week(today)
	var stale [][]byte
	for m, b := range r.bindings {
		if b.LastUsedWeek < thisWeek-store.BindingIdleWeeks || (b.State == store.StateProvisional && today-b.BoundDay > store.ProvisionalDays) {
			stale = append(stale, []byte(m))
		}
	}
	// One transaction for all of them, not one fsync per binding.
	if len(stale) == 0 || !r.persist(r.st.DeleteBindings(stale)) {
		return 0
	}
	for _, m := range stale {
		r.dropBindingLocked(string(m))
	}
	return len(stale)
}

// pruneInstancesLocked removes suspended and revoked records after the block retention, idle instances and
// instances that never delivered, and runs the promotion rules for the rest.
func (r *Relay) pruneInstancesLocked(today int) {
	thisWeek := store.Week(today)
	for id, s := range r.instances {
		in := s.rec
		if in.Tier == store.TierRevoked || in.Tier == store.TierSuspended {
			// Kept for the block retention (12 months), then removed with its bindings.
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
}

// pruneMemoryLocked drops the per-device quota state of tokens without a binding and the challenge days
// of earlier days, so that memory does not grow with tokens that come and go.
func (r *Relay) pruneMemoryLocked(today int) {
	for m := range r.devs {
		if _, ok := r.bindings[m]; !ok {
			delete(r.devs, m)
		}
	}
	for m, d := range r.challengeDay {
		if d != today {
			delete(r.challengeDay, m)
		}
	}
}

// promoteLocked moves a probation instance to standard after seven days with at least one delivered push
// and no anomaly, and raises a standard instance's device limit to 80 after 30 quiet days above 80 % use.
func (r *Relay) promoteLocked(s *instState, today int) {
	in := s.rec
	// A flag counts for the day it was raised and the next one: the daily run can come up to a minute after
	// midnight, and the flag is stored, so neither the day change nor a restart drops it.
	flagged := in.FlaggedDay != 0 && today-in.FlaggedDay <= 1
	if flagged || r.suspiciousLocked(in.ID, today) {
		in.QuietSinceDay = today
	}
	switch in.Tier {
	case store.TierProbation:
		if today-in.CreatedDay >= 7 && in.FirstDeliveryDay != 0 && !r.suspiciousLocked(in.ID, today) && !flagged {
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
	r.dirtyInst[in.ID] = true
}

// suspiciousLocked: over the last seven days more than 20 % invalid tokens (at least 10 sends), or more
// than 20 rebinds.
func (r *Relay) suspiciousLocked(id string, today int) bool {
	var sum store.DayCounters
	for d := today - 6; d <= today; d++ { // seven days, as in the suspects overview
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
