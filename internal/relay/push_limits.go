package relay

import (
	"bytes"
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// charge is what one admitted item counts against. The windows are collected once, so that booking and the
// undo after a refused enqueue always touch the same set; an alert also takes a token from the device alert
// bucket and counts towards the binding's alerts of the day.
type charge struct {
	windows []*limits.Window
	alerts  *limits.Bucket // nil unless the item is an alert
	binding *store.Binding
}

func (c *charge) book(now time.Time) {
	for _, w := range c.windows {
		w.Add(now, 1)
	}
	if c.alerts != nil {
		c.alerts.Allow(now)
		c.binding.AlertsToday++
	}
}

func (c *charge) undo() {
	for _, w := range c.windows {
		w.Undo()
	}
	if c.alerts != nil {
		c.alerts.Refund()
		if c.binding.AlertsToday > 0 {
			c.binding.AlertsToday--
		}
	}
}

// chargeFor lists the windows an item of class c from instance s to device dq counts against.
func (r *Relay) chargeFor(s *instState, b *store.Binding, dq *devQuota, it *wire.Item) *charge {
	ch := &charge{windows: []*limits.Window{&s.pushDay, &s.pushMin, &dq.all}, binding: b}
	switch it.Class {
	case wire.ClassAlert:
		ch.alerts = dq.alerts
	case wire.ClassSilent:
		ch.windows = append(ch.windows, &dq.silentHour)
	case wire.ClassLiveActivity:
		switch it.Event {
		case wire.EventStart:
			ch.windows = append(ch.windows, &dq.laStartDay)
		case wire.EventUpdate:
			aq := r.activity(it.LAToken)
			ch.windows = append(ch.windows, &aq.hour, &aq.day)
		default:
			ch.windows = append(ch.windows, &dq.laDay)
		}
	}
	if s.rec.Tier == store.TierProbation {
		ch.windows = append(ch.windows, &r.probationMin)
	} else {
		ch.windows = append(ch.windows, &r.standardMin)
	}
	ch.windows = append(ch.windows, &r.minuteAll)
	return ch
}

// limitsLocked applies, in order: class pauses, Apple's per-device throttling, the activity statement, the
// provisional and invalid-token rules, instance quotas, device quotas and the tier pools. It books the item
// only when every check passes and returns the charge; on a refusal the charge is nil and the result says why.
func (r *Relay) limitsLocked(s *instState, b *store.Binding, m string, it *wire.Item, now time.Time) (*charge, ItemResult) {
	if res, ok := r.relayGateLocked(s, it, now); !ok {
		return nil, res
	}
	dq := r.dev(m)
	if res, ok := r.deviceGate(s, b, dq, it, now); !ok {
		return nil, res
	}
	if res, ok := r.bindingLimitsLocked(s, b, it.Ref, now); !ok {
		return nil, res
	}
	if res, ok := r.instanceLimits(s, it.Ref, now); !ok {
		return nil, res
	}
	if res, ok := r.deviceLimits(b, dq, it, now); !ok {
		return nil, res
	}
	if res, ok := r.poolLimits(s, it, now); !ok {
		return nil, res
	}
	ch := r.chargeFor(s, b, dq, it)
	ch.book(now)
	if it.Class == wire.ClassAlert {
		r.dirty[m] = true
	}
	r.peakToday = max(r.peakToday, r.minuteAll.Count(now))
	return ch, ItemResult{}
}

// relayGateLocked refuses an item whose class is paused or switched off relay-wide.
func (r *Relay) relayGateLocked(s *instState, it *wire.Item, now time.Time) (ItemResult, bool) {
	if p, d := r.paused(it.Class, s.rec.Tier, now); p {
		return itemRetry(it.Ref, http.StatusServiceUnavailable, "maintenance", "", d), false
	}
	if it.Class == wire.ClassSilent && now.Before(r.silentOffUntil) {
		return itemRetry(it.Ref, http.StatusTooManyRequests, "global", "global", r.silentOffUntil.Sub(now)), false
	}
	return ItemResult{}, true
}

// deviceGate refuses an item while Apple throttles the device for its class, and a Live Activity end
// without a valid activity statement by the binding key.
func (r *Relay) deviceGate(s *instState, b *store.Binding, dq *devQuota, it *wire.Item, now time.Time) (ItemResult, bool) {
	if until, ok := dq.throttled[it.Class]; ok && now.Before(until) {
		return itemRetry(it.Ref, http.StatusTooManyRequests, "device_quota", "device", until.Sub(now)), false
	}
	if it.Class == wire.ClassLiveActivity {
		if b.State == store.StateProvisional || !bytes.Equal(b.KeyHash, keyHash(it.BindingKey)) || !it.VerifyActivity(r.cfg.Host, s.rec.ID, now.Unix()) {
			return itemErr(it.Ref, http.StatusForbidden, "activity_refused"), false
		}
		return activityGate(b, it, now)
	}
	return ItemResult{}, true
}

// activityGate applies the rules of Live Activity start and update: the device's separate consent, and a
// content state inside the closed template.
func activityGate(b *store.Binding, it *wire.Item, now time.Time) (ItemResult, bool) {
	if it.Event != wire.EventStart && it.Event != wire.EventUpdate {
		return ItemResult{}, true
	}
	if b.LAConsentVersion == "" {
		return itemErr(it.Ref, http.StatusForbidden, "liveactivity_consent_required"), false
	}
	if !it.State.Check(now.Unix()) {
		return itemErr(it.Ref, http.StatusUnprocessableEntity, "invalid_item"), false
	}
	return ItemResult{}, true
}

// bindingLimitsLocked applies the rules that depend on the binding state.
func (r *Relay) bindingLimitsLocked(s *instState, b *store.Binding, ref string, now time.Time) (ItemResult, bool) {
	// A soft-invalid binding gets one probe push per day: the day it failed, it is refused, so an instance
	// cannot keep sending to a token Apple has called invalid.
	if b.State == store.StateSoftInvalid && b.SoftInvalidDay == store.Day(now) {
		return itemRetry(ref, http.StatusTooManyRequests, "binding_quota", "device", untilMidnight(now)), false
	}
	// Over the invalid-token budget, only active bindings receive pushes for 24 hours.
	if b.State != store.StateActive && now.Before(s.blockNewUntil) {
		return itemRetry(ref, http.StatusTooManyRequests, "binding_quota", "instance", s.blockNewUntil.Sub(now)), false
	}
	if b.State == store.StateProvisional {
		if active, _ := r.counts(s.rec.ID); active >= r.tierLimits(s.rec).Devices {
			return itemRetry(ref, http.StatusTooManyRequests, "binding_quota", "instance", time.Hour), false
		}
	}
	return ItemResult{}, true
}

// instanceLimits applies the instance's push quotas per day and per minute.
func (r *Relay) instanceLimits(s *instState, ref string, now time.Time) (ItemResult, bool) {
	tl := r.tierLimits(s.rec)
	if s.pushDay.Count(now) >= tl.PushesDay {
		return itemRetry(ref, http.StatusTooManyRequests, "instance_quota", "instance", s.pushDay.RetryAfter(now)), false
	}
	if s.pushMin.Count(now) >= tl.PushesMinute {
		return itemRetry(ref, http.StatusTooManyRequests, "instance_rate", "instance", s.pushMin.RetryAfter(now)), false
	}
	return ItemResult{}, true
}

// deviceLimits applies the per-device quotas: all classes per day, then the class's own limit.
func (r *Relay) deviceLimits(b *store.Binding, dq *devQuota, it *wire.Item, now time.Time) (ItemResult, bool) {
	ref, dl := it.Ref, r.cfg.Limits.Device
	half := now.Before(r.halfUntil) // after a restart, counts from before it are gone: halve until midnight
	if dq.all.Count(now) >= dl.AllDay {
		return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", dq.all.RetryAfter(now)), false
	}
	today := store.Day(now)
	if b.AlertsDay != today {
		b.AlertsDay, b.AlertsToday = today, 0
	}
	switch it.Class {
	case wire.ClassAlert:
		if b.AlertsToday >= dl.AlertDay {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", untilMidnight(now)), false
		}
		if !dq.alerts.Peek(now) {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", dq.alerts.RetryAfter(now)), false
		}
	case wire.ClassSilent:
		if dq.silentHour.Count(now) >= halve(dl.SilentHour, half) {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", dq.silentHour.RetryAfter(now)), false
		}
	case wire.ClassLiveActivity:
		return r.activityLimits(dq, it, half, now)
	}
	return ItemResult{}, true
}

// activityLimits applies the Live Activity limits: ends and starts per device and day, updates per
// activity and hour and day (scope "activity").
func (r *Relay) activityLimits(dq *devQuota, it *wire.Item, half bool, now time.Time) (ItemResult, bool) {
	ref, dl := it.Ref, r.cfg.Limits.Device
	switch it.Event {
	case wire.EventStart:
		if dq.laStartDay.Count(now) >= halve(dl.LiveActivityStartDay, half) {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", dq.laStartDay.RetryAfter(now)), false
		}
	case wire.EventUpdate:
		aq := r.activity(it.LAToken)
		if aq.hour.Count(now) >= dl.ActivityUpdateHour {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "activity", aq.hour.RetryAfter(now)), false
		}
		if aq.day.Count(now) >= dl.ActivityUpdateDay {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "activity", aq.day.RetryAfter(now)), false
		}
	default:
		if dq.laDay.Count(now) >= halve(dl.LiveActivityDay, half) {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", dq.laDay.RetryAfter(now)), false
		}
	}
	return ItemResult{}, true
}

// poolLimits applies the relay-wide minute pools: one for all probation instances, and the global limit for
// standard instances, of which each class may use its share.
func (r *Relay) poolLimits(s *instState, it *wire.Item, now time.Time) (ItemResult, bool) {
	if s.rec.Tier == store.TierProbation {
		if r.probationMin.Count(now) >= r.probationLimit() {
			return itemRetry(it.Ref, http.StatusTooManyRequests, "global", "tier", r.probationMin.RetryAfter(now)), false
		}
		return ItemResult{}, true
	}
	if float64(r.standardMin.Count(now)) >= float64(r.globalLimit())*standardShare(it.Class) {
		return itemRetry(it.Ref, http.StatusTooManyRequests, "global", "global", r.standardMin.RetryAfter(now)), false
	}
	return ItemResult{}, true
}

// standardShare is the part of the global limit a class may use, so that background traffic cannot crowd
// out alerts.
func standardShare(c wire.Class) float64 {
	switch c {
	case wire.ClassSilent:
		return 0.70
	case wire.ClassLiveActivity:
		return 0.85
	}
	return 1.0
}

func halve(n int64, half bool) int64 {
	if half {
		return max(1, n/2)
	}
	return n
}

// globalLimit is five times the highest minute of the last seven days, within [GlobalMin, GlobalMax].
func (r *Relay) globalLimit() int64 {
	peak := r.peakToday
	for _, p := range r.peaks7 {
		peak = max(peak, p)
	}
	return min(r.cfg.Limits.GlobalMax, max(r.cfg.Limits.GlobalMin, 5*peak))
}

// probationLimit is the pool of all probation instances: 10 % of the global limit, at least 60 and at most
// the configured probation pool.
func (r *Relay) probationLimit() int64 {
	return min(r.cfg.Limits.ProbationPoolMin, max(60, r.globalLimit()/10))
}

// countApple429Locked tracks Apple's throttling across all sends: over 2 % TooManyRequests in five minutes
// (at least 50 sends) switches silent pushes off for everyone for 15 minutes.
func (r *Relay) countApple429Locked(now time.Time, throttled bool) {
	size := 30 * time.Second
	start := now.Truncate(size)
	slot := &r.apple429[int(start.Unix()/30)%len(r.apple429)]
	if !slot.start.Equal(start) {
		*slot = apple429Slot{start: start}
	}
	slot.sends++
	if throttled {
		slot.throttled++
	}
	var sends, thr int
	for _, s := range r.apple429 {
		if now.Sub(s.start) < 5*time.Minute {
			sends += s.sends
			thr += s.throttled
		}
	}
	if sends >= 50 && float64(thr)/float64(sends) > 0.02 && !now.Before(r.silentOffUntil) {
		r.silentOffUntil = now.Add(15 * time.Minute)
		r.Metrics.Inc("hlp_silent_paused_total")
		logx.Event("apns.throttled", logx.Str(logx.KClass, "silent"), logx.Str(logx.KState, "paused"))
	}
}

type apple429Slot struct {
	start            time.Time
	sends, throttled int
}
