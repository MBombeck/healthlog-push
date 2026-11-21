package relay

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/queue"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// ItemResult is the per-item answer of POST /v1/push.
type ItemResult struct {
	Ref        string `json:"ref"`
	Status     int    `json:"status"`
	Result     string `json:"result,omitempty"` // accepted, soft_invalid, activity_gone (status 200)
	Error      string `json:"error,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Scope      string `json:"scope,omitempty"`
	RetryAfter int    `json:"retryAfter,omitempty"`
	Duplicate  bool   `json:"duplicate,omitempty"`
}

type pushResp struct {
	Results   []ItemResult `json:"results"`
	Notice    *Notice      `json:"notice"`
	RelayTime int64        `json:"relayTime"`
}

func itemErr(ref string, status int, e string) ItemResult {
	return ItemResult{Ref: ref, Status: status, Error: e}
}

func itemRetry(ref string, status int, e, scope string, d time.Duration) ItemResult {
	return ItemResult{Ref: ref, Status: status, Error: e, Scope: scope, RetryAfter: jitter(d)}
}

// receiptInterval is the shortest gap between two receipt reports of one instance; servers report every
// 55 minutes, which leaves ten minutes of slack.
const receiptInterval = 45 * time.Minute

// minReporters is how many instance reports the delivery signal needs before it can say anything.
const minReporters = 3

// pushWait bounds how long a batch waits for Apple: queue admission refuses beyond 2 s of waiting and each
// request to Apple is limited to 3 s, so 8 s leaves room within the instance's 10 s request timeout.
const pushWait = 8 * time.Second

// handlePush implements POST /v1/push.
func (r *Relay) handlePush(w http.ResponseWriter, req *http.Request) {
	s, body, ok := r.auth(w, req, maxPushBody)
	if !ok {
		return
	}
	pb, err := wire.ParsePushBody(body)
	if err != nil {
		r.fail(w, req, http.StatusUnprocessableEntity, errBody{Error: "invalid_item"})
		return
	}
	if len(pb.Items) > wire.MaxPushItems {
		r.fail(w, req, http.StatusRequestEntityTooLarge, errBody{Error: "too_many_items"})
		return
	}
	now := r.cfg.Now()
	r.mu.Lock()
	if e, status := r.requestGateLocked(s, now); e != nil {
		r.mu.Unlock()
		r.fail(w, req, status, *e)
		return
	}
	results := make([]ItemResult, len(pb.Items))
	waits := make([]chan struct{}, len(pb.Items))
	entries := make([]*idemEntry, len(pb.Items))
	seen := map[string]bool{}
	for i := range pb.Items {
		p := &pb.Items[i]
		if seen[p.Ref] {
			results[i] = itemErr(p.Ref, http.StatusUnprocessableEntity, "invalid_item")
			continue
		}
		seen[p.Ref] = true
		res, ent := r.admitLocked(s, p, now)
		if ent != nil {
			waits[i], entries[i] = ent.done, ent
		} else {
			results[i] = res
		}
	}
	r.mu.Unlock()
	deadline := time.NewTimer(pushWait)
	defer deadline.Stop()
	for i, ch := range waits {
		if ch == nil {
			continue
		}
		select {
		case <-ch:
			r.mu.Lock()
			res := *entries[i].res
			r.mu.Unlock()
			if res.Ref != pb.Items[i].Ref {
				res.Ref = pb.Items[i].Ref
			}
			results[i] = res
		case <-deadline.C:
			results[i] = itemRetry(pb.Items[i].Ref, http.StatusServiceUnavailable, "apns_unavailable", "", 30*time.Second)
			deadline.Reset(0)
		}
	}
	r.mu.Lock()
	n := r.currentNotice(now)
	r.mu.Unlock()
	r.reply(w, req, http.StatusOK, pushResp{Results: results, Notice: n, RelayTime: now.Unix()})
}

// requestGateLocked refuses a whole batch for relay-wide reasons.
func (r *Relay) requestGateLocked(s *instState, now time.Time) (*errBody, int) {
	if p, d := r.paused("all", s.rec.Tier, now); p {
		return &errBody{Error: "maintenance", RetryAfter: jitter(d)}, http.StatusServiceUnavailable
	}
	if r.misconfigured || r.breaker.State(now) == BreakerOpen {
		return &errBody{Error: "relay_misconfigured"}, http.StatusServiceUnavailable
	}
	if now.Before(r.tooManyUntil) {
		return &errBody{Error: "apns_unavailable", RetryAfter: jitter(r.tooManyUntil.Sub(now))}, http.StatusServiceUnavailable
	}
	return nil, 0
}

// admitLocked validates one item, applies every limit and enqueues it. It returns either a final result or
// the idempotency entry to wait on.
func (r *Relay) admitLocked(s *instState, p *wire.PushItem, now time.Time) (ItemResult, *idemEntry) {
	it, err := wire.ValidateItem(p)
	if err != nil {
		r.M.Inc("hlp_push_total", "class", classLabel(p.Class), "result", "invalid_item")
		return itemErr(p.Ref, http.StatusUnprocessableEntity, "invalid_item"), nil
	}
	ik := s.rec.ID + "\x00" + it.Ref
	if e := r.idem[ik]; e != nil && now.Before(e.exp) {
		if e.res == nil {
			return ItemResult{}, e
		}
		res := *e.res
		res.Duplicate = true
		return res, nil
	}
	m := r.tokenMAC(it.Token)
	b := r.bindings[m]
	if b == nil || b.InstanceID != s.rec.ID {
		return itemErr(it.Ref, http.StatusNotFound, "binding_unknown"), nil
	}
	if b.Env != it.Env {
		return itemErr(it.Ref, http.StatusUnprocessableEntity, "invalid_item"), nil
	}
	if res, ok := r.limitsLocked(s, b, m, it, now); !ok {
		r.M.Inc("hlp_push_total", "class", string(it.Class), "result", res.Error)
		return res, nil
	}
	ent := &idemEntry{done: make(chan struct{}), exp: now.Add(idemTTL)}
	push := r.buildPush(it, now)
	job := &queue.Job{Instance: s.rec.ID, High: it.Class != wire.ClassSilent}
	job.Run = func() {
		res := r.sender.Send(context.Background(), push)
		r.complete(s.rec.ID, m, it, ik, ent, res)
	}
	job.Drop = func() {
		r.finish(ik, ent, itemRetry(it.Ref, http.StatusServiceUnavailable, "queue_full", "", 2*time.Second), false)
	}
	if err := r.q.Push(job); err != nil {
		r.undoLimitsLocked(s, m, it, now)
		r.M.Inc("hlp_push_total", "class", string(it.Class), "result", "queue_full")
		scope := ""
		if errors.Is(err, queue.ErrInstanceFull) {
			scope = "instance"
		}
		return itemRetry(it.Ref, http.StatusServiceUnavailable, "queue_full", scope, 2*time.Second), nil
	}
	r.idemPutLocked(ik, ent)
	return ItemResult{}, ent
}

func classLabel(c wire.Class) string {
	if c.Valid() {
		return string(c)
	}
	return "unknown"
}

func (r *Relay) buildPush(it *wire.Item, now time.Time) *apns.Push {
	p := &apns.Push{Token: it.Token, Class: it.Class, Expiration: now.Add(time.Duration(it.TTL) * time.Second), Collapse: it.Collapse, Sandbox: it.Env == "sandbox"}
	switch it.Class {
	case wire.ClassAlert:
		p.Payload = apns.AlertPayload(it.Envelope)
	case wire.ClassSilent:
		p.Payload = apns.SilentPayload(it.Envelope)
	case wire.ClassLiveActivity:
		p.Token = it.LAToken
		p.Payload = apns.LiveActivityEndPayload(now)
	}
	return p
}

// limitsLocked applies, in order: class pauses, Apple's per-device throttling, the activity statement, the
// provisional and invalid-token rules, instance quotas, device quotas and the tier pools. It counts only
// when every check passes.
func (r *Relay) limitsLocked(s *instState, b *store.Binding, m string, it *wire.Item, now time.Time) (ItemResult, bool) {
	ref, c := it.Ref, it.Class
	if p, d := r.paused(c, s.rec.Tier, now); p {
		return itemRetry(ref, http.StatusServiceUnavailable, "maintenance", "", d), false
	}
	if c == wire.ClassSilent && now.Before(r.silentOffUntil) {
		return itemRetry(ref, http.StatusTooManyRequests, "global", "global", r.silentOffUntil.Sub(now)), false
	}
	dq := r.dev(m)
	if until, ok := dq.throttled[c]; ok && now.Before(until) {
		return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", until.Sub(now)), false
	}
	if c == wire.ClassLiveActivity {
		if b.State == store.StateProvisional || !bytes.Equal(b.KeyHash, keyHash(it.BindingKey)) || !it.VerifyActivity(r.cfg.Host, s.rec.ID, now.Unix()) {
			return itemErr(ref, http.StatusForbidden, "activity_refused"), false
		}
	}
	tl := r.tierLimits(s.rec)
	// A soft-invalid binding gets one probe push per day: the day it failed, it is refused (K1).
	if b.State == store.StateSoftInvalid && b.SoftInvalidDay == store.Day(now) {
		return itemRetry(ref, http.StatusTooManyRequests, "binding_quota", "device", now.Truncate(day).Add(day).Sub(now)), false
	}
	// Over the invalid-token budget, only active bindings receive pushes for 24 hours.
	if b.State != store.StateActive && now.Before(s.blockNewUntil) {
		return itemRetry(ref, http.StatusTooManyRequests, "binding_quota", "instance", s.blockNewUntil.Sub(now)), false
	}
	if b.State == store.StateProvisional {
		if active, _ := r.counts(s.rec.ID); active >= tl.Devices {
			return itemRetry(ref, http.StatusTooManyRequests, "binding_quota", "instance", hour), false
		}
	}
	if s.pushDay.Count(now) >= tl.PushesDay {
		return itemRetry(ref, http.StatusTooManyRequests, "instance_quota", "instance", s.pushDay.RetryAfter(now)), false
	}
	if s.pushMin.Count(now) >= tl.PushesMinute {
		return itemRetry(ref, http.StatusTooManyRequests, "instance_rate", "instance", s.pushMin.RetryAfter(now)), false
	}
	dl := r.cfg.Limits.Device
	half := now.Before(r.halfUntil) // after a restart, counts from before it are gone: halve until midnight
	if dq.all.Count(now) >= dl.AllDay {
		return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", dq.all.RetryAfter(now)), false
	}
	today := store.Day(now)
	if b.AlertsDay != today {
		b.AlertsDay, b.AlertsToday = today, 0
	}
	switch c {
	case wire.ClassAlert:
		if b.AlertsToday >= dl.AlertDay {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", now.Truncate(day).Add(day).Sub(now)), false
		}
		if !dq.alerts.Peek(now) {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", dq.alerts.RetryAfter(now)), false
		}
	case wire.ClassSilent:
		if lim := halve(dl.SilentHour, half); dq.silentHour.Count(now) >= lim {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", dq.silentHour.RetryAfter(now)), false
		}
	case wire.ClassLiveActivity:
		if lim := halve(dl.LiveActivityDay, half); dq.laDay.Count(now) >= lim {
			return itemRetry(ref, http.StatusTooManyRequests, "device_quota", "device", dq.laDay.RetryAfter(now)), false
		}
	}
	if s.rec.Tier == store.TierProbation {
		if r.probationMin.Count(now) >= r.probationLimit() {
			return itemRetry(ref, http.StatusTooManyRequests, "global", "tier", r.probationMin.RetryAfter(now)), false
		}
	} else {
		g := r.globalLimit()
		share := map[wire.Class]float64{wire.ClassSilent: 0.70, wire.ClassLiveActivity: 0.85, wire.ClassAlert: 1.0}[c]
		if float64(r.standardMin.Count(now)) >= float64(g)*share {
			return itemRetry(ref, http.StatusTooManyRequests, "global", "global", r.standardMin.RetryAfter(now)), false
		}
	}
	// Commit.
	s.pushDay.Add(now, 1)
	s.pushMin.Add(now, 1)
	dq.all.Add(now, 1)
	switch c {
	case wire.ClassAlert:
		dq.alerts.Allow(now)
		b.AlertsToday++
		r.dirty[m] = true
	case wire.ClassSilent:
		dq.silentHour.Add(now, 1)
	case wire.ClassLiveActivity:
		dq.laDay.Add(now, 1)
	}
	if s.rec.Tier == store.TierProbation {
		r.probationMin.Add(now, 1)
	} else {
		r.standardMin.Add(now, 1)
	}
	r.minuteAll.Add(now, 1)
	r.peakToday = max(r.peakToday, r.minuteAll.Count(now))
	return ItemResult{}, true
}

func halve(n int64, half bool) int64 {
	if half {
		return max(1, n/2)
	}
	return n
}

func (r *Relay) undoLimitsLocked(s *instState, m string, it *wire.Item, now time.Time) {
	s.pushDay.Undo()
	s.pushMin.Undo()
	dq := r.dev(m)
	dq.all.Undo()
	switch it.Class {
	case wire.ClassAlert:
		dq.alerts.Refund()
		if b := r.bindings[m]; b != nil && b.AlertsToday > 0 {
			b.AlertsToday--
		}
	case wire.ClassSilent:
		dq.silentHour.Undo()
	case wire.ClassLiveActivity:
		dq.laDay.Undo()
	}
	if s.rec.Tier == store.TierProbation {
		r.probationMin.Undo()
	} else {
		r.standardMin.Undo()
	}
	r.minuteAll.Undo()
	_ = now
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

func (r *Relay) idemPutLocked(k string, e *idemEntry) {
	r.idem[k] = e
	r.idemOrder = append(r.idemOrder, k)
	if len(r.idemOrder) > idemMax {
		drop := r.idemOrder[:len(r.idemOrder)-idemMax]
		for _, old := range drop {
			if ent := r.idem[old]; ent != nil && ent.res != nil {
				delete(r.idem, old)
			}
		}
		r.idemOrder = append([]string(nil), r.idemOrder[len(r.idemOrder)-idemMax:]...)
	}
}

// finish records the result and wakes waiters. Only results from a definite answer by Apple are kept for
// replay; transient failures are forgotten so that a retry really retries.
func (r *Relay) finish(ik string, ent *idemEntry, res ItemResult, keep bool) {
	r.mu.Lock()
	ent.res = &res
	if !keep {
		delete(r.idem, ik)
	}
	r.mu.Unlock()
	close(ent.done)
}

// complete applies Apple's answer to the binding and the counters (spec/protocol.md, "Failure handling").
func (r *Relay) complete(instID, m string, it *wire.Item, ik string, ent *idemEntry, res apns.Result) {
	r.mu.Lock()
	now := r.cfg.Now()
	today := store.Day(now)
	s := r.instances[instID]
	b := r.bindings[m]
	out, keep := r.applyLocked(instID, s, b, m, it, res, now, today)
	out.Ref = it.Ref
	r.recordSummaryLocked(it.Class, out, res.Latency)
	r.mu.Unlock()
	r.finish(ik, ent, out, keep)
}

func (r *Relay) applyLocked(instID string, s *instState, b *store.Binding, m string, it *wire.Item, res apns.Result, now time.Time, today int) (ItemResult, bool) {
	c := it.Class
	device := c != wire.ClassLiveActivity
	// Only bindings that have had a push accepted count for the breaker: invented tokens never get there.
	established := device && b != nil && b.InstanceID == instID && b.LastSuccessDay != 0
	r.countApple429Locked(now, res.Outcome == apns.DeviceThrottled)
	label := func(v string) {
		r.M.Inc("hlp_push_total", "class", string(c), "result", v)
		r.countGlobalLocked(today, string(c), v)
	}
	switch res.Outcome {
	case apns.Accepted:
		label("accepted")
		r.apnsLastOK = now
		if established {
			r.breaker.Record(now, instID, true, false)
		}
		if b != nil && b.InstanceID == instID {
			if b.State != store.StateActive {
				b.State, b.SoftInvalidDay = store.StateActive, 0
			}
			b.LastSuccessDay, b.LastUsedWeek = today, store.Week(today)
			r.dirty[m] = true
		}
		if s != nil {
			s.pending.Sent++
			if s.rec.FirstDeliveryDay == 0 || s.rec.LastPushDay != today {
				if s.rec.FirstDeliveryDay == 0 {
					s.rec.FirstDeliveryDay = today
				}
				s.rec.LastPushDay = today
				r.dirtyInst[s.rec.ID] = true
			}
		}
		return ItemResult{Status: http.StatusOK, Result: "accepted"}, true
	case apns.Unregistered, apns.SoftInvalid:
		if !device {
			label("activity_gone")
			return ItemResult{Status: http.StatusOK, Result: "activity_gone"}, true
		}
		if established && r.breaker.Record(now, instID, false, true) {
			r.M.Set("hlp_breaker_open", 1)
			logx.Event("breaker.opened", logx.Str(logx.KState, BreakerOpen))
		}
		marking := r.breaker.Marking(now)
		// The invalid-token budget is charged for every token that never delivered, even while the breaker is
		// not closed; only established bindings are spared then, because a misconfiguration hits them.
		if s != nil && (!established || marking) {
			r.countInvalidLocked(s, now)
		}
		if !marking {
			label("relay_misconfigured")
			return ItemResult{Status: http.StatusServiceUnavailable, Error: "relay_misconfigured"}, false
		}
		if res.Outcome == apns.Unregistered {
			label("unregistered")
			if b != nil && b.InstanceID == instID {
				r.deleteBindingLocked(m)
			}
			return ItemResult{Status: http.StatusGone, Error: "unregistered"}, true
		}
		label("soft_invalid")
		if b != nil && b.InstanceID == instID {
			if b.State == store.StateSoftInvalid && b.SoftInvalidDay != today {
				r.deleteBindingLocked(m) // second hit on another day
			} else {
				b.State, b.SoftInvalidDay = store.StateSoftInvalid, today
				r.dirty[m] = true
			}
		}
		return ItemResult{Status: http.StatusOK, Result: "soft_invalid", Reason: res.Reason}, true
	case apns.DeviceThrottled:
		label("device_throttled")
		r.dev(m).throttled[c] = now.Add(hour)
		return itemRetry("", http.StatusTooManyRequests, "device_quota", "device", hour), false
	case apns.ProviderExpired:
		label("apns_unavailable")
		return itemRetry("", http.StatusServiceUnavailable, "apns_unavailable", "", 30*time.Second), false
	case apns.ProviderInvalid:
		label("relay_misconfigured")
		if r.providerBadIat != 0 && res.TokenIat > r.providerBadIat {
			if !r.misconfigured {
				r.misconfigured = true
				r.M.Set("hlp_apns_misconfigured", 1)
				logx.Event("apns.provider_token_rejected", logx.Str(logx.KState, "stopped"))
			}
		} else if r.providerBadIat == 0 {
			r.providerBadIat = res.TokenIat
		}
		return ItemResult{Status: http.StatusServiceUnavailable, Error: "relay_misconfigured"}, false
	case apns.ProviderTooMany:
		label("apns_unavailable")
		r.tooManyUntil = now.Add(20 * time.Minute)
		return itemRetry("", http.StatusServiceUnavailable, "apns_unavailable", "", 20*time.Minute), false
	case apns.Rejected:
		label("apns_rejected")
		return ItemResult{Status: http.StatusBadGateway, Error: "apns_rejected", Reason: res.Reason}, true
	default:
		label("apns_unavailable")
		return itemRetry("", http.StatusServiceUnavailable, "apns_unavailable", "", 30*time.Second), false
	}
}

func (r *Relay) deleteBindingLocked(m string) {
	if r.persist(r.st.DeleteBinding([]byte(m))) {
		r.dropBindingLocked(m)
	}
}

// countInvalidLocked counts an invalid token against the instance's daily budget; over the budget, the
// instance gets no new bindings for 24 hours and pushes only reach active bindings.
func (r *Relay) countInvalidLocked(s *instState, now time.Time) {
	r.rollInstanceDay(s, now)
	s.invalid++
	s.pending.Invalid++
	if s.invalid > r.tierLimits(s.rec).InvalidTokensDay && !now.Before(s.blockNewUntil) {
		s.blockNewUntil = now.Add(day)
		s.flaggedToday = true
		r.M.Inc("hlp_invalid_budget_exceeded_total")
	}
}

// countApple429Locked tracks Apple's throttling across all sends: over 2 % TooManyRequests in five minutes
// (at least 50 sends) switches silent pushes off for everyone for 15 minutes.
func (r *Relay) countApple429Locked(now time.Time, throttled bool) {
	size := 30 * time.Second
	start := now.Truncate(size)
	i := int(start.Unix()/30) % len(r.apple429)
	if !r.apple429[i].start.Equal(start) {
		r.apple429[i].start, r.apple429[i].sends, r.apple429[i].throttled = start, 0, 0
	}
	r.apple429[i].sends++
	if throttled {
		r.apple429[i].throttled++
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
		r.M.Inc("hlp_silent_paused_total")
		logx.Event("apns.throttled", logx.Str(logx.KClass, "silent"), logx.Str(logx.KState, "paused"))
	}
}

func (r *Relay) recordSummaryLocked(c wire.Class, out ItemResult, lat time.Duration) {
	r.summary.pushes++
	if out.Status != http.StatusOK {
		r.summary.errors[out.Error]++
	}
	if len(r.summary.latencies) < 10000 {
		r.summary.latencies = append(r.summary.latencies, lat.Milliseconds())
	}
	_ = c
}

// handleReceipts implements POST /v1/receipts: an instance reports how many of the pushes the relay
// accepted more than six hours ago were confirmed by a device envelope receipt. Counts only, once per hour,
// summed across instances in memory; the result feeds the coarse "delivery" health signal.
func (r *Relay) handleReceipts(w http.ResponseWriter, req *http.Request) {
	s, body, ok := r.auth(w, req, maxOtherBody)
	if !ok {
		return
	}
	rb, err := wire.ParseReceipts(body)
	if err != nil {
		r.fail(w, req, http.StatusUnprocessableEntity, errBody{Error: "invalid_item"})
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	if !s.lastReceipt.IsZero() && now.Sub(s.lastReceipt) < receiptInterval {
		r.fail(w, req, http.StatusTooManyRequests, errBody{Error: "instance_rate", Scope: "instance", RetryAfter: jitter(receiptInterval - now.Sub(s.lastReceipt))})
		return
	}
	// Only standard instances count, and nobody can report more accepted pushes than the relay itself
	// accepted for that instance in the last three days (M1).
	if s.rec.Tier != store.TierStandard {
		r.reply(w, req, http.StatusNoContent, nil)
		return
	}
	s.lastReceipt = now
	var own int64
	for d := store.Day(now) - 2; d <= store.Day(now); d++ {
		own += r.st.Counters(d, s.rec.ID).Sent
	}
	own += s.pending.Sent
	rb.Accepted = min(rb.Accepted, own)
	rb.Confirmed = min(rb.Confirmed, rb.Accepted)
	h := now.Unix() / 3600
	slot := &r.receipts[h%24]
	if slot.hour != h {
		slot.hour, slot.accepted, slot.confirmed, slot.reporters = h, 0, 0, 0
	}
	slot.accepted += rb.Accepted
	slot.confirmed += rb.Confirmed
	slot.reporters++
	r.reply(w, req, http.StatusNoContent, nil)
}

// deliveryLocked is "ok", "degraded" (fewer than 80 % of at least 20 accepted pushes confirmed by devices
// in the last 24 hours, reported by at least three instances so that a single instance cannot turn the
// public health red) or "unknown".
func (r *Relay) deliveryLocked(now time.Time) string {
	h := now.Unix() / 3600
	var acc, conf, reporters int64
	for _, s := range &r.receipts {
		if h-s.hour < 24 {
			acc += s.accepted
			conf += s.confirmed
			reporters += s.reporters
		}
	}
	switch {
	case acc < 20 || reporters < minReporters:
		return "unknown"
	case float64(conf)/float64(acc) < 0.8:
		return "degraded"
	}
	return "ok"
}
