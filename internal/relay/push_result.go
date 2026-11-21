package relay

import (
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// sent is one push that Apple has answered, with the state it belongs to.
type sent struct {
	instID string
	s      *instState     // nil when the instance was deleted meanwhile
	b      *store.Binding // nil unless the token is still bound to instID
	m      string
	it     *wire.Item
}

// complete applies Apple's answer to the binding and the counters (spec/protocol.md, "Failure handling").
func (r *Relay) complete(instID, m string, it *wire.Item, ik string, ent *idemEntry, res apns.Result) {
	r.mu.Lock()
	now := r.cfg.Now()
	p := &sent{instID: instID, s: r.instances[instID], b: r.bindings[m], m: m, it: it}
	if p.b != nil && p.b.InstanceID != instID {
		p.b = nil
	}
	out, keep := r.applyLocked(p, res, now)
	out.Ref = it.Ref
	r.recordSummaryLocked(out, res.Latency)
	r.mu.Unlock()
	r.finish(ik, ent, out, keep)
}

// labelLocked counts one outcome in the metrics and the global day counters.
func (r *Relay) labelLocked(c wire.Class, today int, result string) {
	r.Metrics.Inc("hlp_push_total", "class", string(c), "result", result)
	r.countGlobalLocked(today, string(c), result)
}

// applyLocked maps Apple's answer to the item result and reports whether the result may be replayed.
func (r *Relay) applyLocked(p *sent, res apns.Result, now time.Time) (ItemResult, bool) {
	c := p.it.Class
	today := store.Day(now)
	// Only bindings that have had a push accepted count for the breaker: invented tokens never get there.
	established := c != wire.ClassLiveActivity && p.b != nil && p.b.LastSuccessDay != 0
	r.countApple429Locked(now, res.Outcome == apns.DeviceThrottled)
	switch res.Outcome {
	case apns.Accepted:
		r.labelLocked(c, today, "accepted")
		r.applyAcceptedLocked(p, established, now, today)
		// A newer provider token that Apple accepts clears an earlier rejection: only a rejection of the
		// very next token after a rejection stops the relay.
		if r.providerBadIat != 0 && res.TokenIat > r.providerBadIat {
			r.providerBadIat = 0
		}
		return ItemResult{Status: http.StatusOK, Result: "accepted"}, true
	case apns.Unregistered, apns.SoftInvalid:
		return r.applyTokenFailureLocked(p, res, established, now, today)
	case apns.DeviceThrottled:
		r.labelLocked(c, today, "device_throttled")
		r.dev(p.m).throttled[c] = now.Add(time.Hour)
		return itemRetry("", http.StatusTooManyRequests, "device_quota", "device", time.Hour), false
	case apns.ProviderExpired:
		r.labelLocked(c, today, "apns_unavailable")
		return itemRetry("", http.StatusServiceUnavailable, "apns_unavailable", "", 30*time.Second), false
	case apns.ProviderInvalid:
		r.labelLocked(c, today, "relay_misconfigured")
		r.providerInvalidLocked(res.TokenIat)
		return ItemResult{Status: http.StatusServiceUnavailable, Error: "relay_misconfigured"}, false
	case apns.ProviderTooMany:
		r.labelLocked(c, today, "apns_unavailable")
		r.tooManyUntil = now.Add(20 * time.Minute)
		return itemRetry("", http.StatusServiceUnavailable, "apns_unavailable", "", 20*time.Minute), false
	case apns.Rejected:
		r.labelLocked(c, today, "apns_rejected")
		return ItemResult{Status: http.StatusBadGateway, Error: "apns_rejected", Reason: res.Reason}, true
	default:
		r.labelLocked(c, today, "apns_unavailable")
		return itemRetry("", http.StatusServiceUnavailable, "apns_unavailable", "", 30*time.Second), false
	}
}

// applyAcceptedLocked records a delivery: the binding becomes active, the instance has delivered today.
func (r *Relay) applyAcceptedLocked(p *sent, established bool, now time.Time, today int) {
	r.apnsLastOK = now
	if established {
		r.breaker.Record(now, p.instID, true, false)
	}
	if b := p.b; b != nil {
		if b.State != store.StateActive {
			b.State, b.SoftInvalidDay = store.StateActive, 0
		}
		b.LastSuccessDay, b.LastUsedWeek = today, store.Week(today)
		r.dirty[p.m] = true
	}
	if s := p.s; s != nil {
		s.pending.Sent++
		if s.rec.FirstDeliveryDay == 0 || s.rec.LastPushDay != today {
			if s.rec.FirstDeliveryDay == 0 {
				s.rec.FirstDeliveryDay = today
			}
			s.rec.LastPushDay = today
			r.dirtyInst[s.rec.ID] = true
		}
	}
}

// applyTokenFailureLocked handles Unregistered and the soft failures BadDeviceToken and
// DeviceTokenNotForTopic: it feeds the breaker and the invalid-token budget and, while the breaker is
// closed, deletes or marks the binding.
func (r *Relay) applyTokenFailureLocked(p *sent, res apns.Result, established bool, now time.Time, today int) (ItemResult, bool) {
	c := p.it.Class
	if c == wire.ClassLiveActivity {
		r.labelLocked(c, today, "activity_gone")
		return ItemResult{Status: http.StatusOK, Result: "activity_gone"}, true
	}
	if established && r.breaker.Record(now, p.instID, false, true) {
		r.Metrics.Set("hlp_breaker_open", 1)
		logx.Event("breaker.opened", logx.Str(logx.KState, BreakerOpen))
	}
	marking := r.breaker.Marking(now)
	// The invalid-token budget is charged for every token that never delivered, even while the breaker is
	// not closed; only established bindings are spared then, because a misconfiguration hits them.
	if p.s != nil && (!established || marking) {
		r.countInvalidLocked(p.s, now)
	}
	if !marking {
		r.labelLocked(c, today, "relay_misconfigured")
		return ItemResult{Status: http.StatusServiceUnavailable, Error: "relay_misconfigured"}, false
	}
	if res.Outcome == apns.Unregistered {
		r.labelLocked(c, today, "unregistered")
		if p.b != nil {
			r.deleteBindingLocked(p.m)
		}
		return ItemResult{Status: http.StatusGone, Error: "unregistered"}, true
	}
	r.labelLocked(c, today, "soft_invalid")
	if b := p.b; b != nil {
		if b.State == store.StateSoftInvalid && b.SoftInvalidDay != today {
			r.deleteBindingLocked(p.m) // second hit on another day
		} else {
			b.State, b.SoftInvalidDay = store.StateSoftInvalid, today
			r.dirty[p.m] = true
		}
	}
	return ItemResult{Status: http.StatusOK, Result: "soft_invalid", Reason: res.Reason}, true
}

// providerInvalidLocked handles InvalidProviderToken. The first rejection only records the token's iat; a
// rejection of a newer token proves the key or team is wrong, and the relay stops sending.
func (r *Relay) providerInvalidLocked(iat int64) {
	switch {
	case r.providerBadIat != 0 && iat > r.providerBadIat:
		if !r.misconfigured {
			r.misconfigured = true
			r.Metrics.Set("hlp_apns_misconfigured", 1)
			logx.Event("apns.provider_token_rejected", logx.Str(logx.KState, "stopped"))
		}
	case r.providerBadIat == 0:
		r.providerBadIat = iat
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
		s.blockNewUntil = now.Add(fullDay)
		r.flagLocked(s, now)
		r.Metrics.Inc("hlp_invalid_budget_exceeded_total")
	}
}

func (r *Relay) recordSummaryLocked(out ItemResult, lat time.Duration) {
	r.summary.pushes++
	if out.Status != http.StatusOK {
		r.summary.errors[out.Error]++
	}
	if len(r.summary.latencies) < 10000 {
		r.summary.latencies = append(r.summary.latencies, lat.Milliseconds())
	}
}
