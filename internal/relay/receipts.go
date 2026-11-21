package relay

import (
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// receiptInterval is the shortest gap between two receipt reports of one instance; servers report every
// 55 minutes, which leaves ten minutes of slack.
const receiptInterval = 45 * time.Minute

// minReporters is how many instance reports the delivery signal needs before it can say anything.
const minReporters = 3

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
	if !r.stillThere(s) {
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "unknown_instance"})
		return
	}
	now := r.cfg.Now()
	if !s.lastReceipt.IsZero() && now.Sub(s.lastReceipt) < receiptInterval {
		r.fail(w, req, http.StatusTooManyRequests, errBody{Error: "instance_rate", Scope: "instance", RetryAfter: jitter(receiptInterval - now.Sub(s.lastReceipt))})
		return
	}
	// Only standard instances count, and nobody can report more accepted pushes than the relay itself
	// accepted for that instance in the last three days, so no single instance can turn the signal.
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
		*slot = receiptSlot{hour: h}
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

// receiptsRing sums the receipt reports of the last 24 hours, one slot per hour.
type receiptsRing struct {
	receipts [24]receiptSlot
}

type receiptSlot struct {
	hour                           int64
	accepted, confirmed, reporters int64
}
