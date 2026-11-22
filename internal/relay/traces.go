package relay

import (
	"strings"
	"time"
)

// Delivery traces keep Apple's apns-unique-id of a push for a short time, so that the operator can look up
// one lost push in the delivery log of Apple's Push Notifications Console. Apple sends that header only in
// the development environment, so production pushes leave no trace at all. Traces live in memory only,
// keyed by instance id and the item's ref, never in the store, the export, a log line or a metric, and are
// gone after traceTTL, at a restart, or when the instance is deleted.
const (
	traceTTL = 72 * time.Hour
	traceMax = 50000
)

type trace struct {
	uniqueID string
	result   string
	exp      time.Time
}

type traceSlot struct {
	key string
	exp time.Time
}

// traces is the bounded, time-ordered set of delivery traces. Every entry has the same lifetime, so the
// order of insertion is the order of expiry and pruning only looks at the front.
type traces struct {
	byKey map[string]trace
	order []traceSlot
}

// put records the trace of key, replacing an earlier one (a retry of the same ref), and prunes.
func (t *traces) put(key, uniqueID, result string, now time.Time) {
	if t.byKey == nil {
		t.byKey = map[string]trace{}
	}
	exp := now.Add(traceTTL)
	t.byKey[key] = trace{uniqueID: uniqueID, result: result, exp: exp}
	t.order = append(t.order, traceSlot{key: key, exp: exp})
	t.prune(now)
}

// prune drops expired traces and, beyond traceMax, the oldest ones.
func (t *traces) prune(now time.Time) {
	n := 0
	for n < len(t.order) && (!now.Before(t.order[n].exp) || len(t.order)-n > traceMax) {
		s := t.order[n]
		if cur, ok := t.byKey[s.key]; ok && cur.exp.Equal(s.exp) {
			delete(t.byKey, s.key)
		}
		n++
	}
	if n > 0 {
		t.order = append([]traceSlot(nil), t.order[n:]...)
	}
}

// get returns the live trace of key.
func (t *traces) get(key string, now time.Time) (trace, bool) {
	tr, ok := t.byKey[key]
	if !ok || !now.Before(tr.exp) {
		return trace{}, false
	}
	return tr, true
}

// dropInstance removes every trace of an instance. Its slots in the order stay and expire harmlessly.
func (t *traces) dropInstance(id string) {
	for k := range t.byKey {
		if strings.HasPrefix(k, id+"\x00") {
			delete(t.byKey, k)
		}
	}
}

// DeliveryTrace is the admin command `delivery <instance-id> <ref>`: Apple's apns-unique-id of the last
// push of that ref in the past 72 hours, and its result.
func (r *Relay) DeliveryTrace(instID, ref string) (map[string]string, error) {
	if instID == "" || ref == "" {
		return nil, adminError("delivery <instance-id> <ref>")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	tr, ok := r.traces.get(instID+"\x00"+ref, r.cfg.Now())
	if !ok {
		return nil, adminError("no trace: Apple sends apns-unique-id only in the development environment, and traces are kept 72 hours")
	}
	return map[string]string{"apnsUniqueId": tr.uniqueID, "result": tr.result}, nil
}
