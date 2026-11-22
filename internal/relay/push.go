package relay

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/queue"
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
	// Admitted items are queued and sent on the queue's workers; a client that disconnects must not cancel
	// them, so the sends do not inherit the request context.
	results, entries, status, e := r.admitBatch(s, pb, now) //nolint:contextcheck // queued sends outlive the request
	if e != nil {
		r.fail(w, req, status, *e)
		return
	}
	r.collectResults(pb, entries, results)
	r.mu.Lock()
	n := r.currentNotice(now)
	r.mu.Unlock()
	r.reply(w, req, http.StatusOK, pushResp{Results: results, Notice: n, RelayTime: now.Unix()})
}

// admitBatch admits the items of one batch under the lock, released by defer, so that no panic can leave
// the relay locked.
func (r *Relay) admitBatch(s *instState, pb *wire.PushBody, now time.Time) ([]ItemResult, []*idemEntry, int, *errBody) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stillThere(s) {
		return nil, nil, http.StatusUnauthorized, &errBody{Error: "unknown_instance"}
	}
	if e, status := r.requestGateLocked(s, now); e != nil {
		return nil, nil, status, e
	}
	results := make([]ItemResult, len(pb.Items))
	entries := make([]*idemEntry, len(pb.Items))
	seen := map[string]bool{}
	for i := range pb.Items {
		p := &pb.Items[i]
		if seen[p.Ref] {
			results[i] = itemErr(p.Ref, http.StatusUnprocessableEntity, "invalid_item")
			continue
		}
		seen[p.Ref] = true
		results[i], entries[i] = r.admitLocked(s, p, now)
	}
	return results, entries, 0, nil
}

// collectResults waits, within pushWait for the whole batch, for every item that went to the queue and
// fills its result; an item still open at the deadline is answered as apns_unavailable.
func (r *Relay) collectResults(pb *wire.PushBody, entries []*idemEntry, results []ItemResult) {
	deadline := time.NewTimer(pushWait)
	defer deadline.Stop()
	for i, ent := range entries {
		if ent == nil {
			continue
		}
		select {
		case <-ent.done:
			r.mu.Lock()
			res := *ent.res
			r.mu.Unlock()
			res.Ref = pb.Items[i].Ref
			results[i] = res
		case <-deadline.C:
			deadline.Reset(0)
			// Past the deadline, a result that is already there is still reported as it is.
			select {
			case <-ent.done:
				r.mu.Lock()
				res := *ent.res
				r.mu.Unlock()
				res.Ref = pb.Items[i].Ref
				results[i] = res
			default:
				results[i] = itemRetry(pb.Items[i].Ref, http.StatusServiceUnavailable, "apns_unavailable", "", 30*time.Second)
			}
		}
	}
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
		r.Metrics.Inc("hlp_push_total", "class", classLabel(p.Class), "result", "invalid_item")
		return itemErr(p.Ref, http.StatusUnprocessableEntity, "invalid_item"), nil
	}
	ik := s.rec.ID + "\x00" + it.Ref
	if e := r.idem[ik]; e != nil && now.Before(e.exp) {
		if e.res == nil {
			r.Metrics.Inc("hlp_push_retries_total", "answer", "joined")
			return ItemResult{}, e
		}
		r.Metrics.Inc("hlp_push_retries_total", "answer", "replayed")
		res := *e.res
		res.Duplicate = true
		return res, nil
	}
	m := r.tokenMAC(it.Token)
	b := r.bindings[m]
	if b == nil || b.InstanceID != s.rec.ID {
		return r.refused(it, http.StatusNotFound, "binding_unknown"), nil
	}
	if b.Env != it.Env {
		return r.refused(it, http.StatusUnprocessableEntity, "invalid_item"), nil
	}
	ch, res := r.limitsLocked(s, b, m, it, now)
	if ch == nil {
		r.Metrics.Inc("hlp_push_total", "class", string(it.Class), "result", res.Error)
		if res.Status == http.StatusTooManyRequests {
			r.rateLimited(surfacePush)
		}
		return res, nil
	}
	ent := &idemEntry{done: make(chan struct{}), exp: now.Add(idemTTL)}
	push := r.buildPush(it, now)
	job := &queue.Job{Instance: s.rec.ID, High: it.Class != wire.ClassSilent}
	kind := kindOf(it)
	if it.Class == wire.ClassLiveActivity {
		r.observePriority(push.Urgent)
	}
	job.Run = func() {
		res := r.sender.Send(context.Background(), push)
		r.observeSend(kind, now, res)
		r.complete(s.rec.ID, m, it, ik, ent, res)
	}
	job.Drop = func() {
		r.finish(ik, ent, itemRetry(it.Ref, http.StatusServiceUnavailable, "queue_full", "", 2*time.Second), false)
	}
	if err := r.q.Push(job); err != nil {
		ch.undo()
		r.Metrics.Inc("hlp_push_total", "class", string(it.Class), "result", "queue_full")
		scope := ""
		if errors.Is(err, queue.ErrInstanceFull) {
			scope = "instance"
		}
		return itemRetry(it.Ref, http.StatusServiceUnavailable, "queue_full", scope, 2*time.Second), nil
	}
	r.idemPutLocked(ik, ent)
	return ItemResult{}, ent
}

// refused counts an item refused before it is queued and answers it, so no refusal leaves the metrics out.
func (r *Relay) refused(it *wire.Item, status int, e string) ItemResult {
	r.Metrics.Inc("hlp_push_total", "class", string(it.Class), "result", e)
	return itemErr(it.Ref, status, e)
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
		p.Urgent = apns.LiveActivityUrgent(it.Event, it.State)
		switch it.Event {
		case wire.EventStart:
			p.Payload = apns.LiveActivityStartPayload(now, it.State)
		case wire.EventUpdate:
			p.Payload = apns.LiveActivityUpdatePayload(now, it.State)
		default:
			p.Payload = apns.LiveActivityEndPayload(now)
		}
	}
	return p
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
