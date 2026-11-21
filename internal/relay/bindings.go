package relay

import (
	"bytes"
	"errors"
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

type bindResp struct {
	State string `json:"state"`
}

// handleBind implements POST /v1/bindings (spec/protocol.md, "Device binding").
func (r *Relay) handleBind(w http.ResponseWriter, req *http.Request) {
	s, body, ok := r.auth(w, req, maxOtherBody)
	if !ok {
		return
	}
	now := r.cfg.Now()
	b, err := wire.ParseBind(body, r.cfg.Host, s.rec.ID, now.Unix())
	switch {
	case errors.Is(err, wire.ErrStale):
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "stale_timestamp", RelayTime: now.Unix()})
		return
	case errors.Is(err, wire.ErrSignature):
		r.fail(w, req, http.StatusForbidden, errBody{Error: "binding_refused"})
		return
	case err != nil:
		r.fail(w, req, http.StatusUnprocessableEntity, errBody{Error: "invalid_item"})
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stillThere(s) {
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "unknown_instance"})
		return
	}
	status, resp, e := r.bindLocked(s, b, now)
	if e != nil {
		r.fail(w, req, status, *e)
		return
	}
	r.reply(w, req, status, resp)
}

func (r *Relay) bindLocked(s *instState, b *wire.Bind, now time.Time) (int, *bindResp, *errBody) {
	id := s.rec.ID
	today := store.Day(now)
	if r.instances[id] == nil { // deleted between authentication and this call
		return http.StatusUnauthorized, nil, &errBody{Error: "unknown_instance"}
	}
	if !r.cfg.Environments[b.Env] {
		return http.StatusUnprocessableEntity, nil, &errBody{Error: "env_unsupported"}
	}
	if !r.dbWritable {
		e := errStorage(storageRetry)
		return http.StatusServiceUnavailable, nil, &e
	}
	m := r.tokenMAC(b.Token)
	kh := keyHash(b.BindingKey)
	cur := r.bindings[m]
	blockMAC, block, blocked := r.pairBlock(b.Token, id)
	if status, resp, e := r.bindPrecheckLocked(s, b, m, kh, cur, blocked && !r.optOutReturnLocked(blockMAC, id, block, kh, b), now); status != 0 {
		return status, resp, e
	}
	if code, e := r.admitNewBinding(s, cur, now); e != nil {
		return code, nil, e
	}
	if blocked {
		if !r.persist(r.st.UnblockPair([]byte(blockMAC), id)) {
			e := errStorage(storageRetry)
			return http.StatusServiceUnavailable, nil, &e
		}
		r.Metrics.Inc("hlp_bindings_total", "result", "opt_out_lifted")
	}
	same := cur != nil && cur.InstanceID == id
	nb := newBinding(id, kh, b.Seq, b.Env, b.Consent, today)
	if same {
		nb.State, nb.LastSuccessDay, nb.AlertsToday, nb.AlertsDay = cur.State, cur.LastSuccessDay, cur.AlertsToday, cur.AlertsDay
	}
	if !r.storeBindingLocked(s, m, cur, nb) {
		e := errStorage(storageRetry)
		return http.StatusServiceUnavailable, nil, &e
	}
	if !same {
		s.newBindings++
	}
	r.Metrics.Inc("hlp_bindings_total", "result", "bound")
	if same {
		return http.StatusOK, &bindResp{State: nb.State}, nil
	}
	return http.StatusCreated, &bindResp{State: nb.State}, nil
}

// bindPrecheckLocked decides a binding request before any quota: refused (opt-out or operator block,
// a reused seq), answered (an idempotent repeat) or turned into a conflict challenge. A zero status means
// the request goes on.
func (r *Relay) bindPrecheckLocked(s *instState, b *wire.Bind, m string, kh []byte, cur *store.Binding, optedOut bool, now time.Time) (int, *bindResp, *errBody) {
	id := s.rec.ID
	// A device opt-out holds against the instance. Only the device can undo it: a statement by the same
	// binding key with a higher seq than the binding it left. The instance has no such statement unless the
	// device signed one after leaving.
	if optedOut {
		return http.StatusForbidden, nil, &errBody{Error: "binding_refused"}
	}
	if r.tokenBlocked(b.Token) && (cur == nil || cur.InstanceID != id) {
		return http.StatusForbidden, nil, &errBody{Error: "binding_refused"}
	}
	// After an opt-out the token is unbound, but its binding key stays pinned for a year: a binding with any
	// other key, for example one a second instance made up, needs the challenge only the device can answer.
	if cur == nil {
		if _, pin, pinned := r.optOutPin(b.Token); pinned && (pin.KeyHash == nil || !bytes.Equal(pin.KeyHash, kh)) {
			return http.StatusConflict, nil, r.startChallenge(s, m, b, kh, now)
		}
	}
	// Same key: a repeat of the stored statement is idempotent; anything else needs a higher seq.
	if cur != nil && bytes.Equal(cur.KeyHash, kh) {
		if cur.InstanceID == id && b.Seq == cur.Seq {
			return http.StatusOK, &bindResp{State: cur.State}, nil
		}
		if b.Seq <= cur.Seq {
			return http.StatusForbidden, nil, &errBody{Error: "binding_refused"}
		}
	}
	// A different key on a live binding is a conflict, resolved by a challenge push to the token, never by
	// last-writer-wins. Only the instance that holds the binding may replace it directly, and only after
	// seven days without an accepted push (a restored app with a new key whose challenge did not arrive).
	// Any other instance always needs the challenge, which only the device can answer.
	if cur != nil && !bytes.Equal(cur.KeyHash, kh) {
		lastGood := max(cur.LastSuccessDay, cur.BoundDay)
		if cur.InstanceID != s.rec.ID || store.Day(now)-lastGood < conflictStaleDays {
			return http.StatusConflict, nil, r.startChallenge(s, m, b, kh, now)
		}
	}
	return 0, nil, nil
}

// newBinding is a fresh provisional binding of instID to the binding key hashed in kh.
func newBinding(instID string, kh []byte, seq int64, env string, c wire.Consent, today int) *store.Binding {
	return &store.Binding{
		InstanceID: instID, KeyHash: kh, Seq: seq, Env: env, State: store.StateProvisional, BoundDay: today,
		LastUsedWeek: store.Week(today), ConsentVersion: c.TextVersion, ConsentDay: c.Day,
	}
}

// storeBindingLocked writes nb under the token MAC m, replacing cur, and keeps memory in step. A binding
// taken over from another instance counts as a rebind of instance s. It reports whether the write succeeded.
func (r *Relay) storeBindingLocked(s *instState, m string, cur, nb *store.Binding) bool {
	if !r.persist(r.st.PutBinding([]byte(m), nb)) {
		return false
	}
	if cur != nil && cur.InstanceID != nb.InstanceID {
		s.pending.Rebinds++
	}
	r.setBindingLocked(m, nb)
	return true
}

// optOutReturnLocked reports whether b undoes the opt-out recorded in block: same binding key, a higher seq
// than the binding that left, and signed after the opt-out. The last condition stops an instance that kept
// back a statement the device signed shortly before leaving: such a statement is at most 300 seconds old
// when it is used, so the opt-out time is kept in memory for ten minutes only (never stored), and after a
// restart every statement must be newer than the start. A block without a key (restored from an export) is
// never undone this way.
func (r *Relay) optOutReturnLocked(blockMAC, instID string, block store.PairBlock, kh []byte, b *wire.Bind) bool {
	floor := r.started.Unix()
	if t, ok := r.recentOptOuts[blockMAC+"\x00"+instID]; ok {
		floor = max(floor, t)
	}
	return len(block.KeyHash) > 0 && bytes.Equal(block.KeyHash, kh) && b.Seq > block.Seq && b.Iat > floor
}

// admitNewBinding checks the binding quotas for a binding that is new to this instance.
func (r *Relay) admitNewBinding(s *instState, cur *store.Binding, now time.Time) (int, *errBody) {
	if cur != nil && cur.InstanceID == s.rec.ID {
		return 0, nil
	}
	tl := r.tierLimits(s.rec)
	quota := func(retry time.Duration) *errBody {
		return &errBody{Error: "binding_quota", Scope: "instance", RetryAfter: jitter(retry), Limits: &tl}
	}
	if now.Before(s.blockNewUntil) {
		return http.StatusTooManyRequests, quota(s.blockNewUntil.Sub(now))
	}
	if s.newBindings >= tl.NewBindingsDay {
		return http.StatusTooManyRequests, quota(fullDay)
	}
	active, prov := r.counts(s.rec.ID)
	if prov >= tl.Provisional || active >= tl.Devices {
		return http.StatusTooManyRequests, quota(time.Hour)
	}
	return 0, nil
}

// handleUnbindByInstance implements DELETE /v1/bindings. It answers 204 whether or not the token was bound
// to this instance, so it cannot be used to learn anything.
func (r *Relay) handleUnbindByInstance(w http.ResponseWriter, req *http.Request) {
	s, body, ok := r.auth(w, req, maxOtherBody)
	if !ok {
		return
	}
	tok, err := wire.ParseTokenBody(body)
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
	m := r.tokenMAC(tok)
	if b := r.bindings[m]; b != nil && b.InstanceID == s.rec.ID {
		if !r.persist(r.st.DeleteBinding([]byte(m))) {
			r.fail(w, req, http.StatusServiceUnavailable, errStorage(0))
			return
		}
		r.dropBindingLocked(m)
		r.Metrics.Inc("hlp_bindings_total", "result", "unbound_instance")
	}
	r.reply(w, req, http.StatusNoContent, nil)
}

// handleUnbindSelf implements DELETE /v1/bindings/self: the device leaves an instance without the
// instance's cooperation. The pair stays blocked for 12 months.
func (r *Relay) handleUnbindSelf(w http.ResponseWriter, req *http.Request) {
	body, ok := readBody(w, req, maxOtherBody)
	if !ok {
		r.appFail(w, req, http.StatusRequestEntityTooLarge, errBody{Error: "too_large"})
		return
	}
	now := r.cfg.Now()
	u, err := wire.ParseUnbind(body, now.Unix())
	switch {
	case errors.Is(err, wire.ErrStale):
		r.appFail(w, req, http.StatusUnauthorized, errBody{Error: "stale_timestamp", RelayTime: now.Unix()})
		return
	case err != nil:
		r.appFail(w, req, http.StatusUnprocessableEntity, errBody{Error: "invalid_item"})
		return
	}
	// The signature is checked first and outside the lock, for every request: whether a binding exists
	// must not show in the response time.
	valid := u.Verify(r.cfg.Host)
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.tokenMAC(u.Token)
	b := r.bindings[m]
	if !valid || b == nil || b.InstanceID != u.InstanceID || !bytes.Equal(b.KeyHash, keyHash(u.BindingKey)) {
		r.appFailLocked(w, req, http.StatusNotFound, errBody{Error: "binding_unknown"})
		return
	}
	if !r.appAllowedLocked(w, req, m) {
		return
	}
	block := store.PairBlock{Day: store.Day(now), KeyHash: b.KeyHash, Seq: b.Seq}
	pin := store.OptOutPin{Day: store.Day(now), KeyHash: b.KeyHash}
	if !r.persist(r.st.BlockPair([]byte(m), u.InstanceID, block)) || !r.persist(r.st.PutOptOutPin([]byte(m), pin)) ||
		!r.persist(r.st.DeleteBinding([]byte(m))) {
		r.fail(w, req, http.StatusServiceUnavailable, errStorage(0))
		return
	}
	r.dropBindingLocked(m)
	r.recentOptOuts[m+"\x00"+u.InstanceID] = u.Iat
	for ch, pc := range r.conflicts {
		if pc.mac == m {
			delete(r.conflicts, ch)
		}
	}
	r.Metrics.Inc("hlp_bindings_total", "result", "unbound_self")
	r.countGlobalLocked(store.Day(now), "binding", "opt_out")
	r.reply(w, req, http.StatusNoContent, nil)
}

type selfReadResp struct {
	Kind           string `json:"kind"`
	InstanceID     string `json:"instanceId"`
	State          string `json:"state"`
	Env            string `json:"env"`
	BoundDay       string `json:"boundDay"`
	LastUsedWeekOf string `json:"lastUsedWeekOf"`
	ConsentVersion string `json:"consentVersion"`
	ConsentDay     string `json:"consentDay"`
}

// handleSelfRead implements GET /v1/bindings/self: the device reads everything the relay holds about its
// binding.
func (r *Relay) handleSelfRead(w http.ResponseWriter, req *http.Request) {
	now := r.cfg.Now()
	h := req.Header
	sr, err := wire.ParseSelfRead(h.Get("HL-Token"), h.Get("HL-Binding-Key"), h.Get("HL-Iat"), h.Get("HL-Signature"), now.Unix())
	switch {
	case errors.Is(err, wire.ErrStale):
		r.appFail(w, req, http.StatusUnauthorized, errBody{Error: "stale_timestamp", RelayTime: now.Unix()})
		return
	case err != nil:
		r.appFail(w, req, http.StatusUnprocessableEntity, errBody{Error: "invalid_item"})
		return
	}
	valid := sr.Verify(r.cfg.Host) // first and outside the lock, as for the opt-out
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.tokenMAC(sr.Token)
	b := r.bindings[m]
	if !valid || b == nil || !bytes.Equal(b.KeyHash, keyHash(sr.BindingKey)) {
		r.appFailLocked(w, req, http.StatusNotFound, errBody{Error: "binding_unknown"})
		return
	}
	if !r.appAllowedLocked(w, req, m) {
		return
	}
	r.reply(w, req, http.StatusOK, selfReadResp{
		Kind: "device", InstanceID: b.InstanceID, State: b.State, Env: b.Env, BoundDay: store.DayString(b.BoundDay),
		LastUsedWeekOf: store.DayString(store.WeekStart(b.LastUsedWeek)), ConsentVersion: b.ConsentVersion, ConsentDay: b.ConsentDay,
	})
}
