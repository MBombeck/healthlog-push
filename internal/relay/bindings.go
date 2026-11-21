package relay

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/queue"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

const (
	hour = time.Hour
	r5m  = 5 * time.Minute
	day  = 24 * time.Hour
)

type bindResp struct {
	State     string `json:"state"`
	Challenge string `json:"challenge,omitempty"` // "sent" or "quota" on 409
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
	if r.instances[id] == nil { // deleted between authentication and this call (N2)
		return http.StatusUnauthorized, nil, &errBody{Error: "unknown_instance"}
	}
	if !r.cfg.Environments[b.Env] {
		return http.StatusUnprocessableEntity, nil, &errBody{Error: "env_unsupported"}
	}
	if !r.dbWritable {
		return http.StatusServiceUnavailable, nil, &errBody{Error: "storage_unavailable", RetryAfter: jitter(r5m)}
	}
	m := r.tokenMAC(b.Token)
	kh := keyHash(b.BindingKey)
	cur := r.bindings[m]
	if r.pairBlocked(b.Token, id) {
		return http.StatusForbidden, nil, &errBody{Error: "binding_refused"}
	}
	if r.tokenBlocked(b.Token) && (cur == nil || cur.InstanceID != id) {
		return http.StatusForbidden, nil, &errBody{Error: "binding_refused"}
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
	// last-writer-wins. Only a binding without an accepted push for seven days may be replaced directly.
	if cur != nil && !bytes.Equal(cur.KeyHash, kh) {
		lastGood := max(cur.LastSuccessDay, cur.BoundDay)
		if today-lastGood < conflictStaleDy {
			return http.StatusConflict, nil, r.startChallenge(s, m, b, kh, now)
		}
	}
	if code, e := r.admitNewBinding(s, cur, now); e != nil {
		return code, nil, e
	}
	nb := &store.Binding{
		InstanceID: id, KeyHash: kh, Seq: b.Seq, Env: b.Env, State: store.StateProvisional, BoundDay: today,
		LastUsedWeek: store.Week(today), ConsentVersion: b.Consent.TextVersion, ConsentDay: b.Consent.Day,
	}
	if cur != nil && cur.InstanceID == id {
		nb.State, nb.LastSuccessDay, nb.AlertsToday, nb.AlertsDay = cur.State, cur.LastSuccessDay, cur.AlertsToday, cur.AlertsDay
	}
	if !r.persist(r.st.PutBinding([]byte(m), nb)) {
		return http.StatusServiceUnavailable, nil, &errBody{Error: "storage_unavailable", RetryAfter: jitter(r5m)}
	}
	if cur != nil && cur.InstanceID != id {
		s.pending.Rebinds++
	}
	if cur == nil || cur.InstanceID != id {
		s.newBindings++
	}
	r.setBindingLocked(m, nb)
	r.M.Inc("hlp_bindings_total", "result", "bound")
	status := http.StatusCreated
	if cur != nil && cur.InstanceID == id {
		status = http.StatusOK
	}
	return status, &bindResp{State: nb.State}, nil
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
		return http.StatusTooManyRequests, quota(day)
	}
	active, prov := r.counts(s.rec.ID)
	if prov >= tl.Provisional || active >= tl.Devices {
		return http.StatusTooManyRequests, quota(hour)
	}
	return 0, nil
}

func (r *Relay) startChallenge(s *instState, m string, b *wire.Bind, kh []byte, now time.Time) *errBody {
	today := store.Day(now)
	tl := r.tierLimits(s.rec)
	r.M.Inc("hlp_bindings_total", "result", "conflict")
	if r.challengeDay[m] == today || s.challenges >= tl.ChallengesDay {
		return &errBody{Error: "binding_conflict", Reason: "challenge_quota"}
	}
	r.challengeDay[m] = today
	s.challenges++
	s.flaggedToday = true
	ch := newChallenge()
	r.conflicts[ch] = &pendingConflict{
		mac: m, token: b.Token, tokenTag: wire.TokenTag(b.Token), instanceID: s.rec.ID, keyHash: kh, seq: b.Seq, env: b.Env,
		consent: b.Consent, expires: now.Add(challengeTTL),
	}
	p := &apns.Push{Token: b.Token, Challenge: true, Payload: apns.ChallengePayload(ch), Expiration: now.Add(challengeTTL), Sandbox: b.Env == "sandbox"}
	err := r.q.Push(&queue.Job{Instance: s.rec.ID, Run: func() {
		res := r.sender.Send(context.Background(), p)
		r.M.Inc("hlp_challenges_total", "result", string(res.Outcome))
	}, Drop: func() {}})
	if err != nil {
		// Not sent: give the quota back so the token can be challenged again today (N5).
		delete(r.conflicts, ch)
		delete(r.challengeDay, m)
		s.challenges--
		return &errBody{Error: "binding_conflict", Reason: "challenge_unsent", RetryAfter: jitter(time.Minute)}
	}
	return &errBody{Error: "binding_conflict", Reason: "challenge_sent"}
}

// handleChallenge implements POST /v1/bindings/challenge, called by the app with its binding key.
func (r *Relay) handleChallenge(w http.ResponseWriter, req *http.Request) {
	body, ok := readBody(w, req, maxOtherBody)
	if !ok {
		r.appFail(w, req, http.StatusRequestEntityTooLarge, errBody{Error: "too_large"})
		return
	}
	ans, err := wire.ParseChallenge(body)
	if err != nil {
		r.appFail(w, req, http.StatusUnprocessableEntity, errBody{Error: "invalid_item"})
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	pc := r.conflicts[ans.Challenge]
	if pc == nil || now.After(pc.expires) || !bytes.Equal(pc.tokenTag, ans.TokenTag) ||
		!bytes.Equal(pc.keyHash, keyHash(ans.BindingKey)) || !ans.Verify(r.cfg.Host) {
		r.appFailLocked(w, req, http.StatusForbidden, errBody{Error: "challenge_refused"})
		return
	}
	if !r.appAllowedLocked(w, req, pc.mac) {
		return
	}
	delete(r.conflicts, ans.Challenge)
	s := r.instances[pc.instanceID]
	if s == nil || s.rec.Tier == store.TierRevoked || s.rec.Tier == store.TierSuspended || r.pairBlocked(pc.token, pc.instanceID) {
		r.fail(w, req, http.StatusForbidden, errBody{Error: "challenge_refused"})
		return
	}
	cur := r.bindings[pc.mac]
	if code, e := r.admitNewBinding(s, cur, now); e != nil {
		r.fail(w, req, code, *e)
		return
	}
	today := store.Day(now)
	nb := &store.Binding{InstanceID: pc.instanceID, KeyHash: pc.keyHash, Seq: pc.seq, Env: pc.env, State: store.StateProvisional,
		BoundDay: today, LastUsedWeek: store.Week(today), ConsentVersion: pc.consent.TextVersion, ConsentDay: pc.consent.Day}
	if !r.persist(r.st.PutBinding([]byte(pc.mac), nb)) {
		r.fail(w, req, http.StatusServiceUnavailable, errBody{Error: "storage_unavailable"})
		return
	}
	if cur != nil && cur.InstanceID != pc.instanceID {
		s.pending.Rebinds++
		r.dirtyInst[s.rec.ID] = true
	}
	r.setBindingLocked(pc.mac, nb)
	r.M.Inc("hlp_bindings_total", "result", "challenge_resolved")
	r.summary.events["challenge_resolved"]++
	r.reply(w, req, http.StatusOK, bindResp{State: nb.State})
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
	m := r.tokenMAC(tok)
	if b := r.bindings[m]; b != nil && b.InstanceID == s.rec.ID {
		if !r.persist(r.st.DeleteBinding([]byte(m))) {
			r.fail(w, req, http.StatusServiceUnavailable, errBody{Error: "storage_unavailable"})
			return
		}
		r.dropBindingLocked(m)
		r.M.Inc("hlp_bindings_total", "result", "unbound_instance")
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
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.tokenMAC(u.Token)
	b := r.bindings[m]
	if b == nil || b.InstanceID != u.InstanceID || !bytes.Equal(b.KeyHash, keyHash(u.BindingKey)) || !u.Verify(r.cfg.Host) {
		r.appFailLocked(w, req, http.StatusNotFound, errBody{Error: "binding_unknown"})
		return
	}
	if !r.appAllowedLocked(w, req, m) {
		return
	}
	if !r.persist(r.st.BlockPair([]byte(m), u.InstanceID, store.Day(now))) || !r.persist(r.st.DeleteBinding([]byte(m))) {
		r.fail(w, req, http.StatusServiceUnavailable, errBody{Error: "storage_unavailable"})
		return
	}
	r.dropBindingLocked(m)
	for ch, pc := range r.conflicts {
		if pc.mac == m {
			delete(r.conflicts, ch)
		}
	}
	r.M.Inc("hlp_bindings_total", "result", "unbound_self")
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
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.tokenMAC(sr.Token)
	b := r.bindings[m]
	if b == nil || !bytes.Equal(b.KeyHash, keyHash(sr.BindingKey)) || !sr.Verify(r.cfg.Host) {
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
