package relay

import (
	"errors"
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

type registerResp struct {
	InstanceID string     `json:"instanceId"`
	Tier       string     `json:"tier"`
	Limits     TierLimits `json:"limits"`
}

func (r *Relay) handleRegister(w http.ResponseWriter, req *http.Request) {
	body, ok := readBody(w, req, maxOtherBody)
	if !ok {
		r.fail(w, req, http.StatusRequestEntityTooLarge, errBody{Error: "too_large"})
		return
	}
	now := r.cfg.Now()
	reg, err := wire.ParseRegistration(body, r.cfg.Host, now.Unix())
	switch {
	case errors.Is(err, wire.ErrStale):
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "stale_timestamp", RelayTime: now.Unix()})
		return
	case errors.Is(err, wire.ErrSignature):
		r.fail(w, req, http.StatusUnauthorized, errBody{Error: "bad_signature"})
		return
	case err != nil:
		r.fail(w, req, http.StatusUnprocessableEntity, errBody{Error: "invalid_item"})
		return
	}
	today := store.Day(now)
	r.mu.Lock()
	defer r.mu.Unlock()
	// A known key gets its existing id back (idempotent, and the recovery path after a lost database).
	if id, ok := r.byKey[string(reg.PublicKey)]; ok {
		s := r.instances[id]
		switch s.rec.Tier {
		case store.TierRevoked:
			r.fail(w, req, http.StatusForbidden, errBody{Error: "instance_revoked"})
		case store.TierSuspended:
			r.fail(w, req, http.StatusForbidden, errBody{Error: "instance_suspended", Reason: s.rec.Reason})
		default:
			r.reply(w, req, http.StatusOK, registerResp{InstanceID: id, Tier: s.rec.Tier, Limits: r.tierLimits(s.rec)})
		}
		return
	}
	recovery := r.inRecovery(today)
	if status, e := r.registrationGateLocked(req, reg, recovery, now); e != nil {
		r.fail(w, req, status, *e)
		return
	}
	in := &store.Instance{
		ID: newID(), PublicKey: reg.PublicKey, Tier: store.TierProbation, CreatedDay: today,
		LastSeenWeek: store.Week(today), DeviceLimit: r.cfg.Limits.Standard.Devices, Client: reg.Client,
	}
	if recovery {
		in.Tier, in.QuietSinceDay = store.TierStandard, today
	}
	if !r.persist(r.st.PutInstance(in)) {
		r.fail(w, req, http.StatusServiceUnavailable, errStorage(storageRetry))
		return
	}
	r.addInstance(in)
	r.Metrics.Inc("hlp_registrations_total", "result", "created")
	r.countGlobalLocked(today, "instance", "registered")
	r.summary.events["registered"]++
	r.reply(w, req, http.StatusCreated, registerResp{InstanceID: in.ID, Tier: in.Tier, Limits: r.tierLimits(in)})
}

// registrationGateLocked applies, in order, the store state, the registration mode, the invite and the
// address limiter to a new key. An invite is spent only once the registration passed every limit, so a
// refused attempt cannot burn it.
func (r *Relay) registrationGateLocked(req *http.Request, reg *wire.Registration, recovery bool, now time.Time) (int, *errBody) {
	today := store.Day(now)
	if !r.dbWritable {
		e := errStorage(storageRetry)
		return http.StatusServiceUnavailable, &e
	}
	switch r.control.Registration {
	case RegClosed:
		return http.StatusServiceUnavailable, &errBody{Error: "registration_paused", RetryAfter: jitter(time.Hour)}
	case RegInvite:
		if r.inviteIndex(reg.Invite, today) < 0 {
			return http.StatusForbidden, &errBody{Error: "invite_required"}
		}
	}
	if !r.regs.Allow(remoteAddr(req), now, recovery) {
		r.Metrics.Inc("hlp_registrations_total", "result", "limited")
		return http.StatusServiceUnavailable, &errBody{Error: "registration_paused", RetryAfter: jitter(time.Hour)}
	}
	if r.control.Registration == RegInvite {
		r.consumeInvite(reg.Invite, today)
	}
	return 0, nil
}

func (r *Relay) handleRotate(w http.ResponseWriter, req *http.Request) {
	s, body, ok := r.auth(w, req, maxOtherBody)
	if !ok {
		return
	}
	now := r.cfg.Now()
	reg, err := wire.ParseRegistration(body, r.cfg.Host, now.Unix())
	if err != nil {
		r.fail(w, req, http.StatusUnprocessableEntity, errBody{Error: "invalid_item"})
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	today := store.Day(now)
	if s.rec.RotatedDay == today {
		r.fail(w, req, http.StatusTooManyRequests, errBody{Error: "instance_rate", Scope: "instance", RetryAfter: jitter(time.Hour)})
		return
	}
	if _, used := r.byKey[string(reg.PublicKey)]; used {
		r.fail(w, req, http.StatusConflict, errBody{Error: "key_in_use"})
		return
	}
	old := s.rec.PublicKey
	s.rec.PublicKey, s.rec.RotatedDay = reg.PublicKey, today
	if !r.persist(r.st.ReplaceInstanceKey(s.rec, old)) {
		s.rec.PublicKey, s.rec.RotatedDay = old, 0
		r.fail(w, req, http.StatusServiceUnavailable, errStorage(0))
		return
	}
	delete(r.byKey, string(old))
	r.byKey[string(reg.PublicKey)] = s.rec.ID
	r.summary.events["rotated"]++
	r.reply(w, req, http.StatusOK, registerResp{InstanceID: s.rec.ID, Tier: s.rec.Tier, Limits: r.tierLimits(s.rec)})
}

func (r *Relay) handleDeleteInstance(w http.ResponseWriter, req *http.Request) {
	s, _, ok := r.auth(w, req, maxOtherBody)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id := s.rec.ID
	if !r.persist(r.st.DeleteInstance(id)) {
		r.fail(w, req, http.StatusServiceUnavailable, errStorage(0))
		return
	}
	r.dropInstanceLocked(id)
	r.summary.events["deleted"]++
	r.reply(w, req, http.StatusNoContent, nil)
}

// dropInstanceLocked removes an instance and its bindings from memory.
func (r *Relay) dropInstanceLocked(id string) {
	if s := r.instances[id]; s != nil {
		delete(r.byKey, string(s.rec.PublicKey))
		r.nonceTotal -= len(s.nonces)
	}
	delete(r.instances, id)
	delete(r.dirtyInst, id)
	for m := range r.byInst[id] {
		r.dropBindingLocked(m)
	}
}

type statusResp struct {
	State         string     `json:"state"`
	Tier          string     `json:"tier"`
	Reason        string     `json:"reason,omitempty"`
	Limits        TierLimits `json:"limits"`
	Devices       devCounts  `json:"devices"`
	Notice        *Notice    `json:"notice"`
	KeyRotatedDay string     `json:"keyRotatedDay,omitempty"`
	RelayTime     int64      `json:"relayTime"`
	Registration  string     `json:"registration"`
}

type devCounts struct {
	Active      int `json:"active"`
	Provisional int `json:"provisional"`
	Limit       int `json:"limit"`
}

func (r *Relay) handleStatus(w http.ResponseWriter, req *http.Request) {
	s, _, ok := r.auth(w, req, maxOtherBody)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	tl := r.tierLimits(s.rec)
	a, p := r.counts(s.rec.ID)
	resp := statusResp{State: r.serviceStateLocked(now), Tier: s.rec.Tier, Limits: tl, Devices: devCounts{a, p, tl.Devices},
		Notice: r.currentNotice(now), RelayTime: now.Unix(), Registration: r.control.Registration}
	if s.rec.RotatedDay != 0 && store.Day(now)-s.rec.RotatedDay <= 7 {
		resp.KeyRotatedDay = store.DayString(s.rec.RotatedDay)
	}
	r.reply(w, req, http.StatusOK, resp)
}

// serviceStateLocked is the coarse state an instance sees.
func (r *Relay) serviceStateLocked(t time.Time) string {
	paused, _ := r.paused("all", "all", t)
	switch {
	case r.misconfigured:
		return "misconfigured"
	case paused:
		return "maintenance"
	case r.breaker.State(t) != BreakerClosed || !r.dbWritable:
		return "degraded"
	}
	return "ok"
}
