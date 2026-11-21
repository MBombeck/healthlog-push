package relay

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/queue"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// pendingConflict is a binding request with a different key on a live binding, waiting for the device to
// answer the challenge push. The token stays in memory for at most challengeTTL.
type pendingConflict struct {
	mac        string
	token      []byte // in memory for at most challengeTTL
	tokenTag   []byte
	instanceID string
	keyHash    []byte
	seq        int64
	env        string
	consent    wire.Consent
	expires    time.Time
}

// startChallenge sends a challenge push to the token of a conflicting binding request.
func (r *Relay) startChallenge(s *instState, m string, b *wire.Bind, kh []byte, now time.Time) *errBody {
	today := store.Day(now)
	tl := r.tierLimits(s.rec)
	r.Metrics.Inc("hlp_bindings_total", "result", "conflict")
	// One challenge per token, instance and day: one instance cannot use up the challenge of another, and
	// an instance can wake a device at most once a day.
	ck := m + "\x00" + s.rec.ID
	if r.challengeDay[ck] == today || s.challenges >= tl.ChallengesDay {
		return &errBody{Error: "binding_conflict", Reason: "challenge_quota"}
	}
	r.challengeDay[ck] = today
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
		r.Metrics.Inc("hlp_challenges_total", "result", string(res.Outcome))
	}, Drop: func() {}})
	if err != nil {
		// Not sent: give the quota back so the token can be challenged again today.
		delete(r.conflicts, ch)
		delete(r.challengeDay, ck)
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
	valid := ans.Verify(r.cfg.Host) // first and outside the lock, as for the opt-out
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	pc := r.conflicts[ans.Challenge]
	if !valid || pc == nil || now.After(pc.expires) || !bytes.Equal(pc.tokenTag, ans.TokenTag) ||
		!bytes.Equal(pc.keyHash, keyHash(ans.BindingKey)) {
		r.appFailLocked(w, req, http.StatusForbidden, errBody{Error: "challenge_refused"})
		return
	}
	if !r.appAllowedLocked(w, req, pc.mac) {
		return
	}
	delete(r.conflicts, ans.Challenge)
	s := r.instances[pc.instanceID]
	if s == nil || s.rec.Tier == store.TierRevoked || s.rec.Tier == store.TierSuspended {
		r.fail(w, req, http.StatusForbidden, errBody{Error: "challenge_refused"})
		return
	}
	if _, _, blocked := r.pairBlock(pc.token, pc.instanceID); blocked {
		r.fail(w, req, http.StatusForbidden, errBody{Error: "challenge_refused"})
		return
	}
	cur := r.bindings[pc.mac]
	if code, e := r.admitNewBinding(s, cur, now); e != nil {
		r.fail(w, req, code, *e)
		return
	}
	nb := newBinding(pc.instanceID, pc.keyHash, pc.seq, pc.env, pc.consent, store.Day(now))
	if !r.storeBindingLocked(s, pc.mac, cur, nb) {
		r.fail(w, req, http.StatusServiceUnavailable, errStorage(0))
		return
	}
	if cur == nil || cur.InstanceID != pc.instanceID {
		s.newBindings++ // the same quotas as a direct binding
		r.dirtyInst[s.rec.ID] = true
	}
	// The device proved the new key: an opt-out pin of this token now names that key.
	if pinMAC, _, pinned := r.optOutPin(pc.token); pinned {
		r.persist(r.st.PutOptOutPin([]byte(pinMAC), store.OptOutPin{Day: store.Day(now), KeyHash: pc.keyHash}))
	}
	r.Metrics.Inc("hlp_bindings_total", "result", "challenge_resolved")
	r.summary.events["challenge_resolved"]++
	r.reply(w, req, http.StatusOK, bindResp{State: nb.State})
}
