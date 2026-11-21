package relay

import (
	"bytes"
	"errors"
	"net/http"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// The Live Activity consent is separate from the relay consent. Live Activity start and update carry their
// content state in the clear (ActivityKit cannot decrypt), so with it the relay and Apple see when a dose is
// due. The device signs it (hl-la-consent-v1); its instance passes it on; the device can withdraw it at the
// relay directly (hl-la-withdraw-v1), and its instance can drop it.

type laConsentResp struct {
	LiveActivity string `json:"liveActivity"` // "granted"
}

// handleLAConsent implements POST /v1/bindings/liveactivity.
func (r *Relay) handleLAConsent(w http.ResponseWriter, req *http.Request) {
	s, body, ok := r.auth(w, req, maxOtherBody)
	if !ok {
		return
	}
	now := r.cfg.Now()
	c, err := wire.ParseLAConsent(body, r.cfg.Host, s.rec.ID, now.Unix())
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
	m := r.tokenMAC(c.Token)
	b := r.bindings[m]
	if b == nil || b.InstanceID != s.rec.ID || !bytes.Equal(b.KeyHash, keyHash(c.BindingKey)) {
		r.fail(w, req, http.StatusNotFound, errBody{Error: "binding_unknown"})
		return
	}
	next := *b
	next.LAConsentVersion, next.LAConsentDay = c.TextVersion, c.Day
	if !r.persist(r.st.PutBinding([]byte(m), &next)) {
		r.fail(w, req, http.StatusServiceUnavailable, errStorage(storageRetry))
		return
	}
	*b = next
	r.Metrics.Inc("hlp_bindings_total", "result", "liveactivity_consent")
	r.reply(w, req, http.StatusOK, laConsentResp{LiveActivity: "granted"})
}

// handleLAConsentRemove implements DELETE /v1/bindings/liveactivity: the instance drops the consent (the
// person switched it off in the app). It answers 204 whatever the token, like DELETE /v1/bindings.
func (r *Relay) handleLAConsentRemove(w http.ResponseWriter, req *http.Request) {
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
	if !r.clearLAConsentLocked(r.tokenMAC(tok), s.rec.ID) {
		r.fail(w, req, http.StatusServiceUnavailable, errStorage(storageRetry))
		return
	}
	r.reply(w, req, http.StatusNoContent, nil)
}

// handleLAWithdrawSelf implements DELETE /v1/bindings/self/liveactivity: the device withdraws the consent
// without its instance. Like the opt-out, the signature is checked first and outside the lock.
func (r *Relay) handleLAWithdrawSelf(w http.ResponseWriter, req *http.Request) {
	body, ok := readBody(w, req, maxOtherBody)
	if !ok {
		r.appFail(w, req, http.StatusRequestEntityTooLarge, errBody{Error: "too_large"})
		return
	}
	now := r.cfg.Now()
	u, err := wire.ParseLAWithdraw(body, now.Unix())
	switch {
	case errors.Is(err, wire.ErrStale):
		r.appFail(w, req, http.StatusUnauthorized, errBody{Error: "stale_timestamp", RelayTime: now.Unix()})
		return
	case err != nil:
		r.appFail(w, req, http.StatusUnprocessableEntity, errBody{Error: "invalid_item"})
		return
	}
	valid := u.VerifyWithdraw(r.cfg.Host)
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
	if !r.clearLAConsentLocked(m, u.InstanceID) {
		r.fail(w, req, http.StatusServiceUnavailable, errStorage(0))
		return
	}
	r.reply(w, req, http.StatusNoContent, nil)
}

// clearLAConsentLocked removes the Live Activity consent of the binding under m held by instID, if any.
// It reports false only when the store refused the write.
func (r *Relay) clearLAConsentLocked(m, instID string) bool {
	b := r.bindings[m]
	if b == nil || b.InstanceID != instID || b.LAConsentVersion == "" {
		return true
	}
	next := *b
	next.LAConsentVersion, next.LAConsentDay = "", ""
	if !r.persist(r.st.PutBinding([]byte(m), &next)) {
		return false
	}
	*b = next
	r.Metrics.Inc("hlp_bindings_total", "result", "liveactivity_consent_withdrawn")
	return true
}
