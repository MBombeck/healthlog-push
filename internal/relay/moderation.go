package relay

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// Suspend sets an instance to suspended with a reason from the closed set. Bindings stay.
func (r *Relay) Suspend(id, reason string) error {
	if !store.Reasons[reason] {
		return errors.New("unknown reason")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.instances[id]
	switch {
	case s == nil:
		return errors.New("unknown instance")
	case s.rec.Tier == store.TierRevoked:
		return errors.New("instance is revoked; a revocation cannot be turned into a suspension")
	}
	next := *s.rec
	next.Tier, next.Reason, next.ReasonDay = store.TierSuspended, reason, store.Day(r.cfg.Now())
	if err := r.st.PutInstance(&next); err != nil {
		return err
	}
	*s.rec = next
	logx.Event("admin.suspend", logx.Str(logx.KReason, reason))
	return nil
}

// Unsuspend returns a suspended instance to probation.
func (r *Relay) Unsuspend(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.instances[id]
	if s == nil || s.rec.Tier != store.TierSuspended {
		return errors.New("instance not suspended")
	}
	next := *s.rec
	next.Tier, next.Reason, next.ReasonDay = store.TierProbation, "", 0
	if err := r.st.PutInstance(&next); err != nil {
		return err
	}
	*s.rec = next
	logx.Event("admin.unsuspend")
	return nil
}

// Revoke revokes an instance and deletes its bindings. The instance record stays as revoked so that its key
// cannot register again.
func (r *Relay) Revoke(id, reason string) error {
	if reason == "" {
		reason = "abuse"
	}
	if !store.Reasons[reason] {
		return errors.New("unknown reason")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.instances[id]
	if s == nil {
		return errors.New("unknown instance")
	}
	next := *s.rec
	next.Tier, next.Reason, next.ReasonDay = store.TierRevoked, reason, store.Day(r.cfg.Now())
	// One transaction for record and bindings; memory changes only after the store accepted it.
	if err := r.st.RevokeInstance(&next); err != nil {
		return err
	}
	*s.rec = next
	for m := range r.byInst[id] {
		r.dropBindingLocked(m)
	}
	logx.Event("admin.revoke", logx.Str(logx.KReason, reason))
	return nil
}

// BlockToken blocks a token for every instance except its current holder. Either the raw token (hex) or the
// MAC (hex, as shown by the admin tools) may be given.
func (r *Relay) BlockToken(tokenHex, macHex string, unblock bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var m string
	switch {
	case tokenHex != "":
		tok, err := wire.ParseToken(tokenHex)
		if err != nil {
			return errors.New("token must be hex")
		}
		m = r.tokenMAC(tok)
	case macHex != "":
		b, err := hex.DecodeString(macHex)
		if err != nil || len(b) != 32 {
			return errors.New("mac must be 64 hex characters")
		}
		m = string(b)
	default:
		return errors.New("give --token or --mac")
	}
	if unblock {
		logx.Event("admin.block_token", logx.Str(logx.KState, "unblocked"))
		return r.st.UnblockToken([]byte(m))
	}
	logx.Event("admin.block_token", logx.Str(logx.KState, "blocked"))
	return r.st.BlockToken([]byte(m), store.Day(r.cfg.Now()))
}

// SetDeviceLimit sets the active device limit of an instance, up to the configured maximum.
func (r *Relay) SetDeviceLimit(id string, n int) error {
	if n < 1 || n > r.cfg.Limits.StandardDevicesMax {
		return errors.New("device limit out of range")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.instances[id]
	if s == nil {
		return errors.New("unknown instance")
	}
	s.rec.DeviceLimit = n
	logx.Event("admin.limits", logx.Int(logx.KValue, int64(n)))
	return r.st.PutInstance(s.rec)
}

// BreakerCommand opens or closes the breaker by hand.
func (r *Relay) BreakerCommand(cmd string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch cmd {
	case "open":
		r.breaker.Open(r.cfg.Now())
	case "close":
		r.breaker.Close()
	case "reset-apns":
		r.misconfigured, r.providerBadIat, r.tooManyUntil = false, 0, time.Time{}
		r.Metrics.Set("hlp_apns_misconfigured", 0)
	default:
		return errors.New("use open|close|reset-apns")
	}
	logx.Event("admin.breaker", logx.Str(logx.KState, cmd))
	return nil
}
