package relay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// Registration modes.
const (
	RegOpen   = "open"
	RegInvite = "invite"
	RegClosed = "closed"
)

// Notice levels.
var noticeLevels = []string{"info", "planned", "action_required"}

// Control is the operator state. It is persisted, carries no personal data and expires on its own where a
// duration was given.
type Control struct {
	Pauses        []Pause  `json:"pauses,omitempty"`
	Registration  string   `json:"registration"`
	Notice        *Notice  `json:"notice,omitempty"`
	RecoveryUntil int      `json:"recoveryUntilDay,omitempty"`
	Invites       []Invite `json:"invites,omitempty"`
}

// Pause stops a class (or all) for a tier (or all) until a time.
type Pause struct {
	Class string `json:"class"` // all, alert, silent, liveactivity
	Tier  string `json:"tier"`  // all, probation
	Until int64  `json:"until"` // unix seconds
}

// Notice is a fixed identifier with a level; the text lives in the HealthLog server bundle.
type Notice struct {
	ID    string `json:"id"`
	Level string `json:"level"`
	Until int64  `json:"until,omitempty"`
}

// Invite is a one-time registration code, stored as a hash.
type Invite struct {
	Hash       string `json:"hash"`
	ExpiresDay int    `json:"expiresDay"`
}

func (r *Relay) saveControl() error {
	return r.st.PutControl(&r.control)
}

// paused reports whether class c is paused for tier t at now, and the remaining time.
func (r *Relay) paused(c wire.Class, tier string, now time.Time) (bool, time.Duration) {
	for _, p := range r.control.Pauses {
		if now.Unix() >= p.Until {
			continue
		}
		if (p.Class == "all" || p.Class == string(c)) && (p.Tier == "all" || p.Tier == tier) {
			return true, time.Unix(p.Until, 0).Sub(now)
		}
	}
	return false, 0
}

// SetPause adds a pause.
func (r *Relay) SetPause(class, tier string, d time.Duration) error {
	if !slices.Contains([]string{"all", "alert", "silent", "liveactivity"}, class) || !slices.Contains([]string{"all", "probation"}, tier) {
		return errors.New("class must be all|alert|silent|liveactivity, tier all|probation")
	}
	if d <= 0 || d > 7*24*time.Hour {
		return errors.New("duration must be between 1s and 7 days")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	var keep []Pause
	for _, p := range r.control.Pauses {
		if p.Until > now.Unix() {
			keep = append(keep, p)
		}
	}
	keep = append(keep, Pause{Class: class, Tier: tier, Until: now.Add(d).Unix()})
	r.control.Pauses = keep
	logx.Event("admin.pause", logx.Str(logx.KClass, class), logx.Str(logx.KState, tier), logx.Int(logx.KValue, int64(d.Seconds())))
	return r.saveControl()
}

// Resume removes all pauses.
func (r *Relay) Resume() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.control.Pauses = nil
	logx.Event("admin.resume")
	return r.saveControl()
}

// SetRegistration sets the registration mode.
func (r *Relay) SetRegistration(mode string) error {
	if !slices.Contains([]string{RegOpen, RegInvite, RegClosed}, mode) {
		return errors.New("mode must be open|invite|closed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.control.Registration = mode
	logx.Event("admin.registration", logx.Str(logx.KState, mode))
	return r.saveControl()
}

// NewInvite creates a one-time registration code valid for 7 days and returns it.
func (r *Relay) NewInvite() (string, error) {
	code := newChallenge()[:24]
	r.mu.Lock()
	defer r.mu.Unlock()
	r.control.Invites = append(r.control.Invites, Invite{Hash: hashInvite(code), ExpiresDay: store.Day(r.cfg.Now()) + 7})
	logx.Event("admin.invite")
	return code, r.saveControl()
}

func hashInvite(code string) string {
	s := sha256.Sum256([]byte("hl-invite\n" + code))
	return hex.EncodeToString(s[:])
}

// inviteIndex is the index of a matching, unexpired invite, or -1. Caller holds r.mu.
func (r *Relay) inviteIndex(code string, today int) int {
	if code == "" {
		return -1
	}
	h := hashInvite(code)
	return slices.IndexFunc(r.control.Invites, func(inv Invite) bool { return inv.Hash == h && inv.ExpiresDay >= today })
}

// consumeInvite removes a matching, unexpired invite. Caller holds r.mu.
func (r *Relay) consumeInvite(code string, today int) error {
	i := r.inviteIndex(code, today)
	if i < 0 {
		return nil
	}
	next := slices.Delete(slices.Clone(r.control.Invites), i, i+1)
	prev := r.control.Invites
	r.control.Invites = next
	if err := r.saveControl(); err != nil {
		r.control.Invites = prev // spent only once the store says so; otherwise it stays valid on disk too
		return err
	}
	return nil
}

// SetNotice sets or clears (empty id) the notice.
func (r *Relay) SetNotice(id, level string, d time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id == "" {
		r.control.Notice = nil
		logx.Event("admin.notice", logx.Str(logx.KState, "cleared"))
		return r.saveControl()
	}
	if !wire.ValidNoticeID(id) || !slices.Contains(noticeLevels, level) {
		return errors.New("notice id must match [a-z0-9_]{1,40}, level info|planned|action_required")
	}
	n := &Notice{ID: id, Level: level}
	if d > 0 {
		n.Until = r.cfg.Now().Add(d).Unix()
	}
	r.control.Notice = n
	logx.Event("admin.notice", logx.Str(logx.KState, level))
	return r.saveControl()
}

func (r *Relay) currentNotice(now time.Time) *Notice {
	n := r.control.Notice
	if n == nil || (n.Until != 0 && now.Unix() >= n.Until) {
		return nil
	}
	return n
}

// SetRecovery opens the recovery window until the given day and optionally imports an export.
func (r *Relay) SetRecovery(untilDay int, ex *store.Export) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	if ex != nil {
		var err error
		if err := OpenExport(ed25519.PublicKey(r.cfg.Identity[32:]), r.cfg.Host, ex); err != nil {
			return 0, err
		}
		n, err = r.st.Import(ex, store.Day(r.cfg.Now()), r.cfg.Limits.StandardDevicesMax)
		if err != nil {
			return n, err
		}
		ins, err := r.st.Instances()
		if err != nil {
			return n, err
		}
		for _, in := range ins {
			if _, ok := r.instances[in.ID]; !ok {
				r.addInstance(in)
			}
		}
	}
	r.control.RecoveryUntil = untilDay
	logx.Event("admin.recovery", logx.Int(logx.KCount, int64(n)))
	return n, r.saveControl()
}

func (r *Relay) inRecovery(today int) bool { return r.control.RecoveryUntil >= today }
