package relay

import (
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
			return true, time.Until(time.Unix(p.Until, 0))
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

// consumeInvite removes a matching, unexpired invite. Caller holds r.mu.
func (r *Relay) consumeInvite(code string, today int) bool {
	if code == "" {
		return false
	}
	h := hashInvite(code)
	for i, inv := range r.control.Invites {
		if inv.Hash == h && inv.ExpiresDay >= today {
			r.control.Invites = slices.Delete(r.control.Invites, i, i+1)
			_ = r.saveControl()
			return true
		}
	}
	return false
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
		n, err = r.st.Import(ex, store.Day(r.cfg.Now()))
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

// Suspend sets an instance to suspended with a reason from the closed set. Bindings stay.
func (r *Relay) Suspend(id, reason string) error {
	if !store.Reasons[reason] {
		return errors.New("unknown reason")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.instances[id]
	if s == nil {
		return errors.New("unknown instance")
	}
	s.rec.Tier, s.rec.Reason, s.rec.ReasonDay = store.TierSuspended, reason, store.Day(r.cfg.Now())
	logx.Event("admin.suspend", logx.Str(logx.KReason, reason))
	if err := r.st.PutInstance(s.rec); err != nil {
		return err
	}
	return r.st.PutDeny(&store.DenyEntry{InstanceID: id, Reason: reason, Day: store.Day(r.cfg.Now())})
}

// Unsuspend returns a suspended instance to probation.
func (r *Relay) Unsuspend(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.instances[id]
	if s == nil || s.rec.Tier != store.TierSuspended {
		return errors.New("instance not suspended")
	}
	s.rec.Tier, s.rec.Reason = store.TierProbation, ""
	logx.Event("admin.unsuspend")
	if err := r.st.PutInstance(s.rec); err != nil {
		return err
	}
	return r.st.DeleteDeny(id)
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
	s.rec.Tier, s.rec.Reason, s.rec.ReasonDay = store.TierRevoked, reason, store.Day(r.cfg.Now())
	for m, b := range r.bindings {
		if b.InstanceID == id {
			delete(r.bindings, m)
			delete(r.dirty, m)
		}
	}
	logx.Event("admin.revoke", logx.Str(logx.KReason, reason))
	if err := r.st.DeleteBindingsOf(id); err != nil {
		return err
	}
	if err := r.st.PutInstance(s.rec); err != nil {
		return err
	}
	return r.st.PutDeny(&store.DenyEntry{InstanceID: id, Reason: reason, Day: store.Day(r.cfg.Now())})
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
	logx.Event("admin.block_token", logx.Str(logx.KState, map[bool]string{true: "unblocked", false: "blocked"}[unblock]))
	if unblock {
		return r.st.UnblockToken([]byte(m))
	}
	return r.st.BlockToken([]byte(m), store.Day(r.cfg.Now()))
}

// SetDeviceLimit sets the active device limit of an instance, up to the configured maximum.
func (r *Relay) SetDeviceLimit(id string, n int) error {
	if n < 1 || n > r.cfg.Limits.StandardDevicesMx {
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
		r.M.Set("hlp_apns_misconfigured", 0)
	default:
		return errors.New("use open|close|reset-apns")
	}
	logx.Event("admin.breaker", logx.Str(logx.KState, cmd))
	return nil
}

// Stats is the operator overview: sums only.
type Stats struct {
	Instances    map[string]int `json:"instances"`
	Bindings     map[string]int `json:"bindings"`
	Queue        int            `json:"queue"`
	Breaker      string         `json:"breaker"`
	DBWritable   bool           `json:"dbWritable"`
	Registration string         `json:"registration"`
	Pauses       []Pause        `json:"pauses"`
	Notice       *Notice        `json:"notice"`
	Recovery     string         `json:"recoveryUntil,omitempty"`
	GlobalLimit  int64          `json:"globalLimitPerMinute"`
	Misconfig    bool           `json:"apnsMisconfigured"`
}

// Stats returns the overview.
func (r *Relay) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	s := Stats{Instances: map[string]int{}, Bindings: map[string]int{}, Queue: r.q.Len(), Breaker: r.breaker.State(now),
		DBWritable: r.dbWritable, Registration: r.control.Registration, Pauses: r.control.Pauses, Notice: r.currentNotice(now),
		GlobalLimit: r.globalLimit(), Misconfig: r.misconfigured}
	for _, in := range r.instances {
		s.Instances[in.rec.Tier]++
	}
	for _, b := range r.bindings {
		s.Bindings[b.State]++
	}
	if r.inRecovery(store.Day(now)) {
		s.Recovery = store.DayString(r.control.RecoveryUntil)
	}
	return s
}

// InstanceInfo is what the operator sees about one instance.
type InstanceInfo struct {
	ID          string `json:"id"`
	Tier        string `json:"tier"`
	Reason      string `json:"reason,omitempty"`
	Created     string `json:"created"`
	DeviceLimit int    `json:"deviceLimit"`
	Active      int    `json:"active"`
	Provisional int    `json:"provisional"`
	Delivered   bool   `json:"delivered"`
}

// Instance returns operator information about one instance.
func (r *Relay) Instance(id string) (*InstanceInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.instances[id]
	if s == nil {
		return nil, errors.New("unknown instance")
	}
	a, p := r.counts(id)
	return &InstanceInfo{ID: id, Tier: s.rec.Tier, Reason: s.rec.Reason, Created: store.DayString(s.rec.CreatedDay),
		DeviceLimit: r.tierLimits(s.rec).Devices, Active: a, Provisional: p, Delivered: s.rec.FirstDeliveryDay != 0}, nil
}

// ExportNow writes the registry export immediately.
func (r *Relay) ExportNow() error {
	if r.cfg.ExportDir == "" {
		return errors.New("no export directory configured")
	}
	ex, err := r.st.BuildExport(store.Day(r.cfg.Now()))
	if err != nil {
		return err
	}
	return store.WriteExport(r.cfg.ExportDir, ex)
}
