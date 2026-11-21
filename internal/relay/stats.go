package relay

import (
	"cmp"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
)

// Stats is the operator overview: sums only.
type Stats struct {
	Instances         map[string]int `json:"instances"`
	Bindings          map[string]int `json:"bindings"`
	Queue             int            `json:"queue"`
	Breaker           string         `json:"breaker"`
	DBWritable        bool           `json:"dbWritable"`
	Registration      string         `json:"registration"`
	Pauses            []Pause        `json:"pauses"`
	Notice            *Notice        `json:"notice"`
	Recovery          string         `json:"recoveryUntil,omitempty"`
	GlobalLimit       int64          `json:"globalLimitPerMinute"`
	APNsMisconfigured bool           `json:"apnsMisconfigured"`
}

// Stats returns the overview.
func (r *Relay) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	s := Stats{Instances: map[string]int{}, Bindings: map[string]int{}, Queue: r.q.Len(), Breaker: r.breaker.State(now),
		DBWritable: r.dbWritable, Registration: r.control.Registration, Pauses: r.control.Pauses, Notice: r.currentNotice(now),
		GlobalLimit: r.globalLimit(), APNsMisconfigured: r.misconfigured}
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
	ex, err := r.st.BuildExport(r.cfg.Host, store.Day(r.cfg.Now()))
	if err != nil {
		return err
	}
	if err := SealExport(r.cfg.Identity, ex); err != nil {
		return err
	}
	return store.WriteExport(r.cfg.ExportDir, ex)
}

// Suspect is one row of the abuse overview: what an instance did today and in the last seven days.
type Suspect struct {
	ID              string `json:"id"`
	Tier            string `json:"tier"`
	Created         string `json:"created"`
	InvalidToday    int64  `json:"invalidToday"`
	Invalid7d       int64  `json:"invalid7d"`
	Sent7d          int64  `json:"sent7d"`
	Rebinds7d       int64  `json:"rebinds7d"`
	ChallengesToday int64  `json:"challengesToday"`
	BlockedNewUntil string `json:"blockedNewBindingsUntil,omitempty"`
	Active          int    `json:"active"`
	Provisional     int    `json:"provisional"`
	SoftInvalid     int    `json:"softInvalid"`
}

// Suspects lists instances with any invalid token, rebind or challenge in the last seven days, worst first
// (by invalid tokens today, then over seven days, then rebinds). This is the operator's way to find an
// instance that floods the relay with invented tokens; it lives only on the admin socket.
func (r *Relay) Suspects(limit int) []Suspect {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	today := store.Day(now)
	out := []Suspect{}
	for id, s := range r.instances {
		r.rollInstanceDay(s, now)
		sp := Suspect{ID: id, Tier: s.rec.Tier, Created: store.DayString(s.rec.CreatedDay), InvalidToday: s.invalid,
			ChallengesToday: s.challenges}
		for d := today - 6; d <= today; d++ {
			c := r.st.Counters(d, id)
			sp.Invalid7d += c.Invalid
			sp.Sent7d += c.Sent
			sp.Rebinds7d += c.Rebinds
		}
		sp.Invalid7d += s.pending.Invalid
		sp.Sent7d += s.pending.Sent
		sp.Rebinds7d += s.pending.Rebinds
		if now.Before(s.blockNewUntil) {
			sp.BlockedNewUntil = s.blockNewUntil.UTC().Format(time.RFC3339)
		}
		for m := range r.byInst[id] {
			switch r.bindings[m].State {
			case store.StateActive:
				sp.Active++
			case store.StateProvisional:
				sp.Provisional++
			case store.StateSoftInvalid:
				sp.SoftInvalid++
			}
		}
		if sp.InvalidToday+sp.Invalid7d+sp.Rebinds7d+sp.ChallengesToday > 0 {
			out = append(out, sp)
		}
	}
	slices.SortFunc(out, func(a, b Suspect) int {
		return cmp.Or(cmp.Compare(b.InvalidToday, a.InvalidToday), cmp.Compare(b.Invalid7d, a.Invalid7d),
			cmp.Compare(b.Rebinds7d, a.Rebinds7d), strings.Compare(a.ID, b.ID))
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Usage is the aggregate usage report: counts only, no instance ids, no per-instance values.
type Usage struct {
	Granularity          string      `json:"granularity"` // "day" below 20 active instances, else "day" plus live gauges
	ActiveInstances      int         `json:"activeInstances"`
	PushedLast7Days      int         `json:"instancesPushedLast7Days"`
	PushedLast30Days     int         `json:"instancesPushedLast30Days"`
	ActiveBindings       int         `json:"activeBindings"`
	RegistrationsPerWeek []WeekCount `json:"registrationsPerWeek"`
	OptOutsPerWeek       []WeekCount `json:"optOutsPerWeek"`
	PushesPerDay         []DayPushes `json:"pushesPerDay"`
}

// WeekCount is a count for the week starting on the given day.
type WeekCount struct {
	WeekOf string `json:"weekOf"`
	N      int64  `json:"n"`
}

// DayPushes are the pushes of one completed day by class and outcome.
type DayPushes struct {
	Day          string           `json:"day"`
	Total        int64            `json:"total"`
	ByClass      map[string]int64 `json:"byClass"`
	Accepted     int64            `json:"accepted"`
	SoftFailed   int64            `json:"softFailed"`
	Unregistered int64            `json:"unregistered"`
}

var usageClasses = []string{"alert", "silent", "liveactivity"}

// UsageReport builds the usage report for the last weeks. Days are completed days only (yesterday back),
// so no partial day of a small population is ever shown.
func (r *Relay) UsageReport(days int) Usage {
	r.mu.Lock()
	defer r.mu.Unlock()
	// No flush here: a metrics scrape must not cause a write. Counts not yet flushed are added from memory.
	now := r.cfg.Now()
	today := store.Day(now)
	u := Usage{Granularity: "day", ActiveInstances: r.activeInstancesLocked()}
	for _, s := range r.instances {
		if s.rec.LastPushDay != 0 && today-s.rec.LastPushDay < 7 {
			u.PushedLast7Days++
		}
		if s.rec.LastPushDay != 0 && today-s.rec.LastPushDay < 30 {
			u.PushedLast30Days++
		}
	}
	for _, b := range r.bindings {
		if b.State == store.StateActive || b.State == store.StateSoftInvalid {
			u.ActiveBindings++
		}
	}
	for d := today - days; d < today; d++ {
		dp := DayPushes{Day: store.DayString(d), ByClass: map[string]int64{}}
		for _, c := range usageClasses {
			acc := r.globalLocked(d, c, "accepted")
			soft := r.globalLocked(d, c, "soft_invalid")
			unreg := r.globalLocked(d, c, "unregistered")
			gone := r.globalLocked(d, c, "activity_gone")
			n := acc + soft + unreg + gone
			dp.ByClass[c] = n
			dp.Total += n
			dp.Accepted += acc
			dp.SoftFailed += soft + gone
			dp.Unregistered += unreg
		}
		u.PushesPerDay = append(u.PushesPerDay, dp)
	}
	for w := store.Week(today - days); w < store.Week(today); w++ {
		var reg, opt int64
		for d := store.WeekStart(w); d < store.WeekStart(w)+7; d++ {
			reg += r.globalLocked(d, "instance", "registered")
			opt += r.globalLocked(d, "binding", "opt_out")
		}
		u.RegistrationsPerWeek = append(u.RegistrationsPerWeek, WeekCount{WeekOf: store.DayString(store.WeekStart(w)), N: reg})
		u.OptOutsPerWeek = append(u.OptOutsPerWeek, WeekCount{WeekOf: store.DayString(store.WeekStart(w)), N: opt})
	}
	return u
}

// usageGauges publishes the usage counts as metrics. Gauges for completed days only; the snapshot itself
// refreshes hourly below 20 active instances.
func (r *Relay) usageGauges() {
	u := r.UsageReport(7)
	r.Metrics.Set("hlp_usage_active_instances", float64(u.ActiveInstances))
	r.Metrics.Set("hlp_usage_instances_pushed", float64(u.PushedLast7Days), "window", "7d")
	r.Metrics.Set("hlp_usage_instances_pushed", float64(u.PushedLast30Days), "window", "30d")
	r.Metrics.Set("hlp_usage_active_bindings", float64(u.ActiveBindings))
	if n := len(u.PushesPerDay); n > 0 {
		y := u.PushesPerDay[n-1]
		for c, v := range y.ByClass {
			r.Metrics.Set("hlp_usage_pushes_yesterday", float64(v), "class", c)
		}
		r.Metrics.Set("hlp_usage_outcomes_yesterday", float64(y.Accepted), "outcome", "accepted")
		r.Metrics.Set("hlp_usage_outcomes_yesterday", float64(y.SoftFailed), "outcome", "soft_failed")
		r.Metrics.Set("hlp_usage_outcomes_yesterday", float64(y.Unregistered), "outcome", "unregistered")
	}
	if n := len(u.RegistrationsPerWeek); n > 0 {
		r.Metrics.Set("hlp_usage_registrations_last_week", float64(u.RegistrationsPerWeek[n-1].N))
		r.Metrics.Set("hlp_usage_opt_outs_last_week", float64(u.OptOutsPerWeek[n-1].N))
	}
}

// globalLocked is a global day counter: what the store holds plus what the next flush will add.
func (r *Relay) globalLocked(day int, class, result string) int64 {
	return r.st.Global(day, class, result) + r.global[store.GlobalKey{Day: day, Class: class, Result: result}]
}
