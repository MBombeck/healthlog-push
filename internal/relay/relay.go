package relay

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/metrics"
	"github.com/MBombeck/healthlog-push/internal/queue"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// Sender sends one push to Apple. *apns.Client implements it; tests use a fake HTTP/2 server behind it.
type Sender interface {
	Send(ctx context.Context, p *apns.Push) apns.Result
}

type instState struct {
	rec           *store.Instance
	reqMin        limits.Window
	pushMin       limits.Window
	pushDay       limits.Window
	badSig        *limits.Bucket
	nonces        map[string]int64 // nonce to expiry (unix)
	day           int
	newBindings   int64
	invalid       int64
	challenges    int64
	blockNewUntil time.Time
	lastReceipt   time.Time
	pending       store.DayCounters // not yet flushed
}

type idemEntry struct {
	res  *ItemResult // nil while in flight
	done chan struct{}
	exp  time.Time
}

// Relay is the service state.
type Relay struct {
	cfg     Config
	st      *store.Store
	sender  Sender
	q       *queue.Queue
	started time.Time

	// Metrics is the coarse metrics registry served on the metrics listener.
	Metrics *metrics.Registry
	// ErrLog is the http.Server error log: it counts lines and discards them, because they carry addresses.
	ErrLog *logx.CountingWriter

	// loopBeat is the wall time (unix nanoseconds) of the maintenance loop's last finished pass; the
	// watchdog reads it.
	loopBeat atomic.Int64

	mu            sync.Mutex
	instances     map[string]*instState
	byKey         map[string]string // raw public key to instance id
	bindings      map[string]*store.Binding
	byInst        map[string]map[string]struct{} // instance id to the MACs of its bindings
	dirtyInst     map[string]bool                // instances whose record changed since the last flush
	bodyBytes     atomic.Int64                   // request body bytes currently reserved
	dirty         map[string]bool
	devs          map[string]*devQuota
	idem          map[string]*idemEntry
	idemOrder     []string
	nonceTotal    int
	conflicts     map[string]*pendingConflict
	activities    map[string]*activityQuota // per Live Activity update token MAC, cleared daily
	lastTick      time.Time
	recentOptOuts map[string]int64 // token MAC and instance id to the opt-out statement time, for ten minutes
	challengeDay  map[string]int   // token MAC and instance id to the day of its last challenge
	control       Control
	breaker       *Breaker
	regs          *limits.Registrations
	appDirect     *limits.Bucket
	halfUntil     time.Time
	dbWritable    bool
	lastDay       int
	summary       summary
	global        map[store.GlobalKey]int64 // pending for counters_global
	traces        traces                    // apns-unique-id per instance and ref, 72 hours, memory only

	apnsState
	pools
	receiptsRing
}

// apnsState is what the relay has learned about Apple's answers.
type apnsState struct {
	apnsLastOK     time.Time
	providerBadIat int64 // iat of the first provider token Apple called invalid
	misconfigured  bool  // a newer provider token was refused too: sending stops until an operator resets
	tooManyUntil   time.Time
	silentOffUntil time.Time
	apple429       [10]apple429Slot // 30-second slots over five minutes
}

// pools are the relay-wide minute windows and the peaks the global limit is derived from.
type pools struct {
	probationMin limits.Window
	standardMin  limits.Window
	minuteAll    limits.Window
	peakToday    int64
	peaks7       []int64
}

type summary struct {
	events    map[string]int64 // registrations, rotations, deletions, resolved challenges in the period
	pushes    int64
	errors    map[string]int64
	latencies []int64
	start     time.Time
}

// Idempotency and nonce bounds (spec/protocol.md).
const (
	idemTTL           = 10 * time.Minute
	idemMax           = 200000
	noncePerInst      = 2000
	nonceTotalMax     = 200000
	challengeTTL      = 30 * time.Minute
	conflictStaleDays = 7
)

// Durations used in refusals.
const (
	storageRetry = 5 * time.Minute // retry hint while the store refuses writes
	fullDay      = 24 * time.Hour
)

// untilMidnight is the time from now to the next UTC midnight.
func untilMidnight(now time.Time) time.Duration { return now.Truncate(fullDay).Add(fullDay).Sub(now) }

// New builds a relay over an open store. It loads instances and bindings into memory.
func New(cfg Config, st *store.Store, sender Sender) (*Relay, error) {
	cfg.defaults()
	if len(cfg.MACKeys) == 0 || len(cfg.MACKeys[0]) < 32 {
		return nil, errors.New("token MAC key must be at least 32 bytes")
	}
	if len(cfg.Identity) != 64 {
		return nil, errors.New("relay identity key missing")
	}
	now := cfg.Now()
	r := &Relay{
		cfg: cfg, st: st, sender: sender, started: now, Metrics: metrics.New(), ErrLog: &logx.CountingWriter{},
		instances: map[string]*instState{}, byKey: map[string]string{}, bindings: map[string]*store.Binding{},
		byInst: map[string]map[string]struct{}{}, dirtyInst: map[string]bool{}, dirty: map[string]bool{},
		devs: map[string]*devQuota{}, idem: map[string]*idemEntry{}, conflicts: map[string]*pendingConflict{},
		recentOptOuts: map[string]int64{}, activities: map[string]*activityQuota{},
		challengeDay: map[string]int{}, breaker: NewBreaker(), regs: limits.NewRegistrations(cfg.Registrations, now),
		appDirect: limits.NewBucket(100, 20, now), halfUntil: now.Truncate(fullDay).Add(fullDay), dbWritable: true,
		lastDay: store.Day(now), summary: newSummary(now), global: map[store.GlobalKey]int64{},
		pools: pools{probationMin: limits.Window{Size: time.Minute}, standardMin: limits.Window{Size: time.Minute},
			minuteAll: limits.Window{Size: time.Minute}},
	}
	if err := st.GetControl(&r.control); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if err := r.initRegistration(cfg.Registration); err != nil {
		return nil, err
	}
	ins, err := st.Instances()
	if err != nil {
		return nil, err
	}
	for _, in := range ins {
		r.addInstance(in)
	}
	bs, err := st.Bindings()
	if err != nil {
		return nil, err
	}
	for m, b := range bs {
		r.setBindingLocked(m, b)
	}
	today := store.Day(now)
	for d := today - 7; d < today; d++ {
		r.peaks7 = append(r.peaks7, st.Global(d, "all", "peak_minute"))
	}
	r.peakToday = st.Global(today, "all", "peak_minute")
	r.q = queue.New(cfg.Workers, queue.DefaultCapacity, queue.DefaultPerInstance, queue.DefaultMaxWait)
	r.q.OnDrop = func() { r.Metrics.Inc("hlp_queue_dropped_total") }
	r.describeMetrics()
	// The production client reports how each request to Apple got its connection.
	if c, ok := sender.(*apns.Client); ok {
		c.OnConn = r.observeConn
	}
	return r, nil
}

func newSummary(now time.Time) summary {
	return summary{errors: map[string]int64{}, events: map[string]int64{}, start: now}
}

func (r *Relay) addInstance(in *store.Instance) {
	now := r.cfg.Now()
	s := &instState{
		rec: in, reqMin: limits.Window{Size: time.Minute}, pushMin: limits.Window{Size: time.Minute},
		pushDay: limits.Window{Size: fullDay}, nonces: map[string]int64{}, day: store.Day(now),
	}
	tl := r.tierLimits(in)
	s.badSig = limits.NewBucket(float64(tl.BadSignatureBurst), float64(tl.BadSignatureBurst)/60, now)
	c := r.st.Counters(store.Day(now), in.ID)
	s.pushDay.Add(now, c.Sent)
	s.invalid = c.Invalid
	r.instances[in.ID] = s
	r.byKey[string(in.PublicKey)] = in.ID
}

func (r *Relay) tierLimits(in *store.Instance) TierLimits {
	if in.Tier == store.TierStandard {
		tl := r.cfg.Limits.Standard
		if in.DeviceLimit > 0 {
			tl.Devices = in.DeviceLimit
		}
		return tl
	}
	tl := r.cfg.Limits.Probation
	if in.DeviceLimit > 0 && in.DeviceLimit < tl.Devices {
		tl.Devices = in.DeviceLimit
	}
	return tl
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func newChallenge() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return wire.EncodeB64(b[:])
}

// setBindingLocked stores a binding in memory and keeps the per-instance index in step.
func (r *Relay) setBindingLocked(m string, b *store.Binding) {
	if old := r.bindings[m]; old != nil && old.InstanceID != b.InstanceID {
		delete(r.byInst[old.InstanceID], m)
	}
	r.bindings[m] = b
	set := r.byInst[b.InstanceID]
	if set == nil {
		set = map[string]struct{}{}
		r.byInst[b.InstanceID] = set
	}
	set[m] = struct{}{}
	delete(r.dirty, m)
}

// dropBindingLocked removes a binding from memory and from the index.
func (r *Relay) dropBindingLocked(m string) {
	if b := r.bindings[m]; b != nil {
		delete(r.byInst[b.InstanceID], m)
		if len(r.byInst[b.InstanceID]) == 0 {
			delete(r.byInst, b.InstanceID)
		}
	}
	delete(r.bindings, m)
	delete(r.dirty, m)
}

// counts returns active and provisional bindings of an instance, from the per-instance index.
func (r *Relay) counts(id string) (active, provisional int) {
	for m := range r.byInst[id] {
		b := r.bindings[m]
		if b == nil {
			continue
		}
		if b.State == store.StateProvisional {
			provisional++
		} else {
			active++
		}
	}
	return
}

func (r *Relay) setDBError(err error) {
	if err != nil && r.dbWritable {
		r.dbWritable = false
		r.Metrics.Set("hlp_db_writable", 0)
		logx.Event("store.write_failed", logx.Str(logx.KState, "read_only"))
	}
}

func (r *Relay) persist(err error) bool {
	if err != nil {
		r.setDBError(err)
		return false
	}
	return true
}

func (r *Relay) describeMetrics() {
	r.Metrics.Help("hlp_push_total", "Push items by class and result, without any instance label.")
	r.Metrics.Help("hlp_requests_total", "HTTP responses by status class.")
	r.Metrics.Help("hlp_breaker_open", "1 while the token-failure circuit breaker is open or half-open.")
	r.Metrics.Help("hlp_db_writable", "1 while the store accepts writes.")
	r.Metrics.Help("hlp_instances", "Instances by tier, without any instance label.")
	r.Metrics.Help("hlp_bindings", "Bindings by state, without any instance or device label.")
	r.Metrics.Help("hlp_http_errors_total", "Lines the HTTP server wanted to log; discarded because they carry addresses.")
	r.Metrics.Help("hlp_apns_misconfigured", "1 while Apple rejects the relay's provider token.")
	// Every gauge of the relay's own state exists from the start, so a rule on it has data before the first
	// incident and not only after it.
	r.Metrics.Set("hlp_db_writable", 1)
	r.Metrics.Set("hlp_breaker_open", 0)
	r.Metrics.Set("hlp_apns_misconfigured", 0)
	r.Metrics.Live(liveMetrics...)
	r.describeOperational()
}

// Close stops the queue, flushes counters and bindings and closes nothing else; the caller closes the store.
func (r *Relay) Close() {
	r.q.Close(10 * time.Second)
	r.mu.Lock()
	r.flushLocked()
	r.mu.Unlock()
}

// flagLocked marks an instance as anomalous for today (challenge started, invalid-token budget exceeded):
// it is not promoted and its quiet streak restarts.
func (r *Relay) flagLocked(s *instState, now time.Time) {
	if d := store.Day(now); s.rec.FlaggedDay != d {
		s.rec.FlaggedDay = d
		r.dirtyInst[s.rec.ID] = true
	}
}
