package relay

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	flaggedToday  bool
	lastReceipt   time.Time
	pending       store.DayCounters // not yet flushed
}

type devQuota struct {
	all        limits.Window
	alerts     *limits.Bucket
	silentHour limits.Window
	laDay      limits.Window
	throttled  map[wire.Class]time.Time
	app        *limits.Bucket // verified app-direct calls for this token
}

type idemEntry struct {
	res  *ItemResult // nil while in flight
	done chan struct{}
	exp  time.Time
}

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

// Relay is the service state.
type Relay struct {
	cfg     Config
	st      *store.Store
	sender  Sender
	q       *queue.Queue
	M       *metrics.Registry
	ErrLog  *logx.CountingWriter
	started time.Time

	mu           sync.Mutex
	instances    map[string]*instState
	byKey        map[string]string // raw public key to instance id
	bindings     map[string]*store.Binding
	byInst       map[string]map[string]struct{} // instance id to the MACs of its bindings
	dirtyInst    map[string]bool                // instances whose record changed since the last flush
	bodyBytes    atomic.Int64                   // request body bytes currently reserved
	dirty        map[string]bool
	devs         map[string]*devQuota
	idem         map[string]*idemEntry
	idemOrder    []string
	nonceTotal   int
	conflicts    map[string]*pendingConflict // by challenge
	challengeDay map[string]int              // token MAC to the day of its last challenge
	control      Control
	breaker      *Breaker
	regs         *limits.Registrations
	appDirect    *limits.Bucket
	halfUntil    time.Time
	dbWritable   bool

	apnsLastOK     time.Time
	providerBadIat int64
	misconfigured  bool
	tooManyUntil   time.Time
	silentOffUntil time.Time
	apple429       [10]struct {
		start            time.Time
		sends, throttled int
	}
	probationMin limits.Window
	standardMin  limits.Window
	minuteAll    limits.Window
	peakToday    int64
	peaks7       []int64
	receipts     [24]struct {
		hour                           int64
		accepted, confirmed, reporters int64
	}
	lastDay int
	summary summary
	global  map[[3]string]int64 // (day, class, result) pending for counters_global
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
	idemTTL         = 10 * time.Minute
	idemMax         = 200000
	noncePerInst    = 2000
	nonceTotalMax   = 200000
	challengeTTL    = 30 * time.Minute
	conflictStaleDy = 7
)

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
		cfg: cfg, st: st, sender: sender, M: metrics.New(), ErrLog: &logx.CountingWriter{}, started: now,
		instances: map[string]*instState{}, byKey: map[string]string{}, bindings: map[string]*store.Binding{},
		dirty: map[string]bool{}, devs: map[string]*devQuota{}, idem: map[string]*idemEntry{},
		conflicts: map[string]*pendingConflict{}, challengeDay: map[string]int{},
		breaker: NewBreaker(), regs: limits.NewRegistrations(cfg.Registrations, now),
		appDirect: limits.NewBucket(100, 20, now), halfUntil: now.Truncate(24 * time.Hour).Add(24 * time.Hour),
		dbWritable: true, probationMin: limits.Window{Size: time.Minute}, standardMin: limits.Window{Size: time.Minute},
		minuteAll: limits.Window{Size: time.Minute}, lastDay: store.Day(now),
	}
	r.summary = summary{errors: map[string]int64{}, events: map[string]int64{}, start: now}
	r.byInst, r.dirtyInst = map[string]map[string]struct{}{}, map[string]bool{}
	r.global = map[[3]string]int64{}
	if err := st.GetControl(&r.control); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if r.control.Registration == "" {
		r.control.Registration = RegOpen
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
	r.q.OnDrop = func() { r.M.Inc("hlp_queue_dropped_total") }
	r.describeMetrics()
	return r, nil
}

func (r *Relay) addInstance(in *store.Instance) *instState {
	now := r.cfg.Now()
	s := &instState{
		rec: in, reqMin: limits.Window{Size: time.Minute}, pushMin: limits.Window{Size: time.Minute},
		pushDay: limits.Window{Size: 24 * time.Hour}, nonces: map[string]int64{}, day: store.Day(now),
	}
	tl := r.tierLimits(in)
	s.badSig = limits.NewBucket(float64(tl.BadSignatureBurst), float64(tl.BadSignatureBurst)/60, now)
	c := r.st.Counters(store.Day(now), in.ID)
	s.pushDay.Add(now, c.Sent)
	s.invalid = c.Invalid
	r.instances[in.ID] = s
	r.byKey[string(in.PublicKey)] = in.ID
	return s
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

// tokenMAC returns the MAC under the current key and, when the binding exists only under a previous key,
// moves it to the current key (MAC key rotation).
func (r *Relay) tokenMAC(token []byte) string {
	cur := mac(r.cfg.MACKeys[0], token)
	if _, ok := r.bindings[cur]; ok {
		return cur
	}
	for _, k := range r.cfg.MACKeys[1:] {
		old := mac(k, token)
		if b, ok := r.bindings[old]; ok {
			if err := r.st.RenameBinding([]byte(old), []byte(cur), b); err == nil {
				r.dropBindingLocked(old)
				r.setBindingLocked(cur, b)
				if d, ok := r.devs[old]; ok {
					r.devs[cur] = d
					delete(r.devs, old)
				}
			}
			return cur
		}
	}
	return cur
}

// pairBlocked and tokenBlocked look the token up under every configured MAC key, so a device opt-out or an
// operator block survives a MAC key rotation.
func (r *Relay) pairBlocked(token []byte, instanceID string) bool {
	for _, k := range r.cfg.MACKeys {
		if r.st.PairBlocked([]byte(mac(k, token)), instanceID) {
			return true
		}
	}
	return false
}

func (r *Relay) tokenBlocked(token []byte) bool {
	for _, k := range r.cfg.MACKeys {
		if r.st.TokenBlocked([]byte(mac(k, token))) {
			return true
		}
	}
	return false
}

func mac(key, token []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(token)
	return string(m.Sum(nil))
}

func keyHash(pk []byte) []byte { s := sha256.Sum256(pk); return s[:] }

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
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

func (r *Relay) dev(m string) *devQuota {
	d := r.devs[m]
	if d == nil {
		now := r.cfg.Now()
		dl := r.cfg.Limits.Device
		d = &devQuota{
			all: limits.Window{Size: 24 * time.Hour}, alerts: limits.NewBucket(dl.AlertBurst, dl.AlertPerHour/3600, now),
			silentHour: limits.Window{Size: time.Hour}, laDay: limits.Window{Size: 24 * time.Hour}, throttled: map[wire.Class]time.Time{},
			app: limits.NewBucket(10, 10.0/3600, now),
		}
		r.devs[m] = d
	}
	return d
}

func (r *Relay) setDBError(err error) {
	if err != nil && r.dbWritable {
		r.dbWritable = false
		r.M.Set("hlp_db_writable", 0)
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
	r.M.Help("hlp_push_total", "Push items by class and result, without any instance label.")
	r.M.Help("hlp_requests_total", "HTTP responses by status class.")
	r.M.Help("hlp_breaker_open", "1 while the token-failure circuit breaker is open or half-open.")
	r.M.Help("hlp_db_writable", "1 while the store accepts writes.")
	r.M.Help("hlp_http_errors_total", "Lines the HTTP server wanted to log; discarded because they carry addresses.")
	r.M.Set("hlp_db_writable", 1)
	r.M.Set("hlp_breaker_open", 0)
}

// Close stops the queue, flushes counters and bindings and closes nothing else; the caller closes the store.
func (r *Relay) Close() {
	r.q.Close(10 * time.Second)
	r.mu.Lock()
	r.flushLocked()
	r.mu.Unlock()
}
