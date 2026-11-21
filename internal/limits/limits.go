// Package limits implements the rate limits of the relay: token buckets, fixed windows, the registration
// limiter keyed by IPv4 address, IPv6 /64 and /48 (hashed with a daily salt, in memory only) and the
// connection limiter. Nothing here is persisted and nothing here keeps a raw address.
package limits

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Bucket is a token bucket. The zero value is not usable; use NewBucket.
type Bucket struct {
	Capacity float64
	Rate     float64 // tokens per second
	tokens   float64
	last     time.Time
}

// NewBucket returns a full bucket.
func NewBucket(capacity, perSecond float64, now time.Time) *Bucket {
	return &Bucket{Capacity: capacity, Rate: perSecond, tokens: capacity, last: now}
}

func (b *Bucket) refill(now time.Time) {
	if now.After(b.last) {
		b.tokens = min(b.Capacity, b.tokens+now.Sub(b.last).Seconds()*b.Rate)
		b.last = now
	}
}

// Allow takes one token if available.
func (b *Bucket) Allow(now time.Time) bool {
	b.refill(now)
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Peek reports whether a token is available without taking it.
func (b *Bucket) Peek(now time.Time) bool { b.refill(now); return b.tokens >= 1 }

// Refund returns one token, for an attempt rejected later in the chain.
func (b *Bucket) Refund() { b.tokens = min(b.Capacity, b.tokens+1) }

// RetryAfter is the time until the next token.
func (b *Bucket) RetryAfter(now time.Time) time.Duration {
	b.refill(now)
	if b.tokens >= 1 || b.Rate <= 0 {
		return 0
	}
	return time.Duration((1 - b.tokens) / b.Rate * float64(time.Second))
}

// Window counts events in a fixed window (minute, hour or day).
type Window struct {
	Size  time.Duration
	start time.Time
	n     int64
}

func (w *Window) roll(now time.Time) {
	s := now.Truncate(w.Size)
	if !s.Equal(w.start) {
		w.start, w.n = s, 0
	}
}

// Allow counts one event if the count stays at or below limit.
func (w *Window) Allow(now time.Time, limit int64) bool {
	w.roll(now)
	if w.n >= limit {
		return false
	}
	w.n++
	return true
}

// Add counts n events unconditionally.
func (w *Window) Add(now time.Time, n int64) { w.roll(now); w.n += n }

// Count returns the count of the current window.
func (w *Window) Count(now time.Time) int64 { w.roll(now); return w.n }

// Undo removes one counted event.
func (w *Window) Undo() {
	if w.n > 0 {
		w.n--
	}
}

// RetryAfter is the time until the window rolls over.
func (w *Window) RetryAfter(now time.Time) time.Duration { return w.start.Add(w.Size).Sub(now) }

// Prefixes returns the limiter keys for an address: the IPv4 address itself, or the IPv6 /64 and /48.
// IPv4-mapped IPv6 addresses count as IPv4.
func Prefixes(a netip.Addr) (narrow, wide netip.Prefix) {
	a = a.Unmap()
	if a.Is4() {
		p := netip.PrefixFrom(a, 32)
		return p, p
	}
	n, _ := a.Prefix(64)
	w, _ := a.Prefix(48)
	return n, w
}

// Salter hashes prefixes with a salt that changes every day, so that the in-memory keys cannot be
// reversed into addresses after the day ends.
type Salter struct {
	mu   sync.Mutex
	day  int64
	salt [32]byte
}

// Key returns the salted hash of a prefix for the day of now.
func (s *Salter) Key(p netip.Prefix, now time.Time) string {
	s.mu.Lock()
	d := now.Unix() / 86400
	if d != s.day {
		s.day = d
		_, _ = rand.Read(s.salt[:])
	}
	m := hmac.New(sha256.New, s.salt[:])
	s.mu.Unlock()
	b, _ := p.MarshalBinary()
	m.Write(b)
	return string(m.Sum(nil)[:16])
}

// Registration limits (spec/protocol.md, "Limits").
type RegistrationLimits struct {
	PerNarrowDay int64 // per IPv4 address or IPv6 /64
	PerWideDay   int64 // per IPv6 /48
	GlobalHour   int64
	GlobalDay    int64
}

// DefaultRegistrationLimits are the hosted-relay values.
var DefaultRegistrationLimits = RegistrationLimits{PerNarrowDay: 3, PerWideDay: 10, GlobalHour: 30, GlobalDay: 200}

// Registrations limits new instance registrations by source prefix and globally.
type Registrations struct {
	mu        sync.Mutex
	L         RegistrationLimits
	salt      Salter
	day       int64
	narrow    map[string]int64
	wide      map[string]int64
	hour      Window
	globalDay Window
	halfUntil time.Time // after a restart the global caps are halved until midnight
}

// NewRegistrations returns a limiter. It starts in the halved mode until the next UTC midnight, because
// counts from before a restart are gone.
func NewRegistrations(l RegistrationLimits, now time.Time) *Registrations {
	return &Registrations{
		L: l, narrow: map[string]int64{}, wide: map[string]int64{},
		hour: Window{Size: time.Hour}, globalDay: Window{Size: 24 * time.Hour},
		halfUntil: now.Truncate(24 * time.Hour).Add(24 * time.Hour),
	}
}

// Allow counts a registration attempt from addr. ignoreGlobal skips the global caps (recovery window).
func (r *Registrations) Allow(addr netip.Addr, now time.Time, ignoreGlobal bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d := now.Unix() / 86400; d != r.day {
		r.day, r.narrow, r.wide = d, map[string]int64{}, map[string]int64{}
	}
	n, w := Prefixes(addr)
	kn, kw := r.salt.Key(n, now), r.salt.Key(w, now)
	if r.narrow[kn] >= r.L.PerNarrowDay {
		return false
	}
	if n != w && r.wide[kw] >= r.L.PerWideDay {
		return false
	}
	if !ignoreGlobal {
		gh, gd := r.L.GlobalHour, r.L.GlobalDay
		if now.Before(r.halfUntil) {
			gh, gd = max(1, gh/2), max(1, gd/2)
		}
		if r.hour.Count(now) >= gh || r.globalDay.Count(now) >= gd {
			return false
		}
	}
	r.narrow[kn]++
	if n != w {
		r.wide[kw]++
	}
	r.hour.Add(now, 1)
	r.globalDay.Add(now, 1)
	return true
}

// ConnLimiter wraps a listener and limits concurrent connections in total and per IPv4 address or IPv6 /64.
type ConnLimiter struct {
	net.Listener
	Total, PerPrefix int
	mu               sync.Mutex
	open             int
	per              map[netip.Prefix]int
	Rejected         func()
}

// NewConnLimiter wraps l.
func NewConnLimiter(l net.Listener, total, perPrefix int) *ConnLimiter {
	return &ConnLimiter{Listener: l, Total: total, PerPrefix: perPrefix, per: map[netip.Prefix]int{}}
}

// Accept returns the next connection within the limits; connections over a limit are closed at once.
func (c *ConnLimiter) Accept() (net.Conn, error) {
	for {
		conn, err := c.Listener.Accept()
		if err != nil {
			return nil, err
		}
		p := prefixOf(conn.RemoteAddr())
		c.mu.Lock()
		if c.open >= c.Total || c.per[p] >= c.PerPrefix {
			c.mu.Unlock()
			_ = conn.Close()
			if c.Rejected != nil {
				c.Rejected()
			}
			continue
		}
		c.open++
		c.per[p]++
		c.mu.Unlock()
		return &limitedConn{Conn: conn, l: c, p: p}, nil
	}
}

func prefixOf(a net.Addr) netip.Prefix {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Prefix{}
	}
	n, _ := Prefixes(ap.Addr())
	return n
}

type limitedConn struct {
	net.Conn
	l    *ConnLimiter
	p    netip.Prefix
	once sync.Once
}

func (c *limitedConn) Close() error {
	c.once.Do(func() {
		c.l.mu.Lock()
		c.l.open--
		c.l.per[c.p]--
		if c.l.per[c.p] <= 0 {
			delete(c.l.per, c.p)
		}
		c.l.mu.Unlock()
	})
	return c.Conn.Close()
}

// Open returns the number of open connections.
func (c *ConnLimiter) Open() int { c.mu.Lock(); defer c.mu.Unlock(); return c.open }
