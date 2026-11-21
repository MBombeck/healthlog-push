package relay

import "time"

// Breaker protects every binding from a relay-side misconfiguration (wrong key, wrong topic, bad deploy):
// when more than 30 % of the device sends in five minutes (at least 20) end with Unregistered,
// BadDeviceToken or DeviceTokenNotForTopic, it opens. While open, the relay deletes and marks nothing and
// answers 503 relay_misconfigured. After a cool-down it lets traffic through again in half-open mode, still
// without deleting or marking anything, and closes only when Apple accepts again: at least 20 sends with at
// most 10 % token failures and at least one accepted push.
type Breaker struct {
	Window    time.Duration
	MinSends  int
	OpenRatio float64
	CloseMax  float64
	Cooldown  time.Duration

	state    string // closed, open, half_open
	openedAt time.Time
	slots    [10]breakerSlot
	half     breakerSlot
	opened   int64
}

type breakerSlot struct {
	start        time.Time
	sends, fails int
	accepted     int
}

// Breaker states.
const (
	BreakerClosed   = "closed"
	BreakerOpen     = "open"
	BreakerHalfOpen = "half_open"
)

// NewBreaker returns a closed breaker with the hosted-relay thresholds.
func NewBreaker() *Breaker {
	return &Breaker{Window: 5 * time.Minute, MinSends: 20, OpenRatio: 0.30, CloseMax: 0.10, Cooldown: 10 * time.Minute, state: BreakerClosed}
}

func (b *Breaker) slot(now time.Time) *breakerSlot {
	size := b.Window / time.Duration(len(b.slots))
	start := now.Truncate(size)
	i := int(start.UnixNano()/int64(size)) % len(b.slots)
	s := &b.slots[i]
	if !s.start.Equal(start) {
		*s = breakerSlot{start: start}
	}
	return s
}

func (b *Breaker) totals(now time.Time) (sends, fails int) {
	for _, s := range b.slots {
		if now.Sub(s.start) < b.Window {
			sends += s.sends
			fails += s.fails
		}
	}
	return
}

// State returns the current state, moving from open to half-open after the cool-down.
func (b *Breaker) State(now time.Time) string {
	if b.state == BreakerOpen && now.Sub(b.openedAt) >= b.Cooldown {
		b.state = BreakerHalfOpen
		b.half = breakerSlot{start: now}
	}
	return b.state
}

// Marking reports whether token failures may change bindings now: only while closed.
func (b *Breaker) Marking(now time.Time) bool { return b.State(now) == BreakerClosed }

// Record counts the outcome of one device send. tokenFailure is Unregistered, BadDeviceToken or
// DeviceTokenNotForTopic. It returns true when this call opened the breaker.
func (b *Breaker) Record(now time.Time, accepted, tokenFailure bool) bool {
	switch b.State(now) {
	case BreakerOpen:
		return false
	case BreakerHalfOpen:
		b.half.sends++
		if tokenFailure {
			b.half.fails++
		}
		if accepted {
			b.half.accepted++
		}
		if b.half.sends >= b.MinSends {
			ratio := float64(b.half.fails) / float64(b.half.sends)
			switch {
			case ratio > b.OpenRatio:
				b.open(now)
				return true
			case ratio <= b.CloseMax && b.half.accepted > 0:
				b.Close()
			}
		}
		return false
	}
	s := b.slot(now)
	s.sends++
	if tokenFailure {
		s.fails++
	}
	sends, fails := b.totals(now)
	if sends >= b.MinSends && float64(fails)/float64(sends) > b.OpenRatio {
		b.open(now)
		return true
	}
	return false
}

func (b *Breaker) open(now time.Time) {
	b.state, b.openedAt = BreakerOpen, now
	b.opened++
	for i := range b.slots {
		b.slots[i] = breakerSlot{}
	}
}

// Open forces the breaker open (operator).
func (b *Breaker) Open(now time.Time) { b.open(now) }

// Close forces the breaker closed and clears the window.
func (b *Breaker) Close() {
	b.state = BreakerClosed
	for i := range b.slots {
		b.slots[i] = breakerSlot{}
	}
	b.half = breakerSlot{}
}

// Opened returns how often the breaker opened since start.
func (b *Breaker) Opened() int64 { return b.opened }
