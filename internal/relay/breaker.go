package relay

import "time"

// Breaker protects every binding from a relay-side misconfiguration (wrong key, wrong topic, bad deploy).
//
// It only counts sends to established bindings, those that have had at least one push accepted by Apple: a
// misconfiguration hits exactly those, while tokens an instance invented never reach that state and so
// cannot move the breaker. It opens when, within five minutes, at least 20 such sends happened, more
// than 30 % of them ended with Unregistered, BadDeviceToken or DeviceTokenNotForTopic, and the failures came
// from at least three different instances. While open, the relay deletes and marks nothing and answers
// 503 relay_misconfigured. After a cool-down it lets traffic through in half-open mode, still without
// deleting or marking anything, and closes when Apple accepts again: at least 20 established sends with at
// most 10 % token failures and at least one accepted push.
type Breaker struct {
	window       time.Duration // the sliding window the opening rule looks at
	minSends     int           // established sends needed before the breaker may open or close
	minInstances int           // distinct failing instances needed to open
	openRatio    float64       // token-failure share above which it opens
	closeMax     float64       // token-failure share at or below which half-open closes
	cooldown     time.Duration // time open before half-open

	state    string // closed, open, half_open
	openedAt time.Time
	slots    [10]breakerSlot
	half     breakerSlot
}

type breakerSlot struct {
	start        time.Time
	sends, fails int
	accepted     int
	failInst     map[string]struct{}
}

func (s *breakerSlot) record(inst string, accepted, tokenFailure bool) {
	s.sends++
	if accepted {
		s.accepted++
	}
	if tokenFailure {
		s.fails++
		if s.failInst == nil {
			s.failInst = map[string]struct{}{}
		}
		s.failInst[inst] = struct{}{}
	}
}

// Breaker states.
const (
	BreakerClosed   = "closed"
	BreakerOpen     = "open"
	BreakerHalfOpen = "half_open"
)

// NewBreaker returns a closed breaker with the hosted-relay thresholds.
func NewBreaker() *Breaker {
	return &Breaker{window: 5 * time.Minute, minSends: 20, minInstances: 3, openRatio: 0.30, closeMax: 0.10,
		cooldown: 10 * time.Minute, state: BreakerClosed}
}

func (b *Breaker) slot(now time.Time) *breakerSlot {
	size := b.window / time.Duration(len(b.slots))
	start := now.Truncate(size)
	i := int(start.UnixNano()/int64(size)) % len(b.slots)
	s := &b.slots[i]
	if !s.start.Equal(start) {
		*s = breakerSlot{start: start}
	}
	return s
}

func (b *Breaker) totals(now time.Time) (sends, fails, instances int) {
	seen := map[string]struct{}{}
	for i := range b.slots {
		s := &b.slots[i]
		if now.Sub(s.start) < b.window {
			sends += s.sends
			fails += s.fails
			for i := range s.failInst {
				seen[i] = struct{}{}
			}
		}
	}
	return sends, fails, len(seen)
}

// State returns the current state, moving from open to half-open after the cool-down.
func (b *Breaker) State(now time.Time) string {
	if b.state == BreakerOpen && now.Sub(b.openedAt) >= b.cooldown {
		b.state = BreakerHalfOpen
		b.half = breakerSlot{start: now}
	}
	return b.state
}

// Marking reports whether token failures may change bindings now: only while closed.
func (b *Breaker) Marking(now time.Time) bool { return b.State(now) == BreakerClosed }

// Record counts the outcome of one send to an established binding of instance inst. tokenFailure is
// Unregistered, BadDeviceToken or DeviceTokenNotForTopic. It returns true when this call opened the breaker.
func (b *Breaker) Record(now time.Time, inst string, accepted, tokenFailure bool) bool {
	switch b.State(now) {
	case BreakerOpen:
		return false
	case BreakerHalfOpen:
		b.half.record(inst, accepted, tokenFailure)
		if b.half.sends >= b.minSends {
			ratio := float64(b.half.fails) / float64(b.half.sends)
			switch {
			case ratio > b.openRatio && len(b.half.failInst) >= b.minInstances:
				b.open(now)
				return true
			case ratio <= b.closeMax && b.half.accepted > 0:
				b.Close()
			}
		}
		return false
	}
	b.slot(now).record(inst, accepted, tokenFailure)
	sends, fails, instances := b.totals(now)
	if sends >= b.minSends && float64(fails)/float64(sends) > b.openRatio && instances >= b.minInstances {
		b.open(now)
		return true
	}
	return false
}

func (b *Breaker) open(now time.Time) {
	b.state, b.openedAt = BreakerOpen, now
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
