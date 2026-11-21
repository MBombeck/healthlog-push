package relay

import (
	"testing"
	"time"
)

func TestBreakerThresholds(t *testing.T) {
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	b := NewBreaker()
	for range 19 {
		b.Record(now, false, true) // 19 failures: below the minimum of 20 sends
	}
	if b.State(now) != BreakerClosed {
		t.Fatal("opened below 20 sends")
	}
	b = NewBreaker()
	for k := range 100 {
		b.Record(now, k%10 < 7, k%10 >= 7) // never above 30 %: does not open
	}
	if b.State(now) != BreakerClosed {
		t.Fatal("opened at 30 %")
	}
	if !b.Record(now, false, true) || b.State(now) != BreakerOpen {
		t.Fatal("did not open above 30 %")
	}
	if b.Marking(now) {
		t.Fatal("marking while open")
	}
	later := now.Add(11 * time.Minute)
	if b.State(later) != BreakerHalfOpen || b.Marking(later) {
		t.Fatal("half-open must not mark")
	}
	for range 25 {
		b.Record(later, false, true)
	}
	if b.State(later) != BreakerOpen {
		t.Fatal("half-open did not reopen on failures")
	}
	// Old failures outside the five-minute window do not count.
	b = NewBreaker()
	for range 15 {
		b.Record(now, false, true)
	}
	for range 30 {
		b.Record(now.Add(6*time.Minute), true, false)
	}
	if b.State(now.Add(6*time.Minute)) != BreakerClosed {
		t.Fatal("stale failures counted")
	}
}
