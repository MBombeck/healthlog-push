package relay

import (
	"context"
	"testing"
	"time"
)

func fastWatchdog(reasons chan<- string) *watchdog {
	return &watchdog{every: 5 * time.Millisecond, lockLimit: 100 * time.Millisecond, loopLimit: 300 * time.Millisecond,
		exit: func(reason string) { reasons <- reason }}
}

func TestWatchdogExitsOnHeldLock(t *testing.T) {
	h := newHarness(t)
	reasons := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.r.loopBeat.Store(time.Now().UnixNano())
	h.r.mu.Lock() // a hang: the lock is never released while the watchdog runs
	defer h.r.mu.Unlock()
	go fastWatchdog(reasons).run(ctx, h.r)
	select {
	case got := <-reasons:
		if got != "lock" {
			t.Fatalf("reason %q, want lock", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not fire on a held lock")
	}
}

func TestWatchdogExitsOnStalledLoop(t *testing.T) {
	h := newHarness(t)
	reasons := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.r.loopBeat.Store(time.Now().Add(-time.Second).UnixNano()) // the loop's last pass is older than the limit
	go fastWatchdog(reasons).run(ctx, h.r)
	select {
	case got := <-reasons:
		if got != "loop" {
			t.Fatalf("reason %q, want loop", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog did not fire on a stalled loop")
	}
}

func TestWatchdogQuietWhileHealthy(t *testing.T) {
	h := newHarness(t)
	reasons := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fastWatchdog(reasons).run(ctx, h.r)
	// Short holds and fresh beats, as a busy but healthy relay produces them.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		h.r.loopBeat.Store(time.Now().UnixNano())
		h.r.mu.Lock()
		time.Sleep(20 * time.Millisecond)
		h.r.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	select {
	case got := <-reasons:
		t.Fatalf("watchdog fired (%s) on a healthy relay", got)
	default:
	}
}
