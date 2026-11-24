package relay

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/MBombeck/healthlog-push/internal/logx"
)

// Watchdog limits. Docker does not restart a container that is only unhealthy, so a relay whose core lock
// or maintenance loop hangs ends itself and lets the restart policy bring it back. The critical sections
// under r.mu are short (signatures are checked outside it), so a minute is far beyond any legitimate hold.
// The loop limit allows for one missed minute tick plus a slow daily pass (prune, check, export).
const (
	WatchdogEvery     = 10 * time.Second
	WatchdogLockLimit = 60 * time.Second
	WatchdogLoopLimit = 3 * time.Minute
)

// watchdog ends the process through exit when a lock attempt on r.mu has waited longer than lockLimit or
// the maintenance loop has not finished a pass for loopLimit. It measures wall time, not cfg.Now.
type watchdog struct {
	every, lockLimit, loopLimit time.Duration
	exit                        func(reason string)
	lockWaitSince               atomic.Int64 // unix nanoseconds of the pending lock attempt, 0 when none
}

func newWatchdog() *watchdog {
	return &watchdog{every: WatchdogEvery, lockLimit: WatchdogLockLimit, loopLimit: WatchdogLoopLimit,
		exit: func(reason string) {
			logx.Alert("relay.watchdog", logx.Str(logx.KReason, reason))
			os.Exit(2)
		}}
}

// run probes the lock and the loop until ctx ends. The probe blocks on the lock (Go's mutex hands it over
// fairly once a waiter starves), so heavy contention delays it by milliseconds, while a lock that is never
// released keeps it waiting and trips the limit.
func (w *watchdog) run(ctx context.Context, r *Relay) {
	go func() {
		for ctx.Err() == nil {
			w.lockWaitSince.Store(time.Now().UnixNano())
			r.mu.Lock()
			r.mu.Unlock() //nolint:gocritic,staticcheck // an empty critical section is the probe
			w.lockWaitSince.Store(0)
			select {
			case <-ctx.Done():
			case <-time.After(w.every):
			}
		}
	}()
	t := time.NewTicker(w.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		if since := w.lockWaitSince.Load(); since != 0 && now.Sub(time.Unix(0, since)) > w.lockLimit {
			w.exit("lock")
			return
		}
		if last := r.loopBeat.Load(); last != 0 && now.Sub(time.Unix(0, last)) > w.loopLimit {
			w.exit("loop")
			return
		}
	}
}
