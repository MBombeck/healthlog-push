package relay

import (
	"time"

	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

type devQuota struct {
	all        limits.Window
	alerts     *limits.Bucket
	silentHour limits.Window
	laDay      limits.Window // Live Activity ends
	laStartDay limits.Window // Live Activity starts
	throttled  map[wire.Class]time.Time
	app        *limits.Bucket // verified app-direct calls for this token
}

// activityQuota limits the updates of one Live Activity, keyed by the MAC of its update token.
type activityQuota struct {
	hour, day limits.Window
}

// dev returns the per-device quota state of a token MAC.
func (r *Relay) dev(m string) *devQuota {
	d := r.devs[m]
	if d == nil {
		now := r.cfg.Now()
		dl := r.cfg.Limits.Device
		d = &devQuota{
			all: limits.Window{Size: fullDay}, alerts: limits.NewBucket(dl.AlertBurst, dl.AlertPerHour/3600, now),
			silentHour: limits.Window{Size: time.Hour}, laDay: limits.Window{Size: fullDay}, laStartDay: limits.Window{Size: fullDay}, throttled: map[wire.Class]time.Time{},
			app: limits.NewBucket(10, 10.0/3600, now),
		}
		r.devs[m] = d
	}
	return d
}

// activity returns the update quota of a Live Activity token.
func (r *Relay) activity(laToken []byte) *activityQuota {
	k := mac(r.cfg.MACKeys[0], laToken)
	a := r.activities[k]
	if a == nil {
		a = &activityQuota{hour: limits.Window{Size: time.Hour}, day: limits.Window{Size: fullDay}}
		r.activities[k] = a
	}
	return a
}
