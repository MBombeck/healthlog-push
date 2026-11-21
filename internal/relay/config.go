// Package relay is the HTTP service: instance registration and request signing, device-signed bindings,
// the push path to APNs, the app-direct endpoints, limits, the circuit breaker, maintenance and the admin
// socket. All mutable state is guarded by one mutex; persistence goes through internal/store.
package relay

import (
	"crypto/ed25519"
	"time"

	"github.com/MBombeck/healthlog-push/internal/limits"
)

// TierLimits are the per-instance limits of one tier (spec/protocol.md, "Limits").
type TierLimits struct {
	Devices           int   `json:"devices"`           // active bindings
	Provisional       int   `json:"provisional"`       // concurrent provisional bindings
	NewBindingsDay    int64 `json:"newBindingsPerDay"` // new device bindings per day
	RequestsMinute    int64 `json:"requestsPerMinute"` // authenticated requests per minute
	PushesDay         int64 `json:"pushesPerDay"`
	PushesMinute      int64 `json:"pushesPerMinute"`
	InvalidTokensDay  int64 `json:"invalidTokensPerDay"`
	ChallengesDay     int64 `json:"challengesPerDay"`
	BadSignatureBurst int64 `json:"badSignatureBurst"`
}

// DeviceLimits apply to every device binding regardless of tier.
type DeviceLimits struct {
	AllDay          int64   `json:"allPerDay"`
	AlertBurst      float64 `json:"alertBurst"`
	AlertPerHour    float64 `json:"alertPerHour"`
	AlertDay        int     `json:"alertPerDay"`
	SilentHour      int64   `json:"silentPerHour"`
	LiveActivityDay int64   `json:"liveActivityEndPerDay"`
}

// Limits is the full limit configuration.
type Limits struct {
	Probation          TierLimits   `json:"probation"`
	Standard           TierLimits   `json:"standard"`
	Device             DeviceLimits `json:"device"`
	ProbationPoolMin   int64        `json:"probationPoolPerMinute"`
	GlobalMin          int64        `json:"globalMinPerMinute"`
	GlobalMax          int64        `json:"globalMaxPerMinute"`
	StandardDevicesUp  int          `json:"standardDevicesAuto"` // automatic raise after 30 quiet days
	StandardDevicesMax int          `json:"standardDevicesMax"`  // highest value admin limits may set
}

// DefaultLimits are the values of the hosted relay.
var DefaultLimits = Limits{
	Probation: TierLimits{Devices: 20, Provisional: 10, NewBindingsDay: 20, RequestsMinute: 20, PushesDay: 500, PushesMinute: 30,
		InvalidTokensDay: 20, ChallengesDay: 20, BadSignatureBurst: 30},
	Standard: TierLimits{Devices: 50, Provisional: 20, NewBindingsDay: 100, RequestsMinute: 60, PushesDay: 10000, PushesMinute: 120,
		InvalidTokensDay: 100, ChallengesDay: 20, BadSignatureBurst: 60},
	Device:           DeviceLimits{AllDay: 300, AlertBurst: 20, AlertPerHour: 6, AlertDay: 100, SilentHour: 6, LiveActivityDay: 12},
	ProbationPoolMin: 600, GlobalMin: 600, GlobalMax: 6000, StandardDevicesUp: 80, StandardDevicesMax: 150,
}

// Config configures a Relay.
type Config struct {
	Host         string             // public host name, part of every signed text
	Identity     ed25519.PrivateKey // relay identity key, signs every /v1 response
	MACKeys      [][]byte           // token MAC keys, current first, then previous
	Environments map[string]bool    // APNs environments served, e.g. {"production": true}
	Limits       Limits             // zero means DefaultLimits
	Workers      int                // concurrent sends to Apple; zero means 256
	ExportDir    string             // where the daily registry export goes; empty means no export
	MinClient    [3]int             // minimum HealthLog server version, zero means none
	Version      string             // build version, shown at /version
	Commit       string             // source commit, shown at /version
	ImageDigest  string             // container image digest, shown at /version
	Now          func() time.Time   // the clock; nil means time.Now
	// Registrations overrides the registration limits; zero means limits.DefaultRegistrationLimits.
	Registrations limits.RegistrationLimits
	// ProviderTokenOK reports whether the signer's JWT is available; nil means it is not checked.
	ProviderTokenOK func() bool
}

func (c *Config) defaults() {
	if c.Workers == 0 {
		c.Workers = 256
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Limits == (Limits{}) {
		c.Limits = DefaultLimits
	}
	if c.Registrations == (limits.RegistrationLimits{}) {
		c.Registrations = limits.DefaultRegistrationLimits
	}
	if c.Environments == nil {
		c.Environments = map[string]bool{"production": true}
	}
}
