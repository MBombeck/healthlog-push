// Package relay is the HTTP service: instance registration and request signing, device-signed bindings,
// the push path to APNs, the app-direct endpoints, limits, the circuit breaker, maintenance and the admin
// socket. All mutable state is guarded by one mutex; persistence goes through internal/store.
package relay

import (
	"crypto/ed25519"
	"time"

	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/wallet"
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
	// Live Activity start and update (only with the device's Live Activity consent): starts per device and
	// day, updates per activity and hour and per activity and day.
	LiveActivityStartDay int64 `json:"liveActivityStartPerDay"`
	ActivityUpdateHour   int64 `json:"activityUpdatesPerHour"`
	ActivityUpdateDay    int64 `json:"activityUpdatesPerDay"`
}

// WalletTierLimits are the per-instance Wallet limits of one tier (spec/wallet.md, "Limits").
type WalletTierLimits struct {
	SignsMinute  int64 `json:"signsPerMinute"`
	SignsDay     int64 `json:"signsPerDay"`
	NotifyMinute int64 `json:"passPushesPerMinute"`
	NotifyDay    int64 `json:"passPushesPerDay"`
}

// WalletLimits are the Wallet limits: per tier, relay-wide signatures per minute, and pass pushes per pass
// push token (by its MAC) per hour and per day.
type WalletLimits struct {
	Probation         WalletTierLimits `json:"probation"`
	Standard          WalletTierLimits `json:"standard"`
	GlobalSignsMinute int64            `json:"globalSignsPerMinute"`
	TokenHour         int64            `json:"passPushesPerTokenHour"`
	TokenDay          int64            `json:"passPushesPerTokenDay"`
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
	Wallet             WalletLimits `json:"wallet"`
}

// DefaultLimits are the values of the hosted relay.
var DefaultLimits = Limits{
	Probation: TierLimits{Devices: 20, Provisional: 10, NewBindingsDay: 20, RequestsMinute: 20, PushesDay: 500, PushesMinute: 30,
		InvalidTokensDay: 20, ChallengesDay: 20, BadSignatureBurst: 30},
	Standard: TierLimits{Devices: 50, Provisional: 20, NewBindingsDay: 100, RequestsMinute: 60, PushesDay: 10000, PushesMinute: 120,
		InvalidTokensDay: 100, ChallengesDay: 20, BadSignatureBurst: 60},
	Device: DeviceLimits{AllDay: 300, AlertBurst: 20, AlertPerHour: 6, AlertDay: 100, SilentHour: 6, LiveActivityDay: 12,
		LiveActivityStartDay: 12, ActivityUpdateHour: 12, ActivityUpdateDay: 48},
	ProbationPoolMin: 600, GlobalMin: 600, GlobalMax: 6000, StandardDevicesUp: 80, StandardDevicesMax: 150,
	Wallet: WalletLimits{
		Probation:         WalletTierLimits{SignsMinute: 10, SignsDay: 200, NotifyMinute: 60, NotifyDay: 300},
		Standard:          WalletTierLimits{SignsMinute: 30, SignsDay: 2000, NotifyMinute: 60, NotifyDay: 3000},
		GlobalSignsMinute: 600, TokenHour: 12, TokenDay: 48,
	},
}

// Config configures a Relay.
type Config struct {
	Host         string             // public host name, part of every signed text
	Identity     ed25519.PrivateKey // relay identity key, signs every /v1 response
	IdentitySlot string             // pinned slot of the identity key (current, next, emergency); empty means unpinned
	MACKeys      [][]byte           // token MAC keys, current first, then previous
	Environments map[string]bool    // APNs environments served, e.g. {"production": true}
	Limits       Limits             // zero means DefaultLimits
	Workers      int                // concurrent sends to Apple; zero means 256
	ExportDir    string             // where the daily registry export goes; empty means no export
	MinClient    [3]int             // minimum HealthLog server version, zero means none
	Version      string             // build version, shown at /version
	Commit       string             // source commit, shown at /version
	ImageDigest  string             // container image digest, shown at /version
	BinarySHA256 string             // SHA-256 of the running executable, shown at /version
	PublicStats  bool               // serve GET /stats, the public day aggregates; off by default
	Now          func() time.Time   // the clock; nil means time.Now
	// Registration is the registration mode a store without a stored mode starts in (a new store, or one
	// on which no mode was ever set): open, invite or closed. Empty means invite. A stored mode, set with
	// `admin registration`, always wins, so a restart never reopens what an operator closed.
	Registration string
	// Registrations overrides the registration limits; zero means limits.DefaultRegistrationLimits.
	Registrations limits.RegistrationLimits
	// ProviderTokenOK reports whether the signer's JWT is available; nil means it is not checked.
	ProviderTokenOK func() bool
	// Wallet is the wallet process (internal/wallet, over its unix socket); nil means Wallet signing and pass
	// pushes are off and both endpoints answer 503 wallet_unavailable.
	Wallet WalletBackend
	// WalletPins are the brand image hashes the relay checks before it asks the wallet process, which checks
	// them again; nil means wallet.DefaultPins.
	WalletPins wallet.Pins
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
	if c.WalletPins == nil {
		c.WalletPins = wallet.DefaultPins
	}
	if c.Environments == nil {
		c.Environments = map[string]bool{"production": true}
	}
}
