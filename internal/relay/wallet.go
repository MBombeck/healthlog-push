package relay

import (
	"context"
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// WalletBackend is the wallet process seen from the relay: one request, one answer. *wallet.Client
// implements it over the unix socket; tests use the service in process.
type WalletBackend interface {
	Do(ctx context.Context, req *wire.WalletRequest) (*wire.WalletReply, error)
}

// Wallet timing.
const (
	walletInfoMaxAge = 3 * time.Minute // an older answer counts as "the wallet process is gone"
	walletRetry      = time.Minute     // retry hint while the wallet process is unavailable
	walletIdemMax    = 50000
	walletTokensMax  = 200000
)

// walletState is the relay's view of the wallet process and the Wallet limits that are not per instance.
type walletState struct {
	info      wire.WalletInfo
	infoAt    time.Time // when the wallet process last answered
	signMin   limits.Window
	passToks  map[string]*passTokenQuota // pass push token MAC to its windows, cleared daily
	walletIdm map[string]walletIdem      // instance id and ref to the result of a pass push, ten minutes
	down      bool                       // the last poll failed; logged once per outage
}

// walletWindows are the Wallet limits of one instance, in memory.
type walletWindows struct {
	signMin, signDay, notifyMin, notifyDay limits.Window
}

func newWalletWindows() walletWindows {
	return walletWindows{signMin: limits.Window{Size: time.Minute}, signDay: limits.Window{Size: fullDay},
		notifyMin: limits.Window{Size: time.Minute}, notifyDay: limits.Window{Size: fullDay}}
}

type passTokenQuota struct{ hour, day limits.Window }

type walletIdem struct {
	result string // empty while the push is in flight
	exp    time.Time
}

// walletStatus is the Wallet block of GET /v1/status.
type walletStatus struct {
	Sign               bool   `json:"sign"`
	Notify             bool   `json:"notify"`
	PassTypeIdentifier string `json:"passTypeIdentifier,omitempty"`
	TeamIdentifier     string `json:"teamIdentifier,omitempty"`
	CertNotAfterDay    int    `json:"certNotAfterDay,omitempty"`
}

// walletUpLocked reports whether the wallet process answered recently and can still sign.
func (r *Relay) walletUpLocked(now time.Time) bool {
	return r.cfg.Wallet != nil && !r.wallet.infoAt.IsZero() && now.Sub(r.wallet.infoAt) < walletInfoMaxAge && r.wallet.info.Usable
}

func (r *Relay) walletStatusLocked(s *instState, now time.Time) walletStatus {
	if !r.walletUpLocked(now) {
		return walletStatus{}
	}
	open := !s.rec.WalletBlocked
	return walletStatus{Sign: open, Notify: open, PassTypeIdentifier: r.wallet.info.PassTypeIdentifier,
		TeamIdentifier: r.wallet.info.TeamIdentifier, CertNotAfterDay: r.wallet.info.CertNotAfterDay}
}

// walletGateLocked applies the checks every Wallet request passes after authentication: the instance is
// still there, not blocked for Wallet, no maintenance pause, and the wallet process is up.
func (r *Relay) walletGateLocked(s *instState, now time.Time) (int, *errBody) {
	switch {
	case !r.stillThere(s):
		return http.StatusUnauthorized, &errBody{Error: "unknown_instance"}
	case s.rec.WalletBlocked:
		return http.StatusForbidden, &errBody{Error: "wallet_blocked"}
	}
	if paused, d := r.paused("all", s.rec.Tier, now); paused {
		return http.StatusServiceUnavailable, &errBody{Error: "maintenance", RetryAfter: jitter(d)}
	}
	if !r.walletUpLocked(now) {
		return http.StatusServiceUnavailable, &errBody{Error: "wallet_unavailable", RetryAfter: jitter(walletRetry)}
	}
	return 0, nil
}

func (r *Relay) walletTierLimits(s *instState) WalletTierLimits {
	if s.rec.Tier == store.TierStandard {
		return r.cfg.Limits.Wallet.Standard
	}
	return r.cfg.Limits.Wallet.Probation
}

// noteWalletInfoLocked keeps what the wallet process said about itself.
func (r *Relay) noteWalletInfoLocked(info wire.WalletInfo, now time.Time) {
	r.wallet.info, r.wallet.infoAt = info, now
	r.Metrics.Set("hlp_wallet_cert_days_left", float64(info.CertDaysLeft))
}

// PollWallet asks the wallet process about its identity; the maintenance loop calls it every minute. A
// relay without a wallet process does nothing.
func (r *Relay) PollWallet(ctx context.Context) {
	if r.cfg.Wallet == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rep, err := r.cfg.Wallet.Do(ctx, &wire.WalletRequest{Op: wire.WalletOpInfo})
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil || rep.Error != "" {
		if !r.walletUpLocked(r.cfg.Now()) {
			r.Metrics.Set("hlp_wallet_cert_days_left", -1)
		}
		if !r.wallet.down {
			r.wallet.down = true
			logx.Alert("wallet.unreachable")
		}
		return
	}
	if r.wallet.down {
		r.wallet.down = false
		logx.Event("wallet.reachable")
	}
	r.noteWalletInfoLocked(rep.Info, r.cfg.Now())
}

// walletCall sends one request to the wallet process with the deadline of its operation.
func (r *Relay) walletCall(ctx context.Context, req *wire.WalletRequest, d time.Duration) (*wire.WalletReply, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return r.cfg.Wallet.Do(ctx, req)
}

// pruneWalletLocked drops expired idempotency entries and, on a new day, every token window.
func (r *Relay) pruneWalletLocked(now time.Time, newDay bool) {
	for k, e := range r.wallet.walletIdm {
		if e.result != "" && now.After(e.exp) {
			delete(r.wallet.walletIdm, k)
		}
	}
	if newDay {
		r.wallet.passToks = map[string]*passTokenQuota{}
	}
}

// describeWallet declares the Wallet metrics; the certificate gauge exists from the start when Wallet is
// configured, at -1 until the wallet process first answers.
func (r *Relay) describeWallet() {
	r.Metrics.Help("hlp_wallet_requests_total", "Wallet signatures and pass pushes by operation and result, without any instance label.")
	r.Metrics.Help("hlp_wallet_cert_days_left", "Days the Pass Type ID certificate is still valid; -1 while the wallet process does not answer.")
	if r.cfg.Wallet != nil {
		r.Metrics.Set("hlp_wallet_cert_days_left", -1)
	}
}

func (r *Relay) walletMetric(op, result string) {
	r.Metrics.Inc("hlp_wallet_requests_total", "op", op, "result", result)
}
