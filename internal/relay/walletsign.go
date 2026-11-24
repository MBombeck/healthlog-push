package relay

import (
	"context"
	"crypto/sha256"
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wallet"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// handleWalletSign is POST /v1/wallet/apple/sign (spec/wallet.md): the instance sends the bytes of a pass
// manifest, a list of file hashes, and gets the detached signature. The relay checks the file set and the
// pins, the Wallet block and the limits; the wallet process checks the file set and the pins again before
// it touches the key. The ledger keeps the manifest hash, the instance and the day.
func (r *Relay) handleWalletSign(w http.ResponseWriter, req *http.Request) {
	s, body, ok := r.auth(w, req, wire.WalletBodyMax)
	if !ok {
		return
	}
	now := r.cfg.Now()
	r.mu.Lock()
	status, e := r.walletGateLocked(s, now)
	r.mu.Unlock()
	if e != nil {
		r.walletMetric("sign", walletRefusalLabel(e.Error))
		r.fail(w, req, status, *e)
		return
	}
	manifest, err := wire.ParseWalletSign(body)
	if err == nil {
		_, err = wallet.ParseManifest(manifest, r.cfg.WalletPins)
	}
	if err != nil {
		reason := wallet.ManifestReason(err)
		if reason == "" {
			reason = wallet.ReasonShape
		}
		r.walletMetric("sign", "invalid")
		r.fail(w, req, http.StatusUnprocessableEntity, errBody{Error: "wallet_manifest_invalid", Reason: reason})
		return
	}
	if status, e := r.admitSign(s, now); e != nil {
		r.fail(w, req, status, *e)
		return
	}
	rep, err := r.walletCall(context.WithoutCancel(req.Context()), &wire.WalletRequest{Op: wire.WalletOpSign, Manifest: manifest}, wallet.SignDeadline)
	if status, e := r.signAnswer(rep, err, now); e != nil {
		r.fail(w, req, status, *e)
		return
	}
	sum := sha256.Sum256(manifest)
	if err := r.st.PutWalletSign(sum[:], s.rec.ID, store.Day(now)); err != nil {
		// No signature leaves the relay without its ledger entry.
		r.mu.Lock()
		r.setDBError(err)
		r.mu.Unlock()
		r.walletMetric("sign", "storage")
		r.fail(w, req, http.StatusServiceUnavailable, errStorage(storageRetry))
		return
	}
	r.walletMetric("sign", "ok")
	r.reply(w, req, http.StatusOK, wire.WalletSignResp{Signature: wire.EncodeB64(rep.Signature), PassTypeIdentifier: rep.Info.PassTypeIdentifier,
		TeamIdentifier: rep.Info.TeamIdentifier, SignerSubjectO: rep.Info.SignerSubjectO, CertNotAfterDay: rep.Info.CertNotAfterDay})
}

// admitSign applies the gate and counts the signature against the instance and the relay-wide limits.
func (r *Relay) admitSign(s *instState, now time.Time) (int, *errBody) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if status, e := r.walletGateLocked(s, now); e != nil {
		r.walletMetric("sign", walletRefusalLabel(e.Error))
		return status, e
	}
	tl := r.walletTierLimits(s)
	ww := &s.wallet
	switch {
	case ww.signMin.Count(now) >= tl.SignsMinute:
		r.walletMetric("sign", "rate")
		return http.StatusTooManyRequests, &errBody{Error: "wallet_rate", Scope: "instance", RetryAfter: jitter(ww.signMin.RetryAfter(now))}
	case ww.signDay.Count(now) >= tl.SignsDay:
		r.walletMetric("sign", "quota")
		return http.StatusTooManyRequests, &errBody{Error: "wallet_quota", Scope: "instance", RetryAfter: jitter(ww.signDay.RetryAfter(now))}
	case !r.wallet.signMin.Allow(now, r.cfg.Limits.Wallet.GlobalSignsMinute):
		r.walletMetric("sign", "global")
		return http.StatusTooManyRequests, &errBody{Error: "global", Scope: "global", RetryAfter: jitter(r.wallet.signMin.RetryAfter(now))}
	}
	ww.signMin.Add(now, 1)
	ww.signDay.Add(now, 1)
	return 0, nil
}

// signAnswer turns the wallet process's answer into a refusal, or nil for a signature.
func (r *Relay) signAnswer(rep *wire.WalletReply, err error, now time.Time) (int, *errBody) {
	if err != nil || rep == nil {
		r.walletMetric("sign", "unavailable")
		return http.StatusServiceUnavailable, &errBody{Error: "wallet_unavailable", RetryAfter: jitter(walletRetry)}
	}
	r.mu.Lock()
	r.noteWalletInfoLocked(rep.Info, now)
	r.mu.Unlock()
	switch {
	case rep.Error == wire.WalletErrManifest:
		r.walletMetric("sign", "invalid")
		return http.StatusUnprocessableEntity, &errBody{Error: "wallet_manifest_invalid", Reason: manifestReasonLabel(rep.Reason)}
	case rep.Error != "" || len(rep.Signature) == 0:
		r.walletMetric("sign", "unavailable")
		return http.StatusServiceUnavailable, &errBody{Error: "wallet_unavailable", RetryAfter: jitter(walletRetry)}
	}
	return 0, nil
}

// manifestReasonLabel keeps a reason from the wallet process inside the documented set.
func manifestReasonLabel(reason string) string {
	switch reason {
	case wallet.ReasonShape, wallet.ReasonUnknownFile, wallet.ReasonForeignAsset, wallet.ReasonMissingFile, wallet.ReasonTooMany:
		return reason
	}
	return wallet.ReasonShape
}

// walletRefusalLabel is the metric label of a gate refusal.
func walletRefusalLabel(code string) string {
	switch code {
	case "wallet_blocked":
		return "blocked"
	case "maintenance":
		return "maintenance"
	case "unknown_instance":
		return "unknown_instance"
	}
	return "unavailable"
}
