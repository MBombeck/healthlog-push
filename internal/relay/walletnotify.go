package relay

import (
	"context"
	"net/http"
	"time"

	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/wallet"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// handleWalletNotify is POST /v1/wallet/apple/notify (spec/wallet.md): up to 50 pass update pushes, each a
// pass push token Wallet registered with the instance and a reference. The relay applies the instance and
// per-token limits and the ten-minute idempotency by reference, and the wallet process sends {} to Apple
// with the pass certificate. No token is stored; per-token counters are kept by MAC, in memory.
func (r *Relay) handleWalletNotify(w http.ResponseWriter, req *http.Request) {
	s, body, ok := r.auth(w, req, wire.WalletBodyMax)
	if !ok {
		return
	}
	items, toks, err := wire.ParseWalletNotify(body)
	if err != nil {
		r.walletMetric("notify", "invalid")
		r.fail(w, req, http.StatusUnprocessableEntity, errBody{Error: "invalid_item"})
		return
	}
	now := r.cfg.Now()
	results, send, status, e := r.admitNotify(s, items, toks, now)
	if e != nil {
		r.fail(w, req, status, *e)
		return
	}
	if len(send) > 0 {
		sendToks := make([][]byte, len(send))
		for i, idx := range send {
			sendToks[i] = toks[idx]
		}
		rep, err := r.walletCall(context.WithoutCancel(req.Context()), &wire.WalletRequest{Op: wire.WalletOpNotify, Tokens: sendToks}, wallet.NotifyDeadline)
		r.settleNotify(s, items, send, rep, err, results, now)
	}
	out := wire.WalletNotifyResp{Results: make([]wire.WalletNotifyResult, len(items))}
	for i, it := range items {
		out.Results[i] = wire.WalletNotifyResult{Ref: it.Ref, Result: results[i]}
	}
	r.reply(w, req, http.StatusOK, out)
}

func walletIdemKey(instanceID, ref string) string { return instanceID + "\n" + ref }

// admitNotify applies the gate and the instance limits to the whole request, then per item the
// idempotency and the token limits. It returns the results known so far and the indexes to send.
func (r *Relay) admitNotify(s *instState, items []wire.WalletNotifyItem, toks [][]byte, now time.Time) ([]string, []int, int, *errBody) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if status, e := r.walletGateLocked(s, now); e != nil {
		r.walletMetric("notify", walletRefusalLabel(e.Error))
		return nil, nil, status, e
	}
	tl, ww, n := r.walletTierLimits(s), &s.wallet, int64(len(items))
	switch {
	case ww.notifyMin.Count(now)+n > tl.NotifyMinute:
		r.walletMetric("notify", "rate")
		return nil, nil, http.StatusTooManyRequests, &errBody{Error: "wallet_rate", Scope: "instance", RetryAfter: jitter(ww.notifyMin.RetryAfter(now))}
	case ww.notifyDay.Count(now)+n > tl.NotifyDay:
		r.walletMetric("notify", "quota")
		return nil, nil, http.StatusTooManyRequests, &errBody{Error: "wallet_quota", Scope: "instance", RetryAfter: jitter(ww.notifyDay.RetryAfter(now))}
	}
	ww.notifyMin.Add(now, n)
	ww.notifyDay.Add(now, n)
	results := make([]string, len(items))
	var send []int
	for i, it := range items {
		results[i] = r.admitPassPushLocked(s.rec.ID, it.Ref, toks[i], now)
		if results[i] == "" {
			send = append(send, i)
		}
	}
	return results, send, 0, nil
}

// admitPassPushLocked returns the result of an item decided without Apple (a repeated reference, a token
// over its limit), or "" when the item is to be sent; then its reference is held as in flight.
func (r *Relay) admitPassPushLocked(instanceID, ref string, token []byte, now time.Time) string {
	k := walletIdemKey(instanceID, ref)
	if e, seen := r.wallet.walletIdm[k]; seen && now.Before(e.exp) {
		if e.result == "" {
			return wire.PassUnavailable // the same reference is still in flight: ask again later
		}
		return e.result
	}
	m := mac(r.cfg.MACKeys[0], token)
	q := r.wallet.passToks[m]
	if q == nil {
		if len(r.wallet.passToks) >= walletTokensMax {
			return wire.PassTokenQuota
		}
		q = &passTokenQuota{hour: limits.Window{Size: time.Hour}, day: limits.Window{Size: fullDay}}
		r.wallet.passToks[m] = q
	}
	if q.hour.Count(now) >= r.cfg.Limits.Wallet.TokenHour || q.day.Count(now) >= r.cfg.Limits.Wallet.TokenDay {
		r.walletMetric("notify", wire.PassTokenQuota)
		return wire.PassTokenQuota
	}
	q.hour.Add(now, 1)
	q.day.Add(now, 1)
	if len(r.wallet.walletIdm) < walletIdemMax {
		r.wallet.walletIdm[k] = walletIdem{exp: now.Add(idemTTL)}
	}
	return ""
}

// settleNotify fills in the results of the sent items. An unavailable result frees its reference, so a
// retry is sent again; every other result is kept for ten minutes.
func (r *Relay) settleNotify(s *instState, items []wire.WalletNotifyItem, send []int, rep *wire.WalletReply, err error, results []string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ok := err == nil && rep != nil && rep.Error == "" && len(rep.Results) == len(send)
	if err == nil && rep != nil {
		r.noteWalletInfoLocked(rep.Info, now)
	}
	for j, idx := range send {
		res := wire.PassUnavailable
		if ok {
			res = passResultLabel(rep.Results[j])
		}
		results[idx] = res
		k := walletIdemKey(s.rec.ID, items[idx].Ref)
		if res == wire.PassUnavailable {
			delete(r.wallet.walletIdm, k)
		} else if _, held := r.wallet.walletIdm[k]; held {
			r.wallet.walletIdm[k] = walletIdem{result: res, exp: now.Add(idemTTL)}
		}
		r.walletMetric("notify", res)
	}
}

// passResultLabel keeps a result from the wallet process inside the documented set.
func passResultLabel(s string) string {
	switch s {
	case wire.PassAccepted, wire.PassUnregistered, wire.PassRejected, wire.PassUnavailable:
		return s
	}
	return wire.PassRejected
}
