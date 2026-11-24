package relay

import (
	"errors"

	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/store"
)

// SetWalletBlock blocks or unblocks Wallet signing and pass pushes for one instance; its pushes to the app
// are not affected. The block is stored with the instance and travels in the registry export.
func (r *Relay) SetWalletBlock(id string, blocked bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.instances[id]
	if s == nil {
		return errors.New("unknown instance")
	}
	next := *s.rec
	next.WalletBlocked = blocked
	if err := r.st.PutInstance(&next); err != nil {
		return err
	}
	*s.rec = next
	if blocked {
		logx.Event("admin.wallet_block")
	} else {
		logx.Event("admin.wallet_unblock")
	}
	return nil
}

// WalletLookup returns which instances had the manifest with this SHA-256 (64 hex) signed, and on which
// day: the trace from a reported pass back to the server that asked for its signature.
func (r *Relay) WalletLookup(hexSHA256 string) ([]store.WalletSign, error) {
	out, err := r.st.LookupWalletSign(hexSHA256)
	if errors.Is(err, store.ErrNotFound) {
		return nil, adminError("wallet lookup <sha256 of manifest.json, 64 hex>")
	}
	return out, err
}

// WalletInfo is what `admin wallet status` shows: the identity the wallet process reported and when.
type WalletInfo struct {
	Configured         bool   `json:"configured"`
	Up                 bool   `json:"up"`
	PassTypeIdentifier string `json:"passTypeIdentifier,omitempty"`
	TeamIdentifier     string `json:"teamIdentifier,omitempty"`
	SignerSubjectO     string `json:"signerSubjectO,omitempty"`
	CertNotAfterDay    string `json:"certNotAfterDay,omitempty"`
	CertDaysLeft       int    `json:"certDaysLeft,omitempty"`
	LastAnswerSecsAgo  int64  `json:"lastAnswerSecondsAgo,omitempty"`
}

func (r *Relay) walletInfo() WalletInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	wi := WalletInfo{Configured: r.cfg.Wallet != nil, Up: r.walletUpLocked(now)}
	if !r.wallet.infoAt.IsZero() {
		in := r.wallet.info
		wi.PassTypeIdentifier, wi.TeamIdentifier, wi.SignerSubjectO = in.PassTypeIdentifier, in.TeamIdentifier, in.SignerSubjectO
		wi.CertNotAfterDay, wi.CertDaysLeft = store.DayString(in.CertNotAfterDay), in.CertDaysLeft
		wi.LastAnswerSecsAgo = int64(now.Sub(r.wallet.infoAt).Seconds())
	}
	return wi
}

// adminWallet runs `admin wallet status | lookup <sha256> | block <id> | unblock <id>`.
func (r *Relay) adminWallet(a []string) (any, error) {
	switch arg(a, 0) {
	case "status":
		return r.walletInfo(), nil
	case "lookup":
		return r.WalletLookup(arg(a, 1))
	case "block":
		return nil, r.SetWalletBlock(arg(a, 1), true)
	case "unblock":
		return nil, r.SetWalletBlock(arg(a, 1), false)
	}
	return nil, adminError("wallet status | wallet lookup <sha256> | wallet block <id> | wallet unblock <id>")
}
