package relay

import (
	"context"
	"crypto/sha1" //nolint:gosec // the manifest format is SHA-1
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wallet"
	"github.com/MBombeck/healthlog-push/internal/wallet/wallettest"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

func walletSHA1(s string) string {
	h := sha1.Sum([]byte(s)) //nolint:gosec // the manifest format is SHA-1
	return hex.EncodeToString(h[:])
}

func walletTestPins() wallet.Pins {
	p := wallet.Pins{}
	for _, f := range wallet.PinnedFiles {
		p[f] = []string{walletSHA1("brand " + f)}
	}
	return p
}

// fakePusher answers pass pushes per token prefix and counts what it was asked.
type fakePusher struct {
	mu     sync.Mutex
	tokens []string
	answer func(token string) string
}

func (f *fakePusher) Push(_ context.Context, toks [][]byte) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(toks))
	for i, t := range toks {
		h := hex.EncodeToString(t)
		f.tokens = append(f.tokens, h)
		out[i] = wire.PassAccepted
		if f.answer != nil {
			out[i] = f.answer(h)
		}
	}
	return out
}

func (f *fakePusher) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.tokens) }

// inProcWallet is the wallet process in the test: every request goes through JSON as on the socket.
type inProcWallet struct {
	svc  *wallet.Service
	down atomic.Bool
}

func (w *inProcWallet) Do(ctx context.Context, req *wire.WalletRequest) (*wire.WalletReply, error) {
	if w.down.Load() {
		return nil, errors.New("wallet process not reachable")
	}
	b, _ := json.Marshal(req)
	var in wire.WalletRequest
	if err := wire.DecodeStrict(b, &in); err != nil {
		return nil, err
	}
	b, _ = json.Marshal(w.svc.Handle(ctx, &in))
	var rep wire.WalletReply
	return &rep, json.Unmarshal(b, &rep)
}

type walletHarness struct {
	*harness
	w      *inProcWallet
	pusher *fakePusher
	pki    *wallettest.PKI
}

func newWalletHarness(t *testing.T, opts ...option) *walletHarness {
	t.Helper()
	pki := wallettest.Default(t)
	id, err := wallet.LoadIdentity(pki.KeyPEM(t), wallettest.CertPEM(pki.PassCert), pki.InterCert, wallettest.PassTypeID, wallettest.TeamID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := &fakePusher{}
	svc, err := wallet.NewService(id, walletTestPins(), p)
	if err != nil {
		t.Fatal(err)
	}
	w := &inProcWallet{svc: svc}
	opts = append([]option{func(c *Config) { c.Wallet, c.WalletPins = w, walletTestPins() }}, opts...)
	h := newHarness(t, opts...)
	h.r.PollWallet(context.Background())
	return &walletHarness{harness: h, w: w, pusher: p, pki: pki}
}

// later moves the clock and lets the relay ask the wallet process again, as the maintenance loop does.
func (h *walletHarness) later(d time.Duration) {
	h.clk.Add(d)
	h.r.PollWallet(context.Background())
}

func minimalManifest() []byte {
	b, _ := json.Marshal(map[string]string{"pass.json": walletSHA1("pass " + randNonce()), "icon.png": walletSHA1("brand icon.png")})
	return b
}

func (i *instance) sign(manifest []byte) response {
	return i.do(http.MethodPost, "/v1/wallet/apple/sign", wire.WalletSignBody{V: 1, Manifest: wire.EncodeB64(manifest)})
}

func (i *instance) notify(items ...wire.WalletNotifyItem) (response, []wire.WalletNotifyResult) {
	rp := i.do(http.MethodPost, "/v1/wallet/apple/notify", wire.WalletNotifyBody{Items: items})
	var out wire.WalletNotifyResp
	_ = json.Unmarshal(rp.Raw, &out)
	return rp, out.Results
}

func passToken(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 32) }

// TestWalletSignEndToEnd: a registered instance gets a SignedData over its manifest, the identifiers of
// the certificate, and the status says Wallet is on; the ledger holds the manifest hash with the instance.
func TestWalletSignEndToEnd(t *testing.T) {
	h := newWalletHarness(t)
	i := h.register()
	st := i.do(http.MethodGet, "/v1/status", nil)
	wal, _ := st.Body["wallet"].(map[string]any)
	if st.Status != http.StatusOK || wal["sign"] != true || wal["notify"] != true || wal["passTypeIdentifier"] != wallettest.PassTypeID {
		t.Fatalf("status %s", st.Raw)
	}
	m := minimalManifest()
	rp := i.sign(m)
	if rp.Status != http.StatusOK || rp.str("passTypeIdentifier") != wallettest.PassTypeID || rp.str("teamIdentifier") != wallettest.TeamID ||
		rp.str("signerSubjectO") != wallettest.SubjectO {
		t.Fatalf("sign: %d %s", rp.Status, rp.Raw)
	}
	if der, err := base64.RawURLEncoding.DecodeString(rp.str("signature")); err != nil || len(der) < 1000 || der[0] != 0x30 {
		t.Fatalf("signature: %v", err)
	}
	sum := sha256.Sum256(m)
	got, err := h.st.LookupWalletSign(hex.EncodeToString(sum[:]))
	if err != nil || len(got) != 1 || got[0].InstanceID != i.id {
		t.Fatalf("ledger: %+v %v", got, err)
	}
	if h.w.svc.KeyUses() != 1 {
		t.Fatalf("key uses %d", h.w.svc.KeyUses())
	}
}
