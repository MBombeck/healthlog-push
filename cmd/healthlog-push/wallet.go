package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MBombeck/healthlog-push/internal/buildinfo"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/relay"
	"github.com/MBombeck/healthlog-push/internal/wallet"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// walletDir is the shared directory of the two wallet sockets. Empty (the default) means the relay runs
// without Wallet: no socket, no tunnel, and both Wallet endpoints answer 503 wallet_unavailable.
func walletDir() string { return os.Getenv("HLP_WALLET_DIR") }

// walletPins are the pins the process enforces; the tests set others.
var walletPins = wallet.DefaultPins

// walletIntermediate is the issuer the pass certificate must chain to; the tests set their own.
var walletIntermediate = wallet.AppleWWDRG4

// loadWalletService reads the pass key and certificate and checks them against the intermediate, the
// configured identifiers and the pins.
func loadWalletService(dir string, now time.Time) (*wallet.Service, error) {
	if dir == "" {
		return nil, errors.New("HLP_WALLET_DIR is required")
	}
	ptid, team := os.Getenv("HLP_WALLET_PASS_TYPE_ID"), os.Getenv("HLP_WALLET_TEAM_ID")
	if !wire.ValidPassTypeID(ptid) || !wire.ValidTeamID(team) {
		return nil, errors.New("HLP_WALLET_PASS_TYPE_ID (pass.<...>) and HLP_WALLET_TEAM_ID (ten characters) are required")
	}
	keyPEM, err := os.ReadFile(env("HLP_WALLET_KEY_FILE", "/run/secrets/wallet/pass.key"))
	if err != nil {
		return nil, fmt.Errorf("pass key: %w", err)
	}
	certPEM, err := os.ReadFile(env("HLP_WALLET_CERT_FILE", "/run/secrets/wallet/pass.crt"))
	if err != nil {
		return nil, fmt.Errorf("pass certificate: %w", err)
	}
	inter, err := walletIntermediate()
	if err != nil {
		return nil, err
	}
	id, err := wallet.LoadIdentity(keyPEM, certPEM, inter, ptid, team, now)
	if err != nil {
		return nil, err
	}
	return wallet.NewService(id, walletPins, wallet.NewNotifier(id, filepath.Join(dir, wallet.TunnelName), nil))
}

func runWallet() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return serveWallet(ctx, walletDir())
}

func serveWallet(ctx context.Context, dir string) error {
	svc, err := loadWalletService(dir, time.Now())
	if err != nil {
		return err
	}
	ln, err := wallet.Listen(ctx, filepath.Join(dir, wallet.SocketName))
	if err != nil {
		return err
	}
	logx.Event("wallet.start", logx.Str(logx.KVersion, buildinfo.Version), logx.Int(logx.KValue, int64(svc.Info().CertDaysLeft)))
	return svc.Serve(ctx, ln)
}

// startWalletTunnel serves the byte tunnel for the wallet process when Wallet is configured.
func startWalletTunnel(ctx context.Context, dir string) (relay.WalletBackend, error) {
	if dir == "" {
		return nil, nil
	}
	ln, err := wallet.Listen(ctx, filepath.Join(dir, wallet.TunnelName))
	if err != nil {
		return nil, err
	}
	go func() {
		if err := (&relay.Tunnel{}).Serve(ctx, ln); err != nil {
			logx.Alert("relay.wallet_tunnel_failed")
		}
	}()
	return wallet.NewClient(filepath.Join(dir, wallet.SocketName)), nil
}

// walletHealthcheck asks the wallet process for its identity; it fails when the process does not answer
// or the certificate has less than seven days left.
func walletHealthcheck(dir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	rep, err := wallet.NewClient(filepath.Join(dir, wallet.SocketName)).Do(ctx, &wire.WalletRequest{Op: wire.WalletOpInfo})
	switch {
	case err != nil:
		return err
	case !rep.Info.Usable:
		return fmt.Errorf("pass certificate has %d days left", rep.Info.CertDaysLeft)
	}
	return nil
}

// walletCSR writes a new RSA-2048 key and a certificate signing request for a Pass Type ID certificate,
// both PEM, to out. Run it without network (docker run --network none ...).
func walletCSR(passTypeID, org string, out io.Writer) error {
	if !wire.ValidPassTypeID(passTypeID) {
		return errors.New("keygen wallet-csr <pass type id, e.g. pass.org.example.card> [organization]")
	}
	if org == "" {
		org = "HealthLog"
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: passTypeID, Organization: []string{org}}}, k)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	if err := pem.Encode(out, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return err
	}
	return pem.Encode(out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
}
