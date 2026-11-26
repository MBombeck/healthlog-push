package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/wallet"
	"github.com/MBombeck/healthlog-push/internal/wallet/wallettest"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "hlc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// TestWalletProcessStartsOnlyWhenConfigured: the wallet process refuses to start without its identifiers,
// key and certificate, with an empty pin set, and with a certificate from another intermediate; with
// all of them it serves its socket, the health check passes, and the relay's tunnel side starts.
func TestWalletProcessStartsOnlyWhenConfigured(t *testing.T) {
	logx.SetOutput(&bytes.Buffer{})
	pki := wallettest.Default(t)
	dir := shortDir(t)
	secrets := t.TempDir()
	_ = os.WriteFile(filepath.Join(secrets, "pass.key"), pki.KeyPEM(t), 0o600)
	_ = os.WriteFile(filepath.Join(secrets, "pass.crt"), wallettest.CertPEM(pki.PassCert), 0o600)
	if _, err := loadWalletService("", time.Now()); err == nil {
		t.Fatal("started without HLP_WALLET_DIR")
	}
	if _, err := loadWalletService(dir, time.Now()); err == nil {
		t.Fatal("started without identifiers")
	}
	t.Setenv("HLP_WALLET_PASS_TYPE_ID", wallettest.PassTypeID)
	t.Setenv("HLP_WALLET_TEAM_ID", wallettest.TeamID)
	t.Setenv("HLP_WALLET_KEY_FILE", filepath.Join(secrets, "missing.key"))
	if _, err := loadWalletService(dir, time.Now()); err == nil {
		t.Fatal("started without a key")
	}
	t.Setenv("HLP_WALLET_KEY_FILE", filepath.Join(secrets, "pass.key"))
	t.Setenv("HLP_WALLET_CERT_FILE", filepath.Join(secrets, "pass.crt"))
	// The embedded Apple intermediate did not issue the test certificate.
	if _, err := loadWalletService(dir, time.Now()); err == nil || !strings.Contains(err.Error(), "intermediate") {
		t.Fatalf("started with a certificate Apple did not issue: %v", err)
	}
	walletIntermediate = func() (*x509.Certificate, error) { return pki.InterCert, nil }
	t.Cleanup(func() { walletIntermediate = wallet.AppleWWDRG4; walletPins = wallet.DefaultPins })
	walletPins = wallet.Pins{}
	if _, err := loadWalletService(dir, time.Now()); err == nil || !strings.Contains(err.Error(), "pins") {
		t.Fatalf("started with an empty pin set: %v", err)
	}
	walletPins = wallet.DefaultPins
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveWallet(ctx, dir) }()
	deadline := time.Now().Add(5 * time.Second)
	for walletHealthcheck(dir) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the wallet process never answered its health check")
		}
		time.Sleep(20 * time.Millisecond)
	}
	backend, err := startWalletTunnel(ctx, dir)
	if err != nil || backend == nil {
		t.Fatalf("tunnel: %v", err)
	}
	rep, err := backend.Do(ctx, &wire.WalletRequest{Op: wire.WalletOpInfo})
	if err != nil || rep.Info.PassTypeIdentifier != wallettest.PassTypeID {
		t.Fatalf("info: %+v %v", rep, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if b, err := startWalletTunnel(context.Background(), ""); b != nil || err != nil {
		t.Fatal("a relay without HLP_WALLET_DIR started Wallet")
	}
}

// TestWalletCSR: keygen wallet-csr writes an RSA-2048 PKCS#8 key and a CSR for the Pass Type ID, signed by
// that key.
func TestWalletCSR(t *testing.T) {
	var out bytes.Buffer
	if err := walletCSR("pass.org.example.card", "", &out); err != nil {
		t.Fatal(err)
	}
	keyBlk, rest := pem.Decode(out.Bytes())
	csrBlk, _ := pem.Decode(rest)
	if keyBlk == nil || keyBlk.Type != "PRIVATE KEY" || csrBlk == nil || csrBlk.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("output:\n%s", out.String())
	}
	csr, err := x509.ParseCertificateRequest(csrBlk.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "pass.org.example.card" || csr.Subject.Organization[0] != "HealthLog" {
		t.Fatalf("csr %v %v", csr, err)
	}
	if walletCSR("not-a-pass-id", "", &out) == nil {
		t.Fatal("accepted a malformed Pass Type ID")
	}
}
