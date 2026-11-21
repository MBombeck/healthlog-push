package main

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func tlsConfig(host string) (*tls.Config, error) {
	switch mode := env("HLP_TLS_MODE", "acme"); mode {
	case "files":
		cert, err := tls.LoadX509KeyPair(os.Getenv("HLP_TLS_CERT_FILE"), os.Getenv("HLP_TLS_KEY_FILE"))
		if err != nil {
			return nil, err
		}
		return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}, nil
	case "acme":
		kb, err := os.ReadFile(env("HLP_ACME_ACCOUNT_KEY_FILE", "/run/secrets/relay/acme_account_key"))
		if err != nil {
			return nil, fmt.Errorf("acme account key: %w", err)
		}
		blk, _ := pem.Decode(kb)
		if blk == nil {
			return nil, errors.New("acme account key: no PEM block")
		}
		key, err := parseSigner(blk.Bytes)
		if err != nil {
			return nil, err
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(host),
			Cache:      autocert.DirCache(env("HLP_ACME_CACHE_DIR", "/acme")),
			Email:      os.Getenv("HLP_ACME_EMAIL"),
			Client:     &acme.Client{Key: key, DirectoryURL: env("HLP_ACME_DIRECTORY", autocert.DefaultACMEDirectory)},
		}
		base := m.TLSConfig()
		base.MinVersion = tls.VersionTLS13
		// The TLS-ALPN-01 validation handshake may use TLS 1.2; everything else needs TLS 1.3.
		challenge := base.Clone()
		challenge.MinVersion = tls.VersionTLS12
		base.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			// Only a pure validation handshake (offering nothing but acme-tls/1) gets the TLS 1.2 config.
			if len(h.SupportedProtos) == 1 && h.SupportedProtos[0] == acme.ALPNProto {
				return challenge, nil
			}
			return nil, nil
		}
		return base, nil
	default:
		return nil, fmt.Errorf("HLP_TLS_MODE %q: use acme or files", mode)
	}
}
