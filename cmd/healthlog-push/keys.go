package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

func readSecret(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // fixed names in the secrets directory
	if err != nil {
		return nil, fmt.Errorf("secret %s: %w", name, err)
	}
	return []byte(strings.TrimSpace(string(b))), nil
}

// loadMACKeys reads the current token MAC key and, when present, the previous one.
func loadMACKeys(secrets string) ([][]byte, error) {
	var macKeys [][]byte
	for _, n := range []string{"token_mac_key", "token_mac_key_previous"} {
		b, err := readSecret(secrets, n)
		if err != nil {
			if n == "token_mac_key_previous" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		k, err := decodeKeyMaterial(b)
		if err != nil || len(k) < 32 {
			return nil, fmt.Errorf("%s must be base64 of at least 32 bytes", n)
		}
		macKeys = append(macKeys, k)
	}
	return macKeys, nil
}

// decodeKeyMaterial accepts base64url without padding (what keygen writes) and standard base64 with or
// without padding, so that a key made with "openssl rand -base64 32" works as well.
func decodeKeyMaterial(b []byte) ([]byte, error) {
	s := string(b)
	for _, dec := range []func(string) ([]byte, error){base64.RawURLEncoding.DecodeString, base64.StdEncoding.DecodeString, base64.RawStdEncoding.DecodeString} {
		if v, err := dec(s); err == nil {
			return v, nil
		}
	}
	return nil, errors.New("not base64")
}

// loadIdentity reads the relay identity key: a PKCS#8 PEM Ed25519 key or a base64 32-byte seed.
func loadIdentity(b []byte) (ed25519.PrivateKey, error) {
	if blk, _ := pem.Decode(b); blk != nil {
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		ek, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("relay_id_key is not Ed25519")
		}
		return ek, nil
	}
	seed, err := decodeKeyMaterial(b)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("relay_id_key must be PEM or a base64 32-byte seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func parseSigner(der []byte) (*ecdsa.PrivateKey, error) {
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("acme account key must be an EC key")
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("acme account key must be an EC key")
	}
	return ek, nil
}

func keygen(kind string, out io.Writer) error {
	switch kind {
	case "relay-id":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{
			"relay_id_key": base64.RawURLEncoding.EncodeToString(priv.Seed()),
			"publicKey":    wire.EncodeB64(pub),
		})
	case "token-mac":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, base64.RawURLEncoding.EncodeToString(b))
		return err
	case "acme-account":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		return pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	return errors.New("keygen relay-id|token-mac|acme-account")
}
