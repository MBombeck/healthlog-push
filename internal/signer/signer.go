// Package signer is the process without network access that holds the APNs signing key. Its only output is
// a short-lived provider JWT written to a shared tmpfs; its only input is the presence of an empty refresh
// marker file. It parses no data from the relay.
package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// Timing (spec/protocol.md, "Provider token").
const (
	RenewEvery    = 30 * time.Minute // a fresh JWT every 30 minutes
	MinRefreshGap = 20 * time.Minute // Apple refuses more frequent renewals
	PollInterval  = 10 * time.Second
	TokenFile     = "token"
	RefreshMarker = "refresh"
)

// LoadKey reads a PKCS#8 PEM P-256 key (the .p8 file from the Apple developer portal).
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-provided path
	if err != nil {
		return nil, err
	}
	return ParseKey(b)
}

// ParseKey parses a PKCS#8 PEM P-256 key.
func ParseKey(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("apns key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("apns key: not PKCS#8")
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve.Params().Name != "P-256" {
		return nil, errors.New("apns key: not a P-256 key")
	}
	return ek, nil
}

// MakeJWT builds an ES256 provider token.
func MakeJWT(key *ecdsa.PrivateKey, keyID, teamID string, iat time.Time) (string, error) {
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID})
	c, _ := json.Marshal(map[string]any{"iss": teamID, "iat": iat.Unix()})
	in := wire.EncodeB64(h) + "." + wire.EncodeB64(c)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + wire.EncodeB64(sig), nil
}

// VerifyJWT checks an ES256 token against a public key; used by tests and the fake APNs server.
func VerifyJWT(pub *ecdsa.PublicKey, jwt string) bool {
	dot1, dot2 := -1, -1
	for i := range len(jwt) {
		if jwt[i] == '.' {
			if dot1 < 0 {
				dot1 = i
			} else {
				dot2 = i
			}
		}
	}
	if dot1 < 0 || dot2 < 0 {
		return false
	}
	sig, err := wire.DecodeB64(jwt[dot2+1:], 64)
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(jwt[:dot2]))
	return ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// Signer writes JWTs.
type Signer struct {
	Key        *ecdsa.PrivateKey
	KeyID      string
	TeamID     string
	Dir        string
	RefreshDir string
	Now        func() time.Time
	last       time.Time
}

// Step writes a new token when none exists, when the current one is due, or when a refresh was requested
// and the last token is at least MinRefreshGap old. It returns whether it wrote.
func (s *Signer) Step() (bool, error) {
	now := s.Now()
	if s.last.IsZero() {
		if b, err := os.ReadFile(filepath.Join(s.Dir, TokenFile)); err == nil {
			if iat, err := issuedAt(string(b)); err == nil {
				s.last = time.Unix(iat, 0)
			}
		}
	}
	refresh := false
	if s.RefreshDir != "" {
		// The signer cannot delete the marker (read-only mount); a request counts when the marker was
		// touched after the last token was written.
		if fi, err := os.Stat(filepath.Join(s.RefreshDir, RefreshMarker)); err == nil && fi.ModTime().After(s.last) {
			refresh = true
		}
	}
	age := now.Sub(s.last)
	due := s.last.IsZero() || age >= RenewEvery || (refresh && age >= MinRefreshGap)
	if !due {
		return false, nil
	}
	tok, err := MakeJWT(s.Key, s.KeyID, s.TeamID, now)
	if err != nil {
		return false, err
	}
	if err := writeAtomic(s.Dir, TokenFile, []byte(tok)); err != nil {
		return false, err
	}
	s.last = now
	return true, nil
}

func issuedAt(jwt string) (int64, error) {
	var claims struct {
		Iat int64 `json:"iat"`
	}
	parts := []byte(jwt)
	start, end := -1, -1
	for i, c := range parts {
		if c == '.' {
			if start < 0 {
				start = i + 1
			} else {
				end = i
				break
			}
		}
	}
	if start < 0 || end < 0 {
		return 0, errors.New("not a jwt")
	}
	b, err := wire.DecodeB64(string(parts[start:end]), 0)
	if err != nil {
		return 0, err
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return 0, err
	}
	return claims.Iat, nil
}

func writeAtomic(dir, name string, b []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	tn := tmp.Name()
	defer func() { _ = os.Remove(tn) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tn, filepath.Join(dir, name))
}

// Fresh reports whether the token in dir is younger than maxAge; used by the signer health check.
func Fresh(dir string, maxAge time.Duration, now time.Time) bool {
	b, err := os.ReadFile(filepath.Join(dir, TokenFile)) //nolint:gosec // fixed name
	if err != nil {
		return false
	}
	iat, err := issuedAt(string(b))
	return err == nil && now.Sub(time.Unix(iat, 0)) < maxAge
}
