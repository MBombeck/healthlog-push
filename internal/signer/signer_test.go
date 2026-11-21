package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseKeyFromP8(t *testing.T) {
	k := testKey(t)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	p8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	got, err := ParseKey(p8)
	if err != nil || !got.Equal(k) {
		t.Fatal(err)
	}
	if _, err := ParseKey([]byte("not a key")); err == nil {
		t.Fatal("garbage accepted")
	}
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalPKCS8PrivateKey(k384)
	if _, err := ParseKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("P-384 accepted")
	}
}

func TestJWTShape(t *testing.T) {
	k := testKey(t)
	now := time.Unix(1795000000, 0)
	j, err := MakeJWT(k, "ABC123DEFG", "TEAM123456", now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(j, ".")
	h, _ := wire.DecodeB64(parts[0], 0)
	c, _ := wire.DecodeB64(parts[1], 0)
	var hm, cm map[string]any
	_ = json.Unmarshal(h, &hm)
	_ = json.Unmarshal(c, &cm)
	if hm["alg"] != "ES256" || hm["kid"] != "ABC123DEFG" || cm["iss"] != "TEAM123456" || cm["iat"] != float64(now.Unix()) || len(cm) != 2 {
		t.Fatalf("jwt: %v %v", hm, cm)
	}
	if !VerifyJWT(&k.PublicKey, j) || VerifyJWT(&testKey(t).PublicKey, j) {
		t.Fatal("verification")
	}
}

// TestRenewalTiming: a token every 30 minutes, a refresh request honored only 20 minutes after the last
// token (F7: one renewal, never a burst), and the marker counts only when touched after the last token.
func TestRenewalTiming(t *testing.T) {
	dir, rdir := t.TempDir(), t.TempDir()
	now := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	s := &Signer{Key: testKey(t), KeyID: "K", TeamID: "T", Dir: dir, RefreshDir: rdir, Now: func() time.Time { return now }}
	step := func() bool {
		w, err := s.Step()
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	if !step() {
		t.Fatal("no first token")
	}
	now = now.Add(10 * time.Minute)
	marker := filepath.Join(rdir, RefreshMarker)
	_ = os.WriteFile(marker, nil, 0o600)
	_ = os.Chtimes(marker, now, now)
	if step() {
		t.Fatal("refresh honored 10 minutes after the last token")
	}
	now = now.Add(11 * time.Minute)
	if !step() {
		t.Fatal("refresh not honored after 21 minutes")
	}
	now = now.Add(21 * time.Minute)
	if step() {
		t.Fatal("old marker triggered a second refresh")
	}
	now = now.Add(10 * time.Minute)
	if !step() {
		t.Fatal("no renewal after 30 minutes")
	}
	if !Fresh(dir, time.Hour, now) || Fresh(dir, time.Hour, now.Add(2*time.Hour)) {
		t.Fatal("freshness check")
	}
	// A restarted signer reads the existing token and does not renew early.
	s2 := &Signer{Key: s.Key, KeyID: "K", TeamID: "T", Dir: dir, RefreshDir: rdir, Now: func() time.Time { return now.Add(time.Minute) }}
	if w, _ := s2.Step(); w {
		t.Fatal("restart renewed a fresh token")
	}
	fi, _ := os.Stat(filepath.Join(dir, TokenFile))
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("token mode %v", fi.Mode().Perm())
	}
}
