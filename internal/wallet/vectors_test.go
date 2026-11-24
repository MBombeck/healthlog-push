package wallet

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wallet/wallettest"
)

type walletVectors struct {
	Seeds        map[string]string `json:"seeds"`
	Moduli       map[string]string `json:"moduli"`
	Certificates map[string]string `json:"certificates"`
	PassTypeID   string            `json:"passTypeIdentifier"`
	TeamID       string            `json:"teamIdentifier"`
	SubjectO     string            `json:"signerSubjectO"`
	Pins         Pins              `json:"pins"`
	Manifests    []struct {
		Name     string `json:"name"`
		Manifest string `json:"manifest"`
		Expect   string `json:"expect"`
	} `json:"manifests"`
	WalletSign []struct {
		Name             string `json:"name"`
		Manifest         string `json:"manifest"`
		ManifestSHA256   string `json:"manifestSha256"`
		SigningTime      string `json:"signingTime"`
		SignedAttributes string `json:"signedAttributes"`
		Signature        string `json:"signature"`
	} `json:"walletSign"`
}

func loadWalletVectors(t *testing.T) *walletVectors {
	t.Helper()
	b, err := os.ReadFile("../../spec/vectors/wallet-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v walletVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Manifests) < 20 || len(v.WalletSign) < 2 {
		t.Fatal("vector file too small; the check would prove little")
	}
	return &v
}

// stream and derivePrime are the key derivation of spec/tools/wallet.mjs (deriveRSAKey).
func stream(seed []byte, label string, n int) []byte {
	var out []byte
	for i := uint32(0); len(out) < n; i++ {
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte(label))
		_ = binary.Write(h, binary.BigEndian, i)
		out = h.Sum(out)
	}
	return out[:n]
}

func derivePrime(seed []byte, label string) *big.Int {
	c := new(big.Int).SetBytes(stream(seed, label, 128))
	c.Or(c, new(big.Int).Lsh(big.NewInt(3), 1022))
	c.SetBit(c, 0, 1)
	e, one, two := big.NewInt(65537), big.NewInt(1), big.NewInt(2)
	for {
		if c.ProbablyPrime(20) && new(big.Int).GCD(nil, nil, new(big.Int).Sub(c, one), e).Cmp(one) == 0 {
			return c
		}
		c.Add(c, two)
	}
}

func deriveRSAKey(t *testing.T, seedHex string) *rsa.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	p, q := derivePrime(seed, "p"), derivePrime(seed, "q")
	one := big.NewInt(1)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537},
		D: new(big.Int).ModInverse(big.NewInt(65537), phi), Primes: []*big.Int{p, q}}
	k.Precompute()
	if err := k.Validate(); err != nil {
		t.Fatal(err)
	}
	return k
}

func vectorCert(t *testing.T, v *walletVectors, name string) *x509.Certificate {
	t.Helper()
	der, err := base64.RawURLEncoding.DecodeString(v.Certificates[name])
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c
}

// TestVectorsWalletSign: from the seeds, Go derives the keys the JavaScript reference derived, accepts the
// vector chain as a pass identity, and builds byte-identical signed attributes and SignedData.
func TestVectorsWalletSign(t *testing.T) {
	v := loadWalletVectors(t)
	for name, seed := range v.Seeds {
		if got := hex.EncodeToString(deriveRSAKey(t, seed).N.Bytes()); got != v.Moduli[name] {
			t.Fatalf("%s: derived modulus differs from the vector", name)
		}
	}
	key := deriveRSAKey(t, v.Seeds["pass"])
	inter, pass := vectorCert(t, v, "intermediate"), vectorCert(t, v, "pass")
	root := vectorCert(t, v, "root")
	pool, ipool := x509.NewCertPool(), x509.NewCertPool()
	pool.AddCert(root)
	ipool.AddCert(inter)
	at := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	if _, err := pass.Verify(x509.VerifyOptions{Roots: pool, Intermediates: ipool, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatal(err)
	}
	id := &Identity{Key: key, Cert: pass, Intermediate: inter, PassTypeID: v.PassTypeID, TeamID: v.TeamID}
	if err := id.check(at); err != nil {
		t.Fatalf("the vector chain is not a valid identity: %v", err)
	}
	for _, s := range v.WalletSign {
		m, _ := base64.RawURLEncoding.DecodeString(s.Manifest)
		ts, err := time.Parse(time.RFC3339, s.SigningTime)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(m); hex.EncodeToString(sum[:]) != s.ManifestSHA256 {
			t.Fatalf("%s: manifest hash", s.Name)
		}
		if got := hex.EncodeToString(SignedAttributes(m, ts)); got != s.SignedAttributes {
			t.Fatalf("%s: signed attributes differ", s.Name)
		}
		sig, err := SignedData(m, key, pass, inter, ts)
		if err != nil {
			t.Fatal(err)
		}
		if want, _ := base64.RawURLEncoding.DecodeString(s.Signature); !bytes.Equal(sig, want) {
			t.Fatalf("%s: SignedData differs from the vector", s.Name)
		}
	}
}

// TestVectorsWalletManifests: every vector manifest gets the answer the reference recorded.
func TestVectorsWalletManifests(t *testing.T) {
	v := loadWalletVectors(t)
	if err := v.Pins.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, m := range v.Manifests {
		if got := reasonOf(t, []byte(m.Manifest), v.Pins); got != m.Expect {
			t.Errorf("%s: %s, vector expects %s", m.Name, got, m.Expect)
		}
	}
}

// TestCMSVectorVerifiesWithOpenSSL: OpenSSL verifies the vector signature against the vector root.
func TestCMSVectorVerifiesWithOpenSSL(t *testing.T) {
	v := loadWalletVectors(t)
	s := v.WalletSign[0]
	m, _ := base64.RawURLEncoding.DecodeString(s.Manifest)
	sig, _ := base64.RawURLEncoding.DecodeString(s.Signature)
	root := vectorCert(t, v, "root")
	if err := opensslVerify(t, t.TempDir(), wallettest.CertPEM(root), sig, m); err != nil {
		t.Fatal(err)
	}
}
