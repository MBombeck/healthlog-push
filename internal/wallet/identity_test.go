package wallet

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wallet/wallettest"
)

func loadTestIdentity(t testing.TB, p *wallettest.PKI) *Identity {
	t.Helper()
	id, err := LoadIdentity(p.KeyPEM(t), wallettest.CertPEM(p.PassCert), p.InterCert, wallettest.PassTypeID, wallettest.TeamID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testService(t testing.TB, pins Pins) *Service {
	t.Helper()
	svc, err := NewService(loadTestIdentity(t, wallettest.Default(t)), pins, nil)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestLoadIdentity(t *testing.T) {
	p := wallettest.Default(t)
	id := loadTestIdentity(t, p)
	if id.SubjectO != wallettest.SubjectO || id.PassTypeID != wallettest.PassTypeID || id.DaysLeft(time.Now()) < 360 || !id.Usable(time.Now()) {
		t.Fatalf("%+v", id)
	}
	// A PKCS#1 key works as well (openssl genrsa writes one).
	pk1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(p.PassKey)})
	if _, err := LoadIdentity(pk1, wallettest.CertPEM(p.PassCert), p.InterCert, wallettest.PassTypeID, wallettest.TeamID, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// TestWalletStartRefusesForeignIssuerOrExpiringCert: the process does not start with a certificate from
// another intermediate, one that expires within seven days, one for another Pass Type ID or team, or a key
// that does not belong to it.
func TestWalletStartRefusesForeignIssuerOrExpiringCert(t *testing.T) {
	p := wallettest.Default(t)
	other := wallettest.Default(t)
	now := time.Now()
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	smallPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)})
	cases := map[string]struct {
		key, cert    []byte
		inter        *x509.Certificate
		ptid, team   string
		at           time.Time
		wantContains string
	}{
		"foreign intermediate": {p.KeyPEM(t), wallettest.CertPEM(p.PassCert), other.InterCert, wallettest.PassTypeID, wallettest.TeamID, now, "intermediate"},
		"expires in six days":  {p.KeyPEM(t), wallettest.CertPEM(p.PassCert), p.InterCert, wallettest.PassTypeID, wallettest.TeamID, p.PassCert.NotAfter.Add(-6 * 24 * time.Hour), "less than"},
		"expired":              {p.KeyPEM(t), wallettest.CertPEM(p.PassCert), p.InterCert, wallettest.PassTypeID, wallettest.TeamID, p.PassCert.NotAfter.Add(time.Hour), "less than"},
		"not yet valid":        {p.KeyPEM(t), wallettest.CertPEM(p.PassCert), p.InterCert, wallettest.PassTypeID, wallettest.TeamID, p.PassCert.NotBefore.Add(-time.Hour), "not valid yet"},
		"other pass type id":   {p.KeyPEM(t), wallettest.CertPEM(p.PassCert), p.InterCert, "pass.org.example.other", wallettest.TeamID, now, "UID"},
		"other team":           {p.KeyPEM(t), wallettest.CertPEM(p.PassCert), p.InterCert, wallettest.PassTypeID, "OTHER12345", now, "OU"},
		"key of another cert":  {other.KeyPEM(t), wallettest.CertPEM(p.PassCert), p.InterCert, wallettest.PassTypeID, wallettest.TeamID, now, "does not belong"},
		"small key":            {smallPEM, wallettest.CertPEM(p.PassCert), p.InterCert, wallettest.PassTypeID, wallettest.TeamID, now, "2048"},
		"no key":               {[]byte("x"), wallettest.CertPEM(p.PassCert), p.InterCert, wallettest.PassTypeID, wallettest.TeamID, now, "no PEM"},
		"encrypted key":        {pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}}), wallettest.CertPEM(p.PassCert), p.InterCert, wallettest.PassTypeID, wallettest.TeamID, now, "encrypted"},
		"no cert":              {p.KeyPEM(t), []byte("x"), p.InterCert, wallettest.PassTypeID, wallettest.TeamID, now, "CERTIFICATE"},
		"no intermediate":      {p.KeyPEM(t), wallettest.CertPEM(p.PassCert), nil, wallettest.PassTypeID, wallettest.TeamID, now, "intermediate"},
	}
	for name, c := range cases {
		_, err := LoadIdentity(c.key, c.cert, c.inter, c.ptid, c.team, c.at)
		if err == nil || !strings.Contains(err.Error(), c.wantContains) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestCertificateExpiryStopsSigning: a running process stops signing once fewer than seven days are left.
func TestCertificateExpiryStopsSigning(t *testing.T) {
	p := testPins()
	svc := testService(t, p)
	svc.Now = func() time.Time { return svc.ID.Cert.NotAfter.Add(-6 * 24 * time.Hour) }
	if _, err := svc.Sign(manifestJSON(minimal(p))); err == nil {
		t.Fatal("signed with six days left")
	}
	if info := svc.Info(); info.Usable || info.CertDaysLeft != 6 {
		t.Fatalf("%+v", info)
	}
	if svc.KeyUses() != 0 {
		t.Fatal("key used")
	}
	svc.Now = func() time.Time { return svc.ID.Cert.NotAfter.Add(36 * time.Hour) }
	if d := svc.Info().CertDaysLeft; d != -2 {
		t.Fatalf("days left after expiry: %d", d)
	}
}

// TestEmbeddedWWDRIsApples: the embedded intermediate has its pinned hash, is Apple's WWDR G4 and chains to
// the Apple Root CA (testdata, public).
func TestEmbeddedWWDRIsApples(t *testing.T) {
	c, err := AppleWWDRG4()
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "Apple Worldwide Developer Relations Certification Authority" || len(c.Subject.OrganizationalUnit) != 1 ||
		c.Subject.OrganizationalUnit[0] != "G4" || !c.IsCA {
		t.Fatalf("subject %v", c.Subject)
	}
	rootDER, err := os.ReadFile("testdata/AppleIncRootCertificate.cer")
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := c.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	saved := appleWWDRG4
	appleWWDRG4 = append([]byte(nil), saved...)
	appleWWDRG4[len(appleWWDRG4)-1] ^= 1
	_, err = AppleWWDRG4()
	appleWWDRG4 = saved
	if err == nil {
		t.Fatal("a changed embedded certificate was accepted")
	}
}
