// Package wallettest builds a throwaway test PKI for the wallet tests: a root, an intermediate in the role
// of Apple's WWDR certificate, a Pass Type ID certificate and a TLS server certificate for a fake APNs.
// Every key is generated at run time; no key is ever written to the repository.
package wallettest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // subject key identifiers are SHA-1 by convention (RFC 5280, 4.2.1.2)
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Test identifiers.
const (
	PassTypeID = "pass.org.example.test"
	TeamID     = "TEAMID1234"
	SubjectO   = "Example Test"
)

// PKI is one generated chain.
type PKI struct {
	RootCert, InterCert, PassCert *x509.Certificate
	RootKey, InterKey, PassKey    *rsa.PrivateKey
}

var oidUID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

func ski(pub *rsa.PublicKey) []byte {
	s := sha1.Sum(x509.MarshalPKCS1PublicKey(pub)) //nolint:gosec // identifier, not security
	return s[:]
}

func key(t testing.TB) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func issue(t testing.TB, tmpl, parent *x509.Certificate, pub *rsa.PublicKey, signer *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl.SubjectKeyId = ski(pub)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// New builds a chain whose pass certificate names passTypeID and teamID and is valid until notAfter.
func New(t testing.TB, passTypeID, teamID string, notAfter time.Time) *PKI {
	t.Helper()
	now := time.Now().Add(-time.Hour)
	p := &PKI{RootKey: key(t), InterKey: key(t), PassKey: key(t)}
	ca := func(cn string, serial int64) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, Organization: []string{"Example Test CA"}},
			NotBefore: now, NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	}
	root := ca("Example Test Root", 1)
	p.RootCert = issue(t, root, root, &p.RootKey.PublicKey, p.RootKey)
	p.InterCert = issue(t, ca("Example Test Intermediate", 2), p.RootCert, &p.InterKey.PublicKey, p.RootKey)
	pass := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now, NotAfter: notAfter,
		Subject: pkix.Name{CommonName: "Pass Type ID: " + passTypeID, OrganizationalUnit: []string{teamID}, Organization: []string{SubjectO},
			Country: []string{"US"}, ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidUID, Value: passTypeID}}},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	p.PassCert = issue(t, pass, p.InterCert, &p.PassKey.PublicKey, p.InterKey)
	return p
}

// Default is New with the test identifiers and one year of validity.
func Default(t testing.TB) *PKI { return New(t, PassTypeID, TeamID, time.Now().AddDate(1, 0, 0)) }

// KeyPEM is the pass key as PKCS#8 PEM, what the operator puts into pass.key.
func (p *PKI) KeyPEM(t testing.TB) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(p.PassKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}

// CertPEM returns a certificate as PEM.
func CertPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// ServerTLS returns a TLS certificate for dnsName, issued by the root, for a fake APNs.
func (p *PKI) ServerTLS(t testing.TB, dnsName string) tls.Certificate {
	t.Helper()
	k := key(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 1, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.RootCert, &k.PublicKey, p.RootKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// Roots is a pool with the root, for clients of the fake APNs.
func (p *PKI) Roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.RootCert)
	return pool
}
