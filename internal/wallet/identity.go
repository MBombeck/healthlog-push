package wallet

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// MinValidity is how long the pass certificate must still be valid: the process does not start, and stops
// signing, when less is left, so that no pass is signed that Wallet would soon refuse to update.
const MinValidity = 7 * 24 * time.Hour

// oidUserID is the subject attribute in which Apple writes the Pass Type ID of a pass certificate.
var oidUserID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

// Identity is the pass signing identity: the Pass Type ID certificate, its RSA key and the intermediate
// that issued it.
type Identity struct {
	Key          *rsa.PrivateKey
	Cert         *x509.Certificate
	Intermediate *x509.Certificate
	PassTypeID   string
	TeamID       string
	SubjectO     string
}

// LoadIdentity parses a PEM private key (PKCS#8 or PKCS#1, RSA of at least 2048 bits) and a PEM
// certificate and checks them against each other, the intermediate, the configured identifiers and the
// time.
func LoadIdentity(keyPEM, certPEM []byte, intermediate *x509.Certificate, passTypeID, teamID string, now time.Time) (*Identity, error) {
	key, err := parseRSAKey(keyPEM)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("pass certificate: no PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pass certificate: %w", err)
	}
	id := &Identity{Key: key, Cert: cert, Intermediate: intermediate, PassTypeID: passTypeID, TeamID: teamID}
	if err := id.check(now); err != nil {
		return nil, err
	}
	if len(cert.Subject.Organization) > 0 {
		id.SubjectO = cert.Subject.Organization[0]
	}
	return id, nil
}

func parseRSAKey(b []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("pass key: no PEM block")
	}
	var key any
	var err error
	switch blk.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	default:
		return nil, fmt.Errorf("pass key: unexpected PEM block %q (encrypted keys are not supported)", blk.Type)
	}
	if err != nil {
		return nil, errors.New("pass key: not a PKCS#8 or PKCS#1 key")
	}
	rk, ok := key.(*rsa.PrivateKey)
	if !ok || rk.N.BitLen() < 2048 {
		return nil, errors.New("pass key: not an RSA key of at least 2048 bits")
	}
	return rk, nil
}

// check verifies that the key belongs to the certificate, that the intermediate issued it (key identifiers
// and signature), that the subject names the configured Pass Type ID and team, and that it is valid for at
// least MinValidity from now.
func (id *Identity) check(now time.Time) error {
	c, im := id.Cert, id.Intermediate
	if im == nil {
		return errors.New("pass certificate: no intermediate")
	}
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&id.Key.PublicKey) {
		return errors.New("pass certificate: the key does not belong to the certificate")
	}
	if len(c.AuthorityKeyId) == 0 || !bytes.Equal(c.AuthorityKeyId, im.SubjectKeyId) || !bytes.Equal(c.RawIssuer, im.RawSubject) {
		return errors.New("pass certificate: not issued by the expected intermediate")
	}
	if err := c.CheckSignatureFrom(im); err != nil {
		return fmt.Errorf("pass certificate: intermediate signature: %w", err)
	}
	if uid := subjectUserID(c); uid != id.PassTypeID || id.PassTypeID == "" {
		return fmt.Errorf("pass certificate: subject UID %q is not the configured Pass Type ID %q", uid, id.PassTypeID)
	}
	if len(c.Subject.OrganizationalUnit) != 1 || c.Subject.OrganizationalUnit[0] != id.TeamID {
		return fmt.Errorf("pass certificate: subject OU %v is not the configured team %q", c.Subject.OrganizationalUnit, id.TeamID)
	}
	if now.Before(c.NotBefore) {
		return errors.New("pass certificate: not valid yet")
	}
	if id.DaysLeft(now) < int(MinValidity/(24*time.Hour)) {
		return fmt.Errorf("pass certificate: valid until %s, less than %s from now", c.NotAfter.UTC().Format(time.DateOnly), MinValidity)
	}
	return nil
}

// Usable reports whether the certificate is still valid for at least MinValidity at now.
func (id *Identity) Usable(now time.Time) bool {
	return id.DaysLeft(now) >= int(MinValidity/(24*time.Hour))
}

// DaysLeft is the number of whole days the certificate is still valid at now; negative once expired.
func (id *Identity) DaysLeft(now time.Time) int {
	d := id.Cert.NotAfter.Sub(now)
	if d < 0 {
		return -1 - int(-d/(24*time.Hour))
	}
	return int(d / (24 * time.Hour))
}

// NotAfterDay is the last day of validity as days since the Unix epoch (UTC).
func (id *Identity) NotAfterDay() int { return int(id.Cert.NotAfter.Unix() / 86400) }

func subjectUserID(c *x509.Certificate) string {
	for _, n := range c.Subject.Names {
		if n.Type.Equal(oidUserID) {
			if s, ok := n.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}
