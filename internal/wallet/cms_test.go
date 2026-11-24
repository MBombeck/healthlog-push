package wallet

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wallet/wallettest"
)

// The parsed form of the SignedData, for the structure test.
type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type signedData struct {
	Version      int
	Digests      []algID `asn1:"set"`
	Encap        struct{ Type asn1.ObjectIdentifier }
	Certificates asn1.RawValue `asn1:"tag:0"`
	SignerInfos  []signerInfo  `asn1:"set"`
}

type signerInfo struct {
	Version  int
	IssuerSN struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	Digest    algID
	Attrs     asn1.RawValue `asn1:"tag:0"`
	SigAlg    algID
	Signature []byte
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// TestCMSStructure parses the SignedData and checks each part: SHA-256, the certificates in order, the
// signed attributes sorted with the signing time and the manifest digest, and the signature over them.
func TestCMSStructure(t *testing.T) {
	p := wallettest.Default(t)
	id := loadTestIdentity(t, p)
	manifest := []byte(`{"pass.json":"` + sha1hex("p") + `"}`)
	at := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	der, err := SignedData(manifest, id.Key, id.Cert, id.Intermediate, at)
	if err != nil {
		t.Fatal(err)
	}
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil || len(rest) != 0 || !ci.Type.Equal(oidSignedData) {
		t.Fatalf("content info: %v", err)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatal(err)
	}
	if sd.Version != 1 || len(sd.Digests) != 1 || !sd.Digests[0].Algorithm.Equal(oidSHA256) || !sd.Encap.Type.Equal(oidData) || len(sd.SignerInfos) != 1 {
		t.Fatalf("signed data %+v", sd)
	}
	if want := append(append([]byte(nil), p.PassCert.Raw...), p.InterCert.Raw...); !bytes.Equal(sd.Certificates.Bytes, want) {
		t.Fatal("certificates are not [pass, intermediate]")
	}
	si := sd.SignerInfos[0]
	if si.Version != 1 || !bytes.Equal(si.IssuerSN.Issuer.FullBytes, p.PassCert.RawIssuer) || si.IssuerSN.Serial.Cmp(p.PassCert.SerialNumber) != 0 ||
		!si.SigAlg.Algorithm.Equal(oidRSAEncryption) || !si.Digest.Algorithm.Equal(oidSHA256) {
		t.Fatalf("signer info %+v", si)
	}
	attrs := append([]byte{0x31}, si.Attrs.FullBytes[1:]...)
	if !bytes.Equal(attrs, SignedAttributes(manifest, at)) {
		t.Fatal("signed attributes differ")
	}
	var list []attribute
	if _, err := asn1.UnmarshalWithParams(attrs, &list, "set"); err != nil || len(list) != 3 {
		t.Fatalf("attributes: %v", err)
	}
	for i := 1; i < len(list); i++ {
		a, _ := asn1.Marshal(list[i-1])
		b, _ := asn1.Marshal(list[i])
		if bytes.Compare(a, b) >= 0 {
			t.Fatal("attributes are not in DER order")
		}
	}
	got := map[string][]byte{}
	for _, a := range list {
		got[a.Type.String()] = a.Values.Bytes
	}
	digest := sha256.Sum256(manifest)
	if !bytes.Equal(got[oidMessageDigest.String()], tlv(tagOctetString, digest[:])) ||
		!bytes.Equal(got[oidSigningTime.String()], []byte("\x17\x0d261201100000Z")) || !bytes.Equal(got[oidContentType.String()], derOID(oidData)) {
		t.Fatalf("attribute values %x", got)
	}
	sum := sha256.Sum256(attrs)
	if err := rsa.VerifyPKCS1v15(&p.PassKey.PublicKey, crypto.SHA256, sum[:], si.Signature); err != nil {
		t.Fatal(err)
	}
}

// TestDERLengths covers the long length forms of the writer.
func TestDERLengths(t *testing.T) {
	for n, prefix := range map[int][]byte{0x7f: {0x04, 0x7f}, 0x80: {0x04, 0x81, 0x80}, 0x100: {0x04, 0x82, 0x01, 0x00}, 0x10000: {0x04, 0x83, 0x01, 0x00, 0x00}} {
		if b := tlv(tagOctetString, make([]byte, n)); !bytes.HasPrefix(b, prefix) || len(b) != n+len(prefix) {
			t.Errorf("length %d: %x", n, b[:len(prefix)])
		}
	}
	if _, err := SignedData(nil, nil, nil, nil, time.Now()); err == nil {
		t.Fatal("signed without a key")
	}
}

// opensslVerify runs `openssl smime -verify` on signature over content with the root as the only trust
// anchor. The test fails, never skips, when openssl is missing.
func opensslVerify(t *testing.T, dir string, root, signature, content []byte) error {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Fatal("openssl is required for this test")
	}
	files := map[string][]byte{"root.pem": root, "signature": signature, "manifest.json": content}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("openssl", "smime", "-verify", "-binary", "-inform", "DER", "-in", "signature", "-content", "manifest.json",
		"-purpose", "any", "-CAfile", "root.pem", "-out", os.DevNull)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("openssl: %s", out)
	}
	return err
}

// TestCMSVerifiesWithOpenSSL: OpenSSL verifies the signature against the test root (root, intermediate,
// pass), and refuses it for a changed manifest or another root.
func TestCMSVerifiesWithOpenSSL(t *testing.T) {
	p := wallettest.Default(t)
	svc, err := NewService(loadTestIdentity(t, p), testPins(), nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := manifestJSON(minimal(svc.Pins))
	sig, err := svc.Sign(manifest)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root := wallettest.CertPEM(p.RootCert)
	if err := opensslVerify(t, dir, root, sig, manifest); err != nil {
		t.Fatalf("openssl refused a valid signature: %v", err)
	}
	if opensslVerify(t, dir, root, sig, append(manifest, ' ')) == nil {
		t.Fatal("openssl accepted a changed manifest")
	}
	if opensslVerify(t, dir, wallettest.CertPEM(wallettest.Default(t).RootCert), sig, manifest) == nil {
		t.Fatal("openssl accepted another root")
	}
}
