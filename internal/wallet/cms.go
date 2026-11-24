package wallet

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"time"
)

// SignedAttributes returns the DER SET of the three signed attributes (contentType, signingTime,
// messageDigest over manifest), sorted as DER requires. This is the exact byte string the RSA signature
// covers (RFC 5652, 5.4); inside SignerInfo the same content carries the tag [0] instead of SET.
func SignedAttributes(manifest []byte, signingTime time.Time) []byte {
	digest := sha256.Sum256(manifest)
	attr := func(o []byte, value []byte) []byte { return tlv(tagSequence, o, tlv(tagSet, value)) }
	return derSetOf(tagSet,
		attr(derOID(oidContentType), derOID(oidData)),
		attr(derOID(oidSigningTime), derUTCTime(signingTime)),
		attr(derOID(oidMessageDigest), tlv(tagOctetString, digest[:])),
	)
}

// SignedData builds the detached CMS SignedData (spec/wallet.md, "Signature") over manifest: SHA-256,
// RSA PKCS#1 v1.5, the pass certificate and the intermediate as certificates, and the signed attributes
// contentType, signingTime and messageDigest. PKCS#1 v1.5 is deterministic, so the same key, certificates,
// manifest and time give the same bytes in every implementation.
func SignedData(manifest []byte, key *rsa.PrivateKey, cert, intermediate *x509.Certificate, signingTime time.Time) ([]byte, error) {
	if key == nil || cert == nil || intermediate == nil {
		return nil, errors.New("wallet: key and certificates are required")
	}
	attrs := SignedAttributes(manifest, signingTime)
	sum := sha256.Sum256(attrs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return nil, err
	}
	// Inside SignerInfo the attributes are [0] IMPLICIT: the same content under the context tag.
	implicitAttrs := append([]byte{tagContext0}, attrs[1:]...)
	signerInfo := tlv(tagSequence,
		derSmallInt(1),
		tlv(tagSequence, cert.RawIssuer, derInt(cert.SerialNumber)),
		algorithm(oidSHA256),
		implicitAttrs,
		algorithm(oidRSAEncryption),
		tlv(tagOctetString, sig),
	)
	signed := tlv(tagSequence,
		derSmallInt(1),
		tlv(tagSet, algorithm(oidSHA256)),
		tlv(tagSequence, derOID(oidData)),
		tlv(tagContext0, cert.Raw, intermediate.Raw),
		tlv(tagSet, signerInfo),
	)
	return tlv(tagSequence, derOID(oidSignedData), tlv(tagContext0, signed)), nil
}
