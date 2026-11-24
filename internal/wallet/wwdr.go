package wallet

import (
	"crypto/sha256"
	"crypto/x509"
	_ "embed" // the public Apple intermediate certificate
	"encoding/hex"
	"errors"
)

// AppleWWDRG4SHA256 is the SHA-256 of the DER of "Apple Worldwide Developer Relations Certification
// Authority, G4", the public intermediate that issues Pass Type ID certificates (from
// https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer, valid until 2030-12-10).
const AppleWWDRG4SHA256 = "ea4757885538dd8cb59ff4556f676087d83c85e70902c122e42c0808b5bce14c"

//go:embed AppleWWDRCAG4.cer
var appleWWDRG4 []byte

// AppleWWDRG4 returns the embedded intermediate after checking its pinned hash.
func AppleWWDRG4() (*x509.Certificate, error) {
	sum := sha256.Sum256(appleWWDRG4)
	if hex.EncodeToString(sum[:]) != AppleWWDRG4SHA256 {
		return nil, errors.New("embedded Apple WWDR G4 certificate does not match its pinned hash")
	}
	return x509.ParseCertificate(appleWWDRG4)
}
