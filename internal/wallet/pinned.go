package wallet

import (
	"errors"
	"fmt"
	"slices"
)

// The closed file set of a HealthLog pass (spec/wallet.md, "Manifest"). spec/wallet-manifest-v1.json states
// the same set for implementers; TestManifestSpecMatchesCode holds the two together.
var (
	// RequiredFiles must be in every manifest.
	RequiredFiles = []string{"pass.json", "icon.png"}
	// FreeFiles may carry any hash: the pass itself.
	FreeFiles = []string{"pass.json"}
	// PinnedFiles are the brand images. Each must carry one of the hashes pinned for its path.
	PinnedFiles = []string{
		"icon.png", "icon@2x.png", "icon@3x.png",
		"logo@2x.png", "logo@3x.png",
		"primaryLogo@2x.png", "primaryLogo@3x.png",
		"artwork@2x.png", "artwork@3x.png",
	}
	// Locales may each carry one <locale>.lproj/pass.strings with any hash, and nothing else: an image in a
	// .lproj folder would replace a pinned image on a device in that language. pt-BR and pt_BR are both
	// listed until the device test settles which name Wallet reads.
	Locales = []string{"de", "en", "es", "fr", "it", "ko", "nl", "pl", "pt-BR", "pt_BR", "ru"}
)

// Manifest bounds.
const (
	MaxManifestBytes   = 8 << 10
	MaxManifestEntries = 40
)

// Pins maps each pinned path to the SHA-1 hashes (40 lowercase hex) it may carry. Several hashes per path
// let a changed image take over without a gap.
type Pins map[string][]string

// DefaultPins are the hashes of the HealthLog brand images the hosted service signs. The images are made in
// the HealthLog repository; until their final hashes are entered here, the set is empty and the wallet
// process refuses to start (Validate), so nothing can be signed by accident.
var DefaultPins = Pins{}

// Validate refuses a pin set that names a path outside PinnedFiles, carries a malformed hash, or pins
// nothing for icon.png, the one required image.
func (p Pins) Validate() error {
	for path, hashes := range p {
		if !slices.Contains(PinnedFiles, path) {
			return fmt.Errorf("wallet pins: %q is not a pinned file", path)
		}
		for _, h := range hashes {
			if !isSHA1Hex(h) {
				return fmt.Errorf("wallet pins: %s: %q is not 40 lowercase hex", path, h)
			}
		}
	}
	if len(p["icon.png"]) == 0 {
		return errors.New("wallet pins: no hash pinned for icon.png; the brand images are not final yet")
	}
	return nil
}

func (p Pins) allows(path, hash string) bool { return slices.Contains(p[path], hash) }

func isSHA1Hex(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
