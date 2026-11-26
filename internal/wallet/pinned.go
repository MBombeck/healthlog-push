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
// the HealthLog repository (src/lib/emergency-card/wallet-pass/assets, set v2); each hash here is the SHA-1
// of that file's bytes. A pin set without icon.png does not validate and the wallet process refuses to start,
// so a build with the pins removed cannot sign by accident.
var DefaultPins = Pins{
	"icon.png":           {"15dd664ce7f4829f4c2953a6199723831c9b21cb"},
	"icon@2x.png":        {"418f9e2414beb85f49098839431a527a936753dd"},
	"icon@3x.png":        {"07c36f728609b3c54c277f75774fb1925a7e2197"},
	"logo@2x.png":        {"006f8e9b9b7e3c3a6c05cb272812d5485cd33e3e"},
	"logo@3x.png":        {"fbf67b0a1ec4aa0c4e43cc8d1eabbeef250231d9"},
	"primaryLogo@2x.png": {"600921193c7e98f6b7680f74a2fe2fc5b20b5e67"},
	"primaryLogo@3x.png": {"8caa7de29f7564156018109c910ebb8e6ccaf993"},
	"artwork@2x.png":     {"732e2048b04937c9ae3077f468c02a00a29e0ed6"},
	"artwork@3x.png":     {"36f40bfd80d7949a2316a8cfb01f5980f7a7df5f"},
}

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
		return errors.New("wallet pins: no hash pinned for icon.png")
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
