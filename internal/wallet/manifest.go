package wallet

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// Reasons a manifest is refused (spec/wallet.md, "Manifest"); the relay reports them as the reason of
// 422 wallet_manifest_invalid.
const (
	ReasonShape        = "shape"        // not one JSON object of path to 40 lowercase hex, a duplicate key, too long
	ReasonUnknownFile  = "unknown_file" // a path outside the closed set
	ReasonForeignAsset = "foreign_asset"
	ReasonMissingFile  = "missing_file" // pass.json or icon.png absent
	ReasonTooMany      = "too_many"     // more than MaxManifestEntries entries
)

// ManifestError is a refused manifest with its reason.
type ManifestError struct{ Reason string }

func (e *ManifestError) Error() string { return "wallet manifest refused: " + e.Reason }

func refuse(reason string) error { return &ManifestError{Reason: reason} }

// ManifestReason returns the reason of a refused manifest, or "" when err is not a ManifestError.
func ManifestReason(err error) string {
	var me *ManifestError
	if errors.As(err, &me) {
		return me.Reason
	}
	return ""
}

// ParseManifest checks manifest.json bytes against the closed file set and the pins. It reads the bytes
// as one JSON object whose values are SHA-1 hashes, refuses duplicate keys (where a lenient parser would
// keep the last one) and returns the entries in their order. Nothing outside the set is signed: no image
// in a .lproj folder, no other image name, no path with a folder other than a known locale.
func ParseManifest(b []byte, pins Pins) ([][2]string, error) {
	// Valid UTF-8 and valid JSON first, so that every implementation finds the same first fault.
	if len(b) > MaxManifestBytes || !utf8.Valid(b) || !json.Valid(b) {
		return nil, refuse(ReasonShape)
	}
	entries, err := readObject(b)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		switch path, hash := e[0], e[1]; {
		case slices.Contains(FreeFiles, path), localizedStrings(path):
		case slices.Contains(PinnedFiles, path):
			if !pins.allows(path, hash) {
				return nil, refuse(ReasonForeignAsset)
			}
		default:
			return nil, refuse(ReasonUnknownFile)
		}
	}
	for _, req := range RequiredFiles {
		if !slices.ContainsFunc(entries, func(e [2]string) bool { return e[0] == req }) {
			return nil, refuse(ReasonMissingFile)
		}
	}
	return entries, nil
}

// readObject reads exactly one JSON object of string to SHA-1 hex, in order, with unique keys and at most
// MaxManifestEntries entries.
func readObject(b []byte) ([][2]string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, refuse(ReasonShape)
	}
	var out [][2]string
	seen := map[string]bool{}
	for dec.More() {
		k, err := dec.Token()
		key, ok := k.(string)
		if err != nil || !ok || seen[key] {
			return nil, refuse(ReasonShape)
		}
		v, err := dec.Token()
		val, ok := v.(string)
		if err != nil || !ok || !isSHA1Hex(val) {
			return nil, refuse(ReasonShape)
		}
		if len(out) == MaxManifestEntries {
			return nil, refuse(ReasonTooMany)
		}
		seen[key] = true
		out = append(out, [2]string{key, val})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, refuse(ReasonShape)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, refuse(ReasonShape)
	}
	return out, nil
}

// localizedStrings reports whether path is <locale>.lproj/pass.strings for a known locale.
func localizedStrings(path string) bool {
	dir, file, ok := strings.Cut(path, "/")
	loc, isLproj := strings.CutSuffix(dir, ".lproj")
	return ok && isLproj && file == "pass.strings" && slices.Contains(Locales, loc)
}
