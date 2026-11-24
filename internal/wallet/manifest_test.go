package wallet

import (
	"crypto/sha1" //nolint:gosec // the manifest format is SHA-1
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

func sha1hex(s string) string {
	h := sha1.Sum([]byte(s)) //nolint:gosec // the manifest format is SHA-1
	return hex.EncodeToString(h[:])
}

// testPins pins one hash per brand image.
func testPins() Pins {
	p := Pins{}
	for _, f := range PinnedFiles {
		p[f] = []string{sha1hex("brand " + f)}
	}
	return p
}

func manifestJSON(m map[string]string) []byte {
	b, _ := json.Marshal(m)
	return b
}

func minimal(p Pins) map[string]string {
	return map[string]string{"pass.json": sha1hex("pass"), "icon.png": p["icon.png"][0]}
}

func reasonOf(t *testing.T, b []byte, p Pins) string {
	t.Helper()
	_, err := ParseManifest(b, p)
	if err == nil {
		return "ok"
	}
	r := ManifestReason(err)
	if r == "" {
		t.Fatalf("error without a reason: %v", err)
	}
	return r
}

// TestWalletRefusesForeignLogo: a brand image with a hash that is not pinned is refused before the key is
// touched, whether it is the required icon or an optional logo, and a second pinned hash is accepted.
func TestWalletRefusesForeignLogo(t *testing.T) {
	p := testPins()
	svc := testService(t, p)
	for name, m := range map[string]map[string]string{
		"icon":    {"pass.json": sha1hex("pass"), "icon.png": sha1hex("someone else's icon")},
		"logo":    {"pass.json": sha1hex("pass"), "icon.png": p["icon.png"][0], "logo@2x.png": sha1hex("foreign logo")},
		"artwork": {"pass.json": sha1hex("pass"), "icon.png": p["icon.png"][0], "artwork@3x.png": p["artwork@2x.png"][0]},
	} {
		if _, err := svc.Sign(manifestJSON(m)); ManifestReason(err) != ReasonForeignAsset {
			t.Errorf("%s: got %v, want foreign_asset", name, err)
		}
	}
	if svc.KeyUses() != 0 {
		t.Fatalf("the key was used %d times for refused manifests", svc.KeyUses())
	}
	p["logo@2x.png"] = append(p["logo@2x.png"], sha1hex("next logo"))
	m := minimal(p)
	m["logo@2x.png"] = sha1hex("next logo")
	if _, err := svc.Sign(manifestJSON(m)); err != nil {
		t.Fatalf("a second pinned hash was refused: %v", err)
	}
	if svc.KeyUses() != 1 {
		t.Fatalf("key uses %d, want 1", svc.KeyUses())
	}
}

// TestWalletRefusesUnknownFiles: every path outside the closed set is refused, including images in a
// locale folder, case variants, traversal and too many entries.
func TestWalletRefusesUnknownFiles(t *testing.T) {
	p := testPins()
	for _, path := range []string{"thumbnail.png", "thumbnail@2x.png", "strip.png", "background.png", "footer.png", "logo.png",
		"de.lproj/logo@2x.png", "de.lproj/icon.png", "en.lproj/pass.json", "xx.lproj/pass.strings", "de.lproj/pass.strings/x",
		"personalization.json", "../pass.json", "/pass.json", "Icon.png", "PASS.JSON", "de.LPROJ/pass.strings", "signature", "manifest.json"} {
		m := minimal(p)
		m[path] = sha1hex(path)
		if got := reasonOf(t, manifestJSON(m), p); got != ReasonUnknownFile {
			t.Errorf("%q: %s, want unknown_file", path, got)
		}
	}
	many := map[string]string{}
	for i := range MaxManifestEntries + 1 {
		many[fmt.Sprintf("f%d", i)] = sha1hex(fmt.Sprint(i))
	}
	if got := reasonOf(t, manifestJSON(many), p); got != ReasonTooMany {
		t.Errorf("41 entries: %s", got)
	}
	full := minimal(p)
	for _, f := range PinnedFiles {
		full[f] = p[f][0]
	}
	for _, l := range Locales {
		full[l+".lproj/pass.strings"] = sha1hex(l)
	}
	if got := reasonOf(t, manifestJSON(full), p); got != "ok" {
		t.Errorf("the full set was refused: %s", got)
	}
}

// TestWalletRequiresPassJSONAndIcon: pass.json and icon.png are required; malformed JSON is a shape error.
func TestWalletRequiresPassJSONAndIcon(t *testing.T) {
	p := testPins()
	icon := p["icon.png"][0]
	cases := map[string]string{
		`{"pass.json":"` + sha1hex("p") + `"}`: ReasonMissingFile,
		`{"icon.png":"` + icon + `"}`:          ReasonMissingFile,
		`{}`:                                   ReasonMissingFile,
		`{"pass.json":"` + sha1hex("a") + `","pass.json":"` + sha1hex("b") + `","icon.png":"` + icon + `"}`: ReasonShape,
		`{"pass.json":"` + strings.ToUpper(sha1hex("p")) + `","icon.png":"` + icon + `"}`:                   ReasonShape,
		`{"pass.json":1,"icon.png":"` + icon + `"}`:                                                         ReasonShape,
		`["pass.json"]`: ReasonShape,
		`{"pass.json":"` + sha1hex("p") + `","icon.png":"` + icon + `"} x`:                                         ReasonShape,
		"{\"pass.json\":\"" + sha1hex("p") + "\",\"icon.png\":\"" + icon + "\",\"\xff\":\"" + sha1hex("x") + "\"}": ReasonShape,
		``:  ReasonShape,
		`{`: ReasonShape,
	}
	for in, want := range cases {
		if got := reasonOf(t, []byte(in), p); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
	if got := reasonOf(t, []byte(strings.Repeat(" ", MaxManifestBytes)+"{}"), p); got != ReasonShape {
		t.Errorf("oversized: %s", got)
	}
}

// TestPinsValidate: the default set is empty, so the process refuses to start until the images are final;
// a pin for an unknown path or a malformed hash is refused too.
func TestPinsValidate(t *testing.T) {
	if err := DefaultPins.Validate(); err == nil {
		t.Fatal("the empty default pin set must not validate")
	}
	if err := testPins().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Pins{{"icon.png": {"abc"}}, {"icon.png": {sha1hex("i")}, "thumbnail.png": {sha1hex("t")}}, {"logo@2x.png": {sha1hex("l")}}} {
		if bad.Validate() == nil {
			t.Errorf("%v validated", bad)
		}
	}
}

// TestManifestSpecMatchesCode: spec/wallet-manifest-v1.json, which HealthLog servers compare against, states
// exactly the file set and the pins compiled into the wallet process.
func TestManifestSpecMatchesCode(t *testing.T) {
	b, err := os.ReadFile("../../spec/wallet-manifest-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		MaxBytes   int      `json:"maxBytes"`
		MaxEntries int      `json:"maxEntries"`
		Required   []string `json:"required"`
		Free       []string `json:"free"`
		Localized  struct {
			Locales []string `json:"locales"`
			File    string   `json:"file"`
		} `json:"localized"`
		Pinned map[string][]string `json:"pinned"`
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.MaxBytes != MaxManifestBytes || spec.MaxEntries != MaxManifestEntries || !slices.Equal(spec.Required, RequiredFiles) ||
		!slices.Equal(spec.Free, FreeFiles) || !slices.Equal(spec.Localized.Locales, Locales) || spec.Localized.File != "pass.strings" {
		t.Fatalf("spec and code differ: %+v", spec)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(spec.Pinned)), slices.Sorted(slices.Values(PinnedFiles))) {
		t.Fatalf("pinned paths differ: %v", spec.Pinned)
	}
	for path, hashes := range spec.Pinned {
		if !slices.Equal(hashes, DefaultPins[path]) && (len(hashes) > 0 || len(DefaultPins[path]) > 0) {
			t.Errorf("%s: spec pins %v, code pins %v", path, hashes, DefaultPins[path])
		}
	}
}

func FuzzParseWalletManifest(f *testing.F) {
	p := testPins()
	f.Add(manifestJSON(minimal(p)))
	f.Add([]byte(`{"pass.json":"` + sha1hex("p") + `","de.lproj/pass.strings":"` + sha1hex("d") + `"}`))
	f.Add([]byte(`{"pass.json":"0000000000000000000000000000000000000000","pass.json":"1"}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		entries, err := ParseManifest(b, p)
		if err != nil {
			if ManifestReason(err) == "" {
				t.Fatalf("error without reason: %v", err)
			}
			return
		}
		// Anything accepted is inside the closed set, unique, pinned where it must be, and complete.
		seen := map[string]bool{}
		for _, e := range entries {
			if seen[e[0]] || !isSHA1Hex(e[1]) {
				t.Fatalf("accepted %v", entries)
			}
			seen[e[0]] = true
			pinned := slices.Contains(PinnedFiles, e[0])
			if pinned && !p.allows(e[0], e[1]) || !pinned && e[0] != "pass.json" && !localizedStrings(e[0]) {
				t.Fatalf("accepted %q", e[0])
			}
		}
		if !seen["pass.json"] || !seen["icon.png"] || len(entries) > MaxManifestEntries {
			t.Fatalf("accepted an incomplete or oversized manifest: %v", entries)
		}
	})
}
