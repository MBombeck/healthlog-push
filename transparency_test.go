package healthlogpush_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// feedLegacy are releases whose feed entries were written before every entry had to say both whether a key
// was rotated and whether anything was deprecated. They still need an entry.
var feedLegacy = map[string]bool{"1.0.0": true, "1.0.1": true, "1.0.2": true}

// TestEveryReleaseHasATransparencyEntry: every release in CHANGELOG.md has exactly one entry in the feed of
// docs/transparency.md, written on or after the day of the release, that says whether it rotates a key and
// whether it deprecates anything; and every release the feed names is in the changelog. A release cannot be
// cut without the public feed saying what it changes, and the feed cannot fall behind unnoticed again.
func TestEveryReleaseHasATransparencyEntry(t *testing.T) {
	cl, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("docs/transparency.md")
	if err != nil {
		t.Fatal(err)
	}
	releases := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})$`).FindAllStringSubmatch(string(cl), -1)
	if len(releases) < 9 {
		t.Fatalf("found only %d releases in CHANGELOG.md; the matcher is broken", len(releases))
	}
	_, feed, ok := strings.Cut(string(raw), "\n## Rotations and deprecations\n")
	if !ok {
		t.Fatal("docs/transparency.md has no section Rotations and deprecations")
	}
	// An entry is a bullet with a bold date; its text runs on over the lines indented by two spaces.
	entries := regexp.MustCompile(`(?m)^- \*\*(\d{4}-\d{2}-\d{2})\*\* (.*(?:\n {2}.*)*)`).FindAllStringSubmatch(feed, -1)
	named := regexp.MustCompile(`^Relay v(\d+\.\d+\.\d+)[,. ]`)
	byVersion := map[string][]entry{}
	for _, m := range entries {
		text := strings.Join(strings.Fields(m[2]), " ")
		if v := named.FindStringSubmatch(text); v != nil {
			byVersion[v[1]] = append(byVersion[v[1]], entry{date: m[1], text: text})
		}
	}
	if len(byVersion) < 5 {
		t.Fatalf("found only %d release entries in the feed; the matcher is broken", len(byVersion))
	}
	released := map[string]bool{}
	for _, r := range releases {
		v, day := r[1], r[2]
		released[v] = true
		got := byVersion[v]
		if len(got) != 1 {
			t.Errorf("release %s has %d entries in the feed of docs/transparency.md, want exactly 1", v, len(got))
			continue
		}
		if got[0].date < day {
			t.Errorf("the feed entry for %s is dated %s, before the release on %s", v, got[0].date, day)
		}
		if feedLegacy[v] {
			continue
		}
		lower := strings.ToLower(got[0].text)
		for word, says := range map[string]string{"rotation": "a key is rotated", "deprecation": "anything is deprecated"} {
			if !strings.Contains(lower, word) {
				t.Errorf("the feed entry for %s does not say whether %s", v, says)
			}
		}
	}
	for v := range byVersion {
		if !released[v] {
			t.Errorf("the feed names release %s, which CHANGELOG.md does not have", v)
		}
	}
}

type entry struct{ date, text string }
