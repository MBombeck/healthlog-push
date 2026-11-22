package healthlogpush_test

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"testing"
)

// TestEveryMetricIsInTheTransparencyTable: every metric name the code can register appears as a row of the
// metrics table in docs/transparency.md, and every row names a metric the code has, so the public list
// cannot drift from what the relay exposes.
func TestEveryMetricIsInTheTransparencyTable(t *testing.T) {
	name := regexp.MustCompile(`"(hlp_[a-z0-9_]+)"`)
	inCode := map[string]bool{}
	for _, f := range goFiles(t) {
		for _, m := range name.FindAllStringSubmatch(f.src, -1) {
			inCode[m[1]] = true
		}
	}
	if len(inCode) < 30 {
		t.Fatalf("found only %d metric names in the code; the matcher is broken", len(inCode))
	}
	doc, err := os.ReadFile("docs/transparency.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\| `(hlp_[a-z0-9_]+)` \\|")
	inDoc := map[string]bool{}
	for _, m := range row.FindAllStringSubmatch(string(doc), -1) {
		inDoc[m[1]] = true
	}
	for _, n := range slices.Sorted(maps.Keys(inCode)) {
		if !inDoc[n] {
			t.Errorf("metric %s is registered but not listed in docs/transparency.md", n)
		}
	}
	for _, n := range slices.Sorted(maps.Keys(inDoc)) {
		if !inCode[n] {
			t.Errorf("docs/transparency.md lists %s, which the code does not register", n)
		}
	}
}
