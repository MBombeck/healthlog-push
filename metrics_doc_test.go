package healthlogpush_test

import (
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/MBombeck/healthlog-push/internal/relay"
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

// TestMetricCadenceMatchesTheTransparencyTable: the last column of the metrics table states how current each
// metric is, and it is what the code does: `live` for the metrics in relay.LiveMetrics, `every N min` for
// every other metric, which the scrape serves from a copy taken every relay.HeldRefresh. A metric cannot
// move from one group to the other, and the period cannot change, without the public table saying so.
func TestMetricCadenceMatchesTheTransparencyTable(t *testing.T) {
	raw, err := os.ReadFile("docs/transparency.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	if !strings.Contains(doc, "| Metric | What it counts | Labels | Why it exists | Refreshed |") {
		t.Fatal("the metrics table has no Refreshed column")
	}
	row := regexp.MustCompile("(?m)^\\| `(hlp_[a-z0-9_]+)` \\|.*\\| ([^|]+) \\|$")
	stated := map[string]string{}
	for _, m := range row.FindAllStringSubmatch(doc, -1) {
		stated[m[1]] = strings.TrimSpace(m[2])
	}
	if len(stated) < 30 {
		t.Fatalf("found only %d rows with a cadence; the matcher is broken", len(stated))
	}
	live := relay.LiveMetrics()
	if len(live) < 4 {
		t.Fatalf("only %d live metrics; the check would prove little", len(live))
	}
	heldCell := fmt.Sprintf("every %d min", int(relay.HeldRefresh().Minutes()))
	nLive := 0
	for _, name := range slices.Sorted(maps.Keys(stated)) {
		want := heldCell
		if slices.Contains(live, name) {
			want = "live"
			nLive++
		}
		if stated[name] != want {
			t.Errorf("docs/transparency.md says %s is refreshed %q, the code says %q", name, stated[name], want)
		}
	}
	if nLive != len(live) {
		t.Errorf("docs/transparency.md has rows for %d of the %d live metrics", nLive, len(live))
	}
	// The explanation above the table names the same two cadences.
	for _, want := range []string{"**live**", "**" + heldCell + "**"} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/transparency.md does not explain %s", want)
		}
	}
}
