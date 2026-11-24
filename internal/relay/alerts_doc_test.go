package relay

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// alertTable returns the first cell of every row of the table under "Alerts worth acting on" in
// docs/operations.md.
func alertTable(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/operations.md")
	if err != nil {
		t.Fatal(err)
	}
	_, sec, ok := strings.Cut(string(raw), "\n## Alerts worth acting on\n")
	if !ok {
		t.Fatal("docs/operations.md has no section Alerts worth acting on")
	}
	sec, _, _ = strings.Cut(sec, "\n## ")
	var cells []string
	for _, line := range strings.Split(sec, "\n") {
		if !strings.HasPrefix(line, "| ") || strings.HasPrefix(line, "| Signal |") {
			continue
		}
		cells = append(cells, strings.Split(line, " | ")[0])
	}
	if len(cells) < 15 {
		t.Fatalf("found only %d rows in the alert table; the matcher is broken", len(cells))
	}
	return cells
}

var (
	tableSeries = regexp.MustCompile(`(hlp_[a-z0-9_]+)(?:\{([^}]*)\})?`)
	tablePair   = regexp.MustCompile(`([a-z_]+)="([^"]*)"`)
	tableLabel  = regexp.MustCompile(`^[a-z_]+$`)
)

// TestAlertTableSeriesExistOnAFreshRelay: every series the alert table of docs/operations.md watches is in
// the first scrape of a relay that has done nothing yet, at zero where it counts events, with the label
// value the row names (or, for a row that names only the label, some value of it). A counter that appears
// only with its first event is invisible to increase(), so an alert on it would miss exactly the first
// incident.
func TestAlertTableSeriesExistOnAFreshRelay(t *testing.T) {
	h := newWalletHarness(t)
	rec := httptest.NewRecorder()
	h.r.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody))
	var series []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			series = append(series, line[:strings.LastIndexByte(line, ' ')])
		}
	}
	has := func(name, label, value string) bool {
		for _, s := range series {
			n, labels, _ := strings.Cut(s, "{")
			if n != name && n != name+"_bucket" {
				continue
			}
			switch {
			case label == "":
				return true
			case value == "" && strings.Contains(labels, label+`="`):
				return true
			case strings.Contains(labels, label+`="`+value+`"`):
				return true
			}
		}
		return false
	}
	checked := 0
	for _, cell := range alertTable(t) {
		for _, m := range tableSeries.FindAllStringSubmatch(cell, -1) {
			name, sel := m[1], m[2]
			checked++
			switch {
			case sel == "":
				if !has(name, "", "") {
					t.Errorf("%s is watched by the alert table but missing from a fresh relay's /metrics", name)
				}
			case tableLabel.MatchString(sel):
				if !has(name, sel, "") {
					t.Errorf("%s{%s} is watched by the alert table but has no series on a fresh relay", name, sel)
				}
			default:
				pairs := tablePair.FindAllStringSubmatch(sel, -1)
				if len(pairs) == 0 {
					t.Fatalf("unparsed selector %s{%s}", name, sel)
				}
				for _, p := range pairs {
					if !has(name, p[1], p[2]) {
						t.Errorf("%s{%s=%q} is watched by the alert table but missing from a fresh relay's /metrics", name, p[1], p[2])
					}
				}
			}
		}
	}
	if checked < 20 {
		t.Fatalf("checked only %d series of the alert table; the matcher is broken", checked)
	}
}
