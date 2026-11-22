package metrics

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestHistogramRendersCumulativeBuckets(t *testing.T) {
	r := New()
	r.Histogram("x_seconds", 0.1, 1)
	r.Observe("x_seconds", 0.05)
	r.Observe("x_seconds", 0.5)
	r.Observe("x_seconds", 3)
	r.Observe("undeclared", 1)
	var b strings.Builder
	if err := r.Write(&b, time.Unix(0, 0), 0); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# TYPE x_seconds histogram\n", `x_seconds_bucket{le="0.1"} 1`, `x_seconds_bucket{le="1"} 2`,
		`x_seconds_bucket{le="+Inf"} 3`, "x_seconds_sum 3.55\n", "x_seconds_count 3\n"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in\n%s", want, b.String())
		}
	}
	if strings.Contains(b.String(), "undeclared") {
		t.Error("an undeclared histogram was rendered")
	}
	if n := r.Names(); len(n) != 1 || n[0] != "x_seconds" {
		t.Errorf("names: %v", n)
	}
}

// TestOnlyLiveMetricsAreCurrent: a metric declared live, counter, gauge or histogram, shows its value at
// every write; every other metric shows the copy taken at the last refresh until the interval has passed,
// and a series that appeared after the copy is left out until then.
func TestOnlyLiveMetricsAreCurrent(t *testing.T) {
	r := New()
	r.Live("req_total", "depth", "lat_seconds")
	r.Histogram("lat_seconds", 1)
	r.Histogram("held_seconds", 1)
	t0 := time.Unix(1000, 0)
	write := func(at time.Time) string {
		var b strings.Builder
		if err := r.Write(&b, at, 5*time.Minute); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	r.Set("pop", 1, "tier", "a")
	r.Set("depth", 1)
	r.Inc("req_total")
	r.Inc("sends_total", "kind", "a")
	if !r.HeldDue(t0, 5*time.Minute) {
		t.Fatal("a registry that never wrote is not due")
	}
	first := write(t0)
	for _, want := range []string{"pop{tier=\"a\"} 1\n", "depth 1\n", "req_total 1\n", `sends_total{kind="a"} 1` + "\n",
		"lat_seconds_count 0\n", "held_seconds_count 0\n"} {
		if !strings.Contains(first, want) {
			t.Fatalf("missing %q in\n%s", want, first)
		}
	}
	r.Set("pop", 2, "tier", "a")
	r.Set("pop", 7, "tier", "b")
	r.Set("depth", 3)
	r.Inc("req_total")
	r.Inc("sends_total", "kind", "a")
	r.Inc("sends_total", "kind", "b")
	r.Observe("lat_seconds", 0.2)
	r.Observe("held_seconds", 0.2)
	if r.HeldDue(t0.Add(4*time.Minute), 5*time.Minute) {
		t.Fatal("due before the interval has passed")
	}
	within := write(t0.Add(4 * time.Minute))
	for _, want := range []string{"depth 3\n", "req_total 2\n", "lat_seconds_count 1\n",
		"pop{tier=\"a\"} 1\n", `sends_total{kind="a"} 1` + "\n", "held_seconds_count 0\n"} {
		if !strings.Contains(within, want) {
			t.Errorf("within the interval: missing %q in\n%s", want, within)
		}
	}
	for _, absent := range []string{`tier="b"`, `kind="b"`} {
		if strings.Contains(within, absent) {
			t.Errorf("a held series that appeared after the copy shows before the refresh (%s):\n%s", absent, within)
		}
	}
	after := write(t0.Add(5 * time.Minute))
	for _, want := range []string{"pop{tier=\"a\"} 2\n", "pop{tier=\"b\"} 7\n", `sends_total{kind="a"} 2` + "\n",
		`sends_total{kind="b"} 1` + "\n", "held_seconds_count 1\n"} {
		if !strings.Contains(after, want) {
			t.Errorf("after the interval: missing %q in\n%s", want, after)
		}
	}
	if l := r.LiveNames(); !slices.Equal(l, []string{"depth", "lat_seconds", "req_total"}) {
		t.Errorf("live: %v", l)
	}
}
