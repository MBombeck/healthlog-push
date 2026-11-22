package metrics

import (
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
	if err := r.WriteSnapshot(&b, time.Unix(0, 0), 0); err != nil {
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
