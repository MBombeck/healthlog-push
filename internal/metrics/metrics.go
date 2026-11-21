// Package metrics keeps coarse counters without any instance, device or address label and renders them in
// the Prometheus text format. The exposed values are a snapshot refreshed every minute, or every hour while
// fewer than 20 instances are active, so that a single instance's traffic cannot be read off the scrape.
package metrics

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// Registry holds counters and gauges keyed by metric name and a sorted label string.
type Registry struct {
	mu       sync.Mutex
	counters map[string]float64
	gauges   map[string]float64
	help     map[string]string
	snap     string
	snapAt   time.Time
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{counters: map[string]float64{}, gauges: map[string]float64{}, help: map[string]string{}}
}

func key(name string, labels ...string) string {
	if len(labels) == 0 {
		return name
	}
	parts := make([]string, 0, len(labels)/2)
	for i := 0; i+1 < len(labels); i += 2 {
		parts = append(parts, fmt.Sprintf("%s=%q", labels[i], labels[i+1]))
	}
	slices.Sort(parts)
	return name + "{" + strings.Join(parts, ",") + "}"
}

// Help sets the help text of a metric.
func (r *Registry) Help(name, text string) { r.mu.Lock(); r.help[name] = text; r.mu.Unlock() }

// Add increments a counter. Labels are name/value pairs from closed sets only.
func (r *Registry) Add(name string, v float64, labels ...string) {
	r.mu.Lock()
	r.counters[key(name, labels...)] += v
	r.mu.Unlock()
}

// Inc increments a counter by one.
func (r *Registry) Inc(name string, labels ...string) { r.Add(name, 1, labels...) }

// Set sets a gauge.
func (r *Registry) Set(name string, v float64, labels ...string) {
	r.mu.Lock()
	r.gauges[key(name, labels...)] = v
	r.mu.Unlock()
}

func (r *Registry) render() string {
	var b strings.Builder
	emit := func(m map[string]float64, typ string) {
		seen := map[string]bool{}
		for _, k := range slices.Sorted(maps.Keys(m)) {
			name, _, _ := strings.Cut(k, "{")
			if !seen[name] {
				seen[name] = true
				if h := r.help[name]; h != "" {
					fmt.Fprintf(&b, "# HELP %s %s\n", name, h)
				}
				fmt.Fprintf(&b, "# TYPE %s %s\n", name, typ)
			}
			fmt.Fprintf(&b, "%s %g\n", k, m[k])
		}
	}
	emit(r.counters, "counter")
	emit(r.gauges, "gauge")
	return b.String()
}

// WriteSnapshot writes the exposed snapshot, refreshing it when it is older than interval.
func (r *Registry) WriteSnapshot(w io.Writer, now time.Time, interval time.Duration) error {
	r.mu.Lock()
	if r.snapAt.IsZero() || now.Sub(r.snapAt) >= interval {
		r.snap = r.render()
		r.snapAt = now
	}
	s := r.snap
	r.mu.Unlock()
	_, err := io.WriteString(w, s)
	return err
}
