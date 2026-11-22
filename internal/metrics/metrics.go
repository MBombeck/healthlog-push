// Package metrics keeps coarse counters without any instance, device or address label and renders them in
// the Prometheus text format.
//
// Only the metrics declared with Live are rendered as they are at each scrape. Every other metric, counter,
// gauge or histogram, is served from a held copy that is taken again at most once per interval, so a metric
// that is not declared live can never become current by accident.
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
	hists    map[string]*histogram
	help     map[string]string
	// live names the metrics rendered with their current value; every other metric is served from the
	// held copy below.
	live         map[string]bool
	heldCounters map[string]float64
	heldGauges   map[string]float64
	heldHists    map[string]*histogram
	heldAt       time.Time
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{counters: map[string]float64{}, gauges: map[string]float64{}, hists: map[string]*histogram{},
		help: map[string]string{}, live: map[string]bool{}}
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

func nameOf(k string) string {
	name, _, _ := strings.Cut(k, "{")
	return name
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

// Live declares metrics that are rendered with their current value at every write. Every other metric is
// served from the held copy (see Write).
func (r *Registry) Live(names ...string) {
	r.mu.Lock()
	for _, n := range names {
		r.live[n] = true
	}
	r.mu.Unlock()
}

// LiveNames returns the names declared live, sorted.
func (r *Registry) LiveNames() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Sorted(maps.Keys(r.live))
}

// HeldDue reports whether the held copy is older than interval, so that the caller can compute held gauges
// only when a scrape is going to show them anew.
func (r *Registry) HeldDue(now time.Time, interval time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.heldDueLocked(now, interval)
}

func (r *Registry) heldDueLocked(now time.Time, interval time.Duration) bool {
	return r.heldAt.IsZero() || now.Sub(r.heldAt) >= interval
}

// histogram is a cumulative histogram without labels, with fixed upper bounds.
type histogram struct {
	bounds []float64
	counts []float64 // one per bound; the +Inf bucket is count
	sum    float64
	count  float64
}

// Histogram declares a histogram without labels and its upper bounds. Observing an undeclared histogram
// does nothing, so the bucket layout is set in one place.
func (r *Registry) Histogram(name string, bounds ...float64) {
	r.mu.Lock()
	r.hists[name] = &histogram{bounds: slices.Clone(bounds), counts: make([]float64, len(bounds))}
	r.mu.Unlock()
}

// Observe records one value in a declared histogram.
func (r *Registry) Observe(name string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.hists[name]
	if h == nil {
		return
	}
	for i, b := range h.bounds {
		if v <= b {
			h.counts[i]++
		}
	}
	h.sum += v
	h.count++
}

// Names returns the names of every metric in the registry, histograms included, sorted.
func (r *Registry) Names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	set := map[string]bool{}
	for _, m := range []map[string]float64{r.counters, r.gauges} {
		for k := range m {
			set[nameOf(k)] = true
		}
	}
	for name := range r.hists {
		set[name] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// current returns the entries of m whose metric is live, with the held copy of the others added.
func (r *Registry) current(m, held map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(m))
	for k, v := range m {
		if r.live[nameOf(k)] {
			out[k] = v
		}
	}
	maps.Copy(out, held)
	return out
}

func (r *Registry) render() string {
	var b strings.Builder
	emit := func(m map[string]float64, typ string) {
		seen := map[string]bool{}
		for _, k := range slices.Sorted(maps.Keys(m)) {
			name := nameOf(k)
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
	// A held series shows its held value; one that appeared for the first time since the copy was taken is
	// left out until the next refresh.
	emit(r.current(r.counters, r.heldCounters), "counter")
	emit(r.current(r.gauges, r.heldGauges), "gauge")
	hists := maps.Clone(r.heldHists)
	if hists == nil {
		hists = map[string]*histogram{}
	}
	for name, h := range r.hists {
		if r.live[name] {
			hists[name] = h
		}
	}
	for _, name := range slices.Sorted(maps.Keys(hists)) {
		h := hists[name]
		if t := r.help[name]; t != "" {
			fmt.Fprintf(&b, "# HELP %s %s\n", name, t)
		}
		fmt.Fprintf(&b, "# TYPE %s histogram\n", name)
		for i, bound := range h.bounds {
			fmt.Fprintf(&b, "%s_bucket{le=\"%g\"} %g\n", name, bound, h.counts[i])
		}
		fmt.Fprintf(&b, "%s_bucket{le=\"+Inf\"} %g\n%s_sum %g\n%s_count %g\n", name, h.count, name, h.sum, name, h.count)
	}
	return b.String()
}

// held returns a copy of the entries of m whose metric is not live.
func (r *Registry) held(m map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for k, v := range m {
		if !r.live[nameOf(k)] {
			out[k] = v
		}
	}
	return out
}

// Write renders the registry: the live metrics as they are now, every other metric from the held copy. The
// copy is taken again when it is older than interval, and a zero interval takes it at every call.
func (r *Registry) Write(w io.Writer, now time.Time, interval time.Duration) error {
	r.mu.Lock()
	if r.heldDueLocked(now, interval) {
		r.heldCounters, r.heldGauges = r.held(r.counters), r.held(r.gauges)
		r.heldHists = map[string]*histogram{}
		for name, h := range r.hists {
			if !r.live[name] {
				r.heldHists[name] = &histogram{bounds: h.bounds, counts: slices.Clone(h.counts), sum: h.sum, count: h.count}
			}
		}
		r.heldAt = now
	}
	s := r.render()
	r.mu.Unlock()
	_, err := io.WriteString(w, s)
	return err
}
