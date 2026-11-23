package relay

import (
	"slices"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// Operational metrics about the relay's own work. Every label below comes from a closed set fixed in this
// file; nothing names an instance, a device, a token or a person. docs/transparency.md lists every metric.

// Push kinds as the relay sees them: silent_sync is a background push an instance sends, silent_wake the
// relay's own background push that wakes a device to answer a binding challenge.
const (
	kindAlert      = "alert"
	kindSilentSync = "silent_sync"
	kindSilentWake = "silent_wake"
	kindLAStart    = "la_start"
	kindLAUpdate   = "la_update"
	kindLAEnd      = "la_end"
)

var pushKinds = []string{kindAlert, kindSilentSync, kindSilentWake, kindLAStart, kindLAUpdate, kindLAEnd}

// Surfaces of a rate limit hit.
const (
	surfaceInstanceRequests = "instance_requests"
	surfaceRegistration     = "registration"
	surfaceAppGlobal        = "app_global"
	surfaceAppDevice        = "app_device"
	surfacePush             = "push"
)

var rateSurfaces = []string{surfaceInstanceRequests, surfaceRegistration, surfaceAppGlobal, surfaceAppDevice, surfacePush}

// Reasons a new registration is refused.
var registrationRejections = []string{"no_invite", "bad_signature", "rate_limited"}

// latencyBounds are the coarse upper bounds, in seconds, of the delivery latency histogram. Apple usually
// answers in 100 to 250 ms, so three bounds lie in and just below that range and tell a quick answer from an
// ordinary and a slowish one; the highest lies beyond the longest an item can take (two seconds of queueing
// and Apple's three-second deadline), so a 95th percentile above five seconds is still a number.
var latencyBounds = []float64{0.05, 0.1, 0.15, 0.25, 0.5, 1, 2.5, 5, 10}

// liveMetrics are the only metrics current at every scrape: HTTP responses by status class, requests to
// Apple without any split by kind, Apple's refusals by reason, the delivery latency, and the three gauges
// that say whether the relay itself is healthy. With very few instances these still trace their traffic in
// time, in aggregate and without its kind. Every other metric, every split by push class or kind among them,
// is served from the copy the scrape takes every heldRefresh, and a metric added later is held unless it is
// named here. docs/transparency.md states the cadence of each metric, and a test holds the two together.
var liveMetrics = []string{
	"hlp_requests_total",
	"hlp_apns_requests_total",
	"hlp_apns_rejections_total",
	"hlp_delivery_latency_seconds",
	"hlp_breaker_open",
	"hlp_apns_misconfigured",
	"hlp_db_writable",
}

// LiveMetrics returns the names of the live metrics, for the test that holds docs/transparency.md to the
// code.
func LiveMetrics() []string { return slices.Clone(liveMetrics) }

// identitySlots are the labels of hlp_deliveries_by_key_slot_total; keys.Slots in the main package.
var identitySlots = []string{"current", "next", "emergency", "unpinned"}

func kindOf(it *wire.Item) string {
	switch it.Class {
	case wire.ClassAlert:
		return kindAlert
	case wire.ClassSilent:
		return kindSilentSync
	}
	switch it.Event {
	case wire.EventStart:
		return kindLAStart
	case wire.EventUpdate:
		return kindLAUpdate
	}
	return kindLAEnd
}

func (r *Relay) identitySlot() string {
	for _, s := range identitySlots {
		if s == r.cfg.IdentitySlot {
			return s
		}
	}
	return "unpinned"
}

// observeSend records one request to Apple: in total and by kind, and, when Apple answered, the time from
// the relay's acceptance of the item to Apple's answer and the reason of a refusal.
func (r *Relay) observeSend(kind string, accepted time.Time, res apns.Result) {
	r.Metrics.Inc("hlp_apns_requests_total")
	r.Metrics.Inc("hlp_apns_sends_total", "kind", kind)
	if res.Outcome == apns.NoProviderToken || (res.Outcome == apns.Unavailable && res.Reason == "transport") {
		return
	}
	now := r.cfg.Now()
	r.Metrics.Observe("hlp_delivery_latency_seconds", now.Sub(accepted).Seconds())
	r.latDays.observe(store.Day(now), now.Sub(accepted).Seconds())
	if res.Outcome == apns.Accepted {
		r.Metrics.Inc("hlp_deliveries_by_key_slot_total", "slot", r.identitySlot())
		return
	}
	r.Metrics.Inc("hlp_apns_rejections_total", "reason", apns.ReasonLabel(res.Reason))
}

// Connection kinds of hlp_apns_connections_total.
const (
	connNew    = "new"
	connReused = "reused"
)

// observeConn counts one request to Apple by whether it opened a new connection or reused one. The share
// of reused ones says whether the client keeps its connections warm; every new one costs extra round trips
// to Apple before the push goes out.
func (r *Relay) observeConn(reused bool) {
	c := connNew
	if reused {
		c = connReused
	}
	r.Metrics.Inc("hlp_apns_connections_total", "connection", c)
}

// observePriority counts a Live Activity push by the Apple priority it goes with.
func (r *Relay) observePriority(urgent bool) {
	p := "5"
	if urgent {
		p = "10"
	}
	r.Metrics.Inc("hlp_liveactivity_priority_total", "priority", p)
}

func (r *Relay) rateLimited(surface string) {
	r.Metrics.Inc("hlp_rate_limited_total", "surface", surface)
}

func (r *Relay) describeOperational() {
	m := r.Metrics
	m.Help("hlp_apns_requests_total", "Requests to Apple, every kind together.")
	m.Help("hlp_apns_sends_total", "Requests to Apple by push kind.")
	m.Help("hlp_apns_connections_total", "Requests to Apple by connection: new (opened for it) or reused.")
	m.Help("hlp_delivery_latency_seconds", "Time from the relay accepting an item to Apple's answer.")
	m.Help("hlp_apns_rejections_total", "Apple refusals by Apple's reason code; unknown reasons are other.")
	m.Help("hlp_push_retries_total", "Items an instance sent again under a ref the relay still remembers.")
	m.Help("hlp_queue_depth", "Jobs waiting in the send queue.")
	m.Help("hlp_liveactivity_priority_total", "Live Activity pushes by Apple priority.")
	m.Help("hlp_silent_budget_refused_total", "Background pushes refused by a silent budget, sync or wake.")
	m.Help("hlp_deliveries_by_key_slot_total", "Accepted deliveries by the pinned slot of the relay identity key.")
	m.Help("hlp_registrations_rejected_total", "Refused new registrations by reason.")
	m.Help("hlp_rate_limited_total", "Requests refused by a rate limit, by surface.")
	m.Histogram("hlp_delivery_latency_seconds", latencyBounds...)
	// Every series of the closed sets exists from the start, so a series does not appear only once
	// something happens.
	m.Add("hlp_apns_requests_total", 0)
	for _, k := range pushKinds {
		m.Add("hlp_apns_sends_total", 0, "kind", k)
	}
	for _, c := range []string{connNew, connReused} {
		m.Add("hlp_apns_connections_total", 0, "connection", c)
	}
	for _, reason := range apns.ReasonLabels() {
		m.Add("hlp_apns_rejections_total", 0, "reason", reason)
	}
	for _, a := range []string{"replayed", "joined"} {
		m.Add("hlp_push_retries_total", 0, "answer", a)
	}
	for _, p := range []string{"5", "10"} {
		m.Add("hlp_liveactivity_priority_total", 0, "priority", p)
	}
	for _, k := range []string{"sync", "wake"} {
		m.Add("hlp_silent_budget_refused_total", 0, "kind", k)
	}
	for _, s := range identitySlots {
		m.Add("hlp_deliveries_by_key_slot_total", 0, "slot", s)
	}
	for _, reason := range registrationRejections {
		m.Add("hlp_registrations_rejected_total", 0, "reason", reason)
	}
	for _, s := range rateSurfaces {
		m.Add("hlp_rate_limited_total", 0, "surface", s)
	}
	m.Set("hlp_queue_depth", 0)
}
