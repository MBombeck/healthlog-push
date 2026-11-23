package relay

import (
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// benchLimits lifts every rate and quota limit, so that a benchmark or the load test measures the work and
// not the limits. The values stay far from any overflow, also when a limit is halved after a start.
func benchLimits() Limits {
	const big = int64(1) << 30
	tl := TierLimits{Devices: 1 << 20, Provisional: 1 << 20, NewBindingsDay: big, RequestsMinute: big, PushesDay: big,
		PushesMinute: big, InvalidTokensDay: big, ChallengesDay: big, BadSignatureBurst: big}
	return Limits{Probation: tl, Standard: tl,
		Device: DeviceLimits{AllDay: big, AlertBurst: float64(big), AlertPerHour: float64(big), AlertDay: 1 << 30, SilentHour: big,
			LiveActivityDay: big, LiveActivityStartDay: big, ActivityUpdateHour: big, ActivityUpdateDay: big},
		ProbationPoolMin: big, GlobalMin: big, GlobalMax: big, StandardDevicesUp: 1 << 20, StandardDevicesMax: 1 << 20}
}

// percentile returns the p-quantile (0 to 1) of sorted durations.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[min(len(sorted)-1, int(p*float64(len(sorted))))]
}

// BenchmarkPushEndToEnd is one POST /v1/push with 1, 10 or 50 alert items through the real handler: TLS
// and HTTP/2 on loopback, the instance signature check, the limits, the queue, the send to a fake Apple
// over TLS and HTTP/2 that checks the ES256 provider token, and the signed answer, which the simulated
// server verifies. Everything runs in one process, so the figures are an upper bound of the relay's own
// share of a push. p50-us and p99-us are the request times; ns/op also counts building the items.
func BenchmarkPushEndToEnd(b *testing.B) {
	for _, n := range []int{1, 10, wire.MaxPushItems} {
		b.Run("items="+strconv.Itoa(n), func(b *testing.B) {
			h := newHarness(b, func(c *Config) { c.Workers = 256; c.Limits = benchLimits() })
			i := h.register()
			devs := make([]*device, n)
			for k := range devs {
				devs[k] = newDevice(byte(k + 1))
				i.activate(devs[k])
			}
			var lat []time.Duration
			seq := 0
			for b.Loop() {
				items := make([]wire.PushItem, n)
				for k := range items {
					items[k] = alertItem("b"+strconv.Itoa(seq), devs[k])
					seq++
				}
				// One second per request on the test clock, so nonces leave the replay window as they would.
				h.clk.Add(time.Second)
				start := time.Now()
				rp, res := i.push(items...)
				lat = append(lat, time.Since(start))
				if rp.Status != http.StatusOK || len(res) != n {
					b.Fatalf("push: %d %s", rp.Status, rp.Raw)
				}
				for _, r := range res {
					if r.Result != "accepted" {
						b.Fatalf("item: %+v", r)
					}
				}
			}
			slices.Sort(lat)
			b.ReportMetric(float64(percentile(lat, 0.5).Microseconds()), "p50-us")
			b.ReportMetric(float64(percentile(lat, 0.99).Microseconds()), "p99-us")
		})
	}
}
