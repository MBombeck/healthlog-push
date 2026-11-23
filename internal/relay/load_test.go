//go:build load

package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"io"
	"math/rand/v2"
	"net/http"
	"runtime"
	"runtime/metrics"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// The load test runs the real handler, queue and APNs client against a fake Apple that answers after a
// fixed delay, with many simulated HealthLog servers sending batches at a steady rate. It lives in the test
// binary on purpose: Apple's addresses are constants in internal/apns, so a release binary cannot be
// pointed at a fake, and that stays so. docs/performance.md has the method and a run.
//
//	go test -tags load -run TestLoad -count=1 -cpu 1 ./internal/relay -load.instances=200 -load.duration=60s
var (
	loadInstances = flag.Int("load.instances", 100, "simulated HealthLog servers")
	loadDevices   = flag.Int("load.devices", 10, "devices bound per server")
	loadItems     = flag.Int("load.items", 10, "push items per request (at most 50)")
	loadRate      = flag.Float64("load.rate", 1, "push requests per second per server")
	loadDuration  = flag.Duration("load.duration", 30*time.Second, "how long to send")
	loadAPNsDelay = flag.Duration("load.apnsDelay", 130*time.Millisecond, "how long the fake Apple takes to answer")
)

type loadStats struct {
	mu        sync.Mutex
	lat       []time.Duration
	results   map[string]int
	statuses  map[int]int
	transport int
}

func (s *loadStats) add(d time.Duration, status int, results []ItemResult, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.transport++
		return
	}
	s.lat = append(s.lat, d)
	s.statuses[status]++
	for _, r := range results {
		s.results[r.Result]++
	}
}

// loadPush sends one signed push request and returns the status and the per-item results. It never calls
// t.Fatal, because it runs on many goroutines.
func (i *instance) loadPush(items []wire.PushItem) (int, []ItemResult, error) {
	body, _ := json.Marshal(wire.PushBody{Items: items})
	ts, nonce := i.h.clk.Now().Unix(), randNonce()
	req, _ := http.NewRequest(http.MethodPost, i.h.srv.URL+"/v1/push", bytes.NewReader(body))
	req.Header.Set("HL-Instance", i.id)
	req.Header.Set("HL-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("HL-Nonce", nonce)
	req.Header.Set("HL-Signature", wire.EncodeB64(ed25519.Sign(i.key, []byte(wire.RequestText(host, i.id, http.MethodPost, "/v1/push", ts, nonce, body)))))
	resp, err := i.h.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	var pr pushResp
	_ = json.Unmarshal(raw, &pr)
	return resp.StatusCode, pr.Results, nil
}

func cpuSeconds() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()).Seconds()
}

func TestLoad(t *testing.T) {
	if *loadItems < 1 || *loadItems > wire.MaxPushItems || *loadDevices < 1 || *loadInstances < 1 || *loadRate <= 0 {
		t.Fatal("load.items must be 1 to 50; load.devices, load.instances and load.rate must be positive")
	}
	// The test clock stands still, so no nonce expires during the run, and the relay keeps at most
	// noncePerInst per server (the 10-minute replay window of the protocol).
	if *loadRate*loadDuration.Seconds() >= noncePerInst {
		t.Fatalf("load.rate x load.duration must stay below %d requests per server", noncePerInst)
	}
	h := newHarness(t, func(c *Config) { c.Workers = 256; c.Limits = benchLimits() })
	// Setup, not measured: register the servers and bind and activate their devices.
	insts := make([]*instance, *loadInstances)
	devs := make([][]*device, *loadInstances)
	var tokenN atomic.Uint32
	for k := range insts {
		insts[k] = h.register()
		for range *loadDevices {
			n := tokenN.Add(1)
			d := newDevice(0)
			for b := range 4 {
				d.token[b] = byte(n >> (8 * b))
			}
			insts[k].activate(d)
			devs[k] = append(devs[k], d)
		}
	}

	// Only now does the fake Apple take its time, so the setup stays quick.
	delay := *loadAPNsDelay
	h.apns.mu.Lock()
	h.apns.reqs, h.apns.noRecord = nil, true
	h.apns.mu.Unlock()
	runtime.GC()
	h.apns.setAnswer(func(string, apnsReq) (int, string) { time.Sleep(delay); return 200, "" })

	stats := &loadStats{results: map[string]int{}, statuses: map[int]int{}}
	var peakLive, peakSys uint64
	sample := []metrics.Sample{{Name: "/gc/heap/live:bytes"}, {Name: "/memory/classes/total:bytes"}}
	var peakQueue, peakGoroutines int
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() { // peaks, sampled every 100 ms
		defer close(sampled)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				metrics.Read(sample)
				peakLive, peakSys = max(peakLive, sample[0].Value.Uint64()), max(peakSys, sample[1].Value.Uint64())
				peakQueue, peakGoroutines = max(peakQueue, h.r.q.Len()), max(peakGoroutines, runtime.NumGoroutine())
			}
		}
	}()

	cpu0, start := cpuSeconds(), time.Now()
	deadline := start.Add(*loadDuration)
	interval := time.Duration(float64(time.Second) / *loadRate)
	var wg sync.WaitGroup
	for k, inst := range insts {
		wg.Go(func() {
			// A random start spreads the servers over the interval, as independent servers would be.
			next := start.Add(time.Duration(rand.Int64N(int64(interval)))) //nolint:gosec // load shape, not security
			seq := 0
			for next.Before(deadline) {
				time.Sleep(time.Until(next))
				items := make([]wire.PushItem, *loadItems)
				for j := range items {
					items[j] = alertItem("l"+strconv.Itoa(k)+"-"+strconv.Itoa(seq), devs[k][seq%len(devs[k])])
					seq++
				}
				t0 := time.Now()
				status, res, err := inst.loadPush(items)
				stats.add(time.Since(t0), status, res, err)
				next = next.Add(interval)
			}
		})
	}
	wg.Wait()
	elapsed, cpu := time.Since(start), cpuSeconds()-cpu0
	close(stop)
	<-sampled

	slices.Sort(stats.lat)
	accepted := stats.results["accepted"]
	items := 0
	for _, n := range stats.results {
		items += n
	}
	t.Logf("load: %d servers x %d devices, %d items per request, %.2f requests/s per server, %s, Apple answers after %s, GOMAXPROCS %d",
		*loadInstances, *loadDevices, *loadItems, *loadRate, *loadDuration, delay, runtime.GOMAXPROCS(0))
	t.Logf("requests %d (%d transport errors), statuses %v", len(stats.lat)+stats.transport, stats.transport, stats.statuses)
	t.Logf("items %d, by result %v", items, stats.results)
	t.Logf("accepted %.0f items/s", float64(accepted)/elapsed.Seconds())
	t.Logf("request time p50 %s p90 %s p99 %s max %s (each includes the fake Apple's %s)",
		percentile(stats.lat, 0.5).Round(time.Millisecond), percentile(stats.lat, 0.9).Round(time.Millisecond),
		percentile(stats.lat, 0.99).Round(time.Millisecond), percentile(stats.lat, 1).Round(time.Millisecond), delay)
	if accepted > 0 {
		t.Logf("CPU %.1f s for the whole process, %.0f us per accepted item (relay, simulated servers and fake Apple together)",
			cpu, cpu/float64(accepted)*1e6)
	}
	t.Logf("peaks: live heap %.1f MiB, memory from the OS %.1f MiB, queue depth %d, goroutines %d (whole process)",
		float64(peakLive)/(1<<20), float64(peakSys)/(1<<20), peakQueue, peakGoroutines)

	// What would be a defect, not a capacity limit: a transport error, a 5xx, or an item that was neither
	// accepted nor refused for capacity.
	if stats.transport > 0 {
		t.Errorf("%d requests failed in transport", stats.transport)
	}
	for status, n := range stats.statuses {
		if status >= 500 {
			t.Errorf("%d requests answered %d", n, status)
		}
	}
	for result, n := range stats.results {
		if result != "accepted" && result != "queue_full" {
			t.Errorf("%d items ended as %s", n, result)
		}
	}
	if accepted == 0 {
		t.Error("nothing was accepted")
	}
}
