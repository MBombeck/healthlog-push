# Performance

How fast the relay is, where the time of a push goes, and how to measure it yourself. Every figure here
names its source; the benchmarks and the load test are in the repository and run with one command each.

## In short

| Figure | Value | Source |
|---|---|---|
| Relay work for one push, end to end on loopback | p50 0.3 ms, p99 0.8 ms (one CPU) | `BenchmarkPushEndToEnd`, below |
| Apple's answer to the relay, hosted relay | p50 about 0.13 s, p90 about 0.23 s, p99 about 0.8 s | `hlp_delivery_latency_seconds`, one week, below |
| Capacity, one relay | about 1,900 push items per second with Apple at 130 ms | load test, below |
| Hosted relay limit | 6,000 push items per minute (100 per second) | `GlobalMax` in `internal/relay/config.go` |
| Apple to the iPhone | not under the relay's control, and Apple gives no delivery-time guarantee | |

The relay is nowhere the slow part. A push spends almost all of its time on the way to Apple and in
Apple's own delivery to the device.

## Where the time goes

A push is synchronous: the HealthLog server's request returns when Apple has answered every item
([api.md](api.md)). On the way:

| Leg | Warm connection | New connection | Notes |
|---|---|---|---|
| HealthLog server to relay | 1 round trip | DNS, then TCP, TLS 1.3 and the request: 3 round trips | the relay keeps idle connections for 60 s |
| Inside the relay | about 0.3 ms | the same | signature check, limits, queue, payload, signed answer |
| Relay to Apple | 1 round trip | 2 or 3 more, and the first request waits for Apple's stream limit | `hlp_apns_connections_total` shows how often a new one is needed |
| Apple to the device | Apple's own | | |

Apple's provider API (`api.push.apple.com`) answered a TCP connection from a German consumer line in
110 to 150 ms, and the route entered Apple's network on the first hop that showed that delay. As far as
can be seen from outside, Apple serves the provider API from North America only. Every push therefore
crosses to North America once, wherever the relay stands. The relay in Germany adds one leg from the
HealthLog server to Germany:

| HealthLog server in | Round trip to Frankfurt | Server to Apple's answer, warm |
|---|---|---|
| Germany | 4 to 17 ms | about 0.15 s |
| New York | 86 ms | about 0.22 s |
| Los Angeles | 142 ms | about 0.27 s |
| Tokyo | 221 ms | about 0.35 s |
| Sydney | 247 ms | about 0.38 s |

Round trips from [WonderNetwork's ping table](https://wondernetwork.com/pings/Frankfurt) to Frankfurt,
about 5 ms from the relay's data centre in Falkenstein. The last column adds one round trip to the relay, the relay's own
work and Apple's answer as measured on the hosted relay. A relay in North America would save a server
outside Europe up to one of those round trips and a server in Europe nothing, against a second host, a
shared store and the statement that the hosted relay runs in Germany ([privacy.md](privacy.md)).

## Benchmarks

```sh
go test -run '^$' -bench . -benchmem ./internal/wire ./internal/queue ./internal/apns ./internal/relay
go test -run '^$' -bench PushEndToEnd -cpu 1 ./internal/relay     # one CPU, as the hosted container
```

Measured on 2026-11-24 on an Apple M4 Pro with Go 1.27.4, median of three runs, all cores unless noted:

| Benchmark | What it covers | Time per operation |
|---|---|---|
| `BenchmarkCheckEnvelopeFrame` | the relay's only look at a sealed envelope: version, suite, class byte, length | 19 ns |
| `BenchmarkParseAndValidatePushBody/items=1` | strict JSON parse of a push request and validation of each item | 8.2 us |
| `BenchmarkParseAndValidatePushBody/items=50` | the same for a full batch (81 KB) | 325 us |
| `BenchmarkVerifyRequest/items=1` | Ed25519 check of a signed instance request, body hash included | 28 us |
| `BenchmarkVerifyRequest/items=50` | the same over a full batch | 56 us |
| `BenchmarkParseBind` | parse a binding and verify the device's `hl-bind-v1` statement | 33 us |
| `BenchmarkPushAndRun` | one job through the fair queue to a worker | 2.1 us |
| `BenchmarkSend/serial` | one request to a fake Apple over TLS and HTTP/2 on loopback | 71 us |
| `BenchmarkSend/parallel` | the same, many at once over the shared connection | 22 us |

`BenchmarkPushEndToEnd` sends one `POST /v1/push` through the real handler over TLS and HTTP/2, with the
instance signature, the limits, the queue, the send to a fake Apple that checks the ES256 provider token,
and the signed answer, which the simulated server verifies. Everything runs in one process, so the request
time is an upper bound of the relay's share:

| Items per request | p50, all cores | p99, all cores | p50, one CPU | p99, one CPU |
|---|---|---|---|---|
| 1 | 0.32 ms | 0.63 ms | 0.29 ms | 0.79 ms |
| 10 | 0.70 ms | 1.7 ms | 1.1 ms | 3.0 ms |
| 50 | 2.4 ms | 5.3 ms | 4.8 ms | 11 ms |

CI runs every benchmark a hundred times as a smoke test, because shared runners are too noisy for
figures; the figures on this page come from a quiet machine.

## Load test

The load test runs many simulated HealthLog servers against the real handler, queue and APNs client, with
a fake Apple that answers after a fixed delay. It is part of the test binary, behind the build tag
`load`, because Apple's addresses are constants in the relay and a release binary cannot be pointed at a
fake.

```sh
go test -tags load -run TestLoad -count=1 -cpu 1 -v ./internal/relay \
  -load.instances=100 -load.devices=10 -load.items=10 -load.rate=1 -load.duration=30s -load.apnsDelay=130ms
```

It prints the requests and items by outcome, the accepted items per second, the request times, the CPU
time of the process and the peaks of live heap, memory, queue depth and goroutines. It fails on a
transport error, a 5xx, or an item that ends as anything but `accepted` or `queue_full`. Every limit is
lifted for the run, so it measures the work and not the limits. Two runs on one CPU of the machine above,
with Apple answering after 130 ms:

| | 100 servers, 1,000 items/s offered | 250 servers, 2,500 items/s offered |
|---|---|---|
| Accepted | 996 items/s, all of them | 1,919 items/s, all of them |
| Request time p50 / p99 | 132 ms / 142 ms | 1.30 s / 1.33 s |
| CPU, whole process | 16 % of one core | 36 % of one core |
| Peak queue depth | 11 | 1,445 |
| Peak live heap / memory from the OS | 19.5 MiB / 55 MiB | 61 MiB / 145 MiB |

The CPU and memory figures include the simulated servers, which sign every request and verify every
answer, and the fake Apple, which checks an ES256 token on every request. The ceiling is the 256 send
workers divided by Apple's answer time: 256 / 0.133 s is about 1,920 items per second, and that is what
the second run reaches. Beyond it the queue holds up to two seconds of work, the request time grows, and
work that would wait longer is refused with `queue_full` instead of piling up. The hosted relay's global
limit of 100 items per second is a twentieth of that ceiling.

## The hosted relay

`hlp_delivery_latency_seconds` is the time from the relay accepting an item to Apple's answer, in coarse
buckets ([transparency.md](transparency.md)). Over the week to 2026-11-24, a small sample of under a hundred
deliveries: none below 0.1 s, most between 0.1 and 0.15 s, so a median of about 0.13 s, a 90th percentile
of about 0.23 s and a 99th of about 0.8 s. Apple refused none. The floor of about 0.13 s is one round trip
to North America. The tail from 0.25 s on matches a new connection to Apple, which costs two or three more
round trips; `hlp_apns_connections_total` now counts how often that happens.

A relay can publish such figures as day aggregates once three or more servers use it
([api.md](api.md#get-stats)).

## What the numbers do not say

- They say nothing about how long Apple takes to reach a device; that is Apple's, and it varies with the
  device's network and power state.
- The benchmarks run on loopback on a fast desktop CPU. The hosted relay runs on one shared virtual CPU,
  which is slower per core; the one-CPU columns are the closer guide.
- The load test keeps its test clock still, so no nonce leaves the replay window during a run, and it
  refuses a rate and a duration that would need more than the 2,000 nonces the relay keeps per server.
