# Reactor phase attribution — diagnostic only

Runtime, harness and analyzer: `c7207aaff2b1df24de2977348382d0bbdbffa4d4`,
tree `43d7d4379008bc2775126c6a900f99192946c577`.
This measures the disposable native QUIC-DATAGRAM floor, not production's
reliable-stream transport. No qualification or production integration is claimed.

## Experiment and identity

Each 0%/5% symmetric-loss cell contains four 200-trial blocks with partition
tracing off/on/on/off. Candidate order is native-first/reverse/native-first/reverse,
seeds 1010701–1010704 and 1015701–1015704, with 100 ms gaps. All eight blocks
completed without replacement: 3,200 exact responses and 800 included traced
trials, no exclusions. Warmup is validated but excluded from aggregation.

The clean isolated build and composed bundle share one native binary in both modes:
`4a26e1ce6c96434e3dc5ba9fd7dc1b3414e4c8ef45ed32925684324a64c101ef`.
The frozen zmosh UDP executable and compiled PTY fixtures are reused from the
previous sealed control bundle, not rebuilt independently for each candidate.
Original runtime/control provenance and hashes are retained. Raw block seals
are unchanged. No binaries, credentials or terminal payloads are archived.

## Matched tracing overhead

| Loss | Native off/on p50 (µs) | On/off ratio, central 95% | Control off/on p50 (µs) |
|---|---|---|---|
| 0% | 410.5 / 427 | 1.0402 [0.9679, 1.1010] | 424.5 / 402 |
| 5% | 414.5 / 445.5 | 1.0748 [1.0023, 1.1590] | 445.5 / 463.5 |

These are 20,000 deterministic within-block stratified bootstrap resamples,
not independent experimental replications. Observer overhead and host/block
variation remain material. Instrumented timings do not qualify performance.

## Same-step attribution

The table reports pooled wall-clock medians in microseconds for the initial
post-offer step. **Individual medians must not be added or subtracted.**

| Loss | Outer step | Protocol pump | UDP submission | Segment check | Receive | Event drain | Unattributed |
|---|---|---|---|---|---|---|---|
| 0% | 97.382 | 39.2135 | 35.957 | 0.976 | 4.511 | 1.0335 | 9.4355 |
| 5% | 100.402 | 44.070 | 35.719 | 0.9915 | 4.627 | 1.093 | 9.3335 |

The parser checks every step's phase counts against operation counters and
branch invariants, and checks summed intervals against that same enclosing
step. Unattributed intervals include inter-phase sampling and other work; they
are not established removable overhead. Protocol and socket costs are both
material. These observations do not locate the costly operation inside the
protocol pump or establish a faster alternative.

The following loop-top step now measures 9.714/9.152 µs under the additional
phase instrumentation. Do not interpret its difference from the previous
approximately 3 µs recorder as a runtime regression or optimization opportunity.
Sequential wall/thread-CPU samples are not simultaneous scheduler measurements.
Phase totals include their clock-sampling effects, and no calibration is subtracted.

Production shares noq-proto packet generation but uses reliable stream queues,
application replay and asynchronous driver wakeups. Floor scheduling or datagram
results cannot substitute for production performance and reliability gates.
Any shared-protocol optimization must preserve cryptographic/security behavior,
flow control, congestion handling and delivery correctness, and be qualified
on the real production path. Frozen thresholds remain unchanged.

## Independent review

Independent review verified the archive and eight block seals, source and artifact
identities, and all 800 included traces. Its first numerical aggregation incorrectly
pooled loss cells and included following-loop steps; that calculation was rejected.
The corrected aggregation selects only initial post-offer steps, groups by loss,
and contains exactly 400 pairs per cell. All seven wall-clock medians in each
row above match the independent recomputation. The analysis reproduction is
byte-identical. This review validates diagnostic evidence, not production acceptance.

## Reproduce

From this directory run `sha256sum -c SHA256SUMS --quiet`, then
`PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py > /tmp/partitions-reproduced.json`
and `cmp analysis.json /tmp/partitions-reproduced.json`.
The analyzer checks original block seals, runtime/control provenance links,
artifact hashes, source identities, seeds/order/flags, public timing samples,
exact-response results, qdisc accounting and strict version-2 traces.
Original qdisc whitespace is intentionally preserved.
