# Consecutive reactor turns — diagnostic evidence

Runtime: `080f36fa20f393774fe8ff8b6bdf22545a9ce3e1`, tree
`b5dd17e0cefef31dfe8af961e5a22b851be53cb7`. Harness and parser:
`d1e27dffc632949ad54ba31426e94e5d778bf981`, tree
`652565f0d714f9aad8307e23b740679008db13a2`.
This is the disposable native QUIC-DATAGRAM floor, **not production everudp**.

## Method

Four 200-trial blocks per symmetric-loss cell (0% and 5%), tracing
off/on/on/off, native-first/reverse/native-first/reverse. Preregistered seeds
1000701–1000704 and 1005701–1005704; 100 ms intertrial gap. All eight blocks
completed without interruption or replacement: 3,200 exact responses, 800
valid traced trials, no exclusions. Warmup is validated but not aggregated.

The build used an isolated clean detached worktree. Both modes use the same
runtime binary, hash `4979b712ce8ff17b313f6da14071a4ffd4b6967721b5ff7831e9ab278bb5503f`.
The composed bundle reuses the prior sealed zmosh UDP control and shared compiled
PTY fixtures. Original runtime/control provenance documents and their hashes
are retained; no binaries, terminal payloads, or credentials are archived.
Per-block source identity names the harness, not the separately sealed runtime.

## Results

| Loss | Native off/on p50 (µs) | On/off ratio, central 95% | Control off/on p50 (µs) |
|---|---|---|---|
| 0% | 387 / 384 | 0.9922 [0.9214, 1.0571] | 429.5 / 406 |
| 5% | 389 / 416 | 1.0694 [1.0049, 1.1599] | 456 / 450 |

The 20,000 deterministic within-block stratified bootstrap resamples do not
measure independent experiment replication uncertainty. Tracing overhead and
host/block variation are material; the 0% ratio is not negative-overhead proof.

The initial post-offer step has pooled wall medians 87.8655 µs (0%) and
89.8455 µs (5%). The immediately following loop-top step has medians 2.965 µs
and 3.1095 µs. All 800 following turns call the pump and attempt a receive that
would block; none records send attempts, received descriptors/segments, due
timers, endpoint/application events, or drained application events. This is
observed absence of useful work, not proof the receive/timer opportunity is
unnecessary or safe to skip. It does not support an assumed 20 µs saving.

Intervals include caller event draining. Wall and thread-CPU stamps are
sequential, not simultaneous: their difference is not exact scheduler time.
Back-to-back CPU-clock calibration medians are 683.5 ns and 771 ns, without
subtraction. `transmits_generated` excludes stateless receive responses; receive
and segment counters must also be inspected. Pre-input/admission turns are not
recorded. Initial post-offer intervals include actual UDP submission, so their
larger duration alone does not identify a removable CPU cost.

The next investigation should attribute that post-offer interval before any
architecture change. No runtime optimization is authorized by this receipt.
Frozen floor and production gates are unchanged. These diagnostic results
neither qualify production nor permit integration of the disposable floor.

Independent read-only Luna review verified all 278 archive entries, all eight
block seals, runtime/control identities, and all four strict traces. It
independently confirmed 800 included pairs, no exclusions, the following-turn
durations, and zero recorded useful-work counters in those following turns.
The deterministic bootstrap analysis was reproduced byte-for-byte by the parent.

## Reproduce

Run `sha256sum -c SHA256SUMS --quiet`, then
`PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py > /tmp/reactor-reproduced.json`
and `cmp analysis.json /tmp/reactor-reproduced.json`.
The analyzer checks original block seals, exact identities, shared artifact
hashes, flags/order/seeds, public sample windows, exact-response results, qdisc
accounting, and strict reactor traces. Raw qdisc whitespace is preserved.
