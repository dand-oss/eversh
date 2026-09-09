# everudp network and performance gates

`tune-profiles.sh` is the pre-qualification development sweep. It builds the
feature-gated `everudp-tune` example executable, exercises all 18 registered initial-RTT,
ACK, and GSO profiles at 0% and 5% deterministic bidirectional loss, and writes
validated raw samples, component timings, process-resource measurements, a
manifest, hashes, and `selection.json`.

Run an eligible sweep from a clean worktree:

```sh
crates/everudp/tests/net/tune-profiles.sh 200 OUTDIR
```

Runs below 200 trials are harness checks only. They require
`EVERUDP_ALLOW_SHORT=1`, are marked `selection_eligible: false`, and always
retain the preregistered default. Tuning seeds `910001` and `910003` are frozen
here and must not be reused by final qualification.

This rootless sweep compares everudp profiles against one another. It is not
the release parity gate against either pinned zmosh baseline; that gate uses
the compiled raw-PTY fixture and the final disjoint sample schedule.

The frozen production selection is 100 ms initial RTT, every-packet ACK with a
1 ms bound, and GSO on. Its eligible sweep receipt is
`docs/release-evidence/20260905-everudp-tuning-c032e9c`.

`test-reliability.sh OUTDIR` is the root-required full-product network gate.
It uses a real OpenSSH bootstrap inside isolated IPv4/IPv6 namespaces and then
checks that terminal traffic is UDP-only while exercising loss, jitter,
duplication, reordering, MTU reduction, interface migration, process
sleep/wake, five- and thirty-minute total loss, and output-queue overrun. Set
`EVERUDP_SMOKE=1 EVERUDP_ALLOW_DIRTY=1` only for the bounded development shape;
that receipt is marked `smoke: true` and cannot satisfy release qualification.

`build-performance.sh OUTDIR` creates the exact, immutable artifact set used by
the parity gate. It requires a clean candidate tree, Zig 0.15.2 in
`EVERUDP_ZIG_0152`, and Zig 0.16.0 in `EVERUDP_ZIG_0160`. It builds everudp,
the frozen zmosh UDP baseline at
`dfc8395b5edcd237bf82712fbde879c6e8be7dfa`, and the frozen zmosh QUIC baseline
at `21db4a4de6040b254531f2131b6f1c0cd146a7a1`. The latter commit exposes its
QUIC client API but does not wire it into the command-line client, so the gate
builds the hash-bound `zmosh-quic-bridge.zig` adapter beside an otherwise
unchanged pinned source tree. Build provenance, source identities, tool
identities, adapter inputs, artifacts, and logs are sealed by `SHA256SUMS`.

The production default is built with `cli`. A bounded feature experiment must
set `EVERUDP_CARGO_FEATURES=cli,datagram-spike`; the exact feature list and
build command are then sealed in `provenance.json`. No other feature spelling
is accepted by this qualification builder.

Run the final root-required head-to-head from that artifact set:

```sh
sudo --preserve-env=EVERUDP_ZIG_0152,EVERUDP_ZIG_0160 \
  crates/everudp/tests/net/qualify-performance.sh BUILD_DIR OUTDIR
```

The gate runs every ordering of everudp, zmosh UDP, and zmosh QUIC in six
blocks at both 0% and 5% symmetric loss. Each block contains 200 exact-response
trials per implementation, for 1,200 observations per implementation per
cell. The shared compiled raw-PTY fixture starts timing immediately before the
public terminal-input write and stops only after the exact response reaches
the local output sink; missing, wrong, duplicate, or extra output fails the
trial. Final analysis uses a block-stratified 20,000-resample bootstrap and
applies the frozen p50 and p95 gates independently against both baselines.

For a short harness-only run, pass a smaller third argument with
`EVERUDP_ALLOW_SHORT=1`. Such output is sealed as `SMOKE` and cannot satisfy
release qualification.

`fuzz/qualify-m6.sh` is the exact-candidate production aggregator. After the
pinned toolchain has been installed with `fuzz/qualify-m3.sh setup`, it runs
the inherited M5 gates, focused everudp hostile-admission, process, resource,
combined-binary, and installed-application gates, both 61-second everudp fuzz
campaigns, this full reliability matrix, and the final three-way performance
gate. Raw output remains under `target/qualification` while gates are active.
Its finalizer then writes an immutable receipt tree and `SHA256SUMS` under
`docs/release-evidence`, on PASS or FAIL, so a threshold miss cannot strand an
unsealed result.

## Post-V4 diagnostic capture (not qualification)

The floor example accepts `client --trace-json PATH ...`. It reserves new
0600 files `PATH` and `PATH.server.json`, enables a bounded remote recorder
over the admitted QUIC control stream before warmup, and requests its snapshot
on local cancellation. Export has a two-second diagnostic shutdown budget to
fit the PTY driver's three-second termination grace; it does not change any
production reconnect or outage limit. Missing export is invalid evidence.

For `bench-performance-block.sh`, set `EVERUDP_FLOOR_TRACE=1` to capture these
files inside the floor candidate directory. The manifest identifies tracing;
enable occurs before the packet-window start barrier and export occurs after
the finish barrier. No diagnostic control operations are sent when disabled.
Client capture and server snapshot use process-relative clocks: do not subtract
their timestamps from each other or from public benchmark timestamps without
an independently validated clock mapping. Public timing boundaries are also
preserved in `result.json`, alongside the unchanged latency samples.

Build with `floor-diagnostics` (or `EVERUDP_FLOOR_DIAGNOSTICS=1` for the exact
`build-floor.sh` builder) to add noQ driver and UDP-poll markers and Rust global
allocator counters. The provenance records this feature separately; the
ordinary build excludes those hooks and the counting allocator. Runtime trace
capture still requires `--trace-json`/`EVERUDP_FLOOR_TRACE=1`.

Transmit/receive markers are userspace poll boundaries, not wire timestamps.
Allocator counters are separate process-wide cumulative request counts/bytes,
including reallocations and failed requests, not live memory or native-library
allocations. Thread IDs are process-local. Recorder `valid` means no overflow,
contention or poisoned lock, not completeness or qualification success. Paired
overhead measurements and complete attribution are still required by
`eversh-5fc.20`; floor receipts remain `INVALID` until those requirements are
implemented and validated.

## Production path diagnostics (not qualification)

Build an isolated `cli,path-diagnostics` candidate, then set `EVERUDP_PATH_TRACE=1`
for `bench-performance-block.sh`. Do not combine this with floor or scheduling
experiments. The harness sets explicit private client/gateway trace paths and
requires gateway export on authenticated writer detach before process cleanup.
Forced termination, missing export, overflow, observer admission, or writer
replacement cannot yield valid single-writer attribution. Default builds omit
the recorders; a diagnostic-feature build with tracing disabled is a separate
overhead control, not proof of zero instrumentation overhead.

`analyze_path_trace.py CLIENT_JSON GATEWAY_JSON RESULT_JSON` validates the exact
typed schemas, clock identities and public samples, then matches every measured
trial. Input and output have independent epoch/sequence spaces. Warmup anchors
are counted separately; missing or ambiguous measured anchors fail the run.
Input stream retries are reported, not mistaken for duplicate PTY delivery.

These are userspace boundaries: input queued, accepted by the QUIC stream,
prepared/committed at the gateway sink, output buffered, staged locally and
committed after stdout acceptance. They are not packet timestamps or application
render timestamps. `stream_handoff_ns` is gateway-prepared minus first
client-stream-written; `output_handoff_ns` is client-output-accepted minus public
sink-accepted. Either may be negative because post-write recording and the peer
run on different CPUs. Preserve signed overlap; do not clamp intervals or sum
stage medians into end-to-end latency. Cross-host/time-namespace subtraction is
rejected. Paired tracing-on/off measurements are required before attribution.
The production performance qualifier rejects diagnostic blocks.
