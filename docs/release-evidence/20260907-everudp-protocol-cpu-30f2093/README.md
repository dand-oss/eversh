# Protocol and sender CPU attribution

**DIAGNOSTIC, not qualification or architecture approval.**
Candidate: `30f2093daccceb05d324f63ad445b57ef3fc4081`, clean throughout collection.
Bead: `eversh-5fc.22`.

All twelve preregistered blocks completed: 4,800 measured responses, zero
transcript failures. Each candidate has 200 trials per block, with 100 ms gaps.
Seeds are 90401–90406 at 0% loss and 90501–90506 at 5% loss. Block one uses
plain/instrumented/traced order, floor then zmosh; block two reverses both orders.
All modes use byte-identical zmosh and PTY controls. The separately derived plain
artifact set records its original plain and diagnostic parent provenance hashes.
The sender-readiness experiment remains disabled in both builds.

## Findings and limits

Pooled whole-trace protocol-ready CPU medians are 15.7445 us client and
12.987 us server; accepted sender CPU medians are 27.5365 and 27.3385 us.
These synchronous call populations include warmup, control traffic and recorder
overhead. They are not per-keystroke costs. Do not sum independent medians,
subtract CPU from wall time to infer descheduling, or deduct calibration values.
CPU and wall clocks are sampled at different boundaries. The sender measurement
includes userspace readiness and kernel work; it is not just protocol processing.

The 64-sample back-to-back clock-read reference is present in every trace;
calibration and CPU markers all identify ThreadId(1) within each process.
It measures clock-read deltas, not complete recorder overhead. Raw intervals
are retained without correction. `cpu-summary.json` gives reproducible pooled
counts and medians; full intervals remain in `derived-traces/`.

Plain floor/zmosh medians (us) are 315.5/352 and 381/399.5 at 0% loss,
411/380 and 339/368 at 5%. Block and mode variation is substantial.
The paired mode comparisons are descriptive, not an isolated causal overhead
estimate. No performance PASS or runtime replacement is selected. The next
investigation should distinguish the measured sender call's userspace and
kernel work before choosing an optimization; the failed readiness fast path
must not be readopted from these measurements.

Client event counts are 10298, 10289, 10936, 10719 (capacity 65536); server
counts are 7356, 7327, 7428, 7392 (capacity 8192), in loss/block order.
All recorders are valid without overflow, and all server exports fit 2 MiB.
This echo floor excludes a remote PTY and does not qualify production reconnect,
delivery, observers, recovery or security behavior.

## Collection-check correction

The temporary runner stopped after the third completed, sealed block because
it incorrectly applied the server's 2 MiB wire-export cap to the client's local
trace file (2122047 bytes). The canonical `MAX_SERVER_TRACE_BYTES` limit applies
only to server export; that server file was 1507148 bytes. Both recorders and
CPU-pair analysis were valid. The check was corrected to its actual scope,
the first three blocks were retained without rerunning, and the remaining
preregistered blocks completed in order. No source, binary, recorder capacity,
production limit or performance threshold changed. This interruption is part
of the evidence, not a silently discarded trial.

## Reproduction and integrity

Run `analyze_attribution_overhead.py measurements` from the repository's net
test helpers. For each traced block run `analyze_floor_attribution.py` against
its result, client trace and server trace, writing outside the sealed block.
Run `jq -s -f summarize-cpu.jq derived-traces/*.json` for the pooled CPU summary.
Both analyzers are from the candidate SHA. Build provenance and all raw block
inventories are retained. The outer SHA256SUMS includes nested block seals.
Raw network-counter whitespace is preserved intentionally.
