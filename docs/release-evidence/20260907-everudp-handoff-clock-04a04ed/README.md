# Local terminal handoff attribution

DIAGNOSTIC ONLY. No qualification PASS or architecture approval.
Candidate: `04a04ed8c3156d943fc3584cfa92cd4483fa4bc8`.
Bead: `eversh-5fc.25`.

Four preregistered blocks completed with 200 trials per candidate per block,
100 ms gaps, and the pinned zmosh UDP control. Seeds: 90801/90802 at 0% loss,
91301/91302 at 5%. Candidate order reverses in block two of each cell.
All 1,600 responses passed the exact transcript oracle; all 800 everudp trials
have valid clock-aligned handoff intervals. No run was discarded or retried.
Diagnostic tracing is enabled. ACK-inline storage and send-readiness fast path
are disabled. The worktree was clean throughout build and collection.

## Findings

Median interval bounds in microseconds, not midpoint estimates:

| Loss / block | Input handoff | Output handoff | Clock uncertainty (ns) |
| --- | --- | --- | --- |
| 0% / 1 | 100.2365–100.3595 | 50.8485–50.9715 | 123 |
| 0% / 2 | 108.9625–109.1125 | 53.5885–53.7385 | 150 |
| 5% / 1 | 104.8005–104.9655 | 48.7315–48.8965 | 165 |
| 5% / 2 | 99.8595–100.1105 | 49.8840–50.1350 | 251 |

Input is the public pre-write timestamp to the client's post-read marker.
Output is the client's post-write marker to the benchmark's accepted-sink
timestamp. Both include local PTY, scheduling, and instrumentation work;
neither isolates kernel cost, QUIC cost, or network latency. Do not add
independently computed medians or subtract tracing overhead from results.
The consistently larger input interval motivates distinguishing PTY readiness
from client wake-up/dispatch before selecting an optimization. This does not
establish that an async runtime replacement would improve performance.

Public everudp/zmosh medians were 415/423.5 and 423/416.5 us at 0% loss,
428.5/505 and 434.5/450.5 us at 5%. These traced comparisons are descriptive,
not frozen performance qualification or evidence for adopting either disabled
optimization. The floor omits the remote PTY and production association path.

## Clock validity and limitations

Startup/export samples bracket Rust Instant with CLOCK_MONOTONIC reads.
The analyzer matches boot and time-namespace identity, requires brackets no
wider than 10 us, intersects their origin-offset ranges, checks event containment,
and preserves interval uncertainty. Every capture passed these checks.
There are no additional per-event clock calls. Historical captures without
this metadata remain explicitly UNAVAILABLE for cross-process alignment.

A client can be descheduled after writing output but before recording its
post-write marker; the benchmark may then accept output first. Negative or
zero-crossing inferred intervals fail closed rather than being clamped or
silently excluded. None occurred here. Luna's read-only review confirmed
the interval math and this limitation; it is not the production release review.

## Reproduction and integrity

The preserved collect.sh records exact source, seeds, orders, and commands;
its temporary paths describe this run and must be relocated for reproduction.
Build provenance records artifact hashes and feature flags. Raw blocks retain
their original inventories; derived analysis is outside those sealed blocks.
Re-run the candidate's analyze_floor_attribution.py on each block's result.json,
client-trace.json and client-trace.json.server.json, writing outside this archive,
and compare with analysis/. Run summarize.py to reproduce summary.json.
The outer SHA256SUMS includes every nested block seal. Raw counter whitespace
is preserved. This evidence does not qualify reconnect, observers, recovery,
security, or production performance.
