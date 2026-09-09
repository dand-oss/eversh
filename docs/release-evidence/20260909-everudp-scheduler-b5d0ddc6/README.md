# Full-window scheduler diagnostic — not qualification

Bead eversh-5fc.82. Clean sparse harness b5d0ddc6, sealed production NoQ cli
runtime 9be1b79d. One predeclared zero-loss block, seed 218000001, 200 responses
each in everudp / UDP zmosh / QUIC zmosh order. All 600 exact responses passed.
No transport changes, repeated blocks, dropped observations, or gate changes.

Client/server/fixture threads for everudp and UDP zmosh were selected by sealed
binary inode within the owned network namespaces. Process identities, thread
sets and time namespaces were checked before/after. Three PID-filtered scheduler
tracepoints used CLOCK_MONOTONIC, enabled/disabled with acknowledgements outside
the full public window. Host/SMT CPU and task bookends also stay outside it.
QUIC zmosh has bookends but no scheduler recording. Raw private perf files and
control FIFOs are not archived; the sanitized scheduler records are retained.

Arithmetic sample medians in this instrumented block were 670 us everudp,
538.5 us UDP zmosh, 1,441 us QUIC zmosh. These are NOT qualification numbers.

| Thread | Covered public trials | Runnable wait median / mean / max (us) |
|---|---:|---:|
| everudp client | 199 | 12.064 / 17.300 / 171.627 |
| everudp active server main | 199 | 10.563 / 17.209 / 257.437 |
| everudp echo fixture | 198 | 4.484 / 6.884 / 144.196 |
| UDP zmosh client | 199 | 11.150 / 152.089 / 3232.628 |
| UDP zmosh server (PID 360187) | 198 | 11.244 / 130.217 / 3341.667 |
| UDP zmosh server (PID 360190) | 198 | 8.002 / 96.860 / 1835.380 |

This directly establishes runnable delays in the later control, supporting the
prior resource-receipt drift association. It does not identify a competing
workload or prove those delays caused the earlier .76/.81 results. Typical
client/server runnable waits here are similar for both implementations; this
does not establish scheduling as the explanation for the persistent median gap.
The prior instruction-count difference remains a separate measured lead.

The contemporaneous host bookends also show selected-CPU-plus-SMT-sibling
non-idle tick fractions rising from **7.14%** (everudp window) to **42.51%**
(UDP control) to **86.22%** (QUIC control). Host CPU-pressure `some avg10`
rose from 0.00 to 0.02, then 16.75, then 17.00 across those bookends.
These aggregate intervals include the brief barrier overhead and all host
work on those CPUs, not just the target processes. Non-idle includes iowait;
guest ticks are not double-counted. This is contemporaneous evidence that
the candidates did not run under comparable host load, not identification
of the competing workload or an adjustment to the reported latencies.

Each thread is analyzed with its own conservative first/last-event coverage.
Uncovered trials and idle threads are explicit, not zero-filled. Do not add
thread medians, subtract waits from terminal latency, or interpret overlapping
waits as an exclusive decomposition. This host is not CPU-isolated. A control
block cannot certify a quiet host for another candidate's window.

Reproduce the complete per-thread report and verify both seals:

```sh
python3 -B docs/release-evidence/20260909-everudp-scheduler-b5d0ddc6/analyze.py
```

The original output is /var/tmp/everudp-scheduler-b5d0ddc6-block0. The failed
full checkout exhausted /tmp inodes; only that newly created partial checkout
was removed. Capture used a clean sparse checkout in /var/tmp instead. No
existing builds, historical evidence, or unrelated workloads were removed.
