# Native syscall intervals: diagnostic evidence only

Runtime: `9b67a67a4834daea193af4e6a4270e6155dac048`.
Capture harness: `9e0555b19123f464894679bef06df7ce5abb20c2`.
Bead: `eversh-5fc.31`. No production qualification or adoption is authorized.

Two instrumented 200-trial blocks used the frozen zmosh UDP control, with
0%/5% symmetric loss, seeds 960701/965701, and reversed implementation order.
The ten-second syscall captures cover subsets of those blocks. All 800 benchmark
responses were correct. Neither these instrumented timings nor the short
capture windows replace the frozen performance gates, which this runtime failed.

The observable interval below starts at completion of the single successful
stdin read and ends at entry to the first subsequent successful network send
before the single successful stdout write. Whole public trial windows must be
inside the capture; unsuccessful calls and partial windows cannot be selected.
Multiple sends remain visible. A successful send may carry ACKs or retries:
these observations do not identify terminal packets.

| Symmetric loss | Native included / 200 | Native median µs | zmosh included / 200 | zmosh median µs |
| --- | ---: | ---: | ---: | ---: |
| 0% | 98 | 56.849 | 98 | 9.7975 |
| 5% | 99 | 56.542 | 94 | 9.777 |

All client exclusions were outside capture coverage. Native server windows
validated separately: 99 included at 0% and 98 at 5%. Independent recomputation
confirmed the strict per-public-window client results and capture identities,
filters and clocks. Its earlier episode-only counts included capture-edge
episodes and were rejected; they are not used here.

This local interval is a useful target for further attribution, not a proven
cause or an achievable saving. It includes encoding/queue handling, native
reactor service, protocol processing and syscall instrumentation overhead.
CPU, preemption and other waiting are not separated. Do not add stage medians,
subtract unpaired control medians as guaranteed savings, or claim a causal
comparison with the previous runtime. No transport optimization follows merely
from the size of this interval.

## Capture safety and identity

The first attempt used this kernel's augmented typed write tracepoint, which
records buffer contents. The strict exporter rejected its unexpected format.
That attempt remains INVALID outside this archive; raw perf data is private.
The corrected harness uses x86_64 raw syscall NR1 for write, preserving only
fd, count and return value, and rejects other dynamically augmented tracepoints.
No raw perf files, buffer contents, pointer fields or binaries are archived.

All six captures use one PID/TID, the public benchmark's monotonic clock and
time namespace, 16 PID-filtered typed syscall events and two PID-and-NR1-filtered
raw events. Tracepoint attributes, commands and scalar exports are authoritative.
The original metadata scope prose omits sendto/recvfrom; it is retained unchanged,
and those events are verified in the commands and attributes. Perf's dummy
metadata event is not counted as a measured syscall tracepoint.

## Reproduce

```sh
python3 -B analyze.py > /tmp/everudp-io-reproduced.json
cmp analysis.json /tmp/everudp-io-reproduced.json
sha256sum -c SHA256SUMS --quiet
```

The analyzer verifies frozen identities, block seals, seeds/order, event/filter
sets, clock attributes, scalar event pairing, public boundaries and timing samples.
The copied support code reports each included/excluded client trial. The parser
and selector checkpoint passed all 105 Python tests (two unrelated skips).
