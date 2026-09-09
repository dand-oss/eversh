# Native polling cost: diagnostic evidence only

Bead `eversh-5fc.29`. Runtime binary remains the rejected floor candidate
`a9321d0060cc726b27fcde89ca7d31e9519c5425`; capture harness is
`3c5ec736295de4d1f770752a0fe4e88e5304340b`. Runtime/dependency source differences
were required to be empty before collection. No production integration is authorized.

Two paired blocks, 200 trials per implementation and 100 ms gaps, completed
with 800 correct measured responses. The 0% block uses seed 940701 and native
then zmosh order; 5% uses seed 945701 and reversed order. Each process has a
bounded ten-second capture, so only a subset of public trial windows is covered.
Native client and server were captured concurrently; zmosh client was captured
in its own candidate window. Frozen binaries and build provenance are retained
by hash, not included as executable artifacts.

| Loss | Matched trials | Median client/server union µs | p95 union µs | Descriptive median upper-95 µs |
| --- | ---: | ---: | ---: | ---: |
| 0% | 98 | 10.270 | 24.443 | 12.2275 |
| 5% | 97 | 8.930 | 25.494 | 10.475 |

The native client median is two zero-time polls per included trial; the server
median is one. The zmosh client median is zero. Costs are computed by unioning
actual intervals within matching public send-to-accepted windows, never by
adding independent medians. Normal blocking polls spanning the input arrival
are not mistaken for zero-time work. Every excluded trial remains in the output.

The upper-95 numbers resample trials within one capture per loss cell. They do
not quantify run-to-run variability, measurement overhead, or causal speedup.
These traces are instrumented and cannot replace untraced acceptance gates.
The earlier untraced candidate missed its 0.90 floor ceiling by 20.75/42.9 µs.
Observed polling cost alone does not establish that removing these calls would
close either gap. It identifies concrete avoidable work for a bounded follow-up;
protocol-drive and other userspace costs remain unassigned.
Luna independently checked the identities, measurement seals, clock/filter
evidence, matched interval calculations and reported quantiles. That review
confirmed this narrow descriptive conclusion, not causal savings or acceptance.

## Verification and limits

Recorded attributes use CLOCK_MONOTONIC. Public benchmark and capture boot/time
namespace identities match. Capture checks PID generation, thread set and
affinity before/after recording; all selected targets had one thread. Tracepoint
filters are restricted to each selected PID. Lost-event display was enabled and
no loss was reported. Four syscall boundaries are captured: poll entry/exit and
read entry/exit. No terminal buffer contents are captured; exported buffer and
poll-descriptor pointers are removed. Raw perf files remain private in `/tmp`
because profiler metadata can include incidental process information.

The parser rejects malformed records, timestamp regressions, impossible syscall
overlap, inconsistent byte samples and incomplete zero-time intervals. The union
helper rejects mismatched trials, intervals outside public windows and conflicting
process identities. Eleven focused tests and the full 94-test Python suite passed
(two skips in the full suite). This is not the final independent production review.

Run from this directory:

```sh
python3 -B analyze.py > /tmp/native-poll-reproduced.json
cmp analysis.json /tmp/native-poll-reproduced.json
sha256sum -c SHA256SUMS --quiet
```

The archive includes the analysis support sources and original measurement seals.
Capture source is retained for audit; its original private paths are not portable.
Production reconnect, security, resource and performance gates remain outstanding.
