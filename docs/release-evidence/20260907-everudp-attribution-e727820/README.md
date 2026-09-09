# Safe-floor attribution collection

Result: **DIAGNOSTIC, attribution INCOMPLETE, architecture UNKNOWN**.
No production or actor-integration authorization. Bead: `eversh-5fc.20`.

All twelve preregistered blocks completed at clean source
`e727820c5d36496ef673c7045a02d18eec20ebf0`. There are 4,800 measured
responses, with zero transcript failures. The three modes are plain
(diagnostic feature off), instrumented (feature on, trace off), and traced
(feature on, trace on). Both reversed blocks use 200 trials per candidate,
100 ms gaps, and symmetric loss at 0% or 5%. This is the authenticated
DATAGRAM echo floor, not the production remote-PTY workload.

## Descriptive block results

These are point medians, not overhead confidence intervals or gate verdicts.
Each cell shows floor/zmosh microseconds for the two reversed blocks.

| Loss | Mode | Block 1 | Block 2 |
| --- | --- | --- | --- |
| 0% | plain | 383 / 366.5 | 410.5 / 408 |
| 0% | instrumented | 306 / 359 | 378.5 / 381.5 |
| 0% | traced | 380.5 / 392 | 369 / 394 |
| 5% | plain | 430 / 432 | 393.5 / 441 |
| 5% | instrumented | 431 / 409 | 427 / 413 |
| 5% | traced | 400 / 410 | 413.5 / 431.5 |

The block variation prevents attributing these differences to instrumentation
alone. The independently built plain and diagnostic zmosh binaries differed
in hash despite identical pinned source; the reason was not established.
Both originals were retained. The derived plain-common-control set keeps
plain everudp and substitutes the identical diagnostic-set zmosh artifact.
Every measurement therefore uses one common zmosh and PTY artifact set;
parent provenance hashes and derivation are recorded.

## Verified evidence and remaining gaps

Block hashes, clean source/tree identities, build provenance and binary hashes,
preregistered seeds/orders, and common control identities were checked.
Every public latency equals integer ceiling of its original accepted-minus-send
nanoseconds divided by 1,000. Raw root-netem sent-plus-drop attempts reproduce
the manifest totals. The collection receipt records these checks.

Application trace sequence zero is warmup; public trial i maps to sequence i+1.
No-loss traces have all 201 sequences. Loss traces include retransmissions:
14 and 33 client retry markers, with 207 and 219 server callbacks respectively.
Repeated responses must not be treated as unique-request decomposition.

NoQ events have no request/packet correlation. They cannot establish the delay
from a particular callback through a driver wakeup to its UDP transmission.
Driver polls are not task wakeups. Process-relative timestamp origins differ;
never subtract client and server timestamps. Whole-run resource files cover
the benchmark and waited client descendants, not detached server work or
post-warmup resource windows. Independent host workloads were present.

Next: validate application-level spans with the fail-closed analyzer, quantify
overhead uncertainty, and add the missing causal/resource measurements before
selecting a runtime experiment. The frozen gates and prior V4 negative result
are unchanged.

## Integrity

`measurements/SHA256SUMS` seals the original collection including each nested
block checksum file. Its SHA256 is
`6d2ad6d16c1143e4cede6bb5f1ce7aac52a1ad2d122d6aeae86c963aab27d71c`.
The outer `SHA256SUMS` additionally seals this note and copied build provenance.
Check from this directory with `sha256sum -c SHA256SUMS`, and from
`measurements/` with `sha256sum -c SHA256SUMS`.
