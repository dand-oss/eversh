# Pre-frame attribution from existing evidence

Bead eversh-5fc.75. No new build, benchmark or runtime change. This reuses the
sealed capture in ../20260909-everudp-assembly-0c53e24c, runtime source
0c53e24cf18e68e910ace90daf7433be7a95aeb6: 200 trials per implementation,
zero loss, seed 213200001, all path/I/O/packet tracing enabled.

All 600 exact responses and all 200 input/output packet joins remain valid.
Each packet has exactly one same-connection protocol call enclosing frame
population through packet construction, ending READY rather than IDLE. Each
operation has exactly one driver-service marker between reservation and that
call. Missing, duplicate, cross-connection, nested and incomplete evidence is
rejected, not replaced by the closest timestamp or dropped from the population.

Independent wall-clock medians in microseconds:

| Interval | Client input | Gateway output |
|---|---:|---:|
| Operation reservation to driver service | 13.1465 | 3.4435 |
| Driver service to protocol call | 6.8635 | 1.098 |
| Protocol call to frame population | 16.062 | 2.3845 |

Driver service begins after acquiring the connection lock. Its following
interval includes processing connection events and preparing transmit work.
Protocol-call entry to frame population includes context setup, path/space
selection, congestion/pacing checks and packet header construction. These are
instrumented elapsed intervals, not exclusive CPU or removable delay. Medians
must not be added; the gateway is a different process and workload state.

No individual function has been established as the dominant cause, and no
architecture change or performance acceptance follows from this decomposition.
Normal production still fails the frozen original UDP zmosh performance gate.

Luna independently reproduced the three interval medians from the retained
capture while implementing the analyzer. Parent review repaired the duplicate
service fixture to exercise ambiguity rather than timestamp regression, and
added direct-call integer-bound checks. Seven focused pre-frame tests pass.

Reproduce from repository root:

```sh
python3 -B docs/release-evidence/20260909-everudp-preframes-0c53e24c/analyze.py
```

The analyzer validates the referenced archive and capture seals, frozen source,
seed, ordering, trace modes, build provenance link and public response oracle.
Raw traces are referenced rather than duplicated. Status: DIAGNOSTIC only.
