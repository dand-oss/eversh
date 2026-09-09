# Release scheduling attribution

**DIAGNOSTIC; partial attribution; no qualification or integration approval.**
Candidate: `a3023b8ed41b13e82dfb578bad358dd2e5e95433` (clean during collection).
Bead: `eversh-5fc.20`. Analyzer checkpoint: `8c095fb`.

Twelve preregistered blocks completed, with 4,800 measured responses and zero
transcript failures. Each loss/mode has two reversed 200-trial blocks, with
100 ms gaps. Seeds are 89601–89606 (0%) and 89701–89706 (5%). Modes are plain
(diagnostic feature off), instrumented (feature on, tracing off), and traced.
All modes use identical zmosh and PTY control artifacts. The two independently
built zmosh hashes differed; both originals remain preserved. The separately
sealed plain-common-control set records its two parent provenance hashes.

## What the measurements support

| Loss/block | Plain floor/zmosh p50, µs | Traced queue-to-driver p50, µs | Eligible scheduling trials |
| --- | --- | --- | --- |
| 0% / 1 | 366 / 374 | 3.5095 | 200 |
| 0% / 2 | 379 / 377.5 | 3.6675 | 200 |
| 5% / 1 | 432 / 427.5 | 3.6585 | 178 |
| 5% / 2 | 413 / 413.5 | 3.558 | 173 |

The new markers correlate an application response with its process-local noQ
connection, queue acceptance, wake request and first subsequent driver service.
Ambiguous or retransmitted responses are excluded. These are scheduling
readiness spans, not specific packet-transmission times or confirmed OS wakeups.
Client and server resource windows validate and cover after-warmup through
export, including gaps/control activity. CPU/context-switch counters are
process-only; RSS is lifetime high-water, not a memory delta.

The isolated server scheduling handoff is consistently only a few microseconds.
It does not by itself explain the headroom missing from the plain floor.
This is evidence against selecting a rewrite solely to remove that handoff,
not evidence that every possible single-owner improvement is ineffective.
Protocol processing, socket work and client-side scheduling remain incompletely
attributed. No architecture replacement is selected from these measurements.

The raw/normalized mode ratios and per-loss block sensitivity are in
`overhead-analysis.json`. Instrumented builds sometimes measure faster despite
their extra bookkeeping. Disjoint seeds, build-mode effects and independent
host activity prevent treating this as a causal optimization or interpreting
the differences as a precise instrumentation penalty. Thresholds are unchanged.

## Reproduction and integrity

Run `crates/everudp/tests/net/analyze_attribution_overhead.py` with
`measurements/` as its input. For each traced block, run
`analyze_floor_attribution.py` against its `everudp-floor/result.json`,
`client-trace.json`, and `client-trace.json.server.json`. Derived reports are
kept outside the sealed measurement blocks in `derived-traces/`.

The outer `SHA256SUMS` seals all evidence and this note. The collection and each
block also have their own checksum inventories. Raw `tc` output whitespace is
preserved intentionally. Exact source/build identities do not turn this echo
floor (which excludes a remote PTY) into production qualification.
