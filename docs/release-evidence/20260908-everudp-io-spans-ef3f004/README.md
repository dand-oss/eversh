# Production input I/O call coverage — diagnostic only

Analyzer: `ef3f004633154992501bc2e14572143401b70b94`, bead `eversh-5fc.59`.
This is a reanalysis of existing captures, not a new timed experiment or a
performance PASS. No runtime change is selected by these results.

Inputs are blocks 2 and 3 at each loss level in
`../20260907-everudp-io-25439e3/`. Their original block inventories were verified.
The parent inventory SHA256 is
`8b61e4e999fc7af10e6f613a5ebb0ddc85d4857c710fd19ab151994522d6efa2`.
Measured runtime remains `25439e3596811694686874bfa2a50eb1cb3673a0`, with
`cli,path-io-diagnostics`. It predates the fairness fixes and corrected QUIC
control adapter. Do not use its QUIC-control latency as the current baseline.

The helper revalidates paired path/I/O identities and recomputes public trial
matching. It pairs protocol start with ready/idle, and send poll with
accepted/blocked/error. It rejects nested, unmatched, unfinished, regressing,
or cross-connection call boundaries. Disjoint call intervals are intersected
with each selected window; residual is computed within that same window.
There are 800 included trials, zero excluded trials, and zero clipped calls.

Pooled elapsed medians in microseconds, 400 trials per loss level:

| Loss | Role/window | Whole window | Protocol | Send | Residual |
|---|---|---:|---:|---:|---:|
| 0% | Client stream acceptance to first transmit acceptance | 95.5475 | 37.4450 | 43.4505 | 11.3050 |
| 5% | Client stream acceptance to first transmit acceptance | 80.7015 | 35.0035 | 33.8010 | 10.6395 |
| 0% | Gateway latest receive batch to input readability | 90.7820 | 17.7265 | 29.6410 | 39.3985 |
| 5% | Gateway latest receive batch to input readability | 78.8950 | 15.7940 | 25.7985 | 34.0050 |

Do not add these independent medians. Spans are instrumented wall time, not
exclusive CPU cost or predicted savings. The recorder's previously measured
overhead is material. First transmit and latest receive markers lack packet
identities; they do not prove that one selected send carried the input.
Residual includes all unmarked work and any descheduling.

The client interval is mostly inside packet generation and send calls rather
than before the driver runs. This does not justify another task-handoff
rewrite. Whole-trace call medians include ACKs, warmup and other traffic and
must not substitute for these input-window measurements.

Source inspection at analyzer HEAD confirms protocol generation includes
path/space selection (`vendor/noq-proto/src/connection/mod.rs:1016`), frame
construction (`:6066`), packet protection and sent-packet tracking
(`connection/packet_builder.rs:266`). These are broad necessary operations;
the current markers do not identify a removable leaf operation. The old
single-path ACK-allocation and sender-readiness experiments remain rejected.
No security, congestion, retransmission or delivery work may be removed on
the strength of these elapsed spans.

Reproduce each block from repository root (substitute the other block/loss
directories; pool per-trial rows, not block medians):

```sh
python3 -B crates/everudp/tests/net/analyze_io_spans.py \
  docs/release-evidence/20260907-everudp-io-25439e3/loss0-block2/everudp
python3 -B -m unittest discover -s crates/everudp/tests/net -p test_analyze_io_spans.py
python3 -B -m unittest discover -s crates/everudp/tests/net -p test_validate_io_trace.py
```

Six call-boundary/coverage tests and six schema tests passed. Qualification
remains the failed `bd53692` receipt; this reanalysis does not replace it.
