# Sender API interval attribution

Diagnostic only; no architecture selection or qualification approval.
Bead: eversh-5fc.20. This reanalyzes the existing sealed a3023b8 traces;
no new benchmark or runtime change occurred. ANALYZER_COMMIT records the exact
analyzer revision. INPUT_SHA256SUMS identifies all twelve original inputs,
with paths relative to the repository root. Those inputs remain unchanged.

The analyzer now pairs a sender poll entry only with the corresponding outcome
on the same thread. Missing, nested, falsely sequenced, wrong-thread or
same-thread-interleaved pairs invalidate the report. Other threads may
interleave without being mistaken for this call. All real pairs here are
adjacent in the event stream. Tests went from RED to green; the full Python
harness suite passes 49 tests with two existing skips.

## Observations

Intervals cover the entire trace, including warmup and control traffic, not
just public trials. They have no packet or application sequence identity.
The independent read-only extraction agrees with these counts and medians.

| Loss / block | Client calls | Client median ns | Server calls | Server median ns |
| --- | ---: | ---: | ---: | ---: |
| 0% / 1 | 437 | 30990 | 403 | 26977 |
| 0% / 2 | 444 | 33762 | 402 | 27343 |
| 5% / 1 | 524 | 31309.5 | 405 | 28532 |
| 5% / 2 | 511 | 30308 | 408 | 28905.5 |

Each client trace has one blocked poll; all other client polls and every
server poll were accepted. No error outcome was recorded. This is evidence
about these traces only, not proof that runtime sends never block or fail.

For context, existing application-stage medians are approximately 2.1–2.4 us
for terminal-read to wire-encode, 1.86–1.93 us for server decode-to-encode,
and 5.6–6.7 us for client decode-to-sink. The offer-to-sink median is
213–249 us. These independently computed medians must NOT be added or
subtracted to manufacture a per-request decomposition.

## What remains unknown

Sender API poll wall time includes runtime/readiness work, instrumentation,
kernel work and scheduling. It is not pure syscall latency or thread CPU time,
and may overlap work on the peer. It does not prove that removing 30 us from
one measured call would remove 30 us from end-to-end latency. The previous
readiness fast-path experiment did not demonstrate the required margin.

Exploratory driver-service-to-send pairing was deliberately not promoted into
the analyzer: without a driver-return marker it can bridge idle time. For
example, pairing past application activity produces millisecond-scale client
gaps that are not protocol-processing costs. Filtering known application
markers still does not prove contiguous driver execution.

The next discriminating evidence needed is bounded protocol/driver call
entry-and-exit measurement, separating same-thread CPU consumption from wall
time. Until that distinction is measured, neither a sender rewrite nor a
single-owner core has a demonstrated latency budget. Existing security,
delivery, reliability and performance gates remain unchanged.
