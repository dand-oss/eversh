# Reliable-stream inline receive — diagnostic signal, not adopted

Runtime and harness: `1c71ca893c86642144db1e474565799aba353992`,
tree `3a624806c46a2ae690c1047aa1cd637b0118b412`. Bead: `eversh-5fc.38`.
This is a bounded production-path scheduling experiment, not qualification.

## Contract and identity

Baseline features are `cli`; variant features are `cli,stream-receive-spike`.
The variant enables existing endpoint-side QUIC event processing and application
readiness notification. It does not enable datagrams or immediate transmission.
Queued control events remain ordered, and the connection driver still owns
timers, transmission and socket-error handling. Application replay, partial
writes, ACK retirement, PTY ownership and defaults are unchanged.

Both runtimes were built in separate fresh targets from the same clean source.
Baseline binary SHA256 is
`86d237a941811faa6d594f5c81cffee9d6a9b38990e2830e4e749510ff9002bb`;
variant is `b93079a9aba83e033c31e39e1383b336dc021630f04711ef8ec7801802d490d1`.
All five control/fixture binaries are reused identically from the sealed
`a86efaf` control build. Each runtime's original provenance and that control
provenance are retained separately; the older control source is intentional.
No binaries or authentication credentials are embedded in this archive.

Each 0%/5% symmetric-loss cell contains four 200-trial blocks, with baseline,
variant, variant, baseline builds. Candidate order alternates forward and reverse
(`everudp`, `zmosh-udp`, `zmosh-quic`). Seeds are 1040701–1040704 and
1045701–1045704; CPUs 40,42,44,46 use the performance governor and 100 ms gaps.
All eight blocks completed without replacement: 4,800 exact responses and zero
transcript failures. There are 400 observations per implementation/build/cell.
Timing runs from public PTY send to exact accepted local response, without tracing.

## Results

Nearest-rank latencies in microseconds:

| Loss | everudp baseline p50/p95 | everudp variant p50/p95 | UDP baseline p50/p95 | UDP variant p50/p95 |
|---|---|---|---|---|
| 0% | 686 / 1175 | 644 / 1089 | 410 / 795 | 399 / 741 |
| 5% | 691 / 4056 | 682 / 4106 | 437 / 50652 | 426 / 50673 |

Variant/baseline everudp ratios, with central 95% intervals:

- No loss: p50 0.9388 [0.8997, 0.9751]; p95 0.9268 [0.8639, 0.9888].
- 5% loss: p50 0.9870 [0.9223, 1.0436]; p95 1.0123 [0.9560, 1.1357].

These are 20,000 independent within-block bootstrap resamples, not independent
experimental replications. No-loss results show an improvement signal, while
loss-cell intervals include 1. The UDP control's no-loss p95 also improved
(ratio 0.9321 [0.8648, 0.9936]); its p50 changed by 0.9732 [0.9344, 1.0202].
Do not attribute all observed improvement to the receive-side change.
Full control distributions and packet attempts are retained in `analysis.json`.

The variant still measures 1.6140x/1.6009x the UDP control's p50, and 1.4696x
its no-loss p95. It does not close the production performance gap. Decision:
keep the feature isolated and disabled by default; no production adoption or
qualification PASS. The result narrows the scheduling investigation but does
not establish sufficient or universal benefit. All frozen final performance,
reliability, security and exact-candidate independent-review gates remain required.

## Verification and reproduction

Before building: 86 Rust library/integration tests, 140 Python tests (two
existing skips), formatting, shell syntax and strict feature linting passed.
Independent review approved the bounded receive-side experiment, verified both
artifact bundles and raw blocks, reproduced grouped medians/p95s, and reviewed
the adapted analyzer without finding a concrete issue. These are not substitutes
for the full network qualification.
The complete analysis was rerun and reproduced byte-for-byte.

Run `sha256sum -c SHA256SUMS --quiet`, then
`PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py > /tmp/receive-reproduced.json`
and `cmp analysis.json /tmp/receive-reproduced.json`.
Validation covers origin metadata, source/build/artifact identities, feature
isolation, registered orders/seeds, governors, public boundaries and exact
samples, qdisc accounting and measured loss. Raw block seals and qdisc whitespace
are preserved. Do not use Python `-O`, which disables invariant assertions.
