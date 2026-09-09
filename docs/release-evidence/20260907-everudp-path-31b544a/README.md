# Production path attribution and tracing overhead — DIAGNOSTIC

No production qualification or architecture adoption is claimed.

Runtime/harness/parser source: `31b544a8e33b06ff8563410935a6ecc4c578dbe0`, tree
`200806e0bb552c64a56732c533c13a731163050f`, clean throughout build and measurement.
Runtime binary SHA256: `565bfc4e3322c5379a2801d5d098aab5361f55411cc84afb8c63a3291075aa1e`.
Build provenance SHA256: `be9f37a1f2a11e4fcb636c62369273976b300bca52697ae7740d312bf3f0e99e`.
The build uses only `cli,path-diagnostics`; no DATAGRAM or scheduling experiment.
Five controls are reused unchanged from the sealed a86efaf production build;
`build.json` and both origin documents record identities. Binaries are not archived.

Eight complete blocks: OFF/ON/ON/OFF at each of 0% and 5% symmetric loss, 200
trials per candidate per block. This yields 4,800 exact responses and four ON
blocks × 200 = 800 correlated path rows. CPU affinity 40,42,44,46; performance
governor; 100 ms trial gaps; alternating forward/reverse candidate order.
Seeds are 1061701–1061704 and 1066701–1066704; server seed is client + 1000003.
No block was discarded, retried, or substituted. A preceding five-trial wiring
check was smoke-only and is not included in these measurements.

## Overhead result

Nearest-rank quantiles; 400 observations per candidate/mode/cell. ON/OFF central
95% intervals use 20,000 independent resamples within each fixed block. This is
not independent experimental replication, and four blocks do not satisfy the
frozen six-block production gate.

| Loss | OFF p50/p95 µs | ON p50/p95 µs | p50 ON/OFF [central95] | p95 ON/OFF [central95] |
| --- | --- | --- | --- | --- |
| 0% | 691 / 1108 | 706 / 1219 | 1.0217 [0.9943, 1.0719] | 1.1002 [1.0284, 1.2158] |
| 5% | 742 / 4156 | 705 / 4463 | 0.9501 [0.9073, 1.0029] | 1.0739 [0.9125, 1.1570] |

The no-loss tail is detectably perturbed under this analysis; do not use traced
tail latency as production latency. Both p50 intervals include 1.0. Controls also
move between blocks (full results in `analysis.json`), so this is not proof of
zero overhead or exclusive causal attribution. OFF is the same diagnostic-feature
binary with recording disabled, not the featureless production default.

## Recorded userspace intervals

Each loss cell contains 400 traced rows. Medians below are descriptive, not
exclusive CPU, crypto, kernel or network costs. Do not sum stage medians.

| Interval | 0% median µs | 5% median µs |
| --- | --- | --- |
| Public send → client input queued | 120.088 | 119.589 |
| Input queued → QUIC stream accepted | 9.470 | 9.281 |
| QUIC stream accepted → gateway input prepared | 317.391 | 313.406 |
| Gateway input prepared → sink committed | 12.620 | 12.549 |
| Input committed → PTY output buffered | 100.513 | 97.848 |
| PTY output buffered → client output staged | 103.440 | 102.584 |
| Client output staged → sink committed | 11.369 | 11.178 |
| Client sink marker → public sink accepted | 18.895 | 20.496 |

The input-side stream-to-gateway interval is the largest observed interval and
is the next attribution target. It does not identify removable work by itself.
The output direction is about 103 µs median in both cells; its 5%-loss p95 includes
recovery delays. Delivery/ACK/replay semantics remain unchanged. Production parity
against the custom-UDP baseline is still unmet; no new production gate was run.

## Validation and reproduction

All block seals, source/build identities, seeds, orders, governors, exact public
samples, qdisc accounting and trace correlations were checked. The analyzer
recomputes and compares every archived `path-analysis.json`. Runtime tracing is
payload-free, bounded and opt-in. Missing or invalid traces fail capture; the
performance qualifier rejects diagnostic blocks.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py > /tmp/everudp-path-reproduced.json
cmp analysis.json /tmp/everudp-path-reproduced.json
sha256sum -c SHA256SUMS --quiet
```

Independent Luna review confirmed raw seals, identity, order, seeds, grouping,
quantiles and resampling scope. Its initial 400-row total was rejected and
corrected by checking all four ON paths individually: the correct total is 800.
This is a scoped evidence review, not the final independent release review.
