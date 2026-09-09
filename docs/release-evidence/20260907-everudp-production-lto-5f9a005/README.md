# Production LTO comparison — incomplete diagnostic

Candidate `5f9a0057213b3dc8b562c5c8959ea661868a3277`, tree
`084738b2b60747a6dccc2994fddccf07d9f053af`; bead `eversh-5fc.42`.
No production adoption or qualification PASS is claimed.

## Experiment

Both builds use the unchanged production `cli` feature, no scheduling spike,
and no tracing. Baseline explicitly uses LTO=false/codegen-units=16; variant
uses fat LTO/codegen-units=1. Both use opt-level=3, panic=unwind, empty Rust
flags and portable default CPU targeting. Separate fresh targets built the
same clean source. Unlike earlier disposable floor tests, this experiment
measures the real terminal transport and does not switch panic strategy.

Baseline binary SHA256:
`79c28a7751506f9563ff2aa31fe368d1440d1d3ef235a93a3e5725ba1dc0cafa`.
Variant:
`62c5435cdc98fb39904ecf4a5100c7a5e87b34662076d36e62ceaef7941aad78`.
Build profiles, commands, logs, source/tool/lockfile identities and frozen
control provenance are retained. The five control/fixture binaries are reused
byte-identically from the `a86efaf` build, not rebuilt between profiles.

Recorded design: baseline/variant/variant/baseline in each loss cell (0%, 5%
symmetric), 200 observations per candidate per block, forward/reverse alternating
order, seeds 1121701–1121704 and 1126701–1126704, server offset 1,000,003.
CPUs 40,42,44,46 used the performance governor, with 100 ms trial gaps.

## Failure retained, not replaced

All four no-loss blocks completed. In loss5/block1, everudp and zmosh UDP each
completed 200 exact responses, but the frozen zmosh QUIC bridge remained
`awaiting_ack` and failed to echo the warm-up marker. Its measurement-start
barrier was never reached; no QUIC timing result or complete block manifest exists.
This observation does not establish the underlying cause of the control failure.

The original run stopped. Only the three previously unstarted loss blocks were
then run, with their original seeds/order/builds; all completed. The failed block
was neither rerun nor replaced. Seven complete blocks plus 400 partial responses
give 4,600 recorded correct responses, not a complete 4,800-response study.
Loss-cell results are reported per completed block without comparative inference;
the failed block's partial samples are retained but not pooled.

## Complete no-loss comparison

Nearest-rank p50/p95 in microseconds, 400 samples per build and implementation:

| Build | everudp | zmosh UDP | zmosh QUIC |
|---|---:|---:|---:|
| Baseline | 707 / 1155 | 385 / 790 | 10746 / 11194 |
| Fat LTO | 625 / 1041 | 396 / 801 | 10751 / 11192 |

Everudp variant/baseline p50 ratio: 0.8840, central 95% interval
[0.8471, 0.9326]. p95 ratio: 0.9013 [0.8597, 0.9591]. This supports a
no-loss improvement in this experiment. UDP control p50 ratio is 1.0286
[0.9800, 1.0741]; QUIC control p50 is 1.0005 [0.9976, 1.0030].
The variant still has a 625/396 = 1.5783 median ratio versus zmosh UDP,
well above parity. The profile is not adopted on this incomplete study.

## Redaction, validation and reproduction

Complete blocks preserve their original receipts as `SHA256SUMS.original`.
Only ephemeral keys in `zmosh-quic/connect.log` were redacted; `redaction.json`
records original/current hashes, and new receipts seal the redacted block.
The analyzer verifies all original receipt entries other than that declared
log against current bytes, and checks the original log hash against the
redaction record. No timing or result bytes changed. The failed block omits
its credential-bearing connect log entirely, retaining its hash and omission
reason in `failure.json`; its receipt was created after that documented export.

The analyzer validates complete-block identities, profiles, controls, traces-off,
governors, seeds/order, qdisc counters, exact transcripts and public timing
boundaries. It checks the preserved failure separately. No-loss intervals use
20,000 independent within-block resamples, seed 1131700, nearest-rank quantiles
and central 95% intervals. These are not independent experimental replications
or the frozen six-block production qualification.

From this directory, without Python `-O`:

```sh
sha256sum -c SHA256SUMS --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py > /tmp/lto-reproduced.json
cmp analysis.json /tmp/lto-reproduced.json
```

Next: a separately recorded complete comparison is needed before selecting a
production compiler profile. Final exact-SHA performance, reliability, security,
and independent max-review requirements remain unchanged.
