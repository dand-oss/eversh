# Production LTO confirmation — diagnostic, not qualification

Runtime: `5f9a0057213b3dc8b562c5c8959ea661868a3277`, tree
`084738b2b60747a6dccc2994fddccf07d9f053af`.
Collector: `b24670368f836fd1c52e60a7493ed5f24ea4a24d`, tree
`7b30405d080120b1c3569edc6f780767ddd75389`. Bead `eversh-5fc.42`.
These identities intentionally differ: exact runtime binaries were reused,
while the collector now prevents bootstrap credentials entering evidence logs.

## Design and integrity

Both builds use production `cli`, panic=unwind, opt-level=3, empty Rust flags
and portable default CPU targeting. Baseline uses LTO=false/codegen-units=16;
variant uses fat LTO/codegen-units=1. Runtime source and controls are identical.
Neither build enables scheduling experiments or diagnostic tracing.

Baseline executable SHA256:
`79c28a7751506f9563ff2aa31fe368d1440d1d3ef235a93a3e5725ba1dc0cafa`.
Variant:
`62c5435cdc98fb39904ecf4a5100c7a5e87b34662076d36e62ceaef7941aad78`.
Original runtime/build logs and frozen control provenance are retained.

This is a separately recorded confirmation study, not a replacement for the
incomplete first study in `20260907-everudp-production-lto-5f9a005`.
No observations are pooled between studies. Each loss cell (0%, 5% symmetric)
uses baseline/variant/variant/baseline, 200 trials per implementation per block,
forward/reverse alternating order, seeds 1141701–1141704 / 1146701–1146704,
server offset 1,000,003, 100 ms gaps, and CPUs 40,42,44,46/performance governor.
All eight blocks completed without failures, retries or replacement: 4,800
exact responses. No builds, source edits or heavy analysis ran during timing.

## Results

Nearest-rank p50/p95, microseconds; 400 samples per name/build/cell:

| Loss | Build | everudp | zmosh UDP | zmosh QUIC |
|---|---|---:|---:|---:|
| 0% | Baseline | 675 / 1122 | 409 / 820 | 10735 / 11201 |
| 0% | Fat LTO | 630 / 1051 | 407 / 825 | 10762 / 11281 |
| 5% | Baseline | 730 / 3993 | 413 / 50622 | 10732 / 37402 |
| 5% | Fat LTO | 660 / 3990 | 435 / 50583 | 10757 / 37937 |

Everudp variant/baseline ratios, central 95% intervals:

- No-loss p50: 0.9333 [0.8996, 0.9715]; p95: 0.9367 [0.8930, 0.9982].
- 5%-loss p50: 0.9041 [0.8639, 0.9407]; p95: 0.9992 [0.8993, 1.0381].

Median improvement is supported in both cells; a loss-tail improvement is not
established. UDP control median ratios are 0.9951 [0.9405, 1.0564] and
1.0533 [0.9794, 1.1111]. Host/block variation remains a limitation.
Variant medians versus UDP remain 1.5479 and 1.5172; no-loss p95 is 1.2739.
These miss the frozen production targets. This evidence supports considering
the compiler profile for subsequent development, not declaring the product done.
No source-profile change or production adoption occurs in this archive.

## Validation and reproduction

The analyzer independently validates collector and runtime source identities,
explicit profiles, artifact/control/runtime/log hashes, all block seals, exact
public timing/transcript boundaries, order/seeds, governors, tracing-off flags,
and qdisc accounting. Bootstrap logs must contain exactly one redacted record.
Unlike the first archive, no retrospective redaction occurred: the collector
created redacted logs before sealing, so no original-redaction receipt is needed.
Luna's independent read-only review found no concrete provenance or arithmetic
defect; its suggested stricter whole-log grammar check is incorporated.

Intervals use 20,000 independent within-block resamples, seeds 1151700/1151705,
nearest-rank quantiles, and central 95% intervals. These are not independent
experimental replications or the frozen six-block production qualification.
Do not use Python `-O`, which disables validation assertions.

```sh
sha256sum -c SHA256SUMS --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py > /tmp/lto-confirm-reproduced.json
cmp analysis.json /tmp/lto-confirm-reproduced.json
```

Final exact-SHA performance, reliability, security and independent max-review
gates remain required. Thresholds and release/fleet boundaries are unchanged.
