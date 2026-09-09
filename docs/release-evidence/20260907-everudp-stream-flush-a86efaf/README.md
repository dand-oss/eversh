# Reliable-stream immediate flush — not adopted

Source and harness: `a86efafe2daff03e895616a6e8db9fd58ea48ffa`,
tree `d145fe5eb17f905ba4292ff5887357350d221ae0`. Bead: `eversh-5fc.37`.
This is a production-path scheduling experiment, not final qualification.

## Change and controls

Baseline features are `cli`; variant features are `cli,stream-flush-spike`.
The variant offers normal QUIC protocol transmits on the application task after
a nonempty reliable input batch or a complete output record. It retains the
ordinary driver, socket backpressure, congestion/pacing, timers, partial writes,
and ACK-driven replay retirement. It does not enable QUIC DATAGRAMs.

Both builds use the same clean source. Baseline binary SHA256 is
`86d237a941811faa6d594f5c81cffee9d6a9b38990e2830e4e749510ff9002bb`;
variant is `430086ec6e6257713a266c32c6cecf027310a58839475fa30781006d50b6bf66`.
The five control/fixture artifacts are identical between builds. Original
runtime and control provenance are retained alongside composed variant metadata.
No binaries or authentication credentials are embedded in this archive.

Each 0%/5% symmetric-loss cell has four 200-trial blocks, with baseline,
variant, variant, baseline builds. Candidate order alternates forward and reverse
(`everudp`, `zmosh-udp`, `zmosh-quic`). Seeds are 1020701–1020704 and
1025701–1025704; CPUs 40,42,44,46 use the performance governor, with 100 ms gaps.
All eight blocks completed without replacement: 4,800 exact responses, zero
transcript failures. There are 400 observations per implementation/build/cell.
The timing boundary is public PTY send to exact accepted local response; no
diagnostic tracing is enabled. Both zmosh source SHAs remain frozen.

## Results

Nearest-rank latency in microseconds:

| Loss | everudp baseline p50/p95 | everudp variant p50/p95 | UDP control baseline p50/p95 | UDP control variant p50/p95 |
|---|---|---|---|---|
| 0% | 676 / 1139 | 673 / 1169 | 424 / 797 | 400 / 781 |
| 5% | 723 / 4052 | 713 / 4346 | 432 / 50724 | 427 / 50643 |

Variant/baseline everudp p50 ratios are 0.9956 [0.9412, 1.0391] at no loss
and 0.9862 [0.9260, 1.0363] at 5% loss. Corresponding p95 ratios are
1.0263 [0.9601, 1.1105] and 1.0726 [0.9538, 1.1778]. Brackets are central
95% intervals from 20,000 within-block bootstrap resamples, not independent
experimental replications or causal certainty. All four intervals include 1.
Control changes and loss-tail variation are reported in full in `analysis.json`.

No useful improvement is established. Variant p50 remains 1.6825x/1.6698x
the zmosh UDP control; no-loss p95 remains 1.4968x. This does not close the
production performance gap. Higher p95 point estimates do not by themselves
establish a regression, given the intervals above.

Decision: do not enable this feature by default or treat it as a successful
optimization. The result tests a scheduling opportunity, not a claim that the
whole protocol or socket interval is removable. The feature remains an isolated
experiment. Final six-block, 1,200-observation qualification against both controls,
reliability/security gates and exact-candidate independent review remain required.

## Verification and reproduction

Independent review checked both build seals, shared controls and original
provenance links, then all eight block seals and grouped raw medians/p95s; all
matched the parent calculation. Code validation before the build included 87
Rust tests, 138 Python tests (two existing skips), formatting, default compilation
and strict stream-feature linting. Those checks do not replace network qualification.
Independent analyzer review found no concrete grouping or validation issue;
rerunning the complete analysis produced byte-identical output.

Run `sha256sum -c SHA256SUMS --quiet`, then
`PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py > /tmp/stream-flush-reproduced.json`
and `cmp analysis.json /tmp/stream-flush-reproduced.json`.
The analyzer verifies source/build identities, feature selections, shared control
links, artifact hashes, seeds/order/governors, public boundaries and samples,
exact responses, qdisc accounting and measured loss. Raw block seals and qdisc
whitespace are preserved unchanged. Never run the analyzer with Python `-O`,
which disables its invariant assertions.
