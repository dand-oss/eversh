# Client backpressure repair: diagnostic comparison

Candidate `981975bceed8a315b3c827406dc8c5be029ec272`, tree
`04c8012f84efb6fd0e2e7d98cf967feaba4dc9df`. Beads: `eversh-5fc.55` (repair)
and `eversh-5fc.9` (qualification remains open).

Result: **MEASURED, not production qualification; median parity is not met.**
All 2,400 responses passed the exact transcript/public-boundary checks.

| Symmetric loss | Implementation | Pooled median | Pooled p95 |
| --- | --- | ---: | ---: |
| 0% | everudp | 566 us | 1,002 us |
| 0% | zmosh UDP | 389 us | 732 us |
| 0% | zmosh QUIC, corrected adapter | 614 us | 1,087 us |
| 5% | everudp | 844 us | 8,375 us |
| 5% | zmosh UDP | 386 us | 50,545 us |
| 5% | zmosh QUIC, corrected adapter | 657 us | 36,932 us |

Two reversed-order blocks of 200 observations produce 400 samples per
implementation per cell. Medians average the central pair; p95 is nearest rank.
The current everudp/UDP median ratios are 1.455 and 2.187. Loss-tail advantage
does not waive the median gate. No failed sample or slow block was discarded.

## Block variation matters

| Loss/block | everudp median | UDP median | QUIC median |
| --- | ---: | ---: | ---: |
| 0% / 1 | 544.5 us | 379 us | 589 us |
| 0% / 2 | 593.5 us | 399 us | 645 us |
| 5% / 1 | 667.5 us | 382 us | 585.5 us |
| 5% / 2 | 2,925.5 us | 391 us | 860.5 us |

The second loss block is substantially worse for everudp. The controls also
vary, but not equally. This requires investigation; neither a universal speedup
nor a causal regression estimate follows from comparing sequential runs with
different seeds/builds/host conditions. In particular, this is not a matched
before/after ablation of the backpressure repair. The earlier corrected-adapter
run remains separately archived, unchanged.

### Retained chronology (bead eversh-5fc.56)

Consecutive, non-overlapping groups of 20 trials show sustained deterioration,
not a single extreme observation. Trial indices below are zero-based; no trial
is excluded and the original pooled statistics above remain authoritative.

| First trial | First loss block median | Second loss block median |
| --- | ---: | ---: |
| 0 | 641 us | 557.5 us |
| 20 | 676.5 us | 536.5 us |
| 40 | 539 us | 1,015 us |
| 60 | 638 us | 1,391 us |
| 80 | 557.5 us | 4,130.5 us |
| 100 | 556 us | 4,773.5 us |
| 120 | 821.5 us | 1,722.5 us |
| 140 | 594 us | 6,964 us |
| 160 | 871 us | 4,897.5 us |
| 180 | 1,446.5 us | 7,119.5 us |

Everudp packet attempts/drops were 1,847/96 in the first loss block and
1,786/81 in the second. Thus a greater *total* drop count does not explain the
slow block. Drop timing, transport state and host scheduling remain unresolved.
Recorded involuntary context switches rose from 79 to 222; voluntary switches
were 1,751/1,742 and user-plus-system CPU time was 0.15/0.16 seconds. These are
whole-job resource counters, not per-trial scheduler measurements or gateway
CPU attribution. They neither prove nor rule out scheduler interference.

Reproduce each block's time bins with this command, replacing BLOCK by
`loss5-block1` or `loss5-block2`:

```sh
jq '[range(0;200;20) as $i | {first_trial:$i, median:(.samples_us[$i:$i+20]|sort|(.[9]+.[10])/2)}]' measurement/BLOCK/everudp/result.json
```

The next useful diagnostic is a bounded, explicitly instrumented reproduction
with target-scoped scheduler events aligned to the public monotonic intervals,
not an uninstrumented retry seeking a better median. Preserve a non-reproduction
too. The existing scheduler capture recipe and private perf executable are
available, but its floor-specific analyzer cannot be presented as validating
the production path without adapting and testing the correlation boundary.

## Identity and scope

`measurement/` preserves the original collector, frozen plan, build provenance,
four block command receipts/manifests, raw responses and timing boundaries,
qdisc accounting, environment records, summary and MEASURED receipt. Source,
artifact hashes, fixed schedule, affinity/governor and full seals were checked.
Run `sha256sum --check --quiet SHA256SUMS` inside `measurement/`. Its original
root seal hash is
`2456e55eac98cd9ce625334fc34cca8ae7dea6023c2fb6f349fa88deca655423`.
Do not normalize raw output whitespace.

The exact release build remains outside git at
`/tmp/everudp-backpressure-build-981975b`; provenance SHA256 is
`958a396ec2bcabed34967d3b1b2f1baf1fc26446ef1be39c891194b8a04d840f`.
Controls remain pinned to zmosh UDP
`dfc8395b5edcd237bf82712fbde879c6e8be7dfa` and QUIC
`21db4a4de6040b254531f2131b6f1c0cd146a7a1`. The QUIC adapter includes the
enqueue-before-poll correction; the old biased 10 ms control is not used.

Real QUIC tests separately prove output/cancellation responsiveness under
blocked input, bounded final delivery, and exact partial-record recovery.
All-feature focused tests and strict Clippy passed. The complete all-feature
everudp library/integration command also passed, with the installed-application
test explicitly ignored; that application gate remains outstanding.

This archive does not replace final six-block-per-cell confidence-bound gates,
network outage/security/resource/application qualification or independent
exact-candidate review. No acceptance threshold changed. Release/fleet remain
separate; production acceptance is still unproven.
