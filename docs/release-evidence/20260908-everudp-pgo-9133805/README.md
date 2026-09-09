# PGO candidate: numerical gates fail; not adopted

The profile-guided candidate fails the unchanged comparison against original UDP
zmosh in both loss cells. It passes against QUIC zmosh. All 7,200 exact-transcript
observations pass, but this is an experiment, **not release qualification**.

| Symmetric loss | everudp p50 / p95 (us) | UDP zmosh p50 / p95 (us) | QUIC zmosh p50 / p95 (us) |
|---|---:|---:|---:|
| 0% | 586 / 984 | 406 / 821 | 653 / 1179 |
| 5% | 590 / 4118 | 435 / 50679 | 678 / 51795 |

Against UDP zmosh, median ratios are 1.44335 and 1.35632; upper-95 median
ratios are 1.47160 and 1.39720. The no-loss upper-95 p95 ratio is 1.24559;
the 5% loss p95 upper bound passes at 0.08325. Thus the original thresholds
(median point <=1.00, median upper-95 <=1.10, p95 upper-95 <=1.00) still fail.

This is enough to reject PGO as a sufficient solution, not to measure its isolated
causal effect: the non-PGO build was not measured in a paired run. Comparing
absolute times with older runs would mix compiler effects with machine/run drift.
Do not adopt PGO, retrain against these evaluation results, lower thresholds,
or repeat the unchanged candidate looking for a favorable run.

## Identity and method

- Runtime source: `eecddf15f4d8eb72f0f887cc5ec6ac5bae614bc5`, clean tree
  `a0a4cde8acdcd0e2ef45d750d1184d89a689d250` at `/tmp/eversh-pgo-source`.
- Optimized binary SHA256:
  `913380578f08504470e0265a581844761c24e0afdf3c64330634a88fbc6be607`.
- PGO training was frozen before evaluation: process lifecycle tests plus the
  fixed local terminal workload and two-netns 0%/5% loss workloads. Training
  seeds were 20100001 and 20105001; server seeds add 1000003.
- Only the production build-ID profile was merged. Test-runner counters were
  excluded. Raw/merged hashes, build flags and training receipts are in `training/`.
- Comparison runner: commit `525db07`; six candidate-order permutations per cell,
  200 observations per candidate/block, 1,200 per implementation/cell,
  seeds 920001..920006 and 930001..930006, 20,000 bootstrap resamples,
  CPUs 40,42,44,46. No concurrent project jobs during timing.
- Controls: frozen UDP `dfc8395b5edcd237bf82712fbde879c6e8be7dfa` and QUIC
  `21db4a4de6040b254531f2131b6f1c0cd146a7a1`, reused from the sealed
  `/tmp/everudp-fairness-build-bd53692` artifact bundle after digest verification.
- Original result: `/tmp/everudp-pgo-comparison`, terminal `COMPARED`, numerical
  gates false, qualification false. All twelve blocks completed, without retry.

The unchanged analyzer used `--allow-smoke` solely to permit experimental build
identity: sample counts, order permutations, loss cells, bootstrap count and
thresholds remain full-sized and frozen. No `provenance.json` was fabricated;
the ordinary release qualifier rejects this experimental bundle. The analysis
correctly records `exact_release_evidence: false` and `qualification_outcome: FAIL`.

## Archive verification

`measurement/` retains all block evidence and nested seals, the original analysis
and experiment receipt. Only the six executable artifacts are omitted. Their
hashes remain in the receipt and every block manifest. The original root inventory
is preserved as `original-SHA256SUMS`; it is not a complete local seal because
those binaries are omitted. The archive's outer `SHA256SUMS` covers all retained
files, including the nested seals and this explanation.

Original root-seal SHA256:
`88b8c2553ee9cec7b350361046d714aa35db945d1f73bc89866ed2f608f24047`.
Original experiment-receipt SHA256:
`0e94687881a823d7558e0f4f49876c8b9de82656397df014a7aff1fdf147ae7e`.

Reanalysis uses the twelve archived `measurement/loss*-*` directories with
`analyze-performance.py --trials 200 --bootstrap 20000 --allow-smoke` from the
runtime source SHA. Stored absolute paths name the original measurement location.

Production performance, full exact-SHA reliability/security/application gates and
independent final review remain incomplete. This negative experiment does not
close the product goal.
