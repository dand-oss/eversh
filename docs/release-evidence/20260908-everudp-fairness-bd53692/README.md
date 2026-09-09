# Full frozen performance gate: FAIL

Candidate `bd53692a23e498408f55ee30b03309017a923a4c`, clean tree
`629c6efb4cd6f8c8b960f3d82d2578ead498561b`, ordinary `cli` release build.
This candidate includes the client backpressure and gateway fairness repairs.
No diagnostic trace or experimental transport feature was enabled.

## Verdict

The full gate **fails**. Both comparisons against QUIC zmosh pass, but both
comparisons against original UDP zmosh fail. All 7,200 exact-response checks pass.

| Loss | everudp p50 / p95 (us) | Original UDP zmosh | QUIC zmosh |
| --- | ---: | ---: | ---: |
| 0% | 550 / 957 | 382 / 828 | 574 / 1041 |
| 5% | 562 / 3876 | 387 / 50626 | 597 / 52218 |

Against original UDP zmosh, p50 ratios are 1.4398 and 1.4522, with upper-95
bounds 1.4709 and 1.4829. These miss both the <=1.00 point gate and <=1.10
upper-bound gate. At zero loss the p95 upper-bound ratio is 1.1955, also failing
its <=1.00 gate. At 5% loss the p95 upper-bound ratio is 0.0783 and passes.

Against QUIC zmosh, p50 point ratios are 0.9582 and 0.9414; upper-95 bounds
are 0.9754 and 0.9597. The p95 upper-95 ratios are 0.9555 and 0.0761.
All required comparisons must pass, so those successes do not permit release.

The fairness patches are supported by their behavioral RED/GREEN tests, but
this is not an isolated before/after experiment proving their latency effect.
The remaining median gap to original UDP zmosh is 168 us without loss and
175 us with loss. Do not attribute that gap entirely to QUIC from this comparison.

## Frozen run

- Source worktree: `/tmp/eversh-fairness-bd53692`.
- Exact build: `/tmp/everudp-fairness-build-bd53692`.
- Original measurement: `/tmp/everudp-fairness-performance-bd53692`.
- Command: `qualify-performance.sh EXACT_BUILD OUTROOT 200`, from this SHA.
- CPUs: 40,42,44,46; performance governor checked by the existing harness.
- Six candidate-order permutations per cell, 200 observations per implementation
  per block: 1,200 per implementation per cell. Cells: 0% and 5% symmetric loss.
- Seeds: 920001 through 920006, then 930001 through 930006.
- Baselines: UDP `dfc8395b5edcd237bf82712fbde879c6e8be7dfa` and QUIC
  `21db4a4de6040b254531f2131b6f1c0cd146a7a1`, including the corrected adapter.
- Existing block-stratified 20,000-resample analysis; unchanged thresholds.
- No concurrent project builds, tests, agents or analysis during measurement.
- Runner exited 1 after sealing the FAIL receipt. No retry or omitted block.

## Artifact verification

`measurement/` is the unchanged complete gate output, including build provenance,
artifact identities, all twelve blocks, analysis and receipt. Original root-seal
SHA256: `346027fb2299870c1d4ad4055c37cccd3478564ce3c51e92ccdc593843e73db2`.
Receipt SHA256: `4e37523e6596f04928dfea779c61f1b238a63aa168cd5f9e66ed94cea47de577`.
The copied root seal and every nested block seal were verified. The outer archive
seal additionally includes this explanation and the nested seals.

From the repository root, verify the unchanged gate seal:

```sh
(cd docs/release-evidence/20260908-everudp-fairness-bd53692/measurement && sha256sum --quiet -c SHA256SUMS)
```

Reanalysis uses `crates/everudp/tests/net/analyze-performance.py` at the candidate
SHA with the twelve recorded block directories, `--trials 200 --bootstrap 20000`.
Stored block paths identify the original run; moving the archive does not change
its samples or hashes.

## Consequence

Do not ship, lower thresholds, substitute the QUIC-only comparison, or repeat this
unchanged gate seeking a pass. Further performance work must target the remaining
median overhead with evidence-supported changes. The exact-SHA reliability,
security, installed-application and independent final-review gates also remain
outstanding; this receipt is not acceptance of the complete product.
