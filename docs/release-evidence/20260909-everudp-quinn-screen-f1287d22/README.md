# Quinn engine screen: NOT ADOPTED

Bead eversh-5fc.78. Both clean builds used candidate
`f1287d22d4e0e7591d83792e1e2fb951ac7f9e8c` and the same production application
sources. A selects production NoQ; B selects the isolated Quinn 0.11.11 package.
Both use only `cli`, fat LTO, one codegen unit, opt3, unwind and no tracing.
The five sealed fixture/control binaries are identical across builds.

All eight predeclared blocks and 4,800 exact responses passed. There were no
replacement blocks, discarded observations or retries. The ABBA schedule used
200 observations per implementation per block, 100 ms gaps, CPUs 40/42/44/46,
0% and 5% symmetric loss, and the frozen seeds/order retained in the runner.

Nearest-rank pooled p50/p95 in microseconds; 400 observations per mode/cell:

| Loss | Engine | everudp | UDP zmosh | QUIC zmosh |
|---|---|---:|---:|---:|
| 0% | NoQ | 586 / 1023 | 405 / 738 | 625 / 1112 |
| 0% | Quinn | 536 / 978 | 396 / 736 | 627 / 1114 |
| 5% | NoQ | 578 / 3928 | 439 / 50670 | 642 / 27160 |
| 5% | Quinn | 567 / 3955 | 424 / 50742 | 627 / 51853 |

Quinn's median ratios against its own frozen UDP controls are 1.3535 at zero
loss and 1.3373 at 5% loss. Both miss the unchanged 1.00 point-estimate ceiling;
its zero-loss p95 also exceeds the UDP control. The better loss tail does not
waive either latency requirement. This screen does not pass production gates.

The zero-loss Quinn median is lower than NoQ's in this screen, but that is not
a claim that switching engines delivers parity. The loss-cell difference is
small and controls vary: NoQ's last loss block has a 650 us median versus
555 us in its first block. Every block remains in the analysis. No causal
confidence interval or tuning/adoption claim is inferred from pooled medians.

Conclusion: the authorized bounded engine comparison does not justify replacing
NoQ. Quinn remains isolated, and NoQ remains the default. Do not rerun an
unchanged candidate seeking favorable blocks, or use the selected feasibility
checks as full release qualification. No release, merge, push, tag or rollout.

Reproduce all block and pooled values from the repository root:

```sh
python3 -B docs/release-evidence/20260909-everudp-quinn-screen-f1287d22/analyze.py
```

The analyzer checks all eight raw capture seals, exact source/build identities,
engine/profile selection, shared controls, runner hash, schedule and transcript
oracle. The original production acceptance requirements remain outstanding.
