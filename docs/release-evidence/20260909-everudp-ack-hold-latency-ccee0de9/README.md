# ACK-hold latency screen: incomplete, not adopted

Bead eversh-5fc.83. Exact candidate ccee0de938a043a90795a21c27ae9f5c4b9d3985,
same sealed NoQ builds as the packet screen. A is cli; B adds only
input-ack-hold-spike. Shared controls and release profiles are unchanged.

The frozen runner scheduled ABBA at 0% and 5% symmetric loss, 200 observations
per implementation per block, CPUs 40/42/44/46, 100ms gaps, seeds
221000001 + loss*100 + block. No traces, replacement blocks, or dropped results.
Five blocks completed with 3,000 exact responses. The sixth stopped before
measurement: QUIC zmosh failed to echo the warm-up marker and its bridge remained
in state=awaiting_ack. The measurement barrier never became available. The
runner exited 1; subsequent blocks were not run. Logs establish the startup
failure, not its underlying network/protocol cause.

Completed zero-loss cell, pooled nearest-rank p50/p95 microseconds (400 each):

| Mode | everudp | UDP zmosh | QUIC zmosh |
|---|---:|---:|---:|
| A | 623 / 1057 | 406 / 793 | 595 / 1131 |
| B | 616 / 1007 | 364 / 567 | 574 / 943 |

The 25% packet reduction from the preceding screen did not close the latency
gap: the changed build's median is 1.6923 times its UDP control. The 7us pooled
raw median difference is not a causal speedup claim; controls also changed.
All block values and host bookends are retained. The completed zero-loss cell
clears the permissive investigation cutoff, but the two-cell cutoff cannot be
evaluated, and none of this is production qualification. The first loss block
is retained but is not a complete A/B comparison.

Decision: leave the feature disabled and do not repeat unchanged measurements
or tune this timer further. Packet count alone is not the architecture fix.
The remaining task is to address the established processing-cost gap while
preserving QUIC, delivery, security and recovery; no alternative architecture
is claimed implemented or qualified here. Final frozen gates are unchanged.

Reproduce all completed results and verify their nested seals:

```sh
python3 -B docs/release-evidence/20260909-everudp-ack-hold-latency-ccee0de9/analyze.py
```

The root SHA256SUMS seals the incomplete block as well as completed artifacts.
The analyzer explicitly requires the recorded failed shape; it cannot report
PASS or treat missing blocks as successful. The original capture is
/var/tmp/everudp-ack-hold-ccee0de9-latency-measure; exec session86629 ended exit1.
No release, merge, push, tag or rollout.
