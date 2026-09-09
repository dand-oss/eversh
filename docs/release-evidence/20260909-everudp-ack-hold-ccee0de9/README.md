# Input-ACK wire hold: packet cutoff PASS, not qualification

Bead eversh-5fc.83, plan `plans/everudp-input-ack-hold-experiment.md`.
Both clean release builds use ccee0de938a043a90795a21c27ae9f5c4b9d3985.
A is production NoQ `cli`; B is `cli,input-ack-hold-spike`. The compiler
profile and five sealed control/fixture binaries are identical. The default
transport remains unchanged; the feature only schedules an entirely unwritten
ACK whose input commit and queued control record already exist.

All four frozen ABBA blocks passed: 200 trials per implementation per block,
0% symmetric loss, 100 ms gaps, CPUs 40/42/44/46, fixed alternating orders and
seeds 219000001 through 219000004. All 2,400 responses passed exact delivery.
No blocks or observations were replaced, dropped or retried.

| Block | Mode | everudp packet attempts | UDP control | QUIC control |
|---|---|---:|---:|---:|
| 0 | A | 1608 | 802 | 2062 |
| 1 | B | 1202 | 801 | 2030 |
| 2 | B | 1201 | 811 | 2029 |
| 3 | A | 1609 | 803 | 2020 |

The A mean is 1608.5. B ratios are 0.747280 and 0.746658, reductions of
25.272% and 25.334%. Both clear the predeclared 15% reduction cutoff. Counts
are recomputed from netem sent-plus-dropped packet attempts in both directions;
observed drops are zero. They are not counts of application operations, and
they do not quantify saved CPU time. No claim about packet frame composition
is inferred from these uninstrumented receipts.

This PASS permits a separate bounded latency screen. It does not adopt the
feature, satisfy the frozen zmosh latency gates, or qualify production. Raw
latency samples and host/SMT snapshots remain in the archive but are not used
here to claim a speedup. Prior observed host drift remains relevant. All
eventual exact-SHA reliability, security, resources, observers, recovery,
performance and independent-review requirements remain outstanding.

Reproduce the packet counts and cutoff:

```sh
python3 -B docs/release-evidence/20260909-everudp-ack-hold-ccee0de9/analyze.py
```

The analyzer verifies source/build identity, feature isolation, shared controls,
schedule hash, raw block seals, exact transcripts, netem counts, and host
bookend placement. Root `SHA256SUMS` additionally seals this report and build
provenance. The retained preflight logs are default-library and strict feature
Clippy checks, not exact-SHA release qualification receipts.

Original builds: `/var/tmp/everudp-ack-hold-ccee0de9-{A,B}-build`.
Original measurement: `/var/tmp/everudp-ack-hold-ccee0de9-measure`.
Frozen runner SHA256:
`5848468d86380337067a21bd0acf8b8dce0549ba1dae824b9287b1e5e3fed0ee`.
No merge, push, tag, release or fleet rollout.
