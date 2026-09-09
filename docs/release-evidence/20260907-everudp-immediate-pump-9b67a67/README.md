# Immediate native pump service: NOT ADOPTED

Candidate `9b67a67a4834daea193af4e6a4270e6155dac048`, bead `eversh-5fc.30`.
This is a failed disposable floor experiment, not production qualification.
The single-owner feature remains off by default. No production integration is authorized.

The candidate drives accepted input immediately, checks application events before
blocking, and removes redundant zero-time waits while retaining bounded terminal
polling. It was motivated by the prior measured native polling costs, not by a
change to the frozen protocol, security profile, retry interval, or thresholds.

Four preregistered blocks completed: 200 trials per implementation per block,
100 ms gaps, reversed implementation order, and the frozen zmosh UDP control.
There were 1,600 measured responses and zero transcript failures. Separate
20-trial process checks at 0% and 5% loss passed but are not counted here.

| Symmetric loss | Floor p50 µs | zmosh p50 µs | Ratio | Packet-attempt ratio |
| --- | ---: | ---: | ---: | ---: |
| 0% | 403.5 | 391.5 | 1.030651 | 1.000620 |
| 5% | 389.5 | 399 | 0.976190 | 1.090429 |

Both cells miss the unchanged p50 ratio ceiling of 0.90. Every block and
pooled cell passes the 1.60 packet-attempt ceiling. The unchanged analyzer
reports quantitative FAIL and an INVALID overall receipt because required
allocation/component attribution is incomplete. Neither authorizes adoption.
Independent recomputation confirmed all four block seals, candidate/control
identities, per-loss pooled medians, nearest-rank p95 values, packet totals,
and the failed quantitative conclusion. The reproduction wrapper separately
checks those totals against the archived raw qdisc counters.

Only `cli,reliable-datagram-spike,floor-single-owner` was enabled. Diagnostics,
send-fast-path, and ACK inline-storage experiments were off. The native example
rejects trace requests. The previous candidate a9321d0 was not run in these
blocks, so comparison with its historical medians is not a causal measurement
of this change's effect. The removed waits do not establish that the remaining
latency is in polling; further attribution must follow the current call path.

Before the build, 11 example tests, 65 focused library/protocol tests, native
clippy with warnings denied, the legacy example check, formatting and diff
checks passed. A narrow independent pre-experiment review found no blocker or
major finding. This is not the final independent production review. MTU/error
injection, hostile traffic, extended resource/fairness checks, and full
production reconnect/security/performance qualification remain outstanding.

## Reproduce

From this directory:

```sh
python3 -B analyze.py
sha256sum -c SHA256SUMS --quiet
```

The wrapper validates block identity, build provenance, seeds/order, sample
count, and raw root-netem sent-plus-dropped packet accounting, then executes
the archived unchanged analyzer. Original block seals and artifact hashes
are retained. No credentials or binaries are included.
