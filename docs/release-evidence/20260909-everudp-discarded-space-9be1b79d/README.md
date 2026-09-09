# Discarded-space shortcut: INCONCLUSIVE, NOT ADOPTED

Bead eversh-5fc.81. Exact candidate `9be1b79d25c5fb3347b9335c6899c9f3a7e1b932`.
The default-off shortcut skips non-Data spaces only when their encryption keys
are absent, loss probes are zero, and scheduling is not for an abandoned path.
Data takes its original path; handshake, loss-probe and abandonment fallback
behavior is unchanged. No crypto, replay, congestion or admission rule changes.

Verification: 393 protocol tests passed, including exhaustive guards and a
real client/server fixture invoking the original skipped path and checking no
output, packet-number, pending retransmission or statistics changes. All 66
selected everudp tests and strict Clippy passed; 28 build-option tests passed.
The direct fixture was observed RED before its helper existed. An intermediate
compile error using `stats` as a field was corrected to the actual `stats()` API.
Tests ran in isolated copies excluding unrelated working-tree changes; logs
are retained under `checks/`. These checks are not final qualification.

Both clean release builds passed. A uses `cli`; B adds `discarded-space-spike`.
Both use fat LTO, one codegen unit, opt3/unwind and identical five sealed fixture
and control binaries. Four zero-loss ABBA blocks were preregistered as an
initial screen, with 200 trials per candidate, seeds 216000001..004, CPU affinity
40/42/44/46 and 100 ms gaps. All 2,400 exact responses passed. Every block is
retained; no replacements or discarded observations.

Nearest-rank p50/p95 in microseconds:

| Block | Mode | everudp | UDP zmosh | QUIC zmosh |
|---|---|---:|---:|---:|
| 0 | A | 562 / 979 | 353 / 623 | 568 / 744 |
| 1 | B | 607 / 1096 | 379 / 837 | 511 / 703 |
| 2 | B | 1957 / 7875 | 398 / 800 | 590 / 1098 |
| 3 | A | 2785 / 7551 | 1023 / 6531 | 3044 / 7630 |
| Pooled | A | 820 / 6886 | 435 / 6029 | 764 / 6740 |
| Pooled | B | 782 / 7250 | 388 / 803 | 548 / 1047 |

The late blocks show severe variation, including both controls in the final
baseline block. The lower pooled B median is therefore not evidence of a
causal speedup. Its ratio against its own UDP median is 2.015, and even the
first B block misses parity. No 5% loss or full qualification run is justified
by this initial screen. The shortcut remains disabled by default.

All project builds and agents were stopped before measurement. Two unrelated
compiler processes observed during preflight finished before the screen began.
That is not proof of a quiet host throughout the capture. Afterward, read-only
cgroup checks showed unlimited CPU quota and zero cumulative throttling in the
session and its ancestors, with host CPU pressure present. These after-the-fact
checks cannot establish the cause of the captured drift. Do not relabel blocks
invalid or rerun the unchanged candidate for favorable numbers.

Before another latency experiment, establish contemporaneous scheduler/host
activity evidence and an appropriate measurement environment. This does not
alter the frozen product gates or make the earlier failed qualification pass.

Reproduce from the repository root:

```sh
python3 -B docs/release-evidence/20260909-everudp-discarded-space-9be1b79d/analyze.py
```
