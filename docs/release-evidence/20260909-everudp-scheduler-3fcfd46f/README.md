# Client read-to-send scheduler diagnostic

Bead eversh-5fc.73. Runtime 4221bc1497a4fa0b1cfcbd688b47bd77785ebb55;
harness 3fcfd46fd328c098405691928b82deec3dc96abf. Reuses the clean build with
cli,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike.
No runtime or default-profile change. This is external instrumentation, not qualification.

Two zero-loss blocks, seeds 213100011/213100012, E/U/Q then Q/U/E,
200 responses per implementation per block, CPUs 40,42,44,46, 100ms gaps.
All 1,200 exact-response checks pass. Each everudp and original UDP zmosh client
has a ten-second PID-filtered syscall and sched_switch capture; QUIC zmosh is
an untraced control. No builds or agents overlapped the measurements.

| Read exit to first successful send entry | Forward | Reverse |
|---|---:|---:|
| everudp median (microseconds) | 77.323 | 85.629 |
| UDP zmosh median (microseconds) | 12.499 | 12.243 |
| Included everudp / UDP windows | 99 / 97 | 99 / 97 |

Every included window has zero observed off-CPU time. All remaining trial rows
are retained as outside capture coverage; no in-window malformed or ambiguous
row is silently discarded. These observations rule out descheduling within
these measured intervals, not kernel execution, interrupts or tracing overhead.
Scheduled wall time is not exclusive CPU time. First successful send is not
proof that the packet carries the trial input. This is not remote PTY timing or
proof of an intrinsic QUIC cost. Outer public-send/read medians are also reported
by the analyzer, and independent medians must not be added.

The original seed 213100001 attempt failed during export because perf pads the
scheduler event name with spaces. Its INVALID receipt is retained; reverse seed
213100002 never ran. A regression test reproduced that error, and the parser
repair accepts display padding without weakening body validation. The repaired
attempt used the explicitly recorded new seed pair above, not silent replacement.

Raw perf remains private in /tmp/everudp-scheduler-3fcfd46f-forward and its reverse
counterpart (failed raw: /tmp/everudp-scheduler-c9202cb3-forward). Only scalar
exports, selected capture metadata and logs are archived; no comm names, payloads,
pointers or raw perf are included. Measurement seals, identities, clock, filters,
event attributes, loss logs and response oracle are checked by the analyzer.

Reproduce from repository root:

```sh
python3 -B docs/release-evidence/20260909-everudp-scheduler-3fcfd46f/analyze.py
```

Status: DIAGNOSTIC. Production performance gates remain failed. The next useful
attribution target is work on the scheduled client read-to-send path, not another
scheduler-tuning experiment or a repeat of the negative immediate-flush probe.
