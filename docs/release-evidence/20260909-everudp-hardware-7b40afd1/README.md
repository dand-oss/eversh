# Main-thread hardware counts: additional instruction work established

Bead eversh-5fc.79. Clean harness `7b40afd1e1b7d78ac8ae326781ba780f635bcd45`
measured the existing sealed production NoQ build from
`f1287d22d4e0e7591d83792e1e2fb951ac7f9e8c`. No runtime input changed.
Two preregistered zero-loss blocks used opposite candidate order, 200 trials
per implementation, seeds 214000001/214000002, CPUs 40/42/44/46 and 100 ms gaps.
Both completed; all 1,200 exact responses passed. No block was replaced.

Only the client main thread was counted; each client had exactly one thread
at both identity checks. Counters were grouped user-space cycles, instructions
and cache misses, with no inheritance and 100% running coverage. Acknowledged
enable/disable brackets enclose every measured public response window, exclude
warmup and teardown, and include inter-trial idle intervals. QUIC zmosh was
retained as an uncounted control. These are aggregate counts, not exclusive
per-keystroke CPU measurements or latency qualification.

| Block | Client | Instructions | Cycles | Cache misses |
|---|---|---:|---:|---:|
| Forward | everudp | 27,630,077 | 114,824,312 | 301,468 |
| Forward | UDP zmosh | 2,665,650 | 12,265,119 | 36,982 |
| Reverse | everudp | 27,335,215 | 109,787,470 | 244,943 |
| Reverse | UDP zmosh | 2,665,652 | 12,141,580 | 37,892 |

Everudp executes 10.37x/10.25x as many instructions and consumes 9.36x/9.04x
as many user cycles in this scope. Its IPC is slightly higher (0.241/0.249
versus 0.217/0.220), and its misses per instruction are lower. The data support
substantially more instruction work, not a claim of worse cache efficiency.
They do not locate the excess work, prove cache stalls, or establish how much
latency an optimization could remove. Previous elapsed-time and CPU-clock
profiles remain separate evidence; do not subtract their medians from these counts.

Next attribution should locate this additional instruction work before selecting
an architectural change. No engine change, threshold change, or release follows
from this diagnostic. Production performance qualification remains failed.

Collector preflight caught an installed perf detail: acknowledgements are
`ack\n\0`, not four-byte `ack\n`; the parser has a regression test. Failed
synthetic attempts were retained at `/tmp/everudp-counter-control-preflight-mv0gd2y4`
and `/tmp/everudp-counter-ack-preflight-z8wa9ox5`. Final synthetic preflight
`/tmp/everudp-counter-final-preflight-yha0kkfe` passed. No failed production
capture occurred. Control FIFOs are not archived; all regular capture files are.

Reproduce from the repository root:

```sh
python3 -B docs/release-evidence/20260909-everudp-hardware-7b40afd1/analyze.py
```
