# Instruction-weighted leaves: transport work dominates

Bead eversh-5fc.80. Two preregistered opposite-order zero-loss blocks used
clean harness `f6ad8cb4e6be6ea7a53181542279118b7e680067` and the same sealed
NoQ production build `f1287d22d4e0e7591d83792e1e2fb951ac7f9e8c` as the preceding
hardware-counter comparison. Seeds were 215000001/215000002, 200 trials per
candidate, CPUs 40/42/44/46 and 100 ms gaps. Both blocks completed; all 1,200
exact responses passed. No production capture was replaced.

Selected client main-thread user instructions were sampled every 10,000 events,
with no inheritance, payloads, stacks or registers. Acknowledged enable/disable
brackets enclose the full measured window. Exact process, thread, binary,
affinity and clock identities were checked. Raw perf data remain private in
`/tmp/everudp-instructions-f6ad8cb4-block{0,1}`; sanitized samples and event
attributes are archived. The dummy perf event supplies mapping metadata, not
instruction samples. Unexpected, lost, out-of-scope and wrong-event records
are rejected by the decoder.

| Block | Client | All samples | Inside public send-to-accept windows | Outside |
|---|---|---:|---:|---:|
| Forward | everudp | 2,707 | 2,176 | 531 |
| Forward | UDP zmosh | 264 | 264 | 0 |
| Reverse | everudp | 2,707 | 2,173 | 534 |
| Reverse | UDP zmosh | 264 | 264 | 0 |

Everudp's leading sampled leaves across the full windows:

| Function | Forward | Reverse |
|---|---:|---:|
| NoQ `Connection::poll_transmit` | 261 | 268 |
| NoQ `Connection::space_can_send` | 136 | 112 |
| libc `memmove` | 122 | 120 |
| NoQ `RecvState::poll_socket` | 117 | 118 |
| tracing `Instrumented::poll` | 102 | 112 |
| NoQ Tokio UDP `poll_recv` | 92 | 88 |
| NoQ `RecvStream::poll_read_buf` | 77 | 71 |

The repeated distribution locates substantial work in transport scheduling and
receive handling. About one fifth of everudp samples fall outside individual
response windows, so the earlier aggregate counts must not be presented as
entirely critical-path work. Even inside those windows, sampled leaves are not
exclusive elapsed time: interrupts can skid, inlining affects symbols, and the
profiler perturbs execution. Percentages are not predicted speedups.

Next: inspect concrete repeated scheduling and receive setup operations before
choosing an experiment. Do not repeat the already-negative single-path shortcut
or infer that disabling security is warranted. No performance gate, transport
contract or production engine is changed by this evidence.

Synthetic preflight `/tmp/everudp-instruction-preflight-no0uc3tw` exposed record
finalization via TERM of its bounded sleep workload and the fixed-period sample
attribute layout. The implementation was corrected against the recorded tool
output; `/tmp/everudp-instruction-preflight-8fzoo3t5` then passed with 480 samples.
Both preflights remain separate from production evidence.

Reproduce from the repository root:

```sh
python3 -B docs/release-evidence/20260909-everudp-instructions-f6ad8cb4/analyze.py
```
