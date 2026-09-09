# Current production-client syscall comparison: diagnostic only

Bead eversh-5fc.72. Runtime source 4221bc1497a4fa0b1cfcbd688b47bd77785ebb55;
clean harness 1523210d5a017fcdd6a1cf88ce2b4b9766e284a3. Runtime profile is
cli,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike,
without pty-ready-spike or built-in tracing. The sealed A build from the PTY
readiness experiment and its five frozen controls are reused. The capture tool
checks that runtime/dependency source inputs have not changed between SHAs.

Two predeclared zero-loss blocks: seed 213000001 in E/U/Q order, seed 213000002
in Q/U/E order; 200 trials per implementation per block, CPUs 40,42,44,46,
100ms gaps. All 1,200 exact-response checks passed. During each block, a bounded
10-second external perf capture traces the main client PID for everudp and
original UDP zmosh. QUIC zmosh remains an untraced control. No other builds,
agents or analysis overlapped the run; the capture tool itself decodes its
bounded traces while finishing the enclosing diagnostic block.

The ordinary manifest's built-in tracing flags are false, but these blocks
**are externally instrumented** and cannot be used as qualification timings.

All 200 trial rows per traced client are retained. Forward capture includes
97 everudp and 97 UDP zmosh trials; reverse includes 99 and 97 respectively.
Every remaining row is outside the 10-second capture coverage. There are no
ambiguous, malformed or otherwise excluded in-window trials, and no lost events.
The predeclared minimum of 80 usable windows per client is met in both orders.

Independent wall-clock medians in microseconds:

| Boundary | Forward everudp | Forward UDP | Reverse everudp | Reverse UDP |
|---|---:|---:|---:|---:|
| Public send to stdin read entry | 263.604 | 75.012 | 95.552 | 74.235 |
| Stdin read exit to first successful send entry | 95.147 | 12.856 | 79.313 | 12.969 |
| Stdout write syscall | 10.433 | 4.498 | 4.952 | 4.236 |
| Stdout write exit to public acceptance | 298.396 | 20.557 | 20.361 | 18.430 |

The local read-to-send difference persists in both orders, supporting further
investigation of that client interval. The forward everudp outer handoffs are
much larger than the reverse run; do not suppress them, average them away or
claim these are normal uninstrumented latencies. These intervals include
instrumentation, scheduling and protocol work, not exclusive CPU cost. They
are independent medians and must not be added. A successful send syscall is an
observed edge, not proof that its packet carries that trial's terminal byte.
This capture does not measure remote PTY acceptance or echo readiness.

Production TerminalEdge duplicates terminal descriptors. Before and after each
capture the tool verifies the same-object aliases through procfs, exporting
only descriptor numbers, never argv or link destinations. Everudp's verified
terminal alias sets are [0,1,12,13]; UDP zmosh's are [0,1]. Input and output share
the benchmark PTY, so their sets overlap. The analyzer still requires exactly
one successful one-byte read and write per included trial; it does not guess
which arbitrary descriptor is stdin or silently fall back on malformed metadata.

Only scalar syscall exports, selected identity metadata and sanitized perf
logs are archived. Raw perf files remain private under
/tmp/everudp-production-io-1523210d-forward and the corresponding reverse
directory; they are not in this commit. Clock identity, one-thread PID identity,
event filters, monotonic perf clock attributes and capture seals are validated.

Reproduce from the repository root:

```sh
python3 -B docs/release-evidence/20260909-everudp-production-io-1523210d/analyze.py
```

Tooling validation: 17 capture-plan, descriptor-alias, scalar-export,
syscall-pair and trial-window tests pass. Capture-plan import first failed before
implementation, then passed. Review caught explicit null alias metadata being
treated as absent; it now returns UNKNOWN with regression coverage. Runtime,
security, delivery, replay and production defaults are unchanged.

Status: DIAGNOSTIC, not adoption, qualification or an intrinsic QUIC-versus-UDP
claim. The next source investigation is the current client read-to-first-send
path, informed by these common boundaries and the existing packet/protection
markers. Do not rerun the failed one-shot PTY probe or weaken ACK semantics.
