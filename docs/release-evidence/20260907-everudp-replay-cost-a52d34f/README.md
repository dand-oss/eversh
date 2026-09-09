# Client replay bookkeeping attribution (not qualification)

Source: `a52d34f07ccac4fc6041a16a103db61f394b769e`, tree
`b0113eb11d345441b88a0970301cd96ed23a5b9f`. Worktree was clean at build and run.
Example unit test, strict example Clippy, workspace formatting and diff checks passed.
Independent Luna source review accepted the diagnostic's limited scope.

Build command:

```sh
CARGO_TARGET_DIR=/tmp/everudp-replay-cost-measure-target cargo build --locked --release -p everudp --example replay-cost
taskset -c 40 /tmp/everudp-replay-cost-measure-target/release/examples/replay-cost
```

Build exited zero (47.79 seconds); measurement exited zero. CPU: Intel Xeon
E5-2697 v2 @ 2.70GHz. CPU40 governor was `schedutil` before and after, unchanged.
Rustc 1.95.0 (59807616e 2026-04-14), Cargo 1.95.0 (f2d3ce0bd 2026-03-21),
both source-tarball builds. Cargo.lock SHA256:
`036f87a810d709762a25451d5442bb1d55de6fd1080e45a255676d101d5e322b`.
Executable SHA256:
`8172be49b2eae20e4f5a83d08d96937240fbc1f94a3a653bcd5249bbbc1919e5`.

After 10,000 warmup cycles, six batches of 1,000,000 cycles measured
187.94–198.04 ns per cycle (batch means). All byte, sequence, drained-queue and
control-storage-signature assertions passed. The cycle exercises actual client
input queue/copy/ACK retirement and output staging/accepted-sink bookkeeping/
output ACK queue/copy/retirement. It traverses the real 4 MiB input ring and
64 KiB control ring repeatedly.

This does not support a large local replay-bookkeeping explanation for the
previous end-to-end latency gap. Next attribution should examine the real
gateway/QUIC/I/O scheduling path, not remove replay ownership or weaken ACK rules.
Source inspection also found only record-sized clearing on healthy retirement;
full-buffer clearing belongs to restart/drop paths.

Limitations: diagnostic assertions are included in timing; stdout acceptance is
simulated, not an actual write. No QUIC, gateway fanout, PTY, network or scheduler
latency is measured. These are batch means, not keystroke percentiles or a global
cost upper bound. Storage signature stability is not an allocation-count proof.
The run uses the existing governor, not the frozen production benchmark profile.
Separate ACK records do not establish separate UDP packets. No production code
or qualification threshold changed. Production qualification remains incomplete.

`results.jsonl` transcribes the complete six JSON lines emitted by this run.
