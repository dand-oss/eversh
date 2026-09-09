# Packet diagnostic capture protocol

Frozen source: commit 1732800, clean detached clone
`/tmp/everudp-packet-1732800-source.WoITAq`.
Build: `/tmp/everudp-packet-1732800-build`, canonical build-performance.sh,
features `cli,path-packet-diagnostics`, ordinary release fat LTO profile.
Require completed provenance and binary hashes before capture.

First run is capture validation ONLY: 20 measured trials, 100 warmup,
0% loss, seed 210900001, normal production candidate set ordered
everudp,zmosh-udp,zmosh-quic. Output:
`/tmp/everudp-packet-1732800-capture-check`.
All three tracing flags enabled. This is explicitly short/nonqualification.
Require complete exact transcripts and all measured input/output packet joins.
If any join fails, retain evidence and diagnose; do not discard failed trials.

After valid capture, collect four alternating on/off pairs per cell (0%,5%),
200 measured trials each candidate per block, same frozen diagnostic binary.
Seeds: 210910001 + 100 * cell_index + pair_index, server adds 1000003.
The on/off blocks within each pair use the same seed. Pair orders alternate
on/off, off/on; candidate order rotates across pairs. Freeze artifact hashes
and explicit expanded schedule before executing. No builds, agents or analysis
during timed blocks. Preserve qdisc counters, affinity and governor records.

The on/off comparison estimates active instrumentation overhead only; it does
not establish that the diagnostic-enabled binary has ordinary-build performance.
No product parity or latency improvement claim can use these diagnostic blocks.
Packet durations describe completion packets, not exclusive CPU cost or pure
network time. Compare per-block distributions, not sums of independent medians.
If tracing substantially perturbs behavior, report the limitation and narrow
claims instead of treating observed component timings as ordinary-build costs.

Production qualification retains all existing thresholds and exact-SHA gates.
