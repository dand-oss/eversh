# Packet-correlated diagnostic: not qualification

Source: `1732800e9fcb0116743f10801869d7addb81a8aa`, clean detached build.
Everudp binary SHA256: `196817e1f2e1ae3d61f507b9adfc9ae5f0bc377e77e98411abfa4ea1b603a1fc`.
Build provenance SHA256: `f3a9cb21ffbfabec4750df4da2178b20b43521de2d6a76e73c09e1de9a4f04f4`.
Features: `cli,path-packet-diagnostics`; release fat LTO, portable CPU profile.
Frozen controls remain UDP `dfc8395b5edcd237bf82712fbde879c6e8be7dfa` and
QUIC `21db4a4de6040b254531f2131b6f1c0cd146a7a1`.

## Result and limitations

The initial 20-trial capture passed exact transcripts and all 40 directional
packet/operation joins. Client/gateway recorders were valid, not overflowed.
The overhead schedule completed 14 of 16 blocks: 8,400 measured exact responses.
Two QUIC zmosh warmup failures produced no timing samples. Both halves of loss5
pair1 remained `awaiting_ack` before the measurement-start barrier; the cause
is unproven. Neither block was retried or replaced. Only previously unstarted
blocks continued with their original seeds/order. See `overhead/FAILURE.md`.

Completed pairs: four at 0% loss, three at 5% (pairs0,2,3). Each block has 200
observations per candidate, CPUs40,42,44,46, recorded governors and network
counters. The same diagnostic binary ran with tracing on and off. This measures
active instrumentation effects, NOT the cost of compiling diagnostics into the
binary. No confidence interval or zero-overhead claim is made. Missing pair1
limits inference at 5%; these are descriptive diagnostics, never qualification.

Original pre-registration mistakenly described the runner's `100` argument as
warmup trials. It is the 100ms inter-trial quiet interval. The canonical fixture's
existing warm_up routine was unchanged. Original notes and scripts are retained.

## Active tracing comparison

Nearest-rank p50/p95, microseconds, pooled only across complete pairs:

| Loss | Candidate | Tracing off | Tracing on | On/off p50 | On/off p95 |
| --- | --- | --- | --- | --- | --- |
| 0% | everudp | 650 / 1091 | 660 / 1106 | 1.0154 | 1.0137 |
| 0% | UDP zmosh | 419 / 814 | 420 / 820 | 1.0024 | 1.0074 |
| 0% | QUIC zmosh | 649 / 1146 | 660 / 1183 | 1.0169 | 1.0323 |
| 5%, incomplete | everudp | 675 / 4112 | 682 / 3992 | 1.0104 | 0.9708 |
| 5%, incomplete | UDP zmosh | 427 / 50659 | 448 / 50661 | 1.0492 | 1.0000 |
| 5%, incomplete | QUIC zmosh | 656 / 27568 | 666 / 27100 | 1.0152 | 0.9830 |

There are 800 samples per mode/candidate at 0%, 600 at 5%. Per-pair everudp
p50 on/off ratios were 0.9677,1.0248,0.9768,1.0621 at 0% and
1.0274,0.9408,1.0512 at 5%. Small pooled changes coexist with mixed block drift;
do not infer a precise instrumentation correction and subtract it from timings.

## Packet-stage observations

All 1,400 traced measured trials joined both input and output operations to exact
packet numbers, number spaces, datagram cookies and STREAM byte ranges. Replayed
ranges may span packets. The reported packet is the one completing the operation,
not necessarily its first transmission. No timestamp-proximity join is used.

No-loss pooled stage medians, microseconds (800 trials):

| Stage | Input | Output |
| --- | --- | --- |
| Operation reservation to completion-packet build | 54.588 | 11.346 |
| Packet build to successful send poll | 8.463 | 2.198 |
| Send poll to userspace receive | 101.401 | 30.886 |
| Userspace receive to authenticated packet | 21.818 | 6.126 |
| Authentication to accepted STREAM frame | 13.712 | 2.737 |
| STREAM frame to application preparation/staging | 87.727 | 38.722 |

Send-call duration medians were 48.773us input and 17.009us output. Those durations
overlap send-poll-to-receive and must not be added to it. The receiver can execute
before the sender records return from its send call. Userspace receive is after
socket-copy/segmentation, NOT wire arrival. These are wall-clock boundaries, NOT
exclusive CPU costs. Do not add independent medians to reconstruct a trial.

The available 5% trials show similar median asymmetry. Output reservation to
completion-packet build p95 is 3243.138us there, which can include waiting for a
retransmission; it is not a 3ms packet-building CPU cost.

This evidence localizes substantial input-side time after protocol receipt and
between send poll and userspace receipt, but does NOT prove why everudp is slower
than UDP zmosh. Scheduler dispatch, socket/kernel work, and cold-path CPU effects
remain candidate explanations. No production optimization follows from this
record alone. Next investigate those identified input-side intervals, with a
controlled intervention and unchanged delivery/security contract. Do not rerun
unchanged full qualification as a substitute for attribution.

## Reproduction and identity

`capture-check/` and `overhead/` preserve original artifacts; every completed
block's original SHA256SUMS was verified. Failed blocks have no fabricated PASS
manifest. `build/provenance.json` and build logs are retained; binaries are not
copied into this archive. Their hashes are bound by provenance and block receipts.
Scripts and original pre-registration are under `protocol/`. Top-level SHA256SUMS
seals the entire archive, including both failures. No product PASS is claimed.

Reproduce each traced block's packet analysis using the frozen source's
`crates/everudp/tests/net/analyze_packet_trace.py` with client/gateway path traces,
result.json and the two `.packets.json` sidecars. The output must equal the archived
packet-analysis.json. Schema checks, identity joins and every trial must pass;
do not drop individual unjoinable trials.
