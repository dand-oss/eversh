# Corrected zmosh QUIC adapter comparison: MEASURED

Candidate: `5c065b4024b6c14a117ebed516500b5a020b467f`.
Tree: `e5f78f0145748ffa92e360b0dc02f5e8341acd81`.
Bead: `eversh-5fc.54`. This is diagnostic evidence, not production qualification.

The benchmark-only zmosh QUIC bridge previously queued accepted input after
pumping the transport, then polled for up to 10 ms before pumping again. The
candidate drives the transport immediately after successful input enqueue.
WouldBlock preserves pending input and normal polling; other errors propagate.
The frozen zmosh source and transport profile are unchanged. A focused Zig test
passed against that frozen source, and the full exact-source release build passed.

| Symmetric loss | Implementation | Median | p95 |
| --- | --- | ---: | ---: |
| 0% | everudp | 620 us | 1,000 us |
| 0% | zmosh original UDP | 425 us | 852 us |
| 0% | zmosh QUIC, corrected bridge | 629 us | 1,146 us |
| 5% | everudp | 655 us | 4,514 us |
| 5% | zmosh original UDP | 435.5 us | 50,638 us |
| 5% | zmosh QUIC, corrected bridge | 652 us | 27,423 us |

Each value pools 400 observations from two reversed-order blocks of 200.
All 2,400 responses passed the transcript and public timing-boundary checks.
Medians use the midpoint of the central pair; p95 uses nearest rank.
Source, artifacts, CPU affinity/governor, fixed schedule, qdisc packet accounting
and evidence seals were checked. This does not supply the six blocks per cell,
confidence bounds, reliability/security gates or independent production review
required for final acceptance.

The earlier archived comparison at `20260906-m6-9989564cff6e` reported zmosh QUIC
medians of 10,757/10,864 us. Those measurements include the old bridge behavior
and must not be used as clean transport-latency attribution. The corrected run
strongly supports the adapter-delay explanation, but is not a same-seed paired
ablation assigning every microsecond to that bug. Preserve the earlier receipts.

Original zmosh UDP still wins the median in this run: everudp/UDP ratios are
1.459 and 1.504. Everudp has a better loss tail, but that does not waive the
frozen median gate. No universal QUIC latency floor is established. The separate
native reliable-stream experiment remains NOT-ADOPTED; this correction does not
change its original-UDP comparison or authorize its production integration.

## Reproduction and identity

`measurement/` preserves the complete collector output and its original seal,
including collector source, frozen plan, command receipts, build provenance,
four block receipts, raw samples, packet counters and summary. Verify with
`sha256sum --check --quiet SHA256SUMS` inside that directory. Preserve raw bytes
and whitespace. Its original root seal hash is
`51c9dae27f74c1c4ac652751332f9d3f49f6814d3aec62cdc6029defafff48c4`.

The build binaries and logs remain at
`/tmp/everudp-bridge-corrected-build-5c065b4`, outside git. Build provenance hash:
`26946fc3f1af7f49c63b0277f514223d0b7a58e6935a3020a96420cfdbab14ed`.
Pinned zmosh sources are UDP `dfc8395b5edcd237bf82712fbde879c6e8be7dfa`
and QUIC `21db4a4de6040b254531f2131b6f1c0cd146a7a1`.

The full production goal remains open. Release and fleet rollout are separate.
