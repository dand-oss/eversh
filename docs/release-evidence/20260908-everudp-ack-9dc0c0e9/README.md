# ACK coalescing screening: fewer packets, median improvement, loss-tail cost

Status: **NOT_ADOPTED; not release qualification.** Source
`9dc0c0e9f38b660a0efbe7f694e8e8c648415e3a`, clean build, identical five control
binaries. Both candidates enable application-task-spike and stream-delivery-spike.
A uses every-packet/1 ms QUIC ACK policy; B additionally enables
quic-ack-coalescing-spike (every-other-packet/5 ms). Application acknowledgements,
replay, stream delivery, encryption, RTT and GSO settings are unchanged.

The frozen schedule ran A/B/B/A separately at 0% and 5% symmetric loss, 200
observations per implementation per block, 100 ms inter-trial gap, CPUs
40/42/44/46, tracing disabled. All eight blocks and all 4,800 public responses
passed byte-exact validation. No failed block was dropped or retried.
This is only 400 observations per mode/implementation/cell, not the frozen
1,200-observation qualification protocol. Pooled nearest-rank quantiles are
descriptive, not confidence bounds or proof of statistical significance.

| Loss | Mode | everudp p50/p95 (us) | UDP zmosh p50/p95 (us) | QUIC zmosh p50/p95 (us) | everudp egress attempts/echo |
| --- | --- | --- | --- | --- | --- |
| 0% | A | 583 / 953 | 417 / 832 | 648 / 1138 | 6.0400 |
| 0% | B | 502 / 891 | 408 / 764 | 611 / 1132 | 5.0175 |
| 5% | A | 605 / 3912 | 419 / 50629 | 683 / 52223 | 6.9525 |
| 5% | B | 551 / 8357 | 416 / 50778 | 668 / 48029 | 6.4000 |

The ACK policy is a measurable latency/traffic lever, but this combined threshold
and delay change does not establish which component causes each effect. B's
median is still about 23% above matched original UDP zmosh without loss and 32%
above it with loss. Its loss p95 is over twice A's. Control drift and two blocks
per mode limit inference. Do not adopt this profile or rerun full qualification
unchanged on the strength of its lower median alone.

Both B blocks show the same direction: no-loss p50 491/508 us versus A
575/585 us; loss p50 544/566 us versus A 602/612 us. Both B loss p95 values
(7971/8541 us) exceed both A values (3912/3911 us). An independent read-only
Luna audit reproduced every seal/oracle check, pooled numbers and configuration
mapping and agreed that adoption is not justified. Its proposed next diagnostic
is ACK-delay/retransmission timing under loss; the present capture has tracing
disabled and cannot establish that timing causally.

Egress attempts are the manifest's root-netem sent-plus-dropped deltas over the
post-warmup/pre-teardown measurement window, divided by public trials. They are
not a decoded count of pure ACK packets and may include other protocol traffic.

Reproduce: `python docs/release-evidence/20260908-everudp-ack-9dc0c0e9/analyze.py`.
It validates all block seals, public response oracles, clean source identity,
candidate features, same-control hashes, build provenance hashes, schedule hash,
seeds and candidate order, then prints all per-block and pooled results.
The root SHA256SUMS seals the complete archive; nested block seals are retained
verbatim. The original schedule.sha256 contains its original absolute temporary
path; the analyzer verifies the relocated script by the frozen digest instead.

Raw measurements and build/control provenance are preserved. Binaries remain in
the local sealed build directories named in the receipts; hashes, not binaries,
are archived here. Production defaults remain unchanged. Exact-SHA reliability,
security and independent review for an accepted performance candidate remain
required. Refs: eversh-5fc.69.
