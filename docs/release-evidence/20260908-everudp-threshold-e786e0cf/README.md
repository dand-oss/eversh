# Threshold-only ACK screening after packet-buffer repair

Status: **SCREENING ONLY; not adopted or release-qualified.** Both builds use
clean source `e786e0cf3ff9a1ff41177cd0f5ed56f69e3b490a` and the same five frozen control binaries. A enables
application-task-spike and stream-delivery-spike. B additionally enables
quic-ack-threshold-spike: ACK-eliciting threshold 1 instead of 0, with the same
1 ms requested maximum ACK delay. Application acknowledgements, ordered streams,
replay, encryption, GSO and initial RTT are unchanged. Diagnostics are disabled.

Both builds include `e8341f1b`, which fixes a gateway panic: ACK_FREQUENCY used to
encode without checking the remaining packet capacity. The fix preserves the
pending frame until a complete frame fits, before consuming it or advancing its
sequence. The opt-in threshold profile exposed the panic during handshakes;
changing the client timeout would only have hidden its symptom. Validation of
that repair included 391 protocol tests, a bounded stream test, 60 replacement
generations, and everudp integration. These are not a new full-release receipt.

The frozen schedule ran A/B/B/A separately at 0% and 5% symmetric loss, 200 trials
per implementation per block, 100 ms inter-trial gap, CPUs 40/42/44/46. Every
block passed, with all 4,800 byte-exact public responses and no failed-block
retries. There are only 400 observations per mode/implementation/cell, not the
frozen 1,200-observation qualification protocol. Quantiles below use nearest rank;
they are descriptive, not confidence intervals.

| Loss | Mode | everudp p50/p95 (us) | UDP zmosh p50/p95 (us) | QUIC zmosh p50/p95 (us) | everudp egress attempts/echo |
| --- | --- | --- | --- | --- | --- |
| 0% | A | 576 / 947 | 437 / 848 | 667 / 1190 | 6.0400 |
| 0% | B | 499 / 845 | 418 / 837 | 619 / 1131 | 5.0275 |
| 5% | A | 592 / 4049 | 433 / 50632 | 686 / 27267 | 6.9400 |
| 5% | B | 534 / 4138 | 439 / 50675 | 652 / 51516 | 6.4350 |

B improves the everudp median in both cells, but is still 19.4% and 21.6% above
matched original UDP zmosh. The frozen median gate therefore remains unmet even
at the point-estimate level. No full qualification should be substituted by this
screening result. No production feature or tuning matrix has been enabled or
changed on the strength of these numbers.

Loss p95 is near the matched baseline instead of the large penalty observed in
the earlier every-other-packet/5 ms experiment. That older capture used different
seeds and source: this cross-capture comparison does not prove causality. In this
run both B no-loss medians (526/473 us) are below both A medians (566/586 us).
Both B loss medians (541/515 us) are below both A medians (580/601 us). Loss p95
varies across B blocks (4715/4078 us), versus A (4049/4033 us). Controls also
drift; two blocks per mode cannot establish the frozen confidence-bound gates.

An independent read-only Luna audit reproduced every block seal/oracle check,
source/profile identity, frozen schedule hash, all per-block and pooled numbers,
and the traffic deltas. It also confirmed that original UDP parity remains unmet.

Packet counts are root-netem sent-plus-dropped deltas over the post-warmup to
pre-teardown interval, divided by public trials. They include other protocol
traffic and are not a decoded pure-ACK count.

Reproduce with `python docs/release-evidence/20260908-everudp-threshold-e786e0cf/analyze.py`.
The analyzer validates block seals, public oracles, clean source identity,
features, same-control hashes, build provenance hashes, schedule hash, seeds,
order, loss, affinity, gap and tracing flags, then prints all per-block results.
SHA256SUMS seals the full archive. Nested block seals and the original absolute
schedule.sha256 are preserved; the relocated script is checked by frozen digest.
Build and original-control provenance are included; binaries remain in the
sealed local build directories named in those receipts.

Remaining work is measured attribution of the residual original-UDP median gap,
followed by unchanged exact-SHA performance, reliability, security and independent
review gates. Release and rollout remain separate. Refs: eversh-5fc.70.
