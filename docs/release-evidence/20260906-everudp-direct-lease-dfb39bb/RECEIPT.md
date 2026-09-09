# everudp direct-PTY lease performance spike

Verdict: **FAIL — do not productionize the direct-lease repair as the M6 performance fix.**

The revocable direct-PTY lease is functionally valid, but it does not meet the
pre-registered latency margin against frozen zmosh 0.5.9 custom UDP. This is a
negative spike result, not an everudp release receipt.

## Frozen identity

- everudp source: `dfb39bb4705e5d49924a0751ece57c8f170e8336`
- everudp tree: `74bf011508a86a377f93a28b01c20da70007de8a`
- everudp binary SHA-256: `f57ab43d0b5837672e06ce981c5dc8bebf092b1f0410ee548f74ab9058324b96`
- zmosh custom-UDP source: `dfc8395b5edcd237bf82712fbde879c6e8be7dfa`
- zmosh QUIC source: `21db4a4de6040b254531f2131b6f1c0cd146a7a1`
- fixture: the frozen compiled `pty-bench` plus compiled raw-PTY `pty-echo`
- traffic: exact transcript, 100 ms gap, 200 observations per implementation
  per cell, two reversed 100-observation blocks

The checkout also contained unrelated uncommitted scheduler experiments, so
the harness required `EVERUDP_ALLOW_DIRTY=1`. The measured candidate came only
from the sealed build above, and the benchmark/harness files have no diff from
that source commit.

## Results

| Symmetric loss | Candidate | p50 (us) | p95 (us) | p50 vs zmosh UDP |
|---:|---|---:|---:|---:|
| 0% | everudp direct lease | 695 | 1,042 | 1.791x |
| 0% | zmosh custom UDP | 388 | 776 | 1.000x |
| 0% | zmosh QUIC | 10,706 | 11,234 | 27.593x |
| 5% | everudp direct lease | 668 | 4,003 | 1.525x |
| 5% | zmosh custom UDP | 438 | 50,716 | 1.000x |
| 5% | zmosh QUIC | 10,878 | 62,588 | 24.836x |

The acceptance threshold was everudp p50 at or below `0.90x` zmosh custom UDP
in both cells. The observed ratios are `1.791x` and `1.525x`; both cells fail.
All 1,200 candidate trials across the four blocks passed the exact-transcript
oracle, so this is a latency failure rather than a correctness failure.

## Runs

- 0%, seed `941001`, order `everudp,zmosh-udp,zmosh-quic`
- 0%, seed `941002`, order `zmosh-quic,zmosh-udp,everudp`
- 5%, seed `942001`, order `everudp,zmosh-udp,zmosh-quic`
- 5%, seed `942002`, order `zmosh-quic,zmosh-udp,everudp`

The complete manifests, raw samples, transcript-failure counters, qdisc
counters, status logs, resource records, per-block checksums, and build
provenance are preserved below this directory. The next repair must have a new
explicit contract; this receipt does not amend the reliable-stream-only v2
contract.
