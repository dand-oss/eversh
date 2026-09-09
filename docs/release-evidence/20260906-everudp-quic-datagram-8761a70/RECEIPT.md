# everudp speculative QUIC DATAGRAM performance spike

Verdict: **FAIL — close the immediate-DATAGRAM-plus-stream architecture.**

The authenticated QUIC DATAGRAM fast lane is byte-correct, but it does not
meet the pre-registered latency margin against frozen zmosh 0.5.9 custom UDP.
This is a negative spike result, not an everudp release receipt.

## Frozen identity

- everudp source: `8761a7059add297ad19218ea63f4fa3998c7d6c8`
- everudp tree: `d2bd23efbfc8b5ecd6bb6fef629eecfb3ee5fcc1`
- everudp binary SHA-256: `378e40d34f6d1d4273794e6a534ff61ff7f3407b7ae2b4bd6f7dbb6ca1c63e75`
- everudp Cargo features: `cli,datagram-spike`
- zmosh custom-UDP source: `dfc8395b5edcd237bf82712fbde879c6e8be7dfa`
- zmosh QUIC source: `21db4a4de6040b254531f2131b6f1c0cd146a7a1`
- fixture: the frozen compiled `pty-bench` plus compiled raw-PTY `pty-echo`
- traffic: exact transcript, 100 ms gap, 200 observations per implementation
  per cell, two reversed 100-observation blocks

The clean exact build records the experimental feature set and all six
artifact digests in `build/provenance.json`. `build/SHA256SUMS` preserves the
complete build receipt without embedding the 55 MiB binary set.

## Results

| Symmetric loss | Candidate | p50 (us) | p95 (us) | p50 vs zmosh UDP |
|---:|---|---:|---:|---:|
| 0% | everudp QUIC DATAGRAM | 686 | 1,204 | 1.805x |
| 0% | zmosh custom UDP | 380 | 746 | 1.000x |
| 0% | zmosh QUIC | 10,700 | 11,246 | 28.158x |
| 5% | everudp QUIC DATAGRAM | 761 | 1,381 | 1.884x |
| 5% | zmosh custom UDP | 404 | 50,677 | 1.000x |
| 5% | zmosh QUIC | 10,833 | 62,071 | 26.814x |

The acceptance threshold was everudp p50 at or below `0.90x` zmosh custom
UDP in both cells. The observed ratios are `1.805x` and `1.884x`; both cells
fail. All 1,200 trials across the four blocks passed the exact-transcript
oracle, so this is a latency failure rather than a correctness failure.

The implementation also passed the full everudp `cli,datagram-spike` test
suite, focused warning-denying clippy, and the downstream noQ suite (32 tests
plus the doctest; four upstream stress/integration cases remain ignored by
their source annotations). A cooperative noQ-driver diagnostic was rejected
before this candidate because it did not improve latency and reproducibly
blocked terminal-exit delivery with a writer plus observer; it is not present
in this SHA.

## Runs

- 0%, seed `951001`, order `everudp,zmosh-udp,zmosh-quic`
- 0%, seed `951002`, order `zmosh-quic,zmosh-udp,everudp`
- 5%, seed `952001`, order `everudp,zmosh-udp,zmosh-quic`
- 5%, seed `952002`, order `zmosh-quic,zmosh-udp,everudp`

The complete manifests, raw samples, transcript-failure counters, qdisc
counters, status logs, resource records, per-block checksums, and exact build
provenance are preserved below this directory. The next repair requires a new
explicit contract. It must avoid sending every healthy keystroke immediately
on both a speculative DATAGRAM and the authoritative stream while preserving
bounded reliable fallback, exact sink-commit acknowledgements, reconnect, and
resume.
