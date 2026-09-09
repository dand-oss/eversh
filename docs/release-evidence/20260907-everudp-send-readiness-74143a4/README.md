# UDP send readiness experiment: negative floor result

Bead: eversh-5fc.21. Candidate: 74143a48f05e9b1f3216c3803d0266872756db05,
tree a81265311e32b0d106fb037ef24ae19661dad461. Both builds were clean.
Outcome: NOT ADOPTED. Neither fast-path loss cell meets the frozen 0.90
floor/zmosh median ceiling. This diagnostic is not production qualification.

The opt-in change attempts one nonblocking send before constructing a readiness
future, but only when no pending future exists. WouldBlock uses the unchanged
readiness loop; other errors propagate. The default remains disabled.

## Controlled inputs

Both builds use portable release fat LTO, one codegen unit, abort-on-panic,
pinned dependencies, diagnostics disabled and identical PTY/zmosh control
binaries. Only fast enables floor-send-fast-path. The plain floor binary is
byte-identical to the preceding a3023b8 plain build. Original build provenance
is included for both modes; fast-common-control documents copying the plain
zmosh binary into a separate derived build because independent Zig builds
produced different bytes. The original builds were not modified.

Eight sequential blocks were preregistered in Beads before collection:

| Order | Loss | Mode | Block | Seed | First candidate |
| ---: | ---: | --- | ---: | ---: | --- |
| 1 | 0% | plain | 1 | 90001 | floor |
| 2 | 0% | fast | 1 | 90002 | floor |
| 3 | 0% | fast | 2 | 90003 | zmosh |
| 4 | 0% | plain | 2 | 90004 | zmosh |
| 5 | 5% | fast | 1 | 90101 | floor |
| 6 | 5% | plain | 1 | 90102 | floor |
| 7 | 5% | plain | 2 | 90103 | zmosh |
| 8 | 5% | fast | 2 | 90104 | zmosh |

Each candidate has 200 trials per block, 100 ms gaps, full exact-response
validation and the public send-to-accepted timer. All 3,200 responses passed
with zero transcript failures. The original block seals and raw files are
retained unchanged, including raw counter whitespace. Builds finished before
measurement; no profiling or compilation ran alongside this collection.

## Observed results

Pooled medians combine 400 samples per candidate/mode/loss cell. These are
point estimates, not independent confidence-bound qualification results.

| Loss | Mode | Floor p50 (us) | zmosh p50 (us) | Ratio |
| ---: | --- | ---: | ---: | ---: |
| 0% | plain | 430.5 | 400 | 1.07625 |
| 0% | fast | 431.5 | 416.5 | 1.03601 |
| 5% | plain | 443.5 | 422 | 1.05095 |
| 5% | fast | 419.5 | 452.5 | 0.92707 |

Fast block ratios were 1.02407 and 1.05137 at 0% loss, 0.85169 and 0.99421
at 5% loss. One favorable loss block does not override either failed pooled
cell. All block packet-attempt ratios were below 1.60 (range approximately
0.9852 to 1.0287), but that cannot override the latency miss.

The no-loss raw floor median changed by +1 us, not an improvement. At 5% the
floor median decreased by 24 us, while the control median increased by 30.5 us.
That baseline drift and the small number of blocks prevent a causal speedup
claim. In particular, normalized ratios alone would exaggerate the apparent
benefit. This change has not demonstrated the required floor margin.

## Correctness evidence and limitations

At implementation checkpoint: noQ feature-on library tests 39 passed / 3
existing ignored; feature-off 38 passed / 3 ignored. Seven focused sender tests
were independently rerun after formatting. Everudp all-target/all-feature tests
passed with one existing ignore, and its all-target/all-feature clippy passed
with warnings denied. Python harness suite: 46 tests, two existing skips.
Optional all-feature noQ FIPS lint was unavailable because Go was missing; it
is not claimed as passed.

Scoped read-only review found no proven blocker/major in the helper change,
but the new readiness regression fixtures use a fake socket/future. Real
forced-backpressure/epoll fairness remains unverified. No production security,
outage, observer, recovery or release gate is certified by this experiment.

Do not enable the experiment by default, integrate actors on its strength,
relax the frozen gates, or claim production acceptance. The broader attribution
and production-performance work remains open.
