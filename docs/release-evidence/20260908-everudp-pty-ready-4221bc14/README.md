# One-shot PTY readiness screening: NOT ADOPTED

Bead eversh-5fc.71. Exact clean source
4221bc1497a4fa0b1cfcbd688b47bd77785ebb55 for both builds.
A enables cli,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike.
B adds only pty-ready-spike. All experiments remain default-off.

The candidate requests one zero-wait PTY poll after a byte input operation is
fully accepted and its application ACK is queued. Already-ready output can enter
the output queue before the normal control-first turn. Pending output returns
immediately to normal scheduling; no timer, skipped ACK or echo prediction.
Resize, signals and close do not request the new probe.

Frozen A/B/B/A schedule in each 0% and 5% symmetric-loss cell, 200 trials per
implementation per block: 4,800 exact responses passed with no failed blocks or
replacement runs. Same five sealed control binaries; CPU set 40,42,44,46; 100ms
gaps; tracing disabled; no concurrent builds, agents or analysis during capture.
Seeds 212900001..004 and 212900101..104. Candidate orders are E/U/Q, Q/E/U,
U/Q/E, E/Q/U. Original UDP and QUIC zmosh source identities are frozen in
provenance, unchanged from the preceding threshold experiment.

Pooled nearest-rank p50/p95 in microseconds, 400 observations per mode per cell:

| Loss | Mode | everudp | Original UDP zmosh | QUIC zmosh |
|---|---|---:|---:|---:|
| 0% | A | 556 / 896 | 427 / 828 | 660 / 1150 |
| 0% | B | 578 / 895 | 422 / 872 | 704 / 1154 |
| 5% | A | 588 / 5160 | 474 / 50644 | 678 / 28233 |
| 5% | B | 573 / 4939 | 446 / 50809 | 672 / 27840 |

Both no-loss B block medians (562,578) exceed both A block medians (556,554).
At 5% loss, A medians are 562,608 and B medians 566,574; pooled improvement is
not consistent across blocks. Original UDP control median also falls 28us between
loss-cell modes while everudp falls only 15us. A loss p95 varies 11808 to 3776us,
so the pooled tail difference is not a stable tail win. Packet attempts per echo
are nearly unchanged: 0% A5.0825/B5.0675; 5% A6.335/B6.4375.

B still exceeds its original UDP control median by about 37.0% without loss and
28.5% with loss. No evidence supports adopting the probe. This also does not
prove ACK work is free: the uninstrumented run cannot tell how often the PTY was
already ready, and the source audit limited the hypothesis to that condition.
Do not treat this negative result as a reason to weaken ACK or replay semantics.

Reproduce validation, per-block values and pooled results from repository root:

```sh
python3 -B docs/release-evidence/20260908-everudp-pty-ready-4221bc14/analyze.py
```

The analyzer verifies every capture seal, exact source, features, control hashes,
schedule hash, seed, order, affinity, gap, tracing state, build provenance and
all 200 exact-response samples per implementation per block. Raw qdisc evidence
and build/control provenance are retained; binaries are not archived.

Implementation checks passed: 38 combined-feature and 38 default library tests,
strict combined library Clippy, 22 benchmark-profile tests, admission5,
handshake3, process13, resume4 and transport7. One real-application qualification
test was ignored in this development suite. The feature-policy regression first
failed with the disabled policy, then passed; ready/pending polls and existing
fairness coverage passed. These are development checks, not release gates.

Status: SCREENING_ONLY / NOT_ADOPTED. This is not the frozen full qualification
(1200 observations per implementation per cell and confidence-bound gates).
Production performance remains FAIL; exact-SHA reliability, security and final
independent review remain required.
