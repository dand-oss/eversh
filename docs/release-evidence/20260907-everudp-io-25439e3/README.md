# Production QUIC I/O attribution — diagnostic, not qualification

Candidate: `25439e3596811694686874bfa2a50eb1cb3673a0`, tree
`9084af9cdb5e277d2f28383b5540da2a6c554f59`. Release binary SHA256:
`934da4e1f64233722e86e129de5bb103c7fda084a02fa66bb5a029b816bbed95`.
Features: `cli,path-io-diagnostics`. Bead: `eversh-5fc.41`.

## Scope and identity

Eight completed blocks, with no retries or discarded blocks: OFF/ON/ON/OFF I/O
tracing at each of 0% and 5% symmetric loss. **Path tracing is ON in both modes.**
Each block contains 200 observations for each of everudp, frozen custom-UDP zmosh,
and frozen QUIC zmosh: 4,800 byte-correct responses total. The four I/O-ON blocks
contain 800 correlated input rows. A preceding five-trial capture smoke was
excluded from this archive and all calculations.

Order alternates forward/reverse/forward/reverse. Seeds are 1081701–1081704
and 1086701–1086704, with server seeds offset by 1,000,003. All blocks record
CPUs 40,42,44,46 pinned to the performance governor, release artifact hashes,
source identity, and before/after qdisc accounting. Source was unchanged and no
builds or other heavy jobs ran during the matrix.

`build.json` records a fresh isolated everudp build and reuse of five exact
control binaries. `provenance-inputs/control.json` retains their original build
provenance; `runtime.json` and the build logs identify the new executable. Input
fixture and lockfile hashes still match the control provenance. Frozen zmosh
sources remain `dfc8395b5edcd237bf82712fbde879c6e8be7dfa` (UDP) and
`21db4a4de6040b254531f2131b6f1c0cd146a7a1` (QUIC).

## Recorder overhead

Nearest-rank p50/p95, microseconds; 400 samples per name, mode, and cell:

| Loss | I/O trace | everudp | zmosh UDP | zmosh QUIC |
|---|---|---:|---:|---:|
| 0% | OFF | 569 / 771 | 364 / 712 | 10661 / 11216 |
| 0% | ON | 635 / 1076 | 377 / 768 | 10643 / 11160 |
| 5% | OFF | 555 / 3895 | 376 / 50512 | 10664 / 37249 |
| 5% | ON | 571 / 3955 | 391 / 50546 | 10685 / 37830 |

For everudp, I/O-ON/OFF ratios and central 95% within-block bootstrap intervals:

| Loss | p50 ratio [interval] | p95 ratio [interval] |
|---|---|---|
| 0% | 1.1160 [1.0809, 1.1353] | 1.3956 [1.2957, 1.4862] |
| 5% | 1.0288 [1.0000, 1.0672] | 1.0154 [0.9848, 1.0752] |

The I/O recorder is **not zero-overhead**. No-loss ON results are noticeably
slower, especially at the tail. UDP controls also shift: their ON/OFF p50 ratios
are 1.0357 and 1.0399. These are alternating blocks, not independent replication;
do not assign every difference solely to instrumentation or subtract the
instrumented stage medians from an uninstrumented latency budget. Neither OFF
nor ON is the featureless production build. Production performance has not
passed, and this archive cannot satisfy that gate.

## Input-side observations

Every traced row has exactly one gateway `stream_readable` marker for the first
client unidirectional stream (input stream id 2), between client input queueing
and gateway input preparation. There are 400 such rows per loss cell; no rows
were excluded for ambiguous matching.

Descriptive elapsed intervals, median microseconds (0% / 5% loss):

- Stream-write acceptance to first client transmit acceptance: **95.5 / 80.5**.
- First client transmit acceptance to latest gateway receive-batch marker before
  input readability: **54.3 / 41.7**.
- That latest receive-batch marker to input readability: **90.8 / 78.8**.
- Input readability to gateway input preparation: **21.4 / 19.7**.
- Stream-write acceptance to input readability: **238.6 / 205.5**.

These labels deliberately say *first* and *latest*: the markers have no packet
identities, and are not proof that the selected send and receive correspond to
one packet. They do not isolate CPU, encryption, kernel, network, or descheduling
cost. Do not sum medians. `analysis.json` includes counts, p95s, and signed values.

Each selected receive-to-readability window contains one gateway transmit
acceptance marker. The production `ConnectionDriver::poll` performs transmit and
timer work before `forward_app_events`. This is a concrete ordering to investigate,
not proof of removable delay: the work remains necessary, and an earlier wake
alone does not let application code run while the connection poll/lock is held.
Any bounded deferral experiment must retain timer, retransmit, blocked-send,
error/close handling, and continuous-readable fairness.

The earlier `inline-received-events` experiment already covered reliable streams,
not just DATAGRAM callbacks. Its endpoint path processes connection events and
forwards application events before waking the ordinary driver. Do not relabel
that existing experiment as a new optimization or repeat it without a new
observable hypothesis. This evidence narrows the next investigation; no new
architecture improvement is adopted by this archive.

## Verification and reproduction

All nested checksums pass. Path analyses and sidecar validation reports were
recomputed byte-identically. Sidecar validation requires exact bounded schema,
nondecreasing timestamps, valid/non-overflow status, and the same PID, boot ID,
and time namespace as the paired path trace. Production qualification explicitly
rejects I/O sidecars even when manifest trace flags falsely claim tracing is off.

An independent Luna read-only audit checked the eight raw blocks, exact build
and control identities, samples, grouping, bootstrap method, and interval caveats;
it found no arithmetic or provenance blocker. The reviewer called this “.40” in
its message, but inspected this exact `.41` archive and candidate `25439e3`.
This is not the final independent max-reasoning release review.

Run from this directory:

```sh
sha256sum -c SHA256SUMS --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py > /tmp/everudp-io-reproduced.json
cmp analysis.json /tmp/everudp-io-reproduced.json
```

The analyzer uses 20,000 independent within-block resamples per cell, fixed
bootstrap seeds 1091700 and 1091705, nearest-rank quantiles, and central 95%
ON/OFF intervals. It checks raw seals, manifests, qdisc deltas, exact transcripts,
provenance, and strict paired traces before calculating results. This is a
diagnostic analysis, not the one-sided frozen production qualification test.
