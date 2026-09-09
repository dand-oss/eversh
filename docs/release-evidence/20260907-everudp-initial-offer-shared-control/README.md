# Initial-offer matched comparison — floor cutoff not met

The candidate passes the numerical floor cutoff at 0% loss but fails at 5%.
This is a disposable floor experiment, not production qualification or an
authorization to integrate the native driver into the production actors.
All 3,200 responses passed the exact-byte oracle. Packet-attempt limits pass.

## Frozen identities and protocol

- Baseline runtime: `1bdd3528bc4d257a1f33adc96b1fb48a97a777d9`.
- Candidate runtime: `f90c878dfda16c86b7bd04ee255889450eedb859`.
- Execution harness: `63cfb5be4de895518a9469cef8c3c48649c073e6`, tree
  `c6f455359e944de5cd7ab8f60863104d114e51ee`.
- Frozen zmosh source: `dfc8395b5edcd237bf82712fbde879c6e8be7dfa`;
  shared executable SHA256:
  `de1e96e5ef57df173db266747eb18b8bce6911952410d298f236ab9c1e7fa162`.

Both runtime bundles use the same sealed zmosh and PTY fixture executables.
Composition preserves the original build records under `provenance-inputs/`;
the selected component hashes and original provenance hashes are recorded in
each composed build record. Original builds were not overwritten. Artifact
equality and both full bundle seals were checked before the first trial.

Each cell (0% and 5% symmetric loss) has four 200-trial blocks in runtime order
baseline, candidate, candidate, baseline. Within-block order is everudp-first,
zmosh-first, everudp-first, zmosh-first. Seeds are 990701–990704 and
995701–995704. CPU affinity is 40,42,44,46 with performance governors; trial gap
is 100 ms. Native and legacy tracing are off throughout. There are 400
observations per implementation per runtime grouping per cell.

The previous attempt was rejected for mismatched independently rebuilt control
hashes and remains archived separately at
`../20260907-everudp-initial-offer-f90c878/`. This is a complete new run with
new preregistered seeds, not selective replacement of individual blocks.

## Results

| Loss | Runtime | Native / zmosh p50 (µs) | p50 ratio | Upper 95% ratio | Packet ratio | Numerical cutoff |
|---|---|---|---|---|---|---|
| 0% | Baseline | 382 / 432.5 | 0.883237 | 0.948005 | 1.000620 | PASS |
| 0% | Candidate | 351.5 / 410 | 0.857317 | 0.926020 | 1.001241 | PASS |
| 5% | Baseline | 415.5 / 446 | 0.931614 | 0.989510 | 1.083580 | FAIL |
| 5% | Candidate | 371.5 / 405 | 0.917284 | 0.979950 | 1.085056 | FAIL |

The unchanged floor cutoff is pooled p50 ratio <= 0.90 in each cell and
packet-attempt ratio <= 1.60 in every block and pooled cell. The reported
bootstrap upper 95% ratio is not a floor gate. The separate full production
dual-zmosh performance, reliability, security and review gates remain required.

Raw candidate/baseline native p50 ratios are 0.920157 at 0% loss and 0.894103
at 5% loss. Their central 95% intervals are [0.845387, 1.020520] and
[0.815348, 0.962241]. However, the unchanged control's corresponding ratios
are 0.947977 and 0.908072. The raw native improvements therefore must not be
reported as causal savings from the code change. The 20,000-resample
within-block bootstrap does not capture independent experiment replication
uncertainty. No medians are subtracted as guaranteed latency savings.

Independent read-only review verified the raw seals, identities and protocol.
The review initially pooled different runtime blocks together; that calculation
was rejected. Corrected independent recomputation using baseline blocks 1+4 and
candidate blocks 2+3 agrees with all four rows above. The analyzer also reproduced
`analysis.json` byte-for-byte in a separate invocation.

## Reproduce

From this directory:

```sh
sha256sum -c SHA256SUMS --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py . \
  63cfb5be4de895518a9469cef8c3c48649c073e6 \
  c6f455359e944de5cd7ab8f60863104d114e51ee > /tmp/everudp-shared-control-analysis.json
cmp analysis.json /tmp/everudp-shared-control-analysis.json
```

The analyzer verifies all block seals, source/build/component identities,
original provenance hashes, public sample boundaries, exact-response results,
order/seeds, CPU/governors and measured-window packet accounting. Raw qdisc
whitespace and original block seals are intentionally preserved.
