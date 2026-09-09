# Delivery-before-transmit experiment: not adopted

Bead: eversh-5fc.66. Candidate source: abccb1c81ed142ae494839e9827e50ae68268d24.
This is bounded diagnostic evidence, not production qualification or a parity PASS.
The production default remains unchanged. No release or deployment is authorized here.

## Identity and execution

Three clean-source canonical builds passed: diagnostic (`cli,path-packet-diagnostics,stream-delivery-spike`),
baseline (`cli`), and variant (`cli,stream-delivery-spike`). Their provenance, logs,
and original build seals are retained under builds/. Binaries are not included;
the original build seals therefore describe the original complete bundles, not
an independently verifiable archived binary inventory. The archive's root seal
covers every file actually retained here.

Both zmosh source commits and toolchains stayed frozen. Independent builds have
different control binary hashes; they are NOT byte-identical controls. Preserve
the per-build provenance when interpreting the comparison.

All builds ended before timing. No agents, builds, or analysis ran during timing.
The frozen script is measurement/frozen-schedule.sh, original SHA256
0f46890e810e76eba9b25b8b24289e75fe3980df25fd0d4919dbcda33b9296ba.
Its schedule.sha256 retains its original absolute-path locator.
The diagnostic capture used 20 trials per candidate. The eight ordinary blocks
used A/B/B/A in each 0% and 5% loss cell, 200 trials per candidate per block,
the unchanged compiled fixture, 100 ms gaps, and CPUs 40,42,44,46.
All nine blocks passed, with no retries or substituted blocks. All 4,800 ordinary
and 60 diagnostic measured responses passed exact-transcript checks.

## Descriptive results

Pooled nearest-rank p50/p95 in microseconds, 400 samples per role/cell/candidate:

| Loss | Candidate | Baseline | Variant |
|---|---|---:|---:|
| 0% | everudp | 637 / 1062 | 625 / 1056 |
| 0% | zmosh UDP | 406 / 820 | 430 / 814 |
| 0% | zmosh QUIC | 599 / 1126 | 623 / 1139 |
| 5% | everudp | 674 / 4101 | 625 / 3916 |
| 5% | zmosh UDP | 435 / 50622 | 463 / 50774 |
| 5% | zmosh QUIC | 650 / 52160 | 641 / 27447 |

These are descriptive estimates, not confidence bounds. There are only two
blocks per role per cell, and the controls drift. This does not meet the frozen
production sampling contract or demonstrate parity against UDP zmosh.

## Causal observation

The strict packet/dispatch analyzer resolves all 20 input and output windows.
In the new capture, input receipt-to-readable median is 5.732 us, followed by
78.7915 us readable-to-application; receipt-to-application is 85.26 us.
The older 20-trial diagnostic capture at source1732800 had corresponding
59.3695 / 32.842 / 91.128 us. This cross-capture comparison is unpaired and
descriptive; independent medians are not additive.

Every new input window and every output window contains exactly one driver-service
event AFTER notification and BEFORE the application boundary. Within the input
post-notification window, protocol/transmit call overlap medians are 17.686 and
27.617 us, with residual 31.148 us. These are wall-clock spans, not exclusive CPU
costs. Output post-notification equivalents are 9.8745 / 18.978 / 10.2885 us.

Thus the bounded self-waking handoff did not reliably put application consumption
ahead of driver work: much of the delay moved after the readability marker.
The actual scheduling/wake path must be traced before another intervention;
an earlier marker alone is not an architectural improvement.

Source follow-up: edge.rs runs both application roles directly in runtime.block_on.
The locked Tokio1.53.1 current-thread scheduler polls that root future at the
outer-loop boundary, then processes its scheduled-task batch before reconsidering
the root wake. This supplies a concrete explanation to test: waking the root
application does not queue it ahead of the self-woken driver as a normal task.
No new scheduling change is included or validated by this archive.

A read-only Luna audit independently verified all block seals, source/features,
seeds/orders, result hashes, exact transcript counts, and the pooled quantiles
above. It confirmed the differing control binaries as a limitation rather than
source drift. This bounded evidence audit is not the independent release review.

## Remaining requirements

No full exact-SHA reliability/security/performance qualification or independent
release review has passed for this experiment. The earlier production performance
failure remains authoritative. Preserve security, exact delivery, bounded queues,
observers, and recovery in any subsequent change; do not lower the frozen gates.
