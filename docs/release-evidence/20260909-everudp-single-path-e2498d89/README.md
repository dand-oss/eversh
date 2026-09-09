# Single-path scheduling screen: NOT ADOPTED

Bead eversh-5fc.76. Candidate e2498d89770715ebcdb700d8c72d86feebc85f58.
The default-off shortcut bypasses two path-table scans only for one established,
validated primary path with a remote CID and no abandonment. Every other state
uses the original implementation. No ACK, crypto, congestion, replay or admission
rule changes. Baseline code order is unchanged when the feature is disabled.

All eight predeclared blocks completed, all 4,800 exact public responses passed,
and all original block seals are retained. This screen does not establish a
reliable causal speedup and does not meet the frozen original UDP zmosh median
target. The feature remains disabled by default. Do not rerun the unchanged
candidate looking for a better result, discard slow blocks, or adopt it from
these pooled numbers.

Nearest-rank pooled p50/p95, microseconds; 400 observations per mode/cell:

| Loss | Build | everudp | UDP zmosh | QUIC zmosh |
|---|---|---:|---:|---:|
| 0% | A baseline | 3105 / 9273 | 521 / 7530 | 972 / 8706 |
| 0% | B shortcut | 523 / 7807 | 379 / 6478 | 883 / 7621 |
| 5% | A baseline | 539 / 11400 | 379 / 50596 | 616 / 27881 |
| 5% | B shortcut | 509 / 4765 | 410 / 50608 | 608 / 27823 |

The zero-loss block variation is severe. In the final A block, everudp's median
was 4971us, UDP zmosh's 3668us, and QUIC zmosh's 4566us; the earlier A block was
938/395/661us respectively. Both controls are affected. The cause is not proven,
so these observations are retained rather than reclassified as invalid or used
to claim an 83% speedup. The first 5%-loss baseline block also had a much larger
everudp tail (29097us) than its final baseline block (4908us).

At 5% loss the shortcut's median is 509us versus baseline 539us, but the UDP
control shifts from 379us to 410us. This is a screening observation, not an
isolated causal estimate. Shortcut median ratios against its own UDP controls
remain approximately 1.380 at zero loss and 1.241 at 5% loss. Its better loss
tail does not waive the median requirement. No production qualification PASS
is claimed, and no thresholds were changed.

Frozen setup: A features cli,application-task-spike,stream-delivery-spike,
quic-ack-threshold-spike; B adds single-path-scheduling-spike. Both release builds
use the same clean source, fat LTO, one codegen unit, opt3 and unwind, and reuse
the same five sealed control/fixture binaries. ABBA per 0%/5% loss cell, 200
trials per implementation/block, CPUs 40,42,44,46, 100ms gaps, all tracing off.
Seeds 213300001..004 and 213300101..104; candidate orders E/U/Q, Q/E/U, U/Q/E,
E/Q/U. No other project builds or agents ran during timing.

Verification before timing: 393 protocol tests, 38 everudp library tests,
admission/handshake/resume/transport targets including byte-identical 10MiB
across five reconnects, strict Clippy, and 24 build-option tests. Parent review
caught and corrected initially unconditional shortcut wiring before commitment
or measurement. Tests include all 64 combinations of guard conditions and
equivalence to the general formula for eligible Available and Backup states.
The build-option suite was observed RED before implementing the allowlist.

Reproduce from repository root:

```sh
python3 -B docs/release-evidence/20260909-everudp-single-path-e2498d89/analyze.py
```

The analyzer checks source/features, control identities, frozen schedule hash,
all eight block seals, ordering/seeds/affinity/tracing/provenance, all samples
and exact-response checks. It reports every block, including the slow ones.
Raw binaries stay outside git at /tmp/everudp-single-path-e2498d89-A-build and
the corresponding B-build. Measurement records are retained here without
credentials or executables. Full exact-SHA production performance, reliability,
security and independent-review acceptance remains incomplete.
