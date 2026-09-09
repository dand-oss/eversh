# Native reliable-stream experiment: NOT-ADOPTED

Candidate: `8c6f060d4799c38fdd1fa7399a137d8b64d8fc8c`.
Tree: `88bd4d5fcbfa442617ec4f6be444ee6035f34435`.
Contract: `plans/everudp-native-stream-experiment.md`; bead `eversh-5fc.52`.

The one completed frozen comparison fails the native/zmosh UDP median cutoff
in both cells. No native stream integration is authorized, no threshold changes
or additional tuning runs follow this result, and production acceptance remains
unproven. This is a local-PTY echo experiment, not a production reconnect gate.

| Symmetric loss | Native p50 | Ordinary p50 | zmosh UDP p50 | Native/UDP p50 | Native/ordinary p50 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0% | 503.5 us | 549.5 us | 418 us | 1.20455 | 0.91629 |
| 5% | 550 us | 555 us | 440.5 us | 1.24858 | 0.99099 |

The required native/UDP p50 ratio is <=0.90 in each cell. Native scheduling
reduces the matched ordinary-mode median by about 8.4% without loss and 0.9%
with loss in this run, but does not meet the adoption threshold. This does not
identify every remaining source of overhead or prove a universal QUIC limit.

Native p95 is 842 us without loss and 3,846 us with loss; zmosh UDP p95 is
824 us and 50,693 us respectively. The loss-tail advantage does not waive the
median gate. Native packet-attempt ratios are 0.99814 and 1.17952 pooled;
all individual block packet ratios also pass the <=1.60 limit.

## Evidence and prerequisite gates

- `qualification/` is the original sealed 206-file evidence set, with all four
  reversed-order blocks, all 2,400 samples, resource records, raw qdisc counters,
  frozen plan, command records, analysis and NOT-ADOPTED receipt.
- All 2,400 measured responses have zero transcript failures. The runner
  cross-checks public nanosecond boundaries against every integer-us sample.
- Eight untimed correctness targets pass: 60 library tests, 1 admission,
  4 descriptor I/O, 4 native streams, 4 native echo, 1 native run,
  10 ordinary streams, and 4 example tests (88 total).
- Retained release-binary preflight passes both runtime modes: exact PTY
  bytes, cancellation/restoration, wrong-pin/token rejection, exact per-side
  built profile parity and fixture cleanup. It does not claim all settings are
  negotiated on the wire.
- Both modes share one release binary, built with the recorded portable
  fat-LTO/codegen1/opt3/unwind profile. Frozen UDP control commit is
  `dfc8395b5edcd237bf82712fbde879c6e8be7dfa`.
- Build provenance and binary hashes are retained in the qualification bundle.
  Full build binaries, logs and original build seal remain at
  `/tmp/everudp-stream-build-8c6f060`; they are not committed here.

`invalid-launcher/` preserves the earlier sealed INVALID attempt at `eb22013`.
It stopped before the measurement barrier and produced no timed sample file:
Clap rejected the separate hyphen-leading SSH `-F` option. The sole repair
attached the value (`--ssh-option=-F...`). The source was rebuilt and preflighted;
all previously frozen seeds, orders, CPU/governor settings and thresholds were
preserved. The INVALID attempt is not counted as a performance observation.

Validate each archived directory with its own `SHA256SUMS`; do not normalize
raw output whitespace. The final production performance, reliability, security,
resource and independent max-review gates remain required and are not satisfied
by this archive. Release and fleet rollout remain out of scope.

## Bounded result audit

Luna independently verified the build, preflight and qualification seals,
four frozen command/manifest identities, zero transcript failures, and medians
recomputed from the raw samples. Individual native/UDP packet-attempt ratios
are 810/802, 801/812, 1022/846 and 982/853; all pass the packet gate.
The audit confirms NOT-ADOPTED and confirms that the earlier launcher failure
has no timed result. This is a bounded experiment-result audit, not the final
independent max-reasoning production review.
