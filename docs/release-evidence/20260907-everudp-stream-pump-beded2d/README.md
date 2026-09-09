# Combined reliable-stream scheduling — not adopted

Candidate `beded2d447eb055099fb992eaf7d30ea9ef8e7f7`, tree
`2022d0738cd07d1506179134ef5f8fe0b866199f`. Bead `eversh-5fc.41`.
This is diagnostic A/B evidence, not production qualification.

The baseline uses `cli`; the variant uses `cli,stream-pump-spike`, combining
the existing immediate reliable-stream flush and inline reliable receive
experiments. Neither build enables terminal datagrams or tracing. Defaults,
delivery/ACK/replay behavior, and frozen performance thresholds are unchanged.

## Identity and method

Separate fresh release targets built the same clean source. Baseline binary:
`89eeb262fe42deb95ca17ecdc0aa05c1f009d749c6ae5b5b1dc9acc844afcdd2`.
Variant binary:
`e0fd258dc40c2799391c40b68ce2dcfe15ca38ca54a2cfc0d0154a9d153eb5d2`.
Five frozen control/fixture binaries were reused byte-identically from the
`a86efaf` build; original control provenance, runtime metadata, and build logs
are retained. No executables or authentication credentials are archived.

Both loss cells (0%, 5% symmetric) ran baseline/variant/variant/baseline,
200 trials per implementation per block, alternating forward/reverse order.
Seeds: 1101701–1101704 and 1106701–1106704; server offset 1,000,003.
CPUs 40,42,44,46 used the performance governor and 100 ms trial gaps.
All eight blocks completed without retries or replacement: 4,800 exact responses.
No builds, source edits, or heavy analysis ran during measurement.

## Results

Nearest-rank p50/p95 in microseconds; 400 observations per name/build/cell:

| Loss | Build | everudp | zmosh UDP | zmosh QUIC |
|---|---|---:|---:|---:|
| 0% | Baseline | 702 / 1175 | 435 / 858 | 10734 / 11256 |
| 0% | Variant | 688 / 1127 | 393 / 794 | 10718 / 11242 |
| 5% | Baseline | 707 / 4078 | 433 / 50625 | 10790 / 37576 |
| 5% | Variant | 702 / 4174 | 418 / 50699 | 10805 / 37560 |

Everudp variant/baseline ratios, central 95% intervals:

- No-loss p50: 0.9801 [0.9391, 1.0278]; p95: 0.9591 [0.8930, 1.0232].
- 5%-loss p50: 0.9929 [0.9403, 1.0399]; p95: 1.0235 [0.9249, 2.4948].

All four intervals include 1; benefit is not established. The UDP control's
no-loss median also fell (ratio 0.9034 [0.8523, 0.9452]), so the small everudp
point-estimate changes cannot be assigned solely to scheduling. Variant median
ratios versus UDP remain 1.7506 and 1.6794; no-loss p95 remains 1.4194.
The combined change does not close the production gap. Keep it isolated and
disabled by default. Do not infer that the measured I/O intervals are removable
costs or that combining the two earlier experiments adds their apparent savings.

## Verification and reproduction

The candidate has passing reliable-stream, idle-keepalive, exact echo, and
deterministically injected Pending/retry/error tests. Standalone strict noQ
linting exposed an existing `result_large_err` warning in the unchanged inline
receive API; fixture linting passed with only that warning excluded. This is
not a full strict standalone lint PASS or final security/reliability qualification.

The analyzer validates nested seals, source/build/control identities, raw public
timing boundaries and exact transcripts, tracing flags, governors, and qdisc
accounting. It uses 20,000 independent within-block resamples, seeds 1111700
and 1111705, nearest-rank quantiles, and central 95% intervals. These are not
independent experimental replications or the frozen six-block qualification.
An independent Luna read-only audit found no origin/comparison-direction bug.

From this directory, without Python `-O`:

```sh
sha256sum -c SHA256SUMS --quiet
PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py > /tmp/pump-reproduced.json
cmp analysis.json /tmp/pump-reproduced.json
```

Next work must investigate a distinct source of the remaining latency rather
than adopt this change or repeat these scheduling combinations blindly. Exact-SHA
performance, reliability, security, and independent max-review gates remain open.
