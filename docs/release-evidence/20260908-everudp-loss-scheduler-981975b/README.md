# Loss-block scheduler attribution (diagnostic only)

Runtime: `981975bceed8a315b3c827406dc8c5be029ec272`, tree
`04c8012f84efb6fd0e2e7d98cf967feaba4dc9df`. The analyzer is added separately
with this archive; it was not part of that runtime. This is not qualification,
and does not replace the retained uninstrumented comparison or its failed parity.

## Question and result

The retained 5%-loss block showed sustained latency growth rather than one
outlier. A same-seed scheduler capture asks whether client/gateway runnable
waiting occurs inside the public send-to-accepted-response interval.

The validated capture covers 146 of 200 everudp trials; 54 remain in the
benchmark but are excluded from scheduler attribution because their intervals
are not wholly inside common target-event coverage. All 600 responses across
the three implementations passed the exact-response check.

| Covered group | Trials | Median latency | Client median runnable wait | Gateway median runnable wait |
| --- | ---: | ---: | ---: | ---: |
| All | 146 | 0.644 ms | 0.012 ms | 0.009 ms |
| At most 2 ms | 120 | 0.606 ms | 0.011 ms | 0.009 ms |
| Above 2 ms | 26 | 4.501 ms | 0.266 ms | 0.635 ms |

The 2 ms split is exploratory, not an acceptance threshold. Runnable waits
overlap the slow public intervals, but this does not establish an exclusive
critical-path decomposition. Do not add per-process medians, subtract them
from latency, or call the remainder network cost. Only target main threads
were captured: not the route watcher, broker, echo fixture, or all kernel work.
The full 200-trial everudp median was 716.5 us and p95 was 9025 us;
late 20-trial bin medians again rose to roughly 5.3 ms.

## Capture identity and retained failure

Both attempts use seed 18050002, 5% symmetric loss, 200 trials per implementation,
order zmosh-quic / zmosh-udp / everudp, CPUs 40/42/44/46 with performance governor,
and a 100 ms trial gap. Build provenance, collector source, plans and measurements
are retained in each directory. No concurrent project builds or agents ran in
the timed window.

`invalid/` preserves the first 19-second attempt. Its final client-generation
check failed after the client exited. It is INVALID, even though its benchmark
responses passed. It cannot support validated scheduler attribution. Its original
private root-seal SHA256 was
`18c33756cc66bc1f44055213bd2bad1c23a7c5f96bfafb1a942be828b81481de`.

`capture/` preserves the predeclared corrected 15-second attempt. Before/after
PID generations, binary identity, affinity and time namespaces match. Three
PID-filtered scheduler events use CLOCK_MONOTONIC; 6,703 decoded events have no
reported loss. The original private root-seal SHA256 was
`3892069e1114d4d5ae74a2ab3644217175f4856915eeb9942d808d74ccd20c3f`.

Raw perf files remain private outside git and are deliberately omitted. Exported
task names are sanitized. Each exported directory has its own new seal; it is
not the original private capture seal. Nested measurement seals are preserved.

## Reproduction and review

From the repository root:

```sh
PYTHONPATH=crates/everudp/tests/net python3 -B -m unittest test_public_scheduler -v
python3 -B crates/everudp/tests/net/analyze_public_scheduler.py docs/release-evidence/20260908-everudp-loss-scheduler-981975b/capture
```

The second command reproduces `analysis.json` byte for byte. Five unit tests pass.
The independent bounded Luna review reproduced the 146/54 split and 26 slow
trials and found no defect affecting this receipt. This is not the final product
review. A noted limitation is that a malformed waking-without-wakeup chain is not
fully rejected by the state machine; it was not observed in this capture.

## Next discriminating measurement

No production architecture change follows from this partial trace alone. The
next bounded diagnostic should align reliable-stream progress (send acceptance,
gateway input receipt, broker acceptance, output receipt and local sink acceptance)
with monotonic public boundaries in the same slow trials. Include scheduler
coverage for the broker and fixture and enough lifetime margin for final identity
checks. This distinguishes delayed transport progress from application scheduling
and PTY/broker delay; it must retain non-reproduction and instrumentation overhead
as limitations. Do not repeat benchmarks merely to obtain a passing median, and
do not relax the frozen qualification gates.
