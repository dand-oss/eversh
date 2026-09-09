# Production path plus scheduler capture: diagnostic, not qualification

Runtime source `981975bceed8a315b3c827406dc8c5be029ec272`, built with
`cli,path-diagnostics`, not the ordinary production feature set. Build provenance
SHA256: `b7d49827d48b7df3364a6d9656f311bcffb08d3a89ab2a7ef14785b6af23f947`.
Collector and frozen plan are in `capture/`. This is one instrumented run of the
retained slow block's seed 18050002, 5% symmetric loss, 200 trials per candidate,
order QUIC zmosh / original UDP zmosh / everudp, CPUs 40/42/44/46.

## Result and limits

Capture validation passed and all 600 responses passed the exact-response check.
The sustained late slowdown did **not** reproduce. Everudp's ten consecutive
20-trial median latencies were 629, 594.5, 642.5, 640, 619, 776, 559.5, 664.5,
664.5 and 532.5 us. The full median was 633.5 us; p95 was 4083 us.
This does not supersede the earlier failed uninstrumented comparison.

The 21 trials above 2 ms had median public latency 4.083 ms. Their median
gateway-output-queued to client-output-staged interval was 3.348 ms, versus
0.096 ms for the 179 other trials. Their median gateway-input-prepared to local
write acceptance interval was 0.011 ms, and local acceptance to gateway output
queueing was 0.128 ms. These observations locate this capture's slow trials
primarily in the return-path interval; they do not prove the cause of the earlier
sustained deterioration.

The return interval includes gateway send scheduling, QUIC pacing/loss recovery,
network delivery and client receive scheduling. It is not pure network time.
The gateway input marker follows `PtySession::send_operation`, which may use a
direct PTY descriptor lease or the framed broker edge; it is not proof of remote
application processing. The trace does not identify the negotiated lease mode.
Keep signed handoff intervals: sender completion markers can follow receiver
markers. Group medians must not be added into a causal latency decomposition.

Scheduler coverage includes 148 complete public intervals and excludes 52 from
scheduler attribution only. Among 15 covered trials above 2 ms, median latency
was 4.158 ms, client runnable wait 0.027 ms and gateway runnable wait 0.023 ms.
Only those main threads were traced, not broker/fixture/watcher scheduling. The
2 ms grouping is exploratory and does not change any qualification threshold.

## Reproduction

From the repository root, with `E` set to this archive directory:

```sh
E=docs/release-evidence/20260908-everudp-loss-path-981975b
python3 -B crates/everudp/tests/net/analyze_path_trace.py "$E/capture/measurement/everudp/client-path-trace.json" "$E/capture/measurement/everudp/gateway-path-trace.json" "$E/capture/measurement/everudp/result.json"
jq -n --slurpfile p "$E/capture/measurement/everudp/path-analysis.json" --slurpfile r "$E/capture/measurement/everudp/result.json" -f "$E/summarize.jq"
python3 -B crates/everudp/tests/net/analyze_public_scheduler.py "$E/capture"
PYTHONPATH=crates/everudp/tests/net python3 -B -m unittest test_analyze_path_trace test_path_trace_options test_public_scheduler -q
```

The first three commands reproduce the stored path analysis, path summary and
scheduler summary. The tests pass (21 tests). An additional check verifies that
the signed boundary differences telescope to each public latency for all 200
rows; this is arithmetic validation, not proof of exclusive stage costs.

Raw perf is private outside git. Original private root-seal SHA256:
`bde4dbcbc2dc9b5872dfd55619675018a351aa62f1b258ac64a1387738fd146a`.
The sanitized export has a separate seal; nested measurement seals are intact.
No concurrent project work ran during measurement.

## Consequence

Do not rerun to seek a sustained slowdown or a favorable median. Inspect the
existing return-path send/receive scheduling before selecting another experiment.
The live gateway already uses bounded `poll_outbound`; its awaited `flush_output`
call is in writer revocation, not the healthy echo loop. The available markers do
not separate output queue-to-stream acceptance from stream acceptance-to-receive,
so they cannot justify replacing the transport or claiming a QUIC latency floor.
No runtime improvement or production PASS is claimed by this archive.
