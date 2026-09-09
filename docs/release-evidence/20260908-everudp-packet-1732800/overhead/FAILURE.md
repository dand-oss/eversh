# Diagnostic schedule failure retained

Original runner SHA256 7b9c8ac5e8de1100477a0ca5de59b395d89e6dcc50f49f2c3486b9095a97ba4d
terminated with exit 1 (exec handle 31237).
Ten blocks completed. Block loss5-pair1-trace0 failed in its first candidate,
zmosh-quic, before start.ready. No measured samples exist for this block.
stderr reports `state=awaiting_ack`; fixture reports no warmup marker echo.
The underlying cause is not established. No timeout/threshold/source changed.

Do not rerun or replace the failed block. Continue only the five unstarted
blocks using their original source, artifacts, seeds, affinity and order.
The unmatched loss5-pair1-trace1 block must not enter paired overhead estimates.
Report the failure and incomplete schedule; never claim 16 successful blocks.
The complete 0% loss cell and three completed 5% loss pairs may be summarized
with that explicit missing-pair limitation, not as a complete preregistered run.

Protocol correction: original pre-registration text mistakenly called the
runner's 100 argument warmup trials. It is gap_ms=100; the canonical compiled
fixture's existing warm_up routine was unchanged in every block.

The first continuation (exec85964) also terminated exit1: loss5-pair1-trace1
failed in its first candidate, zmosh-quic, with the same awaiting_ack state
and warmup timeout before start.ready. Both halves used seed210910102;
neither produced measured samples. This repeat establishes the symptom in
both modes at that seed, not the underlying cause. Pair1 is wholly missing.
Only four unstarted blocks remain: loss5 pair2 on/off and pair3 off/on.
