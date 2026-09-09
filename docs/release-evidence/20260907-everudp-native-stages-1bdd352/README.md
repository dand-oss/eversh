# Native client stage attribution — diagnostic only

Measured runtime: `1bdd3528bc4d257a1f33adc96b1fb48a97a777d9`, tree
`a034e66f58ed14dae078752b1ec18bceeb95b06b`. The build provenance seals the
release binaries and frozen zmosh UDP baseline
`dfc8395b5edcd237bf82712fbde879c6e8be7dfa`.
The strict stage analyzer was committed at
`ddae4d054af1587d804256ae5e953df76e36e0fc`; its dependencies are copied here.

## Experiment

Each symmetric-loss cell (0% and 5%) has four 200-trial blocks. Native tracing
is off/on/on/off; candidate order is native-first/reverse/native-first/reverse.
Seeds are 970701–970704 and 975701–975704 respectively. All 3,200 candidate
responses passed the exact-byte oracle. All 800 traced public trial windows
were accepted by the strict analyzer, with no exclusions. Warmup is validated
but excluded from measured windows. Original per-block seals are retained.

The initial execution stopped before starting 0% block 3 because generated
Python cache files violated the clean-source gate. The cache was moved out of
the repository and only the remaining declared blocks were run, with unchanged
seeds. No failed or partial measured block was replaced. Subsequent Python
execution disables bytecode generation.

## Results and limits

| Loss | Native off/on p50 (µs) | On/off ratio, central 95% interval | Control off/on p50 (µs) |
|---|---|---|---|
| 0% | 403 / 378.5 | 0.9392 [0.8681, 1.0013] | 417.5 / 422.5 |
| 5% | 430 / 436 | 1.0140 [0.9610, 1.0894] | 420.5 / 428.5 |

Intervals use 20,000 deterministic within-block stratified resamples. They do
not capture independent experiment replication uncertainty. The apparently
faster traced 0% result is not proof of negative overhead or causal savings;
observer effects and host/block variation remain. Full control intervals are
in `analysis.json`.

Pooled pre-offer reactor wall medians are 20.6505 µs (0%) and 21.020 µs (5%);
individual block medians range from 20.3035 to 21.549 µs. Post-offer medians are
72.6975 and 78.335 µs and include UDP send work. Encoding medians are 6.577 and
7.186 µs. These intervals must not be subtracted from unrelated medians as
predicted savings. Wall and thread-CPU samples are sequential, not simultaneous;
their difference is not an exact scheduler-delay measurement. Back-to-back
CPU-clock calibration medians are 721.5 ns and 566 ns, reported without correction.

Independent read-only Luna review verified all eight seals, build identity,
order, seeds, tracing flags and all 800 accepted windows. It supports a bounded
A/B experiment offering newly encoded initial input before the pre-offer reactor
step, while retaining bounded post-offer service, fairness, retries and
backpressure. It does not establish causality or authorize production adoption.

This archive is **DIAGNOSTIC**, not performance qualification. Instrumented
manifests are rejected by the floor qualifier. Frozen floor and production
thresholds remain unchanged; no production readiness or gate PASS is claimed.

## Reproduce

From this directory, run `sha256sum -c SHA256SUMS --quiet`, then
`PYTHONDONTWRITEBYTECODE=1 python3 -B analyze.py > /tmp/native-stages-reproduced.json`
and `cmp analysis.json /tmp/native-stages-reproduced.json`.
The analyzer validates per-block seals, source/build identity, artifact hashes,
public sample boundaries, exact responses, packet accounting and strict traces.
Raw qdisc output, including its original whitespace, is intentionally preserved.
