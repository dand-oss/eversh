# Packet assembly attribution: diagnostic only

Bead eversh-5fc.74; clean runtime/harness source
0c53e24cf18e68e910ace90daf7433be7a95aeb6. Default-off hooks bracket ordinary
primary-path frame population and preserve packet identity. No normal transport
behavior changed. Features: cli,path-packet-diagnostics,application-task-spike,
stream-delivery-spike,quic-ack-threshold-spike. All three path trace flags are on.

Predeclared zero-loss capture: seed 213200001, E/U/Q order, 200 trials per
implementation, CPUs 40,42,44,46, 100ms gaps. Five frozen control/fixture binaries
were reused unchanged. No concurrent builds or agents. All 600 exact public
responses passed, and all 200 everudp operations joined to exact frame-population
and protection markers. No missing or ambiguous operation was omitted.

Independent interval medians in microseconds:

| Interval | Client input | Gateway output |
|---|---:|---:|
| Operation reservation to frame population | 37.499 | 7.0335 |
| Frame population | 11.7365 | 2.4455 |
| Frame population end to protection | 1.990 | 0.4485 |
| Protection | 5.8005 | 1.2545 |
| Protection end to packet built | 0.5445 | 0.163 |

These are instrumented wall-clock intervals, not exclusive CPU costs. The first
interval includes driver dispatch, protocol selection and header construction;
it is not a measurement of any single function. Do not sum independent medians,
subtract old-run timings or infer a causal optimization gain. The input/output
asymmetry does not by itself explain why the client is slower. A successful
transcript gate is not a performance qualification pass.

The largest measured input interval remains before frame population. The next
analysis should correlate existing same-capture I/O driver/protocol spans with
that interval before proposing a frame-serialization or crypto rewrite. No
architecture or production-profile change is adopted from this diagnostic.

Validation: 22 focused Python tests (new join initially RED for missing function,
then GREEN); 58 instrumented and 34 default everudp library tests; 396 isolated
noq-proto tests; strict Clippy. Real older traces retain 200 valid protection
joins but correctly fail the new assembly mode because markers are absent.

From repository root:

```sh
python3 -B docs/release-evidence/20260909-everudp-assembly-0c53e24c/analyze.py
```

Raw diagnostic traces, manifests, response transcripts and nested seals are
retained in capture/. No binaries or credentials are archived. Build provenance
records frozen control identities. Production performance remains FAIL; full
exact-SHA reliability, security and independent-review acceptance remains pending.
