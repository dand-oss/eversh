# Stdin boundary diagnostic, not qualification

Bead eversh-5fc.67. Exact clean source
579450258a28fa7d41df4f7ffbe1954ded240232, binary
9121913a28b33761574409ea898c36a447b96497fc1d18c02c75e27b1e52ca5d.
Features: cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike.
Both behavioral experiments remain disabled by default.

Frozen protocol: 200 trials per candidate, 0% loss, client seed212300001,
order everudp,zmosh-udp,zmosh-quic, CPUs40,42,44,46, 100ms gaps. All three
diagnostic tracing flags enabled. No concurrent builds or agents during capture.
All600 exact responses passed, without retry; capture and build seals verified.
The five control/fixture binaries were reused byte-identically from the sealed
ordinary abccb1c build. Original control provenance is retained alongside the
candidate provenance. Binaries remain outside this archive.

The strict stdin analyzer accepts all200 everudp rows, with no exclusions.
Each public-send-to-input-queue window must contain exactly one ordered sequence
of readiness, read-start, read-end, positive-data and dispatch markers. Retry,
missing, duplicate or ambiguous windows fail analysis rather than being dropped.

| Boundary | Median microseconds |
|---|---:|
| Public send to stdin readiness delivered | 97.948 |
| Readiness to read start | 0.477 |
| Read syscall | 5.520 |
| Read end to positive-data marker | 0.220 |
| Data to dispatch | 1.3825 |
| Dispatch to input queued | 1.786 |
| Public send to input queued | 110.9275 |

These are independent wall-clock medians, not additive exclusive CPU costs.
The dominant first boundary includes the fixture PTY write, kernel wakeup,
reactor delivery and task scheduling. It cannot be attributed wholly to QUIC
or Tokio, nor treated as a recoverable optimization budget.

Crucially, the older paired scheduler/syscall capture in
../20260907-everudp-input-schedule-b35097b already compared the original UDP
control. Its sealed analysis was reproduced during this audit. Forward/reverse
send-to-scheduled medians were74.551/72.339us for everudp-floor and
80.543/75.995us for zmosh. Scheduled-to-read medians were22.4665/22.165us
versus12.176/12.762us. That older build and partial tracing coverage do not
qualify the current candidate, but show why the whole98us must not be blamed
on a uniquely everudp path. A stdin-only rewrite is not justified here.

Reproduce from the repository root:

```sh
python3 -B crates/everudp/tests/net/analyze_stdin_trace.py docs/release-evidence/20260908-everudp-stdin-57945025/capture/everudp
python3 -B docs/release-evidence/20260908-everudp-stdin-57945025/analyze_sender.py
```

Additional exact-packet analysis accepts all 200 rows. Both directions have
identical completion-packet length distributions: four 45-byte and 196 46-byte
packets, exactly one STREAM frame each, and zero blocked send polls. Payload
size, multiple STREAM frames and blocked socket readiness therefore do not
explain this capture's input/output asymmetry.

Reservation-to-build median is46.748us input versus11.5375us output. Coverage
inside the protocol transmit call is27.208us versus6.806us; outside measured
protocol/send calls it is17.8835us versus4.631us. Send-call overlap is zero.
These independent medians are nonadditive. Protocol call duration can include
preemption and memory/cache effects, not only packet-construction CPU. No
particular cause or implementation change is established by this comparison.

The sender analyzer also requires exactly one ordered driver-poll, matching
connection-service and protocol-start chain before each completion packet.
All 200 rows in each direction meet this requirement without exclusions:

| Sender phase | Input median us | Output median us |
|---|---:|---:|
| Operation reservation to driver poll | 10.3975 | 3.337 |
| Driver poll to lock acquired | 0.478 | 0.198 |
| Driver service to protocol start | 5.772 | 1.095 |
| Protocol start to built packet | 27.208 | 6.806 |

The lock is not the dominant measured boundary. A task-ordering change cannot
be credited with removing the complete reservation-to-build interval.
`packet_builder.rs::finish` emits the built marker after packet/header
encryption, so that final span includes protocol selection, framing and crypto.
It is not an isolated encryption benchmark. Earlier ordinary-production CPU
sampling in ../20260908-everudp-cpu-bd53692 found samples distributed across
protocol instructions and kernel work, not a single proven removable leaf.

The root SHA256SUMS seals the retained raw capture, its original inventory,
provenance and this interpretation. This instrumented single block does not
replace the frozen uninstrumented performance qualification, establish parity,
or certify reliability/security for this SHA. Production performance remains FAIL.
